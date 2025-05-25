//! # Issuance API
//!
//! A (naive) HTTP server for verifiable credential issuance.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Host};
use credibil_core::urlencode;
use credibil_oid4vci::blockstore::BlockStore;
use credibil_oid4vci::http::IntoHttp;
use credibil_oid4vci::status::StatusListRequest;
use credibil_oid4vci::{
    AuthorizationRequest, CreateOfferRequest, CredentialHeaders, CredentialOfferRequest,
    CredentialRequest, DeferredCredentialRequest, MetadataRequest, NonceRequest,
    NotificationHeaders, NotificationRequest, PushedAuthorizationRequest, ServerRequest,
    TokenRequest,
};
use oauth2::CsrfToken;
use serde::Deserialize;
use serde_json::json;
use test_utils::issuer::Issuer;
use test_utils::issuer::data::{CLIENT, NORMAL_USER, SERVER};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
const ISSUER: &[u8] = include_bytes!("../../crates/test-utils/data/issuer/local-issuer.json");
const ISSUER_ID: &str = "http://localhost:8080";

static AUTH_REQUESTS: LazyLock<RwLock<HashMap<String, AuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static PAR_REQUESTS: LazyLock<RwLock<HashMap<String, PushedAuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[tokio::main]
async fn main() {
    let provider = Issuer::new("http://localhost:8080").await;

    // add some data
    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", "normal_user", NORMAL_USER).await.unwrap();
    BlockStore::put(&provider, "owner", "CLIENT", CLIENT_ID, CLIENT).await.unwrap();

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");
    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/credential_offer/{offer_id}", get(credential_offer))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(oauth_server))
        .route("/.well-known/did.json", get(did_json))
        .route("/auth", get(authorize))
        .route("/par", get(par))
        .route("/login", post(handle_login))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .route("/deferred_credential", post(deferred_credential))
        .route("/notification", post(notification))
        .route("/statuslists/{id}", get(statuslists))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(provider);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

#[axum::debug_handler]
async fn create_offer(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Json(req): Json<CreateOfferRequest>,
) -> impl IntoResponse {
    credibil_oid4vci::handle(&format!("http://{host}"), req, &provider).await.into_http()
}

#[axum::debug_handler]
async fn credential_offer(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Path(offer_id): Path<String>,
) -> impl IntoResponse {
    let request = CredentialOfferRequest { id: offer_id };
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

// TODO: override default  Cache-Control header to allow caching
#[axum::debug_handler]
async fn metadata(
    headers: HeaderMap, State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    let request = credibil_oid4vci::Request {
        body: MetadataRequest,
        headers: headers.try_into().expect("should find language header"),
    };
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

// OAuth Server metadata endpoint
#[axum::debug_handler]
async fn oauth_server(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    let req = ServerRequest {
        // Issuer should be derived from path component if necessary
        issuer: None,
    };
    credibil_oid4vci::handle(&format!("http://{host}"), req, &provider).await.into_http()
}

/// Authorize endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-4.1.2
///
/// The authorization server issues an authorization code and delivers it to the
/// client by adding the response parameters to the query component of the
/// redirection URI using the "application/x-www-form-urlencoded" format.
#[axum::debug_handler]
async fn authorize(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Form(req): Form<AuthorizationRequest>,
) -> impl IntoResponse {
    let AuthorizationRequest::Object(object) = req.clone() else {
        panic!("should be an object request");
    };

    // return error if no subject_id
    if object.subject_id.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no subject_id"}))).into_response();
    }

    // show login form if subject_id is unauthorized
    // (subject is authorized if they can be found in the 'authorized' HashMap)
    if AUTH_REQUESTS.read().await.get(&object.subject_id).is_none() {
        // save request
        let csrf = CsrfToken::new_random();
        let token = csrf.secret();

        AUTH_REQUESTS.write().await.insert(token.clone(), req);

        // prompt user to login
        let login_form = format!(
            r#"
            <form method="post" action="/login">
                <input type="text" name="username" placeholder="username" value="bob" />
                <input type="password" name="password" placeholder="password" value="password" />
                <input type="hidden" name="csrf_token" value="{token}" />
                <input type="submit" value="Login" />
            </form>
            "#
        );
        return (StatusCode::UNAUTHORIZED, Html(login_form)).into_response();
    }

    // process request
    let Some(redirect_uri) = object.redirect_uri.clone() else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no redirect_uri"})))
            .into_response();
    };

    match credibil_oid4vci::handle(&format!("http://{host}"), req, &provider).await {
        Ok(v) => (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?code={}", v.body.code)))
            .into_response(),
        Err(e) => {
            let err_params = serde_urlencoded::to_string(&e).unwrap();
            (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?{err_params}")))
                .into_response()
        }
    }
}

/// Authorize endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-4.1.2
///
/// The authorization server issues an authorization code and delivers it to the
/// client by adding the response parameters to the query component of the
/// redirection URI using the "application/x-www-form-urlencoded" format.
#[axum::debug_handler]
async fn par(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Form(req): Form<PushedAuthorizationRequest>,
) -> impl IntoResponse {
    let object = &req.request;

    // return error if no subject_id
    if object.subject_id.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no subject_id"}))).into_response();
    }

    // show login form if subject_id is unauthorized
    // (subject is authorized if they can be found in the 'authorized' HashMap)
    if PAR_REQUESTS.read().await.get(&object.subject_id).is_none() {
        // save request
        let csrf = CsrfToken::new_random();
        let token = csrf.secret();

        PAR_REQUESTS.write().await.insert(token.clone(), req.clone());

        // prompt user to login
        let login_form = format!(
            r#"
            <form method="post" action="/login">
                <input type="text" name="username" placeholder="username" value="bob" />
                <input type="password" name="password" placeholder="password" value="password" />
                <input type="hidden" name="csrf_token" value="{token}" />
                <input type="submit" value="Login" />
            </form>
            "#
        );
        return (StatusCode::UNAUTHORIZED, Html(login_form)).into_response();
    }

    // process request
    credibil_oid4vci::handle(&format!("http://{host}"), req, &provider)
        .await
        .into_http()
        .into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    csrf_token: String,
}

#[axum::debug_handler]
async fn handle_login(
    TypedHeader(host): TypedHeader<Host>, Form(req): Form<LoginRequest>,
) -> impl IntoResponse {
    // check username and password
    if req.username != "bob" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid username"})))
            .into_response();
    }
    if req.password != "password" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid password"})))
            .into_response();
    }

    // update 'authorized' HashMap with subject as key
    let Some(auth_req) = AUTH_REQUESTS.write().await.remove(&req.csrf_token) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid csrf_token"})))
            .into_response();
    };
    AUTH_REQUESTS.write().await.insert(req.username.clone(), auth_req.clone());

    // redirect back to authorize endpoint
    let qs = urlencode::to_string(&auth_req).expect("should serialize");
    (StatusCode::FOUND, Redirect::to(&format!("http://{host}/auth?{qs}"))).into_response()
}

#[axum::debug_handler]
async fn token(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>, body: String,
) -> impl IntoResponse {
    let Ok(tr) = TokenRequest::form_decode(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid request"})))
            .into_response();
    };
    credibil_oid4vci::handle(&format!("http://{host}"), tr, &provider)
        .await
        .into_http()
        .into_response()
}

#[axum::debug_handler]
async fn nonce(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    let request = NonceRequest;
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

#[axum::debug_handler]
async fn credential(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>, Json(request): Json<CredentialRequest>,
) -> impl IntoResponse {
    let request = credibil_oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: auth.token().to_string(),
        },
    };
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

#[axum::debug_handler]
async fn deferred_credential(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<DeferredCredentialRequest>,
) -> impl IntoResponse {
    let request = credibil_oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: auth.token().to_string(),
        },
    };
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

/// Notification endpoint
#[axum::debug_handler]
async fn notification(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<NotificationRequest>,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, auth.token().parse().unwrap());
    let request = credibil_oid4vci::Request {
        body: request,
        headers: NotificationHeaders {
            authorization: auth.token().to_string(),
        },
    };
    credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

// Status Lists endpoint
#[axum::debug_handler]
async fn statuslists(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>, Path(id): Path<String>,
) -> impl IntoResponse {
    let request = StatusListRequest { id: Some(id) };
    credibil_status::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

#[axum::debug_handler]
async fn did_json(State(provider): State<Issuer>) -> impl IntoResponse {
    let doc = provider.did().await.expect("should fetch DID document");
    Json(doc).into_response()
}
