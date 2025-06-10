//! # Issuance API
//!
//! A (naive) HTTP server for OpenID4VCI issuer.

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::Result;
use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Host};
use credibil_oid4vci::http::IntoHttp;
use credibil_oid4vci::identity::did::Document;
use credibil_oid4vci::status::StatusListRequest;
use credibil_oid4vci::{
    AuthorizationRequest, CreateOfferRequest, CredentialHeaders, CredentialOfferRequest,
    CredentialRequest, DeferredCredentialRequest, MetadataRequest, NonceRequest,
    NotificationHeaders, NotificationRequest, PushedAuthorizationRequest, ServerRequest,
    TokenRequest, html,
};
use oauth2::CsrfToken;
use serde::Deserialize;
use serde_json::json;
use test_utils::issuer::Issuer;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

static AUTH_REQUESTS: LazyLock<RwLock<HashMap<String, AuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static PAR_REQUESTS: LazyLock<RwLock<HashMap<String, PushedAuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub async fn serve(issuer_id: &'static str) -> Result<JoinHandle<()>> {
    let issuer = Issuer::new(issuer_id).await;

    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/credential_offer/{offer_id}", get(credential_offer))
        .route("/auth", get(authorize))
        .route("/par", get(par))
        .route("/login", post(handle_login))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .route("/deferred_credential", post(deferred_credential))
        .route("/notification", post(notification))
        .route("/statuslists/{id}", get(statuslists))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(oauth_server))
        .route("/.well-known/did.json", get(did))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(issuer);

    let jh = tokio::spawn(async move {
        let addr = issuer_id.strip_prefix("http://").unwrap_or(issuer_id);
        let listener = TcpListener::bind(&addr).await.expect("should bind");
        tracing::info!("listening on {addr}");
        axum::serve(listener, router).await.expect("server should run");
    });

    Ok(jh)
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
        headers: headers.into(),
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
            let err_params = html::url_encode(&e).unwrap();
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
    let qs = html::url_encode(&auth_req).expect("should serialize");
    (StatusCode::FOUND, Redirect::to(&format!("http://{host}/auth?{qs}"))).into_response()
}

#[axum::debug_handler]
async fn token(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Form(form): Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    let Ok(tr) = TokenRequest::form_decode(&form) else {
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
async fn did(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>, request: Request,
) -> Result<Json<Document>, AppError> {
    let request = credibil_identity::did::DocumentRequest {
        url: format!("http://{host}{}", request.uri()),
    };
    let doc = credibil_identity::did::handle(&format!("http://{host}"), request, &provider)
        .await
        .map_err(AppError::from)?;
    Ok(Json(doc.0.clone()))
}

// Wrap anyhow::Error.
struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self.0)).into_response()
    }
}
