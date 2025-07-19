//! # Issuance API
//!
//! A (naive) HTTP server for OpenID4VCI issuer.

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::Result;
use axum::extract::{Path, Request, State};
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
    AuthorizationRequest, Client, CreateOfferRequest, CredentialHeaders, CredentialOfferRequest,
    CredentialRequest, DeferredCredentialRequest, IssuerRequest, NonceRequest, NotificationHeaders,
    NotificationRequest, PushedAuthorizationRequest, ServerRequest, TokenRequest, html,
};
use oauth2::CsrfToken;
use serde::Deserialize;
use serde_json::json;
use test_utils::Issuer;
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
    let client = Client::new(Issuer::new(issuer_id).await.expect("should create issuer"));

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
        .route("/statuslists", get(statuslists))
        .route("/.well-known/openid-credential-issuer", get(issuer))
        .route("/.well-known/oauth-authorization-server", get(server))
        .route("/.well-known/did.json", get(did))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(client);

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
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    Json(request): Json<CreateOfferRequest>,
) -> impl IntoResponse {
    client.request(request).owner(&format!("http://{host}")).await.into_http()
}

#[axum::debug_handler]
async fn credential_offer(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    Path(offer_id): Path<String>,
) -> impl IntoResponse {
    let request = CredentialOfferRequest { id: offer_id };
    client.request(request).owner(&format!("http://{host}")).await.into_http()
}

// TODO: override default  Cache-Control header to allow caching
#[axum::debug_handler]
async fn issuer(
    headers: HeaderMap, State(client): State<Client<Issuer<'static>>>,
    TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    client
        .request(IssuerRequest)
        .owner(&format!("http://{host}"))
        .headers(headers.into())
        .await
        .into_http()
}

#[axum::debug_handler]
async fn server(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    let request = ServerRequest { issuer: None };
    client.request(request).owner(&format!("http://{host}")).await.into_http()
}

#[axum::debug_handler]
async fn authorize(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    Form(request): Form<AuthorizationRequest>,
) -> impl IntoResponse {
    let AuthorizationRequest::Object(object) = request.clone() else {
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

        AUTH_REQUESTS.write().await.insert(token.clone(), request);

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

    match client.request(request).owner(&format!("http://{host}")).await {
        Ok(v) => (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?code={}", v.body.code)))
            .into_response(),
        Err(e) => {
            let err_params = html::url_encode(&e).unwrap();
            (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?{err_params}")))
                .into_response()
        }
    }
}

#[axum::debug_handler]
async fn par(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    Form(request): Form<PushedAuthorizationRequest>,
) -> impl IntoResponse {
    let object = &request.request;

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

        PAR_REQUESTS.write().await.insert(token.clone(), request.clone());

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
    client.request(request).owner(&format!("http://{host}")).await.into_http().into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    csrf_token: String,
}

#[axum::debug_handler]
async fn handle_login(
    TypedHeader(host): TypedHeader<Host>, Form(request): Form<LoginRequest>,
) -> impl IntoResponse {
    // check username and password
    if request.username != "bob" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid username"})))
            .into_response();
    }
    if request.password != "password" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid password"})))
            .into_response();
    }

    // update 'authorized' HashMap with subject as key
    let Some(auth_req) = AUTH_REQUESTS.write().await.remove(&request.csrf_token) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid csrf_token"})))
            .into_response();
    };
    AUTH_REQUESTS.write().await.insert(request.username.clone(), auth_req.clone());

    // redirect back to authorize endpoint
    let qs = html::url_encode(&auth_req).expect("should serialize");
    (StatusCode::FOUND, Redirect::to(&format!("http://{host}/auth?{qs}"))).into_response()
}

#[axum::debug_handler]
async fn token(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    Form(form): Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    let Ok(r) = TokenRequest::form_decode(&form) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid request"})))
            .into_response();
    };
    client.request(r).owner(&format!("http://{host}")).await.into_http().into_response()
}

#[axum::debug_handler]
async fn nonce(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
) -> impl IntoResponse {
    client.request(NonceRequest).owner(&format!("http://{host}")).await.into_http()
}

#[axum::debug_handler]
async fn credential(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>, Json(r): Json<CredentialRequest>,
) -> impl IntoResponse {
    let headers = CredentialHeaders { authorization: auth.token().to_string() };
    client.request(r).owner(&format!("http://{host}")).headers(headers).await.into_http()
}

#[axum::debug_handler]
async fn deferred_credential(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(r): Json<DeferredCredentialRequest>,
) -> impl IntoResponse {
    let headers = CredentialHeaders { authorization: auth.token().to_string() };
    client.request(r).owner(&format!("http://{host}")).headers(headers).await.into_http()
}

#[axum::debug_handler]
async fn notification(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<NotificationRequest>,
) -> impl IntoResponse {
    let headers = NotificationHeaders { authorization: auth.token().to_string() };
    client.request(request).owner(&format!("http://{host}")).headers(headers).await.into_http()
}

#[axum::debug_handler]
async fn statuslists(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    request: Request,
) -> impl IntoResponse {
    let uri = request.uri().to_string();
    let request = StatusListRequest { uri: Some(uri) };
    client.request(request).owner(&format!("http://{host}")).await.into_http()
}

#[axum::debug_handler]
async fn did(
    State(client): State<Client<Issuer<'static>>>, TypedHeader(host): TypedHeader<Host>,
    request: Request,
) -> Result<Json<Document>, AppError> {
    let request =
        credibil_binding::DocumentRequest { url: format!("http://{host}/{}", request.uri()) };
    let doc =
        client.request(request).owner(&format!("http://{host}")).await.map_err(AppError::from)?;
    Ok(Json(doc.0.clone()))
}

// Wrap anyhow::Error.
struct AppError {
    status: StatusCode,
    error: serde_json::Value,
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, error: json!({"error": e.to_string()}) }
    }
}

impl From<credibil_oid4vci::Error> for AppError {
    fn from(e: credibil_oid4vci::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: serde_json::to_value(&e).unwrap_or_default(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, format!("{}", self.error)).into_response()
    }
}
