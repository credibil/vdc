//! # HTTP Server Example
//!
//! This example demonstrates how to use the Verifiable Credential Issuer (VCI)

mod provider;

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Host};
use credibil_vc::oid4vci::types::{
    AuthorizationRequest, CreateOfferRequest, CreateOfferResponse, CredentialHeaders,
    CredentialOfferRequest, CredentialOfferResponse, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, DeferredCredentialResponse, MetadataRequest, MetadataResponse,
    NotificationHeaders, NotificationRequest, NotificationResponse, OAuthServerRequest,
    OAuthServerResponse, PushedAuthorizationRequest, PushedAuthorizationResponse, TokenRequest,
    TokenResponse,
};
use credibil_vc::oid4vci::{self, endpoint};
use credibil_vc::urlencode;
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use self::provider::ProviderImpl;

static AUTH_REQUESTS: LazyLock<RwLock<HashMap<String, AuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static PAR_REQUESTS: LazyLock<RwLock<HashMap<String, PushedAuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[allow(clippy::needless_return)]
#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/credential_offer/{offer_id}", get(credential_offer))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(oauth_server))
        .route("/auth", get(authorize))
        .route("/par", get(par))
        .route("/login", post(handle_login))
        .route("/notification", post(notification))
        .route("/token", post(token))
        .route("/credential", post(credential))
        .route("/deferred_credential", post(deferred_credential))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(ProviderImpl::new());

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

// Credential Offer endpoint
#[axum::debug_handler]
async fn create_offer(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    Json(req): Json<CreateOfferRequest>,
) -> AxResult<CreateOfferResponse> {
    endpoint::handle(&format!("http://{host}"), req, &provider).await.into()
}

// Retrieve Authorization Request Object endpoint
#[axum::debug_handler]
async fn credential_offer(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    Path(offer_id): Path<String>,
) -> AxResult<CredentialOfferResponse> {
    let request = CredentialOfferRequest { id: offer_id };
    endpoint::handle(&format!("http://{host}"), request, &provider).await.into()
}

// Metadata endpoint
// TODO: override default  Cache-Control header to allow caching
#[axum::debug_handler]
async fn metadata(
    headers: HeaderMap, State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
) -> AxResult<MetadataResponse> {
    let req = MetadataRequest {
        languages: headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string),
    };
    endpoint::handle(&format!("http://{host}"), req, &provider).await.into()
}

// OAuth Server metadata endpoint
#[axum::debug_handler]
async fn oauth_server(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
) -> AxResult<OAuthServerResponse> {
    let req = OAuthServerRequest {
        // Issuer should be derived from path component if necessary
        issuer: None,
    };
    endpoint::handle(&format!("http://{host}"), req, &provider).await.into()
}

/// Authorize endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-4.1.2
///
/// The authorization server issues an authorization code and delivers it to the
/// client by adding the response parameters to the query component of the
/// redirection URI using the "application/x-www-form-urlencoded" format.
#[axum::debug_handler]
async fn authorize(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
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
                <input type="text" name="username" placeholder="username" value="normal_user" />
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

    match endpoint::handle(&format!("http://{host}"), req, &provider).await {
        Ok(v) => (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?code={}", v.code)))
            .into_response(),
        Err(e) => {
            let err_params = e.to_querystring();
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
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
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
                <input type="text" name="username" placeholder="username" value="normal_user" />
                <input type="password" name="password" placeholder="password" value="password" />
                <input type="hidden" name="csrf_token" value="{token}" />
                <input type="submit" value="Login" />
            </form>
            "#
        );
        return (StatusCode::UNAUTHORIZED, Html(login_form)).into_response();
    }

    // process request
    let axresponse: AxResult<PushedAuthorizationResponse> =
        endpoint::handle(&format!("http://{host}"), req, &provider).await.into();
    axresponse.into_response()
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
    if req.username != "normal_user" {
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

/// Token endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-5.1
///
/// The parameters are included in the entity-body of the HTTP response using
/// the "application/json" media type as defined by [RFC4627].  The parameters
/// are serialized into JSON
///
/// The authorization server MUST include the HTTP "Cache-Control" response
/// header field [RFC2616] with a value of "no-store" in any response containing
/// tokens, credentials, or other sensitive information, as well as the "Pragma"
/// response header field [RFC2616] with a value of "no-cache".
///
/// [RFC2616]: (https://www.rfc-editor.org/rfc/rfc2616)
#[axum::debug_handler]
async fn token(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    Form(req): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let Ok(tr) = TokenRequest::form_decode(&req) else {
        tracing::error!("unable to turn HashMap {req:?} into TokenRequest");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid request"})))
            .into_response();
    };

    let response: AxResult<TokenResponse> =
        match endpoint::handle(&format!("http://{host}"), tr, &provider).await {
            Ok(v) => Ok(v).into(),
            Err(e) => {
                tracing::error!("error getting token: {e}");
                Err(e).into()
            }
        };
    response.into_response()
}

// Credential endpoint
#[axum::debug_handler]
async fn credential(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>, Json(request): Json<CredentialRequest>,
) -> AxResult<CredentialResponse> {
    let request = endpoint::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: auth.token().to_string(),
        },
    };

    endpoint::handle(&format!("http://{host}"), request, &provider).await.into()
}

// Deferred endpoint
#[axum::debug_handler]
async fn deferred_credential(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(mut req): Json<DeferredCredentialRequest>,
) -> AxResult<DeferredCredentialResponse> {
    req.access_token = auth.0.token().to_string();

    #[allow(clippy::large_futures)]
    endpoint::handle(&format!("http://{host}"), req, &provider).await.into()
}

/// Notification endpoint
///
/// This endpoint is used by the Wallet to notify the Credential Issuer of
/// certain events for issued Credentials. These events enable the Credential
/// Issuer to take subsequent actions after issuance. The Credential Issuer
/// needs to return one or more notification_id parameters in the Credential
/// Response for the Wallet to be able to use this endpoint. Support for this
/// endpoint is OPTIONAL. The Issuer cannot assume that a notification will be
/// sent for every issued Credential since the use of this Endpoint is not
/// mandatory for the Wallet.
///
/// The Wallet MUST present to the Notification Endpoint a valid Access Token
/// issued at the Token Endpoint.
///
/// The notification from the Wallet is idempotent. When the Credential Issuer
/// receives multiple identical calls from the Wallet for the same
/// notification_id, it returns success. Due to the network errors, there are no
/// guarantees that a Credential Issuer will receive a notification within a
/// certain time period or at all.
///
/// Communication with the Notification Endpoint MUST utilize TLS.
#[axum::debug_handler]
async fn notification(
    State(provider): State<ProviderImpl>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<NotificationRequest>,
) -> AxResult<NotificationResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, auth.token().parse().unwrap());
    let request = endpoint::Request {
        body: request,
        headers: NotificationHeaders {
            authorization: auth.token().to_string(),
        },
    };
    endpoint::handle(&format!("http://{host}"), request, &provider).await.into()
}

// ----------------------------------------------------------------------------
// Axum Response
// ----------------------------------------------------------------------------

/// Wrapper for `axum::Response`
pub struct AxResult<T>(oid4vci::Result<T>);

impl<T> IntoResponse for AxResult<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        match self.0 {
            Ok(v) => (StatusCode::OK, Json(json!(v))),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_json())),
        }
        .into_response()
    }
}

impl<T> From<oid4vci::Result<T>> for AxResult<T> {
    fn from(val: oid4vci::Result<T>) -> Self {
        Self(val)
    }
}
