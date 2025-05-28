//! # Verifiable Credential Verifier
//!
//! A (naive) HTTP server for OpenID4VP verifier.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_oid4vp::http::IntoHttp;
use credibil_oid4vp::identity::did::Document;
use credibil_oid4vp::{AuthorizationResponse, GenerateRequest, RequestUriRequest};
use serde_json::json;
use test_utils::verifier::Verifier;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub async fn serve(addr: impl Into<String>, verifier: Verifier) -> Result<JoinHandle<()>> {
    let router = Router::new()
        .route("/create_request", post(create_request))
        .route("/request/{id}", get(request_uri))
        .route("/callback", get(authorization))
        .route("/post", post(authorization))
        .route("/.well-known/did.json", get(did_json))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .with_state(verifier);

    let addr = addr.into();
    let jh = tokio::spawn(async move {
        let listener = TcpListener::bind(&addr).await.expect("should bind");
        tracing::info!("listening on {addr}");
        axum::serve(listener, router).await.expect("server should run");
    });

    Ok(jh)
}

#[axum::debug_handler]
async fn create_request(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Json(request): Json<GenerateRequest>,
) -> impl IntoResponse {
    credibil_oid4vp::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

#[axum::debug_handler]
async fn request_uri(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>, Path(id): Path<String>,
    body: Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    let Ok(mut request) = RequestUriRequest::form_decode(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid request"})))
            .into_response();
    };
    request.id = id;
    credibil_oid4vp::handle(&format!("http://{host}"), request, &provider)
        .await
        .into_http()
        .into_response()
}

#[axum::debug_handler]
async fn authorization(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Form(form): Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    let Ok(req) = AuthorizationResponse::form_decode(&form) else {
        return (StatusCode::BAD_REQUEST, "issue deserializing `AuthorizationResponse`")
            .into_response();
    };
    credibil_oid4vp::handle(&format!("http://{host}"), req, &provider)
        .await
        .into_http()
        .into_response()
}

use anyhow::Result;

#[axum::debug_handler]
async fn did_json(State(provider): State<Verifier>) -> Result<Json<Document>, AppError> {
    let doc = provider.did().await.map_err(AppError::from)?;
    Ok(Json(doc))
}

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
