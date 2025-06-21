//! # Verifiable Credential Verifier
//!
//! A (naive) HTTP server for OpenID4VP verifier.

use anyhow::Result;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_oid4vp::http::IntoHttp;
use credibil_oid4vp::identity::did::Document;
use credibil_oid4vp::{AuthorizationResponse, Client, CreateRequest, RequestUriRequest};
use serde_json::json;
use test_utils::verifier::Verifier;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub async fn serve(verifier_id: &'static str) -> Result<JoinHandle<()>> {
    let verifier = Verifier::new(verifier_id).await;

    let router = Router::new()
        .route("/create_request", post(create_request))
        .route("/request/{id}", get(request_uri))
        .route("/callback", get(authorization))
        .route("/post", post(authorization))
        .route("/.well-known/did.json", get(did))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .with_state(verifier);

    let jh = tokio::spawn(async move {
        let addr = verifier_id.strip_prefix("http://").unwrap_or(verifier_id);
        let listener = TcpListener::bind(addr).await.expect("should bind");
        tracing::info!("listening on {addr}");
        axum::serve(listener, router).await.expect("server should run");
    });

    Ok(jh)
}

#[axum::debug_handler]
async fn create_request(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Json(request): Json<CreateRequest>,
) -> impl IntoResponse {
    Client::new(&format!("http://{host}"), &provider).handle(request).await.into_http()
    // credibil_oid4vp::handle(&format!("http://{host}"), request, &provider).await.into_http()
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

    // credibil_oid4vp::handle(&format!("http://{host}"), request, &provider)
    //     .await
    //     .into_http()
    //     .into_response()
    Client::new(&format!("http://{host}"), &provider)
        .handle(request)
        .await
        .into_http()
        .into_response()
}

#[axum::debug_handler]
async fn authorization(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Form(form): Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    let Ok(request) = AuthorizationResponse::form_decode(&form) else {
        return (StatusCode::BAD_REQUEST, "issue deserializing `AuthorizationResponse`")
            .into_response();
    };

    // credibil_oid4vp::handle(&format!("http://{host}"), req, &provider)
    //     .await
    //     .into_http()
    //     .into_response()
    Client::new(&format!("http://{host}"), &provider)
        .handle(request)
        .await
        .into_http()
        .into_response()
}

#[axum::debug_handler]
async fn did(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>, request: Request,
) -> Result<Json<Document>, AppError> {
    let request = credibil_proof::DocumentRequest {
        url: format!("http://{host}{}", request.uri()),
    };
    let doc = credibil_proof::handle(&format!("http://{host}"), request, &provider)
        .await
        .map_err(AppError::from)?;
    Ok(Json(doc.0.clone()))
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
