//! # Verifiable Credential Verifier
//!
//! This is a simple Verifiable Credential Verifier (VCP) that implements the
//! [Verifiable Credential HTTP API](
//! https://identity.foundation/verifiable-credential/spec/#http-api).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_core::blockstore::BlockStore;
use credibil_core::http::IntoHttp;
use credibil_openid::oid4vp::{self, AuthorzationResponse, GenerateRequest, RequestUriRequest};
use test_providers::verifier::data::VERIFIER;
use test_providers::verifier::{VERIFIER_ID, Verifier};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[allow(clippy::needless_return)]
#[tokio::main]
async fn main() {
    let provider = Verifier::new("examples_verifier").await;

    // add some data
    BlockStore::put(&provider, "owner", "VERIFIER", VERIFIER_ID, VERIFIER).await.unwrap();

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/create_request", post(create_request))
        .route("/request/{id}", get(request_uri))
        .route("/callback", get(response))
        .route("/post", post(response))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(provider);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("local_addr should be set"));
    axum::serve(listener, router).await.expect("should run");
}

// Generate Authorization Request endpoint
#[axum::debug_handler]
async fn create_request(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Json(request): Json<GenerateRequest>,
) -> impl IntoResponse {
    oid4vp::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

// Retrieve Authorization Request Object endpoint
#[axum::debug_handler]
async fn request_uri(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>, Path(id): Path<String>,
) -> impl IntoResponse {
    // TODO: add wallet_metadata and wallet_nonce
    let request = RequestUriRequest {
        id,
        wallet_metadata: None, // Some(wallet_metadata),
        wallet_nonce: None,    // Some(wallet_nonce)
    };
    oid4vp::handle(&format!("http://{host}"), request, &provider).await.into_http()
}

// Wallet Authorization response endpoint
#[axum::debug_handler]
async fn response(
    State(provider): State<Verifier>, TypedHeader(host): TypedHeader<Host>,
    Form(request): Form<String>,
) -> impl IntoResponse {
    let Ok(req) = AuthorzationResponse::form_decode(&request) else {
        tracing::error!("unable to turn HashMap {request:?} into AuthorzationResponse");
        return (StatusCode::BAD_REQUEST, "unable to turn request into AuthorzationResponse")
            .into_response();
    };
    oid4vp::handle(&format!("http://{host}"), req, &provider).await.into_http().into_response()
}
