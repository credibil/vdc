//! # Web Wallet
//!
//! A (naive) HTTP server for a web wallet.

use anyhow::{Result, anyhow};
use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use credibil_oid4vci::identity::SignerExt;
use credibil_oid4vci::identity::did::Document;
use credibil_oid4vci::jose::JwsBuilder;
use credibil_oid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, Issuer, JwtType, NonceResponse,
    ProofClaims, Server, TokenGrantType, TokenRequest, TokenResponse, sd_jwt,
};
use http::StatusCode;
use serde::Deserialize;
use test_utils::wallet::Wallet;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

#[tokio::main]
async fn main() {
    let provider = Wallet::new("http://localhost:8081").await;

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");
    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/credential_offer", get(credential_offer))
        .route("/.well-known/did.json", get(did_json))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(provider);

    let listener = TcpListener::bind("0.0.0.0:8081").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

#[derive(Deserialize)]
struct OfferUri {
    credential_offer_uri: String,
    tx_code: Option<String>,
}

// extract the credential offer URI from the query string, e.g.
// GET http://localhost:8081/credential_offer?
//   credential_offer_uri=http://localhost:8080/credential-offer/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM
#[axum::debug_handler]
async fn credential_offer(
    State(mut provider): State<Wallet>, Query(offer_uri): Query<OfferUri>,
) -> Result<(), AppError> {
    let http = reqwest::Client::new();

    // --------------------------------------------------
    // fetch offer
    // --------------------------------------------------
    let http_resp = http.get(&offer_uri.credential_offer_uri).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("offer: {body}").into());
    }
    let offer = http_resp.json::<CredentialOffer>().await?;
    let issuer_uri = &offer.credential_issuer;

    // fetch metadata
    let meta_uri = format!("{issuer_uri}/.well-known/openid-credential-issuer");
    let issuer = http.get(&meta_uri).send().await?.json::<Issuer>().await?;

    let server_uri = format!("{issuer_uri}/.well-known/oauth-authorization-server");
    let server = http.get(&server_uri).send().await?.json::<Server>().await?;

    // --------------------------------------------------
    // fetch token
    // --------------------------------------------------
    let Some(grants) = offer.grants else {
        return Err(anyhow!("missing grants").into());
    };
    let Some(pre_auth_grant) = grants.pre_authorized_code else {
        return Err(anyhow!("missing pre-authorized code grant").into());
    };
    let grant_type = TokenGrantType::PreAuthorizedCode {
        pre_authorized_code: pre_auth_grant.pre_authorized_code,
        tx_code: offer_uri.tx_code.clone(),
    };

    let token_req = TokenRequest::builder().client_id(CLIENT_ID).grant_type(grant_type).build();
    let token_uri = server.oauth.token_endpoint;
    let http_resp = http.post(&token_uri).form(&token_req).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("token: {body}").into());
    }
    let token_resp = http_resp.json::<TokenResponse>().await?;

    // --------------------------------------------------
    // proof for credential request
    // --------------------------------------------------
    let Some(nonce_uri) = issuer.nonce_endpoint else {
        return Err(anyhow!("issuer does not support nonce endpoint").into());
    };
    let http_resp = http.post(&nonce_uri).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("nonce: {body}").into());
    }
    let nonce_resp = http_resp.json::<NonceResponse>().await?;

    // proof of possession of key material
    let key = provider.verification_method().await?.try_into()?;

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(
            ProofClaims::new()
                .credential_issuer(&offer.credential_issuer)
                .nonce(&nonce_resp.c_nonce),
        )
        .key_ref(&key)
        .add_signer(&provider)
        .build()
        .await?;
    let jwt = jws.encode()?;

    // --------------------------------------------------
    // fetch credential
    // --------------------------------------------------
    let Some(auth_details) = token_resp.authorization_details.as_ref() else {
        return Err(anyhow::anyhow!("missing authorization details").into());
    };
    let request = CredentialRequest::builder()
        .credential_identifier(&auth_details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();

    let http_resp = http
        .post(&issuer.credential_endpoint)
        .bearer_auth(token_resp.access_token)
        .json(&request)
        .send()
        .await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("credential: {body}").into());
    }
    let credential_resp = http_resp.json::<CredentialResponse>().await?;

    // --------------------------------------------------
    // store credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = credential_resp else {
        return Err(anyhow!("expected credentials in response").into());
    };
    let credential = credentials.first().ok_or_else(|| anyhow!("no credentials"))?;
    let Some(jwt) = credential.credential.as_str() else {
        return Err(anyhow!("credential is not an SD-JWT").into());
    };

    let q = sd_jwt::to_queryable(jwt, &provider).await?;
    provider.add(q);

    Ok(())
}

#[axum::debug_handler]
async fn did_json(State(provider): State<Wallet>) -> Result<Json<Document>, AppError> {
    let doc = provider.did().await.map_err(AppError::from)?;
    Ok(Json(doc))
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
