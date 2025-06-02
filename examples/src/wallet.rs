//! # Web Wallet
//!
//! A (naive) HTTP server for a web wallet.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use credibil_oid4vci::identity::SignerExt;
use credibil_oid4vci::identity::did::Document;
use credibil_oid4vci::jose::JwsBuilder;
use credibil_oid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, IssuerMetadata, JwtType, NonceResponse,
    ProofClaims, ServerMetadata, TokenGrantType, TokenRequest, TokenResponse, sd_jwt,
};
use credibil_oid4vp::identity::se::Algorithm;
use credibil_oid4vp::jose::{self, Jwt};
use credibil_oid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientId, RequestObject, RequestUriMethod,
    RequestUriRequest, RequestUriResponse, ResponseMode, VpFormat, Wallet, did_jwk, vp_token,
};
use http::StatusCode;
use serde::Deserialize;
use test_utils::wallet;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    provider: Arc<Mutex<wallet::Wallet>>,
}

pub async fn serve(wallet_id: &'static str) -> Result<JoinHandle<()>> {
    let wallet = wallet::Wallet::new(wallet_id).await;

    let router = Router::new()
        .route("/credential_offer", get(credential_offer))
        .route("/authorize", get(authorize))
        .route("/.well-known/did.json", get(did))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .with_state(AppState {
            provider: Arc::new(Mutex::new(wallet)),
        });

    let jh = tokio::spawn(async move {
        let addr = wallet_id.strip_prefix("http://").unwrap_or(wallet_id);
        let listener = TcpListener::bind(addr).await.expect("should bind");
        tracing::info!("listening on {addr}");
        axum::serve(listener, router).await.expect("server should run");
    });

    Ok(jh)
}

#[derive(Deserialize)]
struct OfferUri {
    credential_offer_uri: String,
    tx_code: Option<String>,
}

#[axum::debug_handler]
async fn credential_offer(
    State(state): State<AppState>, Query(offer_uri): Query<OfferUri>,
) -> Result<(), AppError> {
    let http = reqwest::Client::new();

    // --------------------------------------------------
    // Fetch offer
    // --------------------------------------------------
    let http_resp = http.get(&offer_uri.credential_offer_uri).send().await?;
    if http_resp.status() != StatusCode::OK {
        let status = http_resp.status();
        let body = http_resp.text().await?;
        return Err(anyhow!("issue fetching offer: {status}, {body}").into());
    }
    let offer = http_resp.json::<CredentialOffer>().await?;
    let issuer_uri = &offer.credential_issuer;

    // --------------------------------------------------
    // Fetch metadata
    // --------------------------------------------------
    let meta_uri = format!("{issuer_uri}/.well-known/openid-credential-issuer");
    let issuer = http.get(&meta_uri).send().await?.json::<IssuerMetadata>().await?;

    let server_uri = format!("{issuer_uri}/.well-known/oauth-authorization-server");
    let server = http.get(&server_uri).send().await?.json::<ServerMetadata>().await?;

    // --------------------------------------------------
    // Fetch token
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

    let provider = state.provider.lock().await;
    let token_req = TokenRequest::builder().client_id(provider.id()).grant_type(grant_type).build();
    let token_uri = server.oauth.token_endpoint;
    let http_resp = http.post(&token_uri).form(&token_req).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("token: {body}").into());
    }
    let token_resp = http_resp.json::<TokenResponse>().await?;
    drop(provider);

    // --------------------------------------------------
    // Proof for credential request
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
    let provider = state.provider.lock().await;
    let key = provider.verification_method().await?.try_into()?;

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(
            ProofClaims::new()
                .credential_issuer(&offer.credential_issuer)
                .nonce(&nonce_resp.c_nonce),
        )
        .key_ref(&key)
        .add_signer(&*provider)
        .build()
        .await?;
    let jwt = jws.encode()?;

    drop(provider);

    // --------------------------------------------------
    // Fetch credential
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
    // Store credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = credential_resp else {
        return Err(anyhow!("expected credentials in response").into());
    };
    let credential = credentials.first().ok_or_else(|| anyhow!("no credentials"))?;
    let Some(jwt) = credential.credential.as_str() else {
        return Err(anyhow!("credential is not an SD-JWT").into());
    };

    let mut provider = state.provider.lock().await;
    let q = sd_jwt::to_queryable(jwt, &*provider).await?;
    (*provider).add(q).await?;
    drop(provider);

    Ok(())
}

#[axum::debug_handler]
async fn authorize(
    State(state): State<AppState>, Query(request): Query<AuthorizationRequest>,
) -> Result<(), AppError> {
    let http = reqwest::Client::new();

    // --------------------------------------------------
    // Fetch Authorization Request Object
    // --------------------------------------------------
    let req_uri = match &request {
        AuthorizationRequest::Uri(req_uri) => req_uri,
        _ => return Err(anyhow!("expected request URI").into()),
    };
    if req_uri.request_uri_method != Some(RequestUriMethod::Post) {
        return Err(anyhow!("`request_uri_method` must be 'post'").into());
    }

    let object_req = RequestUriRequest {
        id: req_uri.request_uri.clone(),
        wallet_metadata: Some(Wallet {
            vp_formats_supported: Some(vec![VpFormat::DcSdJwt {
                sd_jwt_alg_values: Some(vec![Algorithm::EdDSA]),
                kb_jwt_alg_values: Some(vec![Algorithm::EdDSA]),
            }]),
            ..Default::default()
        }),
        wallet_nonce: Some("qPmxiNFCR3QTm19POc8u".to_string()),
    };
    let form = object_req.form_encode().context("encoding request")?;

    let http_resp = http.get(&req_uri.request_uri).form(&form).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}").into());
    }

    // --------------------------------------------------
    // Verify the Authorization Request
    // --------------------------------------------------
    let RequestUriResponse::Jwt(jwt) = http_resp.json::<RequestUriResponse>().await? else {
        return Err(anyhow!("expected JWT in response").into());
    };

    let provider = state.provider.lock().await;
    let jwk = async |kid: String| did_jwk(&kid, &*provider).await;
    let decoded: Jwt<RequestObject> = jose::decode_jws(&jwt, jwk).await?;
    let request_object = decoded.claims;

    // --------------------------------------------------
    // Process the Authorization Request
    // --------------------------------------------------
    let credentials = provider.fetch().await?;
    let results = request_object.dcql_query.execute(&credentials)?;
    if results.is_empty() {
        return Err(anyhow!("no matching credentials found").into());
    }

    // --------------------------------------------------
    // Generate a VP token
    // --------------------------------------------------
    let vp_token = vp_token::generate(&request_object, &results, &*provider).await?;
    let response = AuthorizationResponse {
        vp_token,
        state: request_object.state,
    };

    // --------------------------------------------------
    // Return an Authorization Response
    // --------------------------------------------------
    let response_uri = match &request_object.response_mode {
        ResponseMode::DirectPostJwt { response_uri }
        | ResponseMode::DirectPost { response_uri } => response_uri,
        ResponseMode::Fragment { redirect_uri: _ } => {
            return Err(anyhow!("`response_mode` must be 'direct_post'").into());
        }
    };
    if req_uri.client_id != ClientId::RedirectUri(response_uri.clone()) {
        return Err(anyhow!("invalid client id").into());
    }

    let form = response.form_encode().context("encoding response")?;
    let http_resp = http.post(response_uri).form(&form).send().await?;
    if http_resp.status() != StatusCode::OK {
        let status = http_resp.status();
        let body = http_resp.text().await?;
        return Err(anyhow!("issue sending response: {status}, {body}").into());
    }

    Ok(())
}

#[axum::debug_handler]
async fn did(State(state): State<AppState>) -> Result<Json<Document>, AppError> {
    let provider = state.provider.lock().await;
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
