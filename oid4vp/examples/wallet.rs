//! # Web Wallet
//!
//! A (naive) HTTP server for a web wallet.

use anyhow::{Context, Result, anyhow};
use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use credibil_oid4vp::blockstore::BlockStore;
use credibil_oid4vp::identity::did::Document;
use credibil_oid4vp::identity::se::Algorithm;
use credibil_oid4vp::identity::{Key, SignerExt};
use credibil_oid4vp::jose::{self, Jwt, PublicKeyJwk};
use credibil_oid4vp::status::{StatusClaim, StatusList, TokenBuilder};
use credibil_oid4vp::vdc::{SdJwtVcBuilder, sd_jwt};
use credibil_oid4vp::{
    RequestObject, RequestUriRequest, RequestUriResponse, VpFormat, Wallet, did_jwk,
};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use test_utils::issuer::{ISSUER_ID, Issuer};
use test_utils::verifier::VERIFIER_ID;
use test_utils::wallet;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    let mut provider = wallet::Wallet::new("http://localhost:8081").await;
    populate(&mut provider).await;

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("should set subscriber");
    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/authorize", get(authorize))
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

#[derive(Debug, Deserialize)]
struct Request {
    client_id: String,
    request_uri: String,
    request_uri_method: String,
}

// GET http://localhost:8081/authorize?
//   client_id=x509_san_dns%3Aclient.example.org
//   &request_uri=https%3A%2F%2Fclient.example.org%2Frequest%2Fvapof4ql2i7m41m68uep
//   &request_uri_method=post
#[axum::debug_handler]
async fn authorize(
    State(provider): State<wallet::Wallet>, Query(request): Query<Request>,
) -> Result<(), AppError> {
    let http = reqwest::Client::new();

    // --------------------------------------------------
    // fetch Request Object
    // --------------------------------------------------
    if request.client_id != format!("{VERIFIER_ID}/post") {
        return Err(anyhow!("invalid client id").into());
    }
    if request.request_uri_method != "post" {
        return Err(anyhow!("`request_uri_method` must be 'post'").into());
    }

    let object_req = RequestUriRequest {
        id: request.request_uri.clone(),
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

    let http_resp = http.get(&request.request_uri).form(&form).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}").into());
    }

    let RequestUriResponse::Jwt(jwt) = http_resp.json::<RequestUriResponse>().await? else {
        return Err(anyhow!("expected JWT in response").into());
    };
    let jwk = async |kid: String| did_jwk(&kid, &provider).await;
    let decoded: Jwt<RequestObject> = jose::decode_jws(&jwt, jwk).await?;
    let request_object = decoded.claims;

    // --------------------------------------------------
    // process the Authorization Request
    // --------------------------------------------------
    let stored_vcs = provider.fetch();
    let results = request_object.dcql_query.execute(stored_vcs).expect("should execute");

    // let vp_token =
    //     vp_token::generate(&request_object, &results, wallet).await.expect("should get token");
    // let request = AuthorizationResponse {
    //     vp_token,
    //     state: request_object.state,
    // };

    // --------------------------------------------------
    // return an Authorization Response
    // --------------------------------------------------

    Ok(())
}

#[axum::debug_handler]
async fn did_json(State(provider): State<wallet::Wallet>) -> Result<Json<Document>, AppError> {
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

// Initialise a mock "wallet" with test credentials.
async fn populate(wallet: &mut wallet::Wallet) {
    let issuer = Issuer::new("https://dcql.io/issuer").await;

    let Key::KeyId(did_url) = wallet.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let holder_jwk = did_jwk(&did_url, wallet).await.expect("should get key");

    // create a status list token
    let mut status_list = StatusList::new().expect("should create status list");
    let status_claim = status_list.add_entry("http://credibil.io/statuslists/1").unwrap();
    let token = TokenBuilder::new()
        .status_list(status_list.clone())
        .uri("https://example.com/statuslists/1")
        .signer(&issuer)
        .build()
        .await
        .expect("should build status list token");
    let data = serde_json::to_vec(&token).expect("should serialize");
    BlockStore::put(&issuer, "owner", "STATUSTOKEN", "http://credibil.io/statuslists/1", &data)
        .await
        .unwrap();

    // load credentials
    let vct = "https://credentials.example.com/identity_credential";
    let claims = json!({
        "given_name": "Alice",
        "family_name": "Holder",
        "address": {
            "street_address": "123 Elm St",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "90210",
            "country": "USA"
        },
        "birthdate": "2000-01-01"
    });
    let jwt = sd_jwt(&issuer, vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, &issuer).await.expect("should be SD-JWT");
    wallet.add(q);

    let vct = "https://othercredentials.example/pid";
    let claims = json!({
        "given_name": "John",
        "family_name": "Doe",
        "address": {
            "street_address": "34 Drake St",
            "locality": "Auckland",
            "region": "Auckland",
            "postal_code": "1010",
            "country": "New Zealand"
        },
        "birthdate": "2000-01-01"
    });
    let jwt = sd_jwt(&issuer, vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, &issuer).await.expect("should be SD-JWT");
    wallet.add(q);
}

async fn sd_jwt(
    issuer: &Issuer, vct: &str, claims: Value, holder_jwk: &PublicKeyJwk,
    status_claim: &StatusClaim,
) -> String {
    SdJwtVcBuilder::new()
        .vct(vct)
        .claims(claims.as_object().unwrap().clone())
        .issuer(ISSUER_ID)
        .key_binding(holder_jwk.clone())
        .status(status_claim.clone())
        .signer(issuer)
        .build()
        .await
        .expect("should build")
}
