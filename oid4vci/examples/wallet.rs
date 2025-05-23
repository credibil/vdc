use anyhow::{Result, anyhow};
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_oid4vci::identity::SignerExt;
use credibil_oid4vci::jose::JwsBuilder;
use credibil_oid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, Issuer, JwtType, NonceResponse,
    ProofClaims, Server, TokenGrantType, TokenRequest, TokenResponse,
};
use http::StatusCode;
use serde::Deserialize;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    let provider = Issuer::new("examples_issuer").await;

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/credential_offer", get(credential_offer))
        // .route("/authorize/", post(authorize))
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
}

#[axum::debug_handler]
async fn credential_offer(
    State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
    Query(offer_uri): Query<OfferUri>,
) -> Result<(), AppError> {
    // let provider = Provider::new(&holder).await;
    let client = reqwest::Client::new();

    // --------------------------------------------------
    // fetch offer
    // --------------------------------------------------
    let offer: CredentialOffer =
        client.get(&offer_uri.credential_offer_uri).send().await?.json().await?;
    let issuer_uri = &offer.credential_issuer;

    // fetch metadata
    let meta_uri = format!("{issuer_uri}/.well-known/openid-credential-issuer");
    let issuer: Issuer = client.get(&meta_uri).send().await?.json().await?;

    let server_uri = format!("{issuer_uri}/.well-known/oauth-authorization-server");
    let server: Server = client.get(&server_uri).send().await?.json().await?;

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
        tx_code: Some("tx_code".to_string()),
    };

    let token_req = TokenRequest::builder().client_id("client_id").grant_type(grant_type).build();
    let token_uri = format!("{issuer_uri}/{}", server.oauth.token_endpoint);
    let token_resp =
        client.post(&token_uri).form(&token_req).send().await?.json::<TokenResponse>().await?;

    // --------------------------------------------------
    // prepare a proof for a credential request
    // --------------------------------------------------
    let nonce_uri =
        format!("{issuer_uri}/{}", issuer.nonce_endpoint.unwrap_or("nonce".to_string()));
    let nonce_resp = client.post(&nonce_uri).send().await?.json::<NonceResponse>().await?;

    // proof of possession of key material

    // let key = provider.verification_method().await?;
    // let jws = JwsBuilder::new()
    //     .typ(JwtType::ProofJwt)
    //     .payload(
    //         ProofClaims::new()
    //             .credential_issuer(&offer.credential_issuer)
    //             .nonce(&nonce_resp.c_nonce),
    //     )
    //     .key_ref(&key.try_into()?)
    //     .add_signer(&provider)
    //     .build()
    //     .await?;
    // let jwt = jws.encode()?;
    let jwt = String::new();

    // --------------------------------------------------
    // fetch credential
    // --------------------------------------------------
    let Some(auth_details) = &token_resp.authorization_details.as_ref() else {
        return Err(anyhow::anyhow!("missing authorization details").into());
    };
    let request = CredentialRequest::builder()
        .credential_identifier(&auth_details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();
    let credential_uri = format!("{issuer_uri}/{}", issuer.credential_endpoint);

    let credential_resp = client
        .post(&credential_uri)
        .json(&request)
        .send()
        .await?
        .json::<CredentialResponse>()
        .await?;

    Ok(())
}

// #[axum::debug_handler]
// async fn authorize(
//     headers: HeaderMap, State(provider): State<Issuer>, TypedHeader(host): TypedHeader<Host>,
// ) -> impl IntoResponse {
//     // let request = credibil_oid4vci::Request {
//     //     body: MetadataRequest,
//     //     headers: headers.try_into().expect("should find language header"),
//     // };
//     // credibil_oid4vci::handle(&format!("http://{host}"), request, &provider).await.into_http()
//     todo!()
// }

// async fn handle_error(e: anyhow::Error) -> (StatusCode, String) {
//     (StatusCode::INTERNAL_SERVER_ERROR, format!("Something went wrong: {e}"))
// }

// Make our own error that wraps `anyhow::Error`.
struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Something went wrong: {}", self.0))
            .into_response()
    }
}
