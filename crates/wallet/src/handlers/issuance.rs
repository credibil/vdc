use anyhow::{Context, Result, anyhow};
use chrono::{Duration, Utc};
use credibil_core::state::StateStore;
use credibil_oid4vci::identity::Signature;
use credibil_oid4vci::jose::JwsBuilder;
use credibil_oid4vci::vdc::sd_jwt;
use credibil_oid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, IssuerMetadata, JwtType, NonceResponse,
    OfferType, ProofClaims, ServerMetadata, State, TokenGrantType, TokenRequest, TokenResponse,
    html,
};
// use jsonrpc::JsonRpcRequest;
// use rpc_types::client::OfferReceived;
// use rpc_types::wallet::OfferAccepted;
use serde::Deserialize;

// use wasi_bindings::messaging::producer;
// use wasi_bindings::messaging::types::{Client as MsgClient, Message};
// use wasi_http_ext::{Client, Request, Response};
use crate::provider::Provider;

// FIXME: replace with env var
const HOST: &str = "http://localhost:8082";

#[derive(Debug, Deserialize)]
struct OfferParams {
    credential_offer_uri: String,
}

// Process a credential offer from an issuer.
async fn create_request(owner: &str, provider: &impl Provider, request: OfferType) -> Result<()> {
    // --------------------------------------------------
    // Fetch offer
    // --------------------------------------------------
    let OfferType::Uri(credential_offer_uri) = request else {
        return Err(anyhow!("expected offer type to be URI"));
    };
    let response = Client::new().get(credential_offer_uri).send().context("fetching offer")?;
    let credential_offer: CredentialOffer = response.json().context("parsing offer")?;

    // --------------------------------------------------
    // Fetch metadata
    // --------------------------------------------------
    let credential_issuer = &credential_offer.credential_issuer;
    let meta_uri = format!("{credential_issuer}/.well-known/openid-credential-issuer");
    let response = Client::new().get(meta_uri).send().context("fetching issuer metadata")?;
    let issuer_meta: IssuerMetadata = response.json().context("parsing issuer metadata")?;

    // configurations for offered credentials
    let mut offered_configs = vec![];
    for config_id in &credential_offer.credential_configuration_ids {
        let Some(config) = issuer_meta.credential_configurations_supported.get(config_id) else {
            return Err(anyhow!("unsupported credential configuration: {config_id}"));
        };
        offered_configs.push(config.clone());
    }

    // --------------------------------------------------
    // Notify client of new offer
    // --------------------------------------------------
    let client_offer = OfferReceived {
        issuer: credential_issuer.to_string(),
        subject: subject.to_string(),
        credentials: offered_configs.clone(),
    };
    let rpc = JsonRpcRequest::notify("client.offer", client_offer);
    let client = MsgClient::connect("nats").context("connecting to NATS")?;
    let message = Message::new(&rpc.to_json().context("serializing RPC request")?);
    producer::send(&client, &rpc.method, message).context("sending NATS message")?;

    // --------------------------------------------------
    // Save offer to state
    // --------------------------------------------------
    // FIXME: find better state key
    let state = State { expires_at: Utc::now() + Duration::minutes(20), body: credential_offer };
    block_on(async { StateStore::put(&provider, &owner, "offer", &state).await })
        .context("saving offer to state")?;

    Ok(vec![].into())
}

// Accept a credential offer and fetch the credential.
pub fn accept_offer(accepted: &OfferAccepted) -> Result<()> {
    // --------------------------------------------------
    // Get offer from state
    // --------------------------------------------------
    let owner = format!("{HOST}/{}", accepted.subject);
    let provider = block_on(async { Wallet::new(&owner).await }).context("creating provider")?;

    let state: State<CredentialOffer> =
        block_on(async { StateStore::get(&provider, &owner, "offer").await })
            .context("retrieving offer from state")?;
    let offer = state.body;
    let credential_issuer = &offer.credential_issuer;

    // --------------------------------------------------
    // Fetch metadata
    // --------------------------------------------------
    tracing::trace!("fetching issuer metadata");
    let meta_uri = format!("{credential_issuer}/.well-known/openid-credential-issuer");
    let response = Client::new().get(meta_uri).send().context("fetching issuer metadata")?;
    let issuer_meta: IssuerMetadata = response.json().context("parsing issuer metadata")?;

    let server_uri = format!("{credential_issuer}/.well-known/oauth-authorization-server");
    let response = Client::new().get(server_uri).send().context("fetching server metadata")?;
    let server_meta: ServerMetadata = response.json().context("parsing  server metadata")?;

    // --------------------------------------------------
    // Fetch token
    // --------------------------------------------------
    let Some(grants) = offer.grants else {
        return Err(anyhow!("missing grants"));
    };
    let Some(pre_auth_grant) = grants.pre_authorized_code else {
        return Err(anyhow!("missing pre-authorized code grant"));
    };
    let grant_type = TokenGrantType::PreAuthorizedCode {
        pre_authorized_code: pre_auth_grant.pre_authorized_code,
        tx_code: accepted.tx_code.clone(),
    };

    let token_req =
        TokenRequest::builder().client_id("public-client").grant_type(grant_type).build();
    let token_uri = server_meta.oauth.token_endpoint;
    let response =
        Client::new().post(&token_uri).form(token_req).send().context("fetching token")?;
    let token_resp = response.json::<TokenResponse>().context("parsing token response")?;

    // --------------------------------------------------
    // Proof for credential request
    // --------------------------------------------------
    let Some(nonce_uri) = issuer_meta.nonce_endpoint else {
        return Err(anyhow!("issuer does not support nonce endpoint"));
    };
    let response = Client::new().post(&nonce_uri).send().context("fetching nonce")?;
    let nonce_resp = response.json::<NonceResponse>().context("deserializing response")?;

    // proof of possession of key material
    let jws = block_on(async {
        let vm = provider.verification_method().await.context("getting verification method")?;
        let key_binding = vm.try_into().context("getting key binding")?;

        JwsBuilder::new()
            .typ(JwtType::ProofJwt)
            .payload(
                ProofClaims::new().credential_issuer(credential_issuer).nonce(&nonce_resp.c_nonce),
            )
            .key_binding(&key_binding)
            .add_signer(&provider)
            .build()
            .await
    })
    .context("building proof JWS")?;
    let proof_jws = jws.encode().context("encoding proof JWS")?;

    // --------------------------------------------------
    // Fetch credential
    // --------------------------------------------------
    let Some(auth_details) = &token_resp.authorization_details.as_ref() else {
        return Err(anyhow!("missing authorization details"));
    };

    let request = CredentialRequest::builder()
        .credential_identifier(&auth_details[0].credential_identifiers[0])
        .with_proof(proof_jws)
        .build();
    let response = Client::new()
        .post(&issuer_meta.credential_endpoint)
        .bearer_auth(&token_resp.access_token)
        .json(&request)
        .send()
        .context("fetching credential")?;
    let credential_resp =
        response.json::<CredentialResponse>().context("deserializing credential response")?;

    // --------------------------------------------------
    // Store credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = credential_resp else {
        return Err(anyhow!("expected credentials in response"));
    };
    let credential = credentials.first().ok_or_else(|| anyhow!("no credentials"))?;
    let Some(sd_jwt) = credential.credential.as_str() else {
        return Err(anyhow!("credential is not an SD-JWT"));
    };

    let q = block_on(async { sd_jwt::to_queryable(sd_jwt, &provider).await })
        .context("converting SD-JWT to queryable")?;
    provider.add(&q).context("storing credential")?;

    Ok(())
}
