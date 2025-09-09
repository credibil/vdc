//! # Request Object Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created
//! Authorization Request Object.
//!
//! The Request Object is created by the Verifier when calling the `generate`
//! endpoint to create an Authorization Request. Instead of sending the Request
//! Object to the Wallet, the Verifier sends an Authorization Request
//! containing the `request_uri` endpoint which can be used to retrieve the
//! saved Request Object.
//!
//! At the same time, the Wallet can use the call to the endpoint to
//! communicate information about it's capabilities to the Verifier. This
//! information (using `wallet_metadata`) can be used tailor the Request Object
//! to match the Wallet's capabilities.

use anyhow::Context;
use credibil_api::{Body, Handler, Request, Response};
use credibil_jose::JwsBuilder;

use crate::JwtType;
use crate::error::invalid;
use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::types::{ClientId, RequestObject, RequestUriRequest, RequestUriResponse};

/// Endpoint for the Wallet to request the Verifier's Request Object when
/// engaged in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
pub async fn request_uri(
    verifier: &str, provider: &impl Provider, request: RequestUriRequest,
) -> Result<RequestUriResponse> {
    // retrieve request object from state
    let state = StateStore::get::<RequestObject>(provider, verifier, &request.id)
        .await
        .context("issue retrieving state")?;

    let mut request_object = state.body;
    request_object.wallet_nonce = request.wallet_nonce;

    // verify client_id (perhaps should use 'verify' method?)
    if request_object.client_id != ClientId::RedirectUri(format!("{verifier}/post")) {
        return Err(invalid!("client ID mismatch"));
    }

    // FIXME: use wallet_metadata to determine supported formats, alg_values, etc.
    if let Some(wallet_metadata) = request.wallet_metadata
        && let Some(_supported_algs) = wallet_metadata.request_object_signing_alg_values_supported
    {
        // FIXME: ensure we use a supported alg for signing
        // TODO: Encryption - check jwks/jwks_uri param for Wallet's public key
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post
    }

    let kid = provider.verification_method().await.context("issue getting verification method")?;
    let key_binding = kid.try_into().context("issue converting key_binding")?;
    let jws = JwsBuilder::new()
        .typ(JwtType::OauthAuthzReqJwt)
        .payload(request_object)
        .key_binding(&key_binding)
        .add_signer(provider)
        .build()
        .await
        .context("issue building jwt")?;

    Ok(RequestUriResponse::Jwt(jws.encode().context("issue encoding jwt")?))
}

impl<P: Provider> Handler<RequestUriResponse, P> for Request<RequestUriRequest> {
    type Error = Error;

    async fn handle(self, verifier: &str, provider: &P) -> Result<Response<RequestUriResponse>> {
        Ok(request_uri(verifier, provider, self.body).await?.into())
    }
}

impl Body for RequestUriRequest {}
