//! # Request Object Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created
//! Authorization Request Object.
//!
//! The Request Object is created by the Verifier when calling the `Create
//! Request` endpoint to create an Authorization Request. Instead of sending the
//! Request Object to the Wallet, the Verifier sends an Authorization Request
//! containing a `request_uri` which can be used to retrieve the saved Request
//! Object.
//!
//! Per the [JWT VC Presentation Profile], the Request Object MUST be returned
//! as an encoded JWT.
//!
//! [JWT VC Presentation Profile]: (https://identity.foundation/jwt-vc-presentation-profile)

use credibil_infosec::jose::JwsBuilder;

use crate::oid4vp::endpoint::{Body, Handler, NoHeaders, Request, Response};
use crate::oid4vp::provider::{Provider, StateStore};
use crate::oid4vp::state::State;
use crate::oid4vp::types::{ClientIdentifier, RequestObjectRequest, RequestObjectResponse};
use crate::oid4vp::{Error, Result};
use crate::w3c_vc::proof::Type;

/// Endpoint for the Wallet to request the Verifier's Request Object when
/// engaged in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
pub async fn request(
    verifier: &str, provider: &impl Provider, request: RequestObjectRequest,
) -> Result<RequestObjectResponse> {
    // retrieve request object from state
    let state = StateStore::get::<State>(provider, &request.id)
        .await
        .map_err(|e| Error::ServerError(format!("issue fetching state: {e}")))?;
    let req_obj = state.request_object;

    // verify client_id (perhaps should use 'verify' method?)
    if req_obj.client_id != ClientIdentifier::RedirectUri(format!("{verifier}/post")) {
        return Err(Error::InvalidRequest("client ID mismatch".to_string()));
    }

    // TODO: use wallet_metadata to determine supported formats, alg_values, etc.
    // if let Some(wallet_metadata) = request.wallet_metadata {
    //     let vp_formats = wallet_metadata.vp_formats_supported.unwrap_or_default();
    //     if !vp_formats.is_empty() {
    //
    //     }
    // }

    // TODO: add wallet_nonce to request object

    let jws = JwsBuilder::new()
        .typ(Type::OauthAuthzReqJwt)
        .payload(req_obj)
        .add_signer(provider)
        .build()
        .await
        .map_err(|e| Error::ServerError(format!("issue building jwt: {e}")))?;
    let req_obj_jwt =
        jws.encode().map_err(|e| Error::ServerError(format!("issue encoding jwt: {e}")))?;

    Ok(RequestObjectResponse::Jwt(req_obj_jwt))
}

impl Handler for Request<RequestObjectRequest, NoHeaders> {
    type Response = RequestObjectResponse;

    async fn handle(
        self, verifier: &str, provider: &impl Provider,
    ) -> Result<impl Into<Response<Self::Response>>> {
        request(verifier, provider, self.body).await
    }
}

impl Body for RequestObjectRequest {}
