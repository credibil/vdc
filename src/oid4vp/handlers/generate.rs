//! # Create Request handler
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use when requesting a Verifiable Presentation from
//! a Wallet.

use chrono::Utc;

use crate::core::generate;
use crate::oid4vp::endpoint::{Body, Handler, NoHeaders, Request, Response};
use crate::oid4vp::provider::{Provider, StateStore};
use crate::oid4vp::state::{Expire, State};
use crate::oid4vp::types::{
    ClientIdentifier, DeviceFlow, GenerateRequest, GenerateResponse, Query, RequestObject,
    ResponseMode, ResponseType,
};
use crate::oid4vp::{Error, Result};

/// Create an Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn generate(
    verifier: &str, provider: &impl Provider, request: GenerateRequest,
) -> Result<GenerateResponse> {
    // TODO: build dynamically...
    // let fmt = ClaimFormat {
    //     alg: Some(vec![Algorithm::EdDSA.to_string()]),
    //     proof_type: None,
    // };

    let uri_token = generate::uri_token();

    // get client metadata
    // let Ok(verifier_meta) = Metadata::verifier(provider, verifier).await else {
    //     return Err(Error::InvalidRequest("invalid client_id".to_string()));
    // };

    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(uri_token.clone()),
        nonce: generate::nonce(),
        query: Query::Dcql(request.query),
        client_metadata: None, //Some(verifier_meta),
        ..Default::default()
    };

    // Response Mode "direct_post" is RECOMMENDED for cross-device flows.
    // TODO: replace hard-coded endpoints with Provider-set values
    let response = if request.device_flow == DeviceFlow::CrossDevice {
        req_obj.response_mode = ResponseMode::DirectPost {
            response_uri: format!("{verifier}/post"),
        };
        req_obj.client_id = ClientIdentifier::RedirectUri(format!("{verifier}/post"));
        GenerateResponse::Uri(format!("{verifier}/request/{uri_token}"))
    } else {
        req_obj.client_id = ClientIdentifier::RedirectUri(format!("{verifier}/callback"));
        GenerateResponse::Object(req_obj.clone())
    };

    // save request object in state
    let state = State {
        expires_at: Utc::now() + Expire::Request.duration(),
        request_object: req_obj,
    };

    StateStore::put(provider, &uri_token, &state, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(response)
}

impl Handler for Request<GenerateRequest, NoHeaders> {
    type Response = GenerateResponse;

    fn handle(
        self, verifier: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<impl Into<Response<Self::Response>>>> + Send {
        generate(verifier, provider, self.body)
    }
}

impl Body for GenerateRequest {}
