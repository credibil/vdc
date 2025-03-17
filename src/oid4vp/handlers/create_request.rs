//! # Create Request handler
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use when requesting a Verifiable Presentation from
//! a Wallet.

use std::collections::HashMap;

use chrono::Utc;
use credibil_infosec::Algorithm;
use uuid::Uuid;

use crate::core::generate;
use crate::dif_exch::{ClaimFormat, PresentationDefinition};
use crate::oid4vp::endpoint::{Body, Handler, NoHeaders, Request};
use crate::oid4vp::provider::{Provider, StateStore};
use crate::oid4vp::state::{Expire, State};
use crate::oid4vp::types::{
    CreateRequestRequest, CreateRequestResponse, DeviceFlow, RequestObject, RequestType,
    ResponseType,
};
use crate::oid4vp::{Error, Result};

/// Create an Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn create_request(
    verifier: &str, provider: &impl Provider, request: CreateRequestRequest,
) -> Result<CreateRequestResponse> {
    verify(&request).await?;

    // TODO: build dynamically...
    let fmt = ClaimFormat {
        alg: Some(vec![Algorithm::EdDSA.to_string()]),
        proof_type: None,
    };

    let definition = PresentationDefinition {
        id: Uuid::new_v4().to_string(),
        purpose: Some(request.purpose.clone()),
        input_descriptors: request.input_descriptors.clone(),
        format: Some(HashMap::from([("jwt_vc".to_string(), fmt)])),
        name: None,
    };
    let uri_token = generate::uri_token();

    // get client metadata
    // let Ok(verifier_meta) = Metadata::verifier(provider, verifier).await else {
    //     return Err(Error::InvalidRequest("invalid client_id".to_string()));
    // };

    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(uri_token.clone()),
        nonce: generate::nonce(),
        request_type: RequestType::Definition(definition),
        client_metadata: None, //Some(verifier_meta),
        ..Default::default()
    };

    let mut response = CreateRequestResponse::default();

    // Response Mode "direct_post" is RECOMMENDED for cross-device flows.
    // TODO: replace hard-coded endpoints with Provider-set values
    if request.device_flow == DeviceFlow::CrossDevice {
        req_obj.response_mode = Some("direct_post".to_string());
        req_obj.client_id = format!("{verifier}/post");
        req_obj.response_uri = Some(format!("{verifier}/post"));
        response.request_uri = Some(format!("{verifier}/request/{uri_token}"));
    } else {
        req_obj.client_id = format!("{verifier}/callback");
        response.request_object = Some(req_obj.clone());
    }

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

impl Handler for Request<CreateRequestRequest, NoHeaders> {
    type Response = CreateRequestResponse;

    fn handle(
        self, verifier: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        create_request(verifier, provider, self.body)
    }
}

impl Body for CreateRequestRequest {}

#[allow(clippy::unused_async)]
async fn verify(request: &CreateRequestRequest) -> Result<()> {
    tracing::debug!("create_request::verify");

    if request.input_descriptors.is_empty() {
        return Err(Error::InvalidRequest("no credentials specified".to_string()));
    }
    Ok(())
}
