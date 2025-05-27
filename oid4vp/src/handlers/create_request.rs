//! # Create Request handler
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use when requesting a Verifiable Presentation from
//! a Wallet.

use anyhow::Context;
use chrono::Utc;

use crate::common::generate;
use crate::common::state::State;
use crate::error::invalid;
use crate::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::provider::{Metadata, Provider, StateStore};
use crate::state::Expire;
use crate::types::{
    ClientId, DeviceFlow, GenerateRequest, GenerateResponse, RequestObject, ResponseType,
};

/// Create an Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn create_request(
    verifier: &str, provider: &impl Provider, request: GenerateRequest,
) -> Result<GenerateResponse> {
    let uri_token = generate::uri_token();

    let Ok(metadata) = Metadata::verifier(provider, verifier).await else {
        return Err(invalid!("{verifier} is not a valid client_id"));
    };

    // TODO: Response Mode "direct_post" is RECOMMENDED for cross-device flows.

    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(uri_token.clone()),
        nonce: generate::nonce(),
        dcql_query: request.dcql_query,
        client_metadata: Some(metadata.client_metadata),
        response_mode: request.response_mode,
        ..RequestObject::default()
    };

    // FIXME: replace hard-coded endpoints with Provider-set values
    let response = if request.device_flow == DeviceFlow::CrossDevice {
        req_obj.client_id = ClientId::RedirectUri(format!("{verifier}/post"));
        GenerateResponse::Uri(format!("{verifier}/request/{uri_token}"))
    } else {
        req_obj.client_id = ClientId::RedirectUri(format!("{verifier}/callback"));
        GenerateResponse::Object(req_obj.clone())
    };

    // save request object in state
    let state = State {
        expires_at: Utc::now() + Expire::Request.duration(),
        body: req_obj,
    };
    StateStore::put(provider, &uri_token, &state).await.context("saving state")?;

    Ok(response)
}

impl<P: Provider> Handler<GenerateResponse, P> for Request<GenerateRequest> {
    type Error = Error;

    async fn handle(
        self, verifier: &str, provider: &P,
    ) -> Result<impl Into<Response<GenerateResponse>>, Self::Error> {
        create_request(verifier, provider, self.body).await
    }
}

impl Body for GenerateRequest {}
