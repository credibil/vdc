//! # Create Request Handler
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use when requesting a Verifiable Presentation from
//! a Wallet.

use anyhow::Context;
use chrono::Utc;
use credibil_api::{Body, Handler, Request, Response};
use credibil_core::state::State;

use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::state::Expire;
use crate::types::{
    ClientId, CreateRequest, CreateResponse, DeviceFlow, RequestObject, ResponseType,
};
use crate::{AuthorizationRequest, RequestUri, RequestUriMethod, generate};

/// Create an Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn create_request(
    verifier: &str, provider: &impl Provider, request: CreateRequest,
) -> Result<CreateResponse> {
    // TODO: get client metadata
    // let Ok(metadata) = Metadata::verifier(provider, verifier).await else {
    //     return Err(invalid!("{verifier} is not a valid client_id"));
    // };

    // TODO: Response Mode "direct_post" is RECOMMENDED for cross-device flows.

    let uri_token = generate::uri_token();
    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(uri_token.clone()),
        nonce: generate::nonce(),
        dcql_query: request.dcql_query,
        client_metadata: None, //Some(metadata.client_metadata),
        response_mode: request.response_mode,
        ..RequestObject::default()
    };

    // FIXME: replace hard-coded endpoints with Provider-set values
    let auth_req = if request.device_flow == DeviceFlow::CrossDevice {
        req_obj.client_id = ClientId::RedirectUri(format!("{verifier}/post"));
        let req_uri = RequestUri {
            client_id: req_obj.client_id.clone(),
            request_uri: format!("{verifier}/request/{uri_token}"),
            request_uri_method: Some(RequestUriMethod::Post),
        };
        AuthorizationRequest::Uri(req_uri)
    } else {
        req_obj.client_id = ClientId::RedirectUri(format!("{verifier}/callback"));
        AuthorizationRequest::Object(req_obj.clone())
    };

    let state = State { expires_at: Utc::now() + Expire::Request.duration(), body: req_obj };
    StateStore::put(provider, verifier, &uri_token, &state).await.context("issue saving state")?;

    Ok(CreateResponse(auth_req))
}

impl<P: Provider> Handler<CreateResponse, P> for Request<CreateRequest> {
    type Error = Error;

    async fn handle(self, owner: &str, provider: &P) -> Result<Response<CreateResponse>> {
        Ok(create_request(owner, provider, self.body).await?.into())
    }
}

impl Body for CreateRequest {}
