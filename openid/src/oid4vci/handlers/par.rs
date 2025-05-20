//! # Pushed Authorization Request Endpoint [RFC9126]
//!
//! This endpoint allows clients to push the payload of an authorization request
//! to the server, returning a request URI to use in a subsequent call to the
//! authorization endpoint.
//!
//! [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)

use anyhow::Context as _;
use chrono::{Duration, Utc};

use crate::common::generate;
use crate::common::state::State;
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result, authorize};
use crate::oid4vci::issuer::{PushedAuthorizationRequest, PushedAuthorizationResponse};
use crate::oid4vci::provider::{Metadata, Provider, StateStore};

/// Endpoint for the Wallet to push an Authorization Request when using Pushed
/// Authorization Requests.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn par(
    issuer: &str, provider: &impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    // TODO: authenticate client using client assertion (same as token endpoint)

    // verify the pushed RequestObject using `/authorize` endpoint logic
    let Ok(issuer) = Metadata::issuer(provider, issuer).await else {
        return Err(Error::InvalidClient("invalid `credential_issuer`".to_string()));
    };
    let mut ctx = authorize::Context {
        issuer,
        ..authorize::Context::default()
    };
    ctx.verify(provider, &request.request).await?;

    // generate a request URI and expiry between 5 - 600 secs
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", generate::uri_token());
    let expires_in = Duration::seconds(600);

    // save request to state for retrieval by authorization endpoint
    let state = State {
        body: request.request.clone(),
        expires_at: Utc::now() + expires_in,
    };
    StateStore::put(provider, &request_uri, &state).await.context("saving state")?;

    Ok(PushedAuthorizationResponse {
        request_uri,
        expires_in: expires_in.num_seconds(),
    })
}

impl<P: Provider> Handler<PushedAuthorizationResponse, P> for Request<PushedAuthorizationRequest> {
    type Error = Error;

    async fn handle(
        self, issuer: &str, provider: &P,
    ) -> Result<impl Into<Response<PushedAuthorizationResponse>>, Self::Error> {
        par(issuer, provider, self.body).await
    }
}

impl Body for PushedAuthorizationRequest {}
