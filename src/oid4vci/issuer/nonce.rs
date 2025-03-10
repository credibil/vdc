// TODO: implement Nonce endpoint

//! # Nonce Endpoint
//!
//! This endpoint allows a Client to acquire a fresh `c_nonce` value.
//!
//! Any Credential Issuer requiring `c_nonce` values in Credential
//! Request proofs will support the Nonce Endpoint.

use chrono::Utc;
use tracing::instrument;

use crate::core::generate;
use crate::oid4vci::Result;
use crate::oid4vci::endpoint::{Body, NoHeaders, Handler, Request};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Expire;
use crate::oid4vci::types::{NonceRequest, NonceResponse};
use crate::server;

/// Nonce request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn nonce(
    issuer: &str, provider: &impl Provider, request: NonceRequest,
) -> Result<NonceResponse> {
    tracing::debug!("nonce");

    let c_nonce = generate::nonce();
    let expire_at = Utc::now() + Expire::Authorized.duration();

    StateStore::put(provider, &c_nonce, &c_nonce, expire_at)
        .await
        .map_err(|e| server!("failed to purge state: {e}"))?;

    Ok(NonceResponse { c_nonce })
}

impl Handler for Request<NonceRequest,NoHeaders> {
    type Response = NonceResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        nonce(issuer, provider, self.body)
    }
}

impl Body for NonceRequest {}
