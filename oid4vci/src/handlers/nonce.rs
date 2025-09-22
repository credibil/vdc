// TODO: implement Nonce endpoint

//! # Nonce Endpoint
//!
//! This endpoint allows a Client to acquire a fresh `c_nonce` value.
//!
//! Any Credential Issuer requiring `c_nonce` values in Credential
//! Request proofs will support the Nonce Endpoint.

use anyhow::Context as _;
use chrono::Utc;
use credibil_api::{Body, Handler, Request, Response};
use credibil_core::state::State;

use crate::generate;
use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::state::Expire;
use crate::types::{NonceRequest, NonceResponse};

/// Nonce request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn nonce(issuer: &str, provider: &impl Provider, _: NonceRequest) -> Result<NonceResponse> {
    let c_nonce = generate::nonce();

    let state =
        &State { body: c_nonce.clone(), expires_at: Utc::now() + Expire::Authorized.duration() };
    StateStore::put(provider, issuer, &c_nonce, state)
        .await
        .context("issue failed to purge state")?;

    Ok(NonceResponse { c_nonce })
}

impl<P: Provider> Handler<NonceResponse, P> for Request<NonceRequest> {
    type Error = Error;

    async fn handle(self, owner: &str, provider: &P) -> Result<Response<NonceResponse>> {
        Ok(nonce(owner, provider, self.body).await?.into())
    }
}

impl Body for NonceRequest {}
