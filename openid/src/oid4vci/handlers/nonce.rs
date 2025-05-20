// TODO: implement Nonce endpoint

//! # Nonce Endpoint
//!
//! This endpoint allows a Client to acquire a fresh `c_nonce` value.
//!
//! Any Credential Issuer requiring `c_nonce` values in Credential
//! Request proofs will support the Nonce Endpoint.

use anyhow::Context as _;
use chrono::Utc;

use crate::common::generate;
use crate::common::state::State;
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::issuer::{NonceRequest, NonceResponse};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Expire;

/// Nonce request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn nonce(_issuer: &str, provider: &impl Provider, _: NonceRequest) -> Result<NonceResponse> {
    let c_nonce = generate::nonce();

    let state = &State {
        body: c_nonce.clone(),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };
    StateStore::put(provider, &c_nonce, state).await.context("failed to purge state")?;

    Ok(NonceResponse { c_nonce })
}

impl<P: Provider> Handler<NonceResponse, P> for Request<NonceRequest> {
    type Error = Error;

    async fn handle(
        self, issuer: &str, provider: &P,
    ) -> Result<impl Into<Response<NonceResponse>>, Self::Error> {
        nonce(issuer, provider, self.body).await
    }
}

impl Body for NonceRequest {}
