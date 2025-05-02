// TODO: implement Nonce endpoint

//! # Nonce Endpoint
//!
//! This endpoint allows a Client to acquire a fresh `c_nonce` value.
//!
//! Any Credential Issuer requiring `c_nonce` values in Credential
//! Request proofs will support the Nonce Endpoint.

use anyhow::Context as _;
use chrono::Utc;

use crate::core::generate;
use crate::oid4vci::endpoint::{Body, Error, Handler, NoHeaders, Request, Response, Result};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Expire;
use crate::oid4vci::types::{NonceRequest, NonceResponse};

/// Nonce request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn nonce(_issuer: &str, provider: &impl Provider, _: NonceRequest) -> Result<NonceResponse> {
    let c_nonce = generate::nonce();
    let expire_at = Utc::now() + Expire::Authorized.duration();

    StateStore::put(provider, &c_nonce, &c_nonce, expire_at)
        .await
        .context("failed to purge state")?;

    Ok(NonceResponse { c_nonce })
}

impl<P: Provider> Handler<P> for Request<NonceRequest, NoHeaders> {
    type Error = Error;
    type Provider = P;
    type Response = NonceResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        nonce(issuer, provider, self.body).await
    }
}

impl Body for NonceRequest {}
