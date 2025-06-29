//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this
//! endpoint returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use anyhow::Context;
use credibil_core::api::{Body, Handler, Request, Response};

use crate::handlers::{Error, Result};
use crate::provider::{Metadata, Provider};
use crate::types::{VerifierRequest, VerifierResponse};

/// Endpoint for Wallets to request Verifier (Client) metadata.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn metadata(
    _verifier: &str, provider: &impl Provider, request: VerifierRequest,
) -> Result<VerifierResponse> {
    Ok(VerifierResponse {
        client: Metadata::verifier(provider, &request.client_id)
            .await
            .context("getting metadata")?,
    })
}

impl<P: Provider> Handler<VerifierResponse, P> for Request<VerifierRequest> {
    type Error = Error;

    async fn handle(
        self, verifier: &str, provider: &P,
    ) -> Result<impl Into<Response<VerifierResponse>>> {
        metadata(verifier, provider, self.body).await
    }
}

impl Body for VerifierRequest {}
