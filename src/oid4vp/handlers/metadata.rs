//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this
//! endpoint returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use anyhow::Context;

use crate::oid4vp::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vp::provider::{Metadata, Provider};
use crate::oid4vp::verifier::{MetadataRequest, MetadataResponse};

/// Endpoint for Wallets to request Verifier (Client) metadata.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn metadata(
    _verifier: &str, provider: &impl Provider, request: MetadataRequest,
) -> Result<MetadataResponse> {
    Ok(MetadataResponse {
        client: Metadata::verifier(provider, &request.client_id)
            .await
            .context("getting metadata")?,
    })
}

impl<P: Provider> Handler<P> for Request<MetadataRequest> {
    type Error = Error;
    type Provider = P;
    type Response = MetadataResponse;

    async fn handle(
        self, verifier: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        metadata(verifier, provider, self.body).await
    }
}

impl Body for MetadataRequest {}
