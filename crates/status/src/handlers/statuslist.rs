//! # Status List Endpoint

use anyhow::Context;
use credibil_core::api::{Body, Handler, Request, Response};

use crate::error::invalid;
use crate::handlers::{Error, Result};
use crate::provider::{Provider, StatusStore};
use crate::{StatusListRequest, StatusListResponse};

/// Status List request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn statuslist(
    issuer: &str, provider: &impl Provider, request: StatusListRequest,
) -> Result<StatusListResponse> {
    let Some(id) = request.id else {
        return Err(invalid!("missing id"));
    };

    let Some(token) = StatusStore::get(provider, issuer, &id).await.context("issue getting metadata")?
    else {
        return Err(invalid!("status token not found"));
    };

    Ok(StatusListResponse(token))
}

impl<P: Provider> Handler<StatusListResponse, P> for Request<StatusListRequest> {
    type Error = Error;

    async fn handle(self, issuer: &str, provider: &P) -> Result<Response<StatusListResponse>> {
        Ok(statuslist(issuer, provider, self.body).await?.into())
    }
}

impl Body for StatusListRequest {}
