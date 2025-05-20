//! # Status List Endpoint

use anyhow::Context as _;
use credibil_status::{StatusListRequest, StatusListResponse, StatusStore};

use crate::oid4vci::error::invalid;
use crate::oid4vci::handlers::{Error, Handler, Request, Response, Result};
use crate::oid4vci::provider::Provider;

/// Status List request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn statuslist(
    _issuer: &str, provider: &impl Provider, request: StatusListRequest,
) -> Result<StatusListResponse> {
    let Some(id) = request.id else {
        return Err(invalid!("missing id"));
    };

    let Some(token) = StatusStore::get(provider, &id).await.context("getting metadata")? else {
        return Err(invalid!("status token not found"));
    };

    Ok(StatusListResponse(token))
}

impl<P: Provider> Handler<StatusListResponse, P> for Request<StatusListRequest> {
    type Error = Error;

    async fn handle(
        self, issuer: &str, provider: &P,
    ) -> Result<impl Into<Response<StatusListResponse>>, Self::Error> {
        statuslist(issuer, provider, self.body).await
    }
}

// impl Body for StatusListRequest {}
