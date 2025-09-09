//! # Verifiable Presentation Retrieval Endpoint

use anyhow::Context;
use credibil_api::{Body, Handler, Request, Response};
use credibil_core::state::State;
use credibil_vdc::dcql::Queryable;

use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::types::{VpDataRequest, VpDataResponse};

/// Endpoint for the Wallet to respond Verifier's Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn vp_data(
    verifier: &str, provider: &impl Provider, request: VpDataRequest,
) -> Result<VpDataResponse> {
    // retrieve specified presentation
    let state: State<Vec<Queryable>> =
        StateStore::get(provider, verifier, &request.vp_data_id).await?;
    StateStore::purge(provider, verifier, &request.vp_data_id)
        .await
        .context("issue purging state")?;
    Ok(VpDataResponse { vp_data: state.body })
}

impl<P: Provider> Handler<VpDataResponse, P> for Request<VpDataRequest> {
    type Error = Error;

    async fn handle(self, verifier: &str, provider: &P) -> Result<Response<VpDataResponse>> {
        Ok(vp_data(verifier, provider, self.body).await?.into())
    }
}

impl Body for VpDataRequest {}
