//! # Dynamic Client Registration Endpoint

use tracing::instrument;

use crate::oid4vci::Result;
use crate::oid4vci::endpoint::{Body, NoHeaders, Handler, Request};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::State;
use crate::oid4vci::types::{RegistrationRequest, RegistrationResponse};
use crate::server;

/// Registration request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn register(
    issuer: &str, provider: &impl Provider, request: RegistrationRequest,
) -> Result<RegistrationResponse> {
    tracing::debug!("register");

    verify(provider, &request).await?;

    let Ok(client_metadata) = provider.register(&request.client_metadata).await else {
        return Err(server!("Registration failed"));
    };

    Ok(RegistrationResponse { client_metadata })
}

impl Handler for Request<RegistrationRequest, NoHeaders> {
    type Response = RegistrationResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        register(issuer, provider, self.body)
    }
}

impl Body for RegistrationRequest {}

async fn verify(provider: &impl Provider, request: &RegistrationRequest) -> Result<()> {
    tracing::debug!("register::verify");

    // verify state is still accessible (has not expired)
    match StateStore::get::<State>(provider, &request.access_token).await {
        Ok(_) => Ok(()),
        Err(e) => Err(server!("State not found: {e}")),
    }
}
