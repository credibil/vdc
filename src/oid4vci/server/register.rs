//! # Dynamic Client Registration Endpoint

use crate::oid4vci::Result;
use crate::oid4vci::endpoint::{Body, Handler, Request};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::State;
use crate::oid4vci::types::{RegistrationHeaders, RegistrationRequest, RegistrationResponse};
use crate::server;

/// Registration request handler.
///
/// # Errors
///
/// Returns an `OpenID4VCI` error if the request is invalid or if the provider is
/// not available.
async fn register(
    _issuer: &str, provider: &impl Provider,
    request: Request<RegistrationRequest, RegistrationHeaders>,
) -> Result<RegistrationResponse> {
    // verify access token
    StateStore::get::<State>(provider, &request.headers.authorization)
        .await
        .map_err(|e| server!("state not found: {e}"))?;

    let Ok(client_metadata) = provider.register(&request.body.client_metadata).await else {
        return Err(server!("Registration failed"));
    };

    Ok(RegistrationResponse { client_metadata })
}

impl Handler for Request<RegistrationRequest, RegistrationHeaders> {
    type Response = RegistrationResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        register(issuer, provider, self)
    }
}

impl Body for RegistrationRequest {}
