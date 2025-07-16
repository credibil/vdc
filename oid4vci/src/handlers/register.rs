//! # Dynamic Client Registration Endpoint

use anyhow::Context as _;
use credibil_core::api::{Body, Handler, Request, Response};

use crate::error::server;
use crate::handlers::{Error, RegistrationHeaders, Result};
use crate::provider::{Provider, StateStore};
use crate::state::Token;
use crate::types::{RegistrationRequest, RegistrationResponse};

/// Registration request handler.
///
/// # Errors
///
/// Returns an `OpenID4VCI` error if the request is invalid or if the provider is
/// not available.
async fn register(
    issuer: &str, provider: &impl Provider,
    request: Request<RegistrationRequest, RegistrationHeaders>,
) -> Result<RegistrationResponse> {
    // verify access token
    StateStore::get::<Token>(provider, issuer, &request.headers.authorization)
        .await
        .context("issue retrieving state")?;

    let Ok(client_metadata) = provider.register(issuer, &request.body.client_metadata).await else {
        return Err(server!("registration failed"));
    };

    Ok(RegistrationResponse { client_metadata })
}

impl<P: Provider> Handler<RegistrationResponse, P>
    for Request<RegistrationRequest, RegistrationHeaders>
{
    type Error = Error;

    async fn handle(self, issuer: &str, provider: &P) -> Result<Response<RegistrationResponse>> {
        Ok(register(issuer, provider, self).await?.into())
    }
}

impl Body for RegistrationRequest {}
