//! # Dynamic Client Registration Endpoint

use anyhow::Context as _;

use crate::oid4vci::error::server;
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::issuer::{RegistrationHeaders, RegistrationRequest, RegistrationResponse};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Token;

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
    StateStore::get::<Token>(provider, &request.headers.authorization)
        .await
        .context("retrieving state")?;

    let Ok(client_metadata) = provider.register(&request.body.client_metadata).await else {
        return Err(server!("registration failed"));
    };

    Ok(RegistrationResponse { client_metadata })
}

impl<P: Provider> Handler<RegistrationResponse, P>
    for Request<RegistrationRequest, RegistrationHeaders>
{
    type Error = Error;

    async fn handle(
        self, issuer: &str, provider: &P,
    ) -> Result<impl Into<Response<RegistrationResponse>>, Self::Error> {
        register(issuer, provider, self).await
    }
}

impl Body for RegistrationRequest {}
