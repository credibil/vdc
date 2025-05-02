//! # Authorization Server Metadata Endpoint
//!
//! The metadata for an authorization server is retrieved from a well-
//! known location as a JSON [RFC8259] document, which declares its
//! endpoint locations and authorization server capabilities.
//!
//! The data model for this metadata is defined in
//! [`openid::oauth::OAuthServer`] and [`openid::issuer::Server`].
//!
//! Credential Issuers publishing authorization server metadata MUST make a JSON
//! document available. This is usually at the path formed by concatenating the
//! string `/.well-known/oauth-authorization-server` to the Credential Issuer
//! Identifier.
//!
//! If the issuer identifier is different from the Credential Issuer Identifier,
//! this is added as a path component such as
//! `/.well-known/oauth-authorization-server/issuer1`.

use anyhow::Context as _;

use crate::oid4vci::endpoint::{Body, Error, Handler, NoHeaders, Request, Response, Result};
use crate::oid4vci::provider::{Metadata, Provider};
use crate::oid4vci::types::{ServerRequest, ServerResponse};

/// OAuth server metadata request handler.
///
/// # Errors
///
/// Returns an `OpenID4VCI` error if the request is invalid or if the provider is
/// not available.
async fn metadata(
    issuer: &str, provider: &impl Provider, _request: ServerRequest,
) -> Result<ServerResponse> {
    let auth_server = Metadata::server(provider, issuer)
        .await
        .context("issue getting authorization server metadata")?;

    Ok(ServerResponse {
        authorization_server: auth_server,
    })
}

impl<P: Provider> Handler<P> for Request<ServerRequest, NoHeaders> {
    type Error = Error;
    type Provider = P;
    type Response = ServerResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        metadata(issuer, provider, self.body).await
    }
}

impl Body for ServerRequest {}
