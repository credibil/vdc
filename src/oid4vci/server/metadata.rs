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

use crate::oid4vci::Result;
use crate::oid4vci::endpoint::{Body, Handler, NoHeaders, Request};
use crate::oid4vci::provider::{Metadata, Provider};
use crate::oid4vci::types::{OAuthServerRequest, OAuthServerResponse};
use crate::server;

/// OAuth server metadata request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn metadata(
    issuer: &str, provider: &impl Provider, request: OAuthServerRequest,
) -> Result<OAuthServerResponse> {
    let auth_server = Metadata::server(provider, issuer, request.issuer.as_deref())
        .await
        .map_err(|e| server!("issue getting authorization server metadata: {e}"))?;

    Ok(OAuthServerResponse {
        authorization_server: auth_server,
    })
}

impl Handler for Request<OAuthServerRequest, NoHeaders> {
    type Response = OAuthServerResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        metadata(issuer, provider, self.body)
    }
}

impl Body for OAuthServerRequest {}
