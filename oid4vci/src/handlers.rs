//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

mod authorize;
mod create_offer;
mod credential;
mod credential_offer;
mod deferred;
mod issuer;
mod nonce;
mod notification;
mod par;
mod register;
mod server;
mod token;

use std::fmt::Debug;

pub use credibil_core::api::{Body, Handler, Headers, NoHeaders, Request, Response};
use http::HeaderMap;
use http::header::ACCEPT_LANGUAGE;
use tracing::instrument;

pub use crate::error::Error;
use crate::error::invalid;
use crate::provider::Provider;

/// Result type for `OpenID` for Verifiable Credential Issuance.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

/// Handle incoming messages.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the imcoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
#[instrument(level = "debug", skip(provider))]
pub async fn handle<B, H, P, U>(
    issuer: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    P: Provider,
    Request<B, H>: Handler<U, P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    Ok(request.handle(issuer, provider).await?.into())
}

/// An authorization-only header for use by handlers that soley require
/// authorization.
#[derive(Clone, Debug)]
pub struct AuthorizationHeader {
    /// The authorization header (access token).
    pub authorization: String,
}

/// An language-only header for use by handlers that soley require
/// the `accept-language` header.
#[derive(Clone, Debug)]
pub struct LanguageHeader {
    /// The `accept-language` header.
    pub accept_language: String,
}

impl TryFrom<HeaderMap> for LanguageHeader {
    type Error = Error;

    fn try_from(headers: HeaderMap) -> Result<Self> {
        let accept_language = headers
            .get(ACCEPT_LANGUAGE)
            .ok_or_else(|| invalid!("missing `accept-language` header"))?
            .to_str()
            .map_err(|_| invalid!("invalid `accept-language` header"))?
            .to_string();
        Ok(Self { accept_language })
    }
}
