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
mod metadata;
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

/// Credential request headers.
pub type CredentialHeaders = AuthorizationHeader;

/// Deferred Credential request headers.
pub type DeferredHeaders = AuthorizationHeader;

/// Registration request headers.
pub type MetadataHeaders = LanguageHeader;

/// Notification request headers.
pub type NotificationHeaders = AuthorizationHeader;

/// Registration request headers.
pub type RegistrationHeaders = AuthorizationHeader;

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
    pub accept_language: Option<String>,
}

impl From<HeaderMap> for LanguageHeader {
    fn from(headers: HeaderMap) -> Self {
        let accept_language =
            headers.get(ACCEPT_LANGUAGE).map(|h| h.to_str().ok().unwrap_or("en").to_string());
        Self { accept_language }
    }
}

/// Build an API `Client` to execute the request.
pub struct Client<'a, P: Provider, H> {
    owner: &'a str,
    provider: &'a P,
    headers: H,
}

/// The request has no headers.
#[doc(hidden)]
pub struct Headerless;
/// The request has headers.
#[doc(hidden)]
pub struct WithHeaders<H: Headers>(H);

impl<'a, P: Provider> Client<'a, P, Headerless> {
    /// Create a new `Client`.
    #[must_use]
    pub const fn new(owner: &'a str, provider: &'a P) -> Self {
        Self {
            owner,
            provider,
            headers: Headerless,
        }
    }
}

impl<'a, P: Provider> Client<'a, P, Headerless> {
    /// Set the headers for the request.
    #[must_use]
    pub fn headers<H: Headers>(self, headers: H) -> Client<'a, P, WithHeaders<H>> {
        Client {
            owner: self.owner,
            provider: self.provider,
            headers: WithHeaders(headers),
        }
    }
}

impl<'a, P: Provider> Client<'a, P, Headerless> {
    /// Build the Create Offer request with a pre-authorized code grant.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn handle<B, U>(&self, body: B) -> Result<Response<U>>
    where
        B: Body,
        Request<B, NoHeaders>: Handler<U, P, Error = Error> + From<B>,
    {
        let request: Request<B, NoHeaders> = body.into();
        Ok(request.handle(self.owner, self.provider).await?.into())
        // self::handle(self.owner, body, self.provider).await
    }
}

impl<'a, P: Provider, H: Headers> Client<'a, P, WithHeaders<H>> {
    /// Build the Create Offer request with a pre-authorized code grant.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn handle<B, U>(&self, body: B) -> Result<Response<U>>
    where
        B: Body,
        Request<B, H>: Handler<U, P, Error = Error>,
    {
        let request = Request {
            body,
            headers: self.headers.0.clone(),
        };
        Ok(request.handle(self.owner, self.provider).await?.into())
        // self::handle(self.owner, request, self.provider).await
    }
}
