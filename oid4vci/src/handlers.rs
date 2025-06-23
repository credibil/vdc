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
#[derive(Clone, Debug)]
pub struct Client<P: Provider> {
    /// The owner of the client, typically a DID or URL.
    pub owner: String,

    /// The provider to use while handling of the request.
    pub provider: P,
}

impl<P: Provider> Client<P> {
    /// Create a new `Client`.
    #[must_use]
    pub fn new(owner: impl Into<String>, provider: P) -> Self {
        Self {
            owner: owner.into(),
            provider,
        }
    }
}

impl<P: Provider> Client<P> {
    /// Create a new `Request` with no headers.
    pub fn request<B: Body>(&self, body: B) -> RequestBuilder<P, Unset, B> {
        RequestBuilder::new(self.clone(), body)
    }
}

/// Request builder.
#[derive(Debug)]
pub struct RequestBuilder<P: Provider, H, B: Body> {
    client: Client<P>,
    headers: H,
    body: B,
}

/// The request has no headers.
#[doc(hidden)]
pub struct Unset;
/// The request has headers.
#[doc(hidden)]
pub struct HeaderSet<H: Headers>(H);

impl<P: Provider, B: Body> RequestBuilder<P, Unset, B> {
    /// Create a new `Request` instance.
    pub const fn new(client: Client<P>, body: B) -> Self {
        Self {
            client,
            headers: Unset,
            body,
        }
    }

    /// Set the headers for the request.
    #[must_use]
    pub fn headers<H: Headers>(self, headers: H) -> RequestBuilder<P, HeaderSet<H>, B> {
        RequestBuilder {
            client: self.client,
            headers: HeaderSet(headers),
            body: self.body,
        }
    }
}

impl<P: Provider, B: Body> RequestBuilder<P, Unset, B> {
    /// Process the request and return a response.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    #[instrument(level = "debug", skip(self))]
    pub async fn execute<U>(self) -> Result<Response<U>>
    where
        B: Body,
        Request<B, NoHeaders>: Handler<U, P, Error = Error> + From<B>,
    {
        let request: Request<B, NoHeaders> = self.body.into();
        Ok(request.handle(&self.client.owner, &self.client.provider).await?.into())
    }
}

impl<P: Provider, H: Headers, B: Body> RequestBuilder<P, HeaderSet<H>, B> {
    /// Process the request and return a response.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn execute<U>(self) -> Result<Response<U>>
    where
        B: Body,
        Request<B, H>: Handler<U, P, Error = Error>,
    {
        let request = Request {
            body: self.body,
            headers: self.headers.0.clone(),
        };
        Ok(request.handle(&self.client.owner, &self.client.provider).await?.into())
    }
}
