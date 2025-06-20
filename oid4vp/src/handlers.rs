//! # Endpoint
//!
//! `Endpoint` provides the entry point for the `OpenId4VP` API. Requests are
//! routed to the appropriate handler for processing, returning a response
//! that can be serialized to JSON or directly to HTTP (using the
//! [`crate::core::http::IntoHttp`] trait).

mod create_request;
mod metadata;
mod request_uri;
mod response;

use std::fmt::Debug;

pub use credibil_core::api::{Body, Handler, Headers, NoHeaders, Request, Response};
use tracing::instrument;

pub use crate::error::Error;
use crate::provider::Provider;

/// Result type for `OpenID` for Verifiable Presentations.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

/// Handle incoming OpenID for Verifiable Presentations requests.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the incoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
#[instrument(level = "debug", skip(provider))]
pub async fn handle<B, H, P, U>(
    verifier: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    P: Provider,
    Request<B, H>: Handler<U, P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    Ok(request.handle(verifier, provider).await?.into())
}

/// Build a Credential Offer for a Credential Issuer.
pub struct Client<O, H: Headers, B, P> {
    owner: O,
    headers: Option<H>,
    body: B,
    provider: P,
}

impl<H: Headers> Default for Client<NoOwner, H, NoBody, NoProvider> {
    fn default() -> Self {
        Self::new()
    }
}

/// request body is set.
#[doc(hidden)]
pub struct NoOwner;
/// The request body is set.
#[doc(hidden)]
pub struct HasOwner<'a>(&'a str);

/// request body is set.
#[doc(hidden)]
pub struct NoBody;
/// The request body is set.
#[doc(hidden)]
pub struct HasBody<B: Body>(B);

/// request body is set.
#[doc(hidden)]
pub struct NoProvider;
/// The request body is set.
#[doc(hidden)]
pub struct HasProvider<'a, P: Provider>(&'a P);

impl<H: Headers> Client<NoOwner, H, NoBody, NoProvider> {
    /// Create a new `Client`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: NoOwner,
            body: NoBody,
            headers: None,
            provider: NoProvider,
        }
    }
}

impl<H: Headers, B, P> Client<NoOwner, H, B, P> {
    /// Set the provider.
    #[must_use]
    pub fn owner(self, owner: &str) -> Client<HasOwner<'_>, H, B, P> {
        Client {
            owner: HasOwner(owner),
            body: self.body,
            headers: self.headers,
            provider: self.provider,
        }
    }
}

impl<O, H: Headers, P> Client<O, H, NoBody, P> {
    /// Set the request body.
    #[must_use]
    pub fn body<B: Body>(self, body: B) -> Client<O, H, HasBody<B>, P> {
        Client {
            owner: self.owner,
            body: HasBody(body),
            headers: self.headers,
            provider: self.provider,
        }
    }
}

impl<O, H: Headers, B> Client<O, H, B, NoProvider> {
    /// Set the provider.
    #[must_use]
    pub fn provider<P: Provider>(self, provider: &P) -> Client<O, H, B, HasProvider<'_, P>> {
        Client {
            owner: self.owner,
            body: self.body,
            headers: self.headers,
            provider: HasProvider(provider),
        }
    }
}

impl<H: Headers, B: Body, P: Provider> Client<HasOwner<'_>, H, HasBody<B>, HasProvider<'_, P>> {
    /// Build the Create Offer request with a pre-authorized code grant.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn handle<U>(self) -> Result<Response<U>>
    where
        Request<B, H>: Handler<U, P, Error = Error> + From<B>,
    {
        self::handle(self.owner.0, self.body.0, self.provider.0).await
    }
}
