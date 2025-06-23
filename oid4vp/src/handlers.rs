//! # Handlers
//!
//! `Handlers` provide the entry point for the `OpenId4VP` API. Requests are
//! routed to the appropriate handler for processing, returning a response
//! that can be serialized to JSON or directly to HTTP (using the
//! [`crate::core::http::IntoHttp`] trait).

mod create_request;
mod metadata;
mod request_uri;
mod response;

pub use credibil_core::api::{Body, Handler, Headers, NoHeaders, Request, Response};
use tracing::instrument;

pub use crate::error::Error;
use crate::provider::Provider;

/// Result type for `OpenID` for Verifiable Presentations.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

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
