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

/// Build an API `Client` to execute the request.
#[derive(Clone)]
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
    pub fn request<B: Body>(&self, body: B) -> Request2<P, NoHeaders, B> {
        Request2::new(self.clone(), body)
    }
}

/// Request builder.
pub struct Request2<P: Provider, H: Headers, B: Body> {
    client: Client<P>,
    headers: Option<H>,
    body: B,
}

impl<P: Provider, H: Headers, B: Body> Request2<P, H, B> {
    /// Create a new `Request` instance.
    pub const fn new(client: Client<P>, body: B) -> Self {
        Self {
            client,
            headers: None,
            body,
        }
    }

    /// Set the headers for the request.
    #[must_use]
    pub fn headers(mut self, headers: H) -> Self {
        self.headers = Some(headers);
        self
    }
}

impl<P: Provider, H: Headers, B: Body> Request2<P, H, B> {
    /// Process the request and return a response.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn execute<U>(self) -> Result<Response<U>>
    where
        B: Body,
        Request<B, NoHeaders>: Handler<U, P, Error = Error> + From<B>,
    {
        // self::handle(&self.client.owner, self.body, &self.client.provider).await
        let request: Request<B, NoHeaders> = self.body.into();
        Ok(request.handle(&self.client.owner, &self.client.provider).await?.into())
    }
}
