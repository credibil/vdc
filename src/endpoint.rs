//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

pub use anyhow::Result;
use http::HeaderMap;

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Handler<P> {
    /// The provider type used to access the implementer's capability provider.
    type Provider;
    /// The inner reply type specific to the implementing message.
    type Response;
    /// The error type returned by the handler.
    type Error;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> impl Future<Output = Result<impl Into<Response<Self::Response>>, Self::Error>> + Send;

    /// Perform initial validation of the request.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    fn validate(
        &self, _credential_issuer: &str, _provider: &Self::Provider,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async {
            // if !tenant.active(credential_issuer)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }
            Ok(())
        }
    }
}

/// A request to process.
#[derive(Clone, Debug)]
pub struct Request<B, H>
where
    B: Body,
    H: Headers,
{
    /// The request to process.
    pub body: B,

    /// Headers associated with this request.
    pub headers: H,
}

impl<B: Body> From<B> for Request<B, NoHeaders> {
    fn from(body: B) -> Self {
        Self {
            body,
            headers: NoHeaders,
        }
    }
}

/// Top-level response data structure common to all handler.
#[derive(Clone, Debug)]
pub struct Response<T> {
    /// Response HTTP status code.
    pub status: u16,

    /// Response HTTP headers, if any.
    pub headers: Option<HeaderMap>,

    /// The endpoint-specific response.
    pub body: T,
}

impl<T> From<T> for Response<T> {
    fn from(body: T) -> Self {
        Self {
            status: 200,
            headers: None,
            body,
        }
    }
}

pub(crate) use seal::{Body, Headers};
pub(crate) mod seal {
    use std::fmt::Debug;

    /// The `Body` trait is used to restrict the types able to implement
    /// request body. It is implemented by all `xxxRequest` types.
    pub trait Body: Clone + Debug + Send + Sync {}

    /// The `Headers` trait is used to restrict the types able to implement
    /// request headers.
    pub trait Headers: Clone + Debug + Send + Sync {}
}

/// Implement empty headers for use by handlers that do not require headers.
#[derive(Clone, Debug)]
pub struct NoHeaders;
impl Headers for NoHeaders {}
