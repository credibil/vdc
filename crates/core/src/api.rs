//! # API
//!
//! The api module provides the entry point to the public API. Requests are routed
//! to the appropriate handler for processing, returning a response that can
//! be serialized to a JSON object or directly to HTTP.

use std::fmt::Debug;
use std::ops::Deref;

use http::StatusCode;

/// A request to process.
#[derive(Clone, Debug)]
pub struct Request<B, H = NoHeaders>
where
    B: Body,
    H: Headers,
{
    /// The request to process.
    pub body: B,

    /// Headers associated with this request.
    pub headers: H,
}

impl<B: Body> From<B> for Request<B> {
    fn from(body: B) -> Self {
        Self {
            body,
            headers: NoHeaders,
        }
    }
}

/// Top-level response data structure common to all handler.
#[derive(Clone, Debug)]
pub struct Response<T, H = NoHeaders>
where
    H: Headers,
{
    /// Response HTTP status code.
    pub status: StatusCode,

    /// Response HTTP headers, if any.
    pub headers: Option<H>,

    /// The endpoint-specific response.
    pub body: T,
}

impl<T> From<T> for Response<T> {
    fn from(body: T) -> Self {
        Self {
            status: StatusCode::OK,
            headers: None,
            body,
        }
    }
}

impl<T> Deref for Response<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

/// Request handler.
///
/// The primary role of this trait is to provide a common interface for
/// requests so they can be handled by [`handle`] method.
pub trait Handler<U, P> {
    /// The error type returned by the handler.
    type Error;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, tenant: &str, provider: &P,
    ) -> impl Future<Output = Result<impl Into<Response<U>>, Self::Error>> + Send;
}

/// The `Body` trait is used to restrict the types able to implement
/// request body. It is implemented by all `xxxRequest` types.
pub trait Body: Clone + Debug + Send + Sync {}

/// The `Headers` trait is used to restrict the types able to implement
/// request headers.
pub trait Headers: Clone + Debug + Send + Sync {}

/// Implement empty headers for use by handlers that do not require headers.
#[derive(Clone, Debug)]
pub struct NoHeaders;
impl Headers for NoHeaders {}
