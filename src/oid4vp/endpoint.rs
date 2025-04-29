//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use http::HeaderMap;
use tracing::instrument;

use crate::oid4vp::Result;
use crate::oid4vp::provider::Provider;

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
pub async fn handle<B, H, U>(
    verifier: &str, request: impl Into<Request<B, H>> + Debug, provider: &impl Provider,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    Request<B, H>: Handler<Response = U>,
{
    let request: Request<B, H> = request.into();
    request.validate(verifier, provider).await?;
    Ok(request.handle(verifier, provider).await?.into())
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

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Handler: Clone + Debug + Send + Sync {
    /// The inner reply type specific to the implementing message.
    type Response;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<impl Into<Response<Self::Response>>>> + Send;

    /// Perform initial validation of the message.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    fn validate(
        &self, _credential_issuer: &str, _provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant.active(credential_issuer)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }
            Ok(())
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
