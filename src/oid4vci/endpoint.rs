//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;
use std::ops::Deref;

use http::header::ACCEPT_LANGUAGE;
use http::{HeaderMap, StatusCode};
use tracing::instrument;

use crate::invalid;
use crate::oid4vci::provider::Provider;
use crate::oid4vci::{Error, Result};

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
    issuer: &str, request: impl Into<Request<B, H>> + Debug, provider: &impl Provider,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    Request<B, H>: Handler<Response = U>,
{
    let request: Request<B, H> = request.into();
    request.validate(issuer, provider).await?;
    Ok(request.handle(issuer, provider).await?.into())
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
    pub status: StatusCode,

    /// Response HTTP headers, if any.
    pub headers: Option<HeaderMap>,

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
        &self, issuer: &str, _provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant.active(issuer)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }

            // `credential_issuer` required
            if issuer.is_empty() {
                return Err(invalid!("no `credential_issuer` specified"));
            }

            // // validate the message schema during development
            // #[cfg(debug_assertions)]
            // schema::validate(self)?;

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

/// An authorization-only header for use by handlers that soley require
/// authorization.
#[derive(Clone, Debug)]
pub struct AuthorizationHeaders {
    /// The authorization header (access token).
    pub authorization: String,
}

/// An language-only header for use by handlers that soley require
/// the `accept-language` header.
#[derive(Clone, Debug)]
pub struct LanguageHeaders {
    /// The `accept-language` header.
    pub accept_language: String,
}

impl TryFrom<HeaderMap> for LanguageHeaders {
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
