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
pub struct Client<'a, P: Provider, H: Headers> {
    owner: &'a str,
    provider: &'a P,
    // body: B,
    headers: H,
}

// /// request body is set.
// #[doc(hidden)]
// pub struct NoBody;
// /// The request body is set.
// #[doc(hidden)]
// pub struct HasBody<B: Body>(B);

impl<'a, P: Provider> Client<'a, P, NoHeaders> {
    /// Create a new `Client`.
    #[must_use]
    pub const fn new(owner: &'a str, provider: &'a P) -> Self {
        Self {
            owner,
            provider,
            // body: NoBody,
            headers: NoHeaders,
        }
    }
}

// impl<'a, P: Provider, H: Headers> Client<'a, P, NoBody, H> {
//     /// Set the request body.
//     #[must_use]
//     pub fn body<B: Body>(self, body: B) -> Client<'a, P, HasBody<B>, H> {
//         Client {
//             owner: self.owner,
//             provider: self.provider,
//             body: HasBody(body),
//             headers: self.headers,
//         }
//     }
// }

// impl<'a, P: Provider, B, H: Headers> Client<'a, P, B, H> {
//     /// Set the headers for the request.
//     #[must_use]
//     pub fn headers(mut self, headers: H) -> Self {
//         self.headers = headers;
//         self
//     }
// }

// impl<'a, P: Provider, B: Body, H: Headers> Client<'a, P, HasBody<B>, H> {
//     /// Build the Create Offer request with a pre-authorized code grant.
//     ///
//     /// # Errors
//     ///
//     /// Will fail if request cannot be processed.
//     pub async fn handle<U>(self) -> Result<Response<U>>
//     where
//         Request<B, H>: Handler<U, P, Error = Error> + From<B>,
//     {
//         self::handle(self.owner, self.body.0, self.provider).await
//     }
// }

impl<'a, P: Provider, H: Headers> Client<'a, P, H> {
    /// Set the headers for the request.
    #[must_use]
    pub fn headers(mut self, headers: H) -> Self {
        self.headers = headers;
        self
    }
}

impl<'a, P: Provider, H: Headers> Client<'a, P, H> {
    /// Build the Create Offer request with a pre-authorized code grant.
    ///
    /// # Errors
    ///
    /// Will fail if request cannot be processed.
    pub async fn handle<B, U>(&self, body: B) -> Result<Response<U>>
    where
        B: Body,
        Request<B, H>: Handler<U, P, Error = Error> + From<B>,
    {
        self::handle(self.owner, body, self.provider).await
    }
}
