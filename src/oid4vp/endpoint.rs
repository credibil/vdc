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

use tracing::instrument;

pub use crate::endpoint::{Body, Handler, Headers, NoHeaders, Request, Response};
pub use crate::oid4vp::error::Error;
use crate::oid4vp::provider::Provider;

/// Result type for `OpenID` for Verifiable Presentations.
// pub type Result<T, E = Error> = std::result::Result<T, E>;
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
    Request<B, H>: Handler<P, Response = U, Provider = P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    request.validate(verifier, provider).await?;
    Ok(request.handle(verifier, provider).await?.into())
}
