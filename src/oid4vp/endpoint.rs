//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use tracing::instrument;

pub(crate) use crate::endpoint::{Body, Headers};
pub use crate::endpoint::{Handler, NoHeaders, Request, Response, Result};
use crate::oid4vp::error::Error;
// use crate::oid4vp::Result;
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
pub async fn handle<B, H, P, U>(
    verifier: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Response<U>, Error>
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
