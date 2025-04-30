//! # Token Status List
//!
//! Support for IETF Token Status List.

use std::fmt::Debug;

pub use anyhow::Error;
use serde::{Deserialize, Serialize};
use tracing::instrument;

pub(crate) use crate::endpoint::{Body, Headers};
pub use crate::endpoint::{Handler, NoHeaders, Request, Response};
use crate::oid4vp::provider::Provider;

/// Result type for .
pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// Handle incoming messages.
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

/// Request to retrieve the Verifier's client metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetadataRequest {
    /// The Verifier's Client Identifier for which the configuration is to be
    /// returned.
    #[serde(default)]
    pub client_id: String,
}
