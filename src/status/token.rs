//! # Token Status List
//!
//! Support for IETF Token Status List.

use std::fmt::Debug;

pub use anyhow::Error;
use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
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

// `typ` statuslist+jwt

/// Claims for the Status List Token.
///
/// The token is used to cryptographically sign and protect the integrity of
/// the Status List. This allows for the Status List Token to be hosted by
/// third parties or be transferred for offline use cases.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusListClaims {
    /// The URI of the Status List Token. This must be the `uri` claim
    /// contained in the `status_list` claim of the referenced token.
    pub sub: String,

    /// The time at which the Status List Token was issued
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The time at which the Status List Token expires.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<DateTime<Utc>>,

    /// The maximum amount of time, in seconds, that the Status List Token can
    /// be cached by a consumer before a fresh copy should be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<usize>,

    /// The status list.
    pub status_list: StatusList,
}

/// Request to retrieve the Verifier's client metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusList {
    /// Specifies the number of bits per referenced token in the compressed
    /// byte array. The allowed values for bits are 1,2,4 and 8.
    pub bits: BitsPerToken,

    /// The status values for all the referenced tokens it conveys statuses
    /// for, as a base64url-encoded compressed byte array.
    pub lst: String,

    /// The URI to retrieve the Status List Aggregation for this type of
    /// referenced token or issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregation_uri: Option<String>,
}

/// Allowed values for  bits per referenced token in the compressed byte array.
#[derive(Clone, Debug, Default, Deserialize_repr, Serialize_repr)]
#[repr(i64)]
pub enum BitsPerToken {
    /// 1 bit per token
    #[default]
    One = 1,

    /// 2 bits per token
    Two = 2,

    /// 4 bits per token
    Four = 4,

    /// 8 bits per token
    Eight = 8,
}
