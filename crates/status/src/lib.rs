//! # Token Status List
//!
//! Support for IETF Token Status List.
//!
//! The `status` module provides a trait for looking up the status of a
//! credential. There are provider traits that need to be implemented by an
//! issuer and/or verifier implementations, and helper functions for dealing
//! with supported status endpoint formats.

mod error;
mod handlers;
mod issue;
mod provider;
mod verify;

use std::fmt::Debug;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
pub use handlers::*;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub use self::error::*;
pub use self::issue::*;
pub use self::provider::*;

// `typ` statuslist+jwt
// https://example.com/statuslists/1
// OAuth Server metadata: `status_list_aggregation_endpoint`

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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exp: Option<DateTime<Utc>>,

    /// The maximum amount of time, in seconds, that the Status List Token can
    /// be cached by a consumer before a fresh copy should be retrieved.
    #[serde(skip_serializing_if = "Option::is_none", default)]
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
    ///
    /// NOTE: should be the same as `status_list_aggregation_endpoint` in
    /// Issuer metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

/// Returned by the status list aggregation endpoint.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusListAggregation {
    /// URIs linking to Status List Tokens.
    pub status_lists: Vec<String>,
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

/// Used by credential (Referenced Token) issuers to specify how to retrieve
/// status information about the Referenced Token.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusClaim {
    /// The reference to the credential's status in a Status List Token.
    pub status_list: StatusListEntry,
}

/// An entry referencing a credential's (Referenced Token's) status in a
/// Status List Token.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListEntry {
    /// The index to check for status information in the Status List for the
    /// credential.
    pub idx: usize,

    /// Identifies the Status List Token containing the status information for
    /// the Referenced Token.
    pub uri: String,
}

/// Valid credential status types.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[repr(i64)]
pub enum StatusType {
    /// The credential is valid.
    #[default]
    Valid = 0,

    /// The credential is revoked.
    Invalid = 1,

    /// The credential is suspended.
    Suspended = 2,
}

/// Used to query the Status List endpoint in order to return Status List
/// Token(s).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListRequest {
    /// The full URI of the Status List to retrieve. When not specified, all
    /// status lists should be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Used to query the Status List endpoint in order to return Status List
/// Token(s).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListResponse(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn new() {
        let status_list = StatusList::new().expect("should create status list");
        dbg!(status_list);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn add_entry() {
        let mut status_list = StatusList::new().expect("should create status list");
        let status_claim = status_list.add_entry("https://example.com/status").unwrap();

        assert_eq!(status_claim.status_list.uri, "https://example.com/status");
    }
}
