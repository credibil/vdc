//! # `OpenID` for Verifiable Credential Issuance

mod authorization;
mod credential;
mod credential_offer;
mod metadata;
mod notification;
mod token;

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use self::authorization::*;
pub use self::credential::*;
pub use self::credential_offer::*;
pub use self::metadata::*;
pub use self::notification::*;
pub use self::token::*;
pub use crate::oauth::GrantType;

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Dataset {
    /// The credential configuration ID of the credential this dataset is for.
    pub credential_configuration_id: String,

    /// The credential subject populated for the user.
    pub claims: Map<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// A request for a nonce is made by sending an empty request to the Issuer's
/// Nonce endpoint (`nonce_endpoint` Credential Issuer Metadata).
#[derive(Clone, Debug, Default)]
pub struct NonceRequest;

/// Used by the Issuer to return a new nonce.
///
/// The Issuer MUST make the response uncacheable by adding a Cache-Control
/// header field including the value `no-store`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NonceResponse {
    /// The nonce value.
    pub c_nonce: String,
}
