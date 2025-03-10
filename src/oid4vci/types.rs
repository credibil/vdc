//! # `OpenID` for Verifiable Credential Issuance

mod authorization;
mod credential;
mod credential_offer;
mod metadata;
mod token;

use std::fmt::Debug;

pub use authorization::*;
pub use credential::*;
pub use credential_offer::*;
pub use metadata::*;
use serde::{Deserialize, Serialize};
pub use token::*;

pub use crate::oauth::GrantType;

/// TODO: Add documentation
#[derive(Clone, Debug)]
pub struct NotificationHeaders {
    /// TODO: Add documentation
    pub authorization: String,
}

/// Used by the Wallet to notify the Credential Issuer of certain events for
/// issued Credentials. These events enable the Credential Issuer to take
/// subsequent actions after issuance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationRequest {
    /// The `notification_id` received in the Credential Response or Deferred
    /// Credential Response. It is used to identify an issuance flow that
    /// contained one or more Credentials with the same Credential
    /// Configuration and Credential Dataset.
    pub notification_id: String,

    /// Type of the notification event.
    pub event: NotificationEvent,

    /// Human-readable ASCII text providing additional information, used to
    /// assist the Credential Issuer developer in understanding the event
    /// that occurred.
    ///
    /// Values for the `event_description` parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

/// Used by the Credential Issuer to notify the Wallet of certain events for
/// issued Credentials. These events enable the Wallet to take subsequent
/// actions after issuance.
///
/// Partial errors (a failure for one of the Credentials in the batch) will be
/// treated as the entire issuance flow failing.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum NotificationEvent {
    /// Credential(s) was successfully stored in the Wallet.
    CredentialAccepted,

    /// Used when unsuccessful Credential issuance was caused by a user action.
    CredentialDeleted,

    /// Used in any other unsuccessful case.
    #[default]
    CredentialFailure,
}

/// When the Credential Issuer has successfully received the Notification
/// Request from the Wallet, it MUST respond with an HTTP status code in the 2xx
/// range.
///
/// Use of the HTTP status code 204 (No Content) is RECOMMENDED.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationResponse;

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
