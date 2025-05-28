//! # Notification

use serde::{Deserialize, Serialize};

/// Build a [`NotificationRequest`].
#[derive(Debug)]
pub struct NotificationRequestBuilder<N> {
    notification_id: N,
    event: NotificationEvent,
    event_description: Option<String>,
}

impl Default for NotificationRequestBuilder<NoNotification> {
    fn default() -> Self {
        Self {
            notification_id: NoNotification,
            event: NotificationEvent::CredentialAccepted,
            event_description: None,
        }
    }
}

/// No credential configuration id is set.
#[doc(hidden)]
pub struct NoNotification;
/// A credential identifier id is set.
#[doc(hidden)]
pub struct Notification(String);

impl NotificationRequestBuilder<NoNotification> {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl NotificationRequestBuilder<NoNotification> {
    /// Specify only when credential Authorization Details was returned in the
    /// Token Response.
    #[must_use]
    pub fn notification_id(
        self, credential_identifier: impl Into<String>,
    ) -> NotificationRequestBuilder<Notification> {
        NotificationRequestBuilder {
            notification_id: Notification(credential_identifier.into()),
            event: self.event,
            event_description: self.event_description,
        }
    }
}

impl<N> NotificationRequestBuilder<N> {
    /// Specify when the credential response is to be encrypted.
    #[must_use]
    pub const fn event(mut self, event: NotificationEvent) -> Self {
        self.event = event;
        self
    }

    /// Specify the access token to use for this credential request.
    #[must_use]
    pub fn event_description(mut self, event_description: impl Into<String>) -> Self {
        self.event_description = Some(event_description.into());
        self
    }
}

impl NotificationRequestBuilder<Notification> {
    /// Build the Notification request.
    #[must_use]
    pub fn build(self) -> NotificationRequest {
        NotificationRequest {
            notification_id: self.notification_id.0,
            event: self.event,
            event_description: self.event_description,
        }
    }
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

impl NotificationRequest {
    /// Create a new `AuthorizationRequestBuilder`.
    #[must_use]
    pub fn builder() -> NotificationRequestBuilder<NoNotification> {
        NotificationRequestBuilder::new()
    }
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
