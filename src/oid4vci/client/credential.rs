//! # Credential Request Builder

use crate::oid4vci::types::{
    CredentialRequest, CredentialResponseEncryption, MultipleProofs, NotificationEvent,
    NotificationRequest, Proof, RequestBy, SingleProof,
};

impl CredentialRequest {
    /// Create a new `CredentialRequestBuilder`.
    #[must_use]
    pub fn builder() -> CredentialRequestBuilder<NoCredential, NoProofs> {
        CredentialRequestBuilder::new()
    }
}

impl NotificationRequest {
    /// Create a new `NotificationRequest`.
    #[must_use]
    pub fn builder() -> NotificationRequestBuilder<NoNotification> {
        NotificationRequestBuilder::new()
    }
}

/// Build a Credential Offer for a Credential Issuer.
#[derive(Debug)]
pub struct CredentialRequestBuilder<C, P> {
    credential: C,
    proofs: P,
    response_encryption: Option<CredentialResponseEncryption>,
}

impl Default for CredentialRequestBuilder<NoCredential, NoProofs> {
    fn default() -> Self {
        Self {
            credential: NoCredential,
            proofs: NoProofs,
            response_encryption: None,
        }
    }
}

/// No credential configuration id is set.
#[doc(hidden)]
pub struct NoCredential;
/// A credential identifier id is set.
#[doc(hidden)]
pub struct Credential(RequestBy);

/// No proof of possession of key material is set.
#[doc(hidden)]
pub struct NoProofs;
/// Proof of possession of key material is set.
#[doc(hidden)]
pub struct Proofs(Vec<String>);

impl CredentialRequestBuilder<NoCredential, NoProofs> {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<P> CredentialRequestBuilder<NoCredential, P> {
    /// Specify only when credential Authorization Details was returned in the
    /// Token Response.
    #[must_use]
    pub fn credential_identifier(
        self, credential_identifier: impl Into<String>,
    ) -> CredentialRequestBuilder<Credential, P> {
        CredentialRequestBuilder {
            credential: Credential(RequestBy::Identifier(credential_identifier.into())),
            proofs: self.proofs,
            response_encryption: self.response_encryption,
        }
    }

    /// Specify only when credential Authorization Details was not returned in the
    /// Token Response.
    #[must_use]
    pub fn credential_configuration_id(
        self, credential_configuration_id: impl Into<String>,
    ) -> CredentialRequestBuilder<Credential, P> {
        CredentialRequestBuilder {
            credential: Credential(RequestBy::ConfigurationId(credential_configuration_id.into())),
            proofs: self.proofs,
            response_encryption: self.response_encryption,
        }
    }
}

impl<C> CredentialRequestBuilder<C, NoProofs> {
    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    #[must_use]
    pub fn with_proof(self, proof_jwt: impl Into<String>) -> CredentialRequestBuilder<C, Proofs> {
        CredentialRequestBuilder {
            credential: self.credential,
            proofs: Proofs(vec![proof_jwt.into()]),
            response_encryption: self.response_encryption,
        }
    }
}

impl<C> CredentialRequestBuilder<C, Proofs> {
    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    #[must_use]
    pub fn with_proof(mut self, proof_jwt: impl Into<String>) -> Self {
        self.proofs.0.push(proof_jwt.into());
        self
    }
}

impl<C, P> CredentialRequestBuilder<C, P> {
    /// Specify when the credential response is to be encrypted.
    #[must_use]
    pub fn response_encryption(
        mut self, response_encryption: CredentialResponseEncryption,
    ) -> Self {
        self.response_encryption = Some(response_encryption);
        self
    }
}

impl CredentialRequestBuilder<Credential, Proofs> {
    /// Build the Create Offer request.
    #[must_use]
    pub fn build(self) -> CredentialRequest {
        let proof = if self.proofs.0.len() == 1 {
            Some(Proof::Single(SingleProof::Jwt {
                jwt: self.proofs.0[0].clone(),
            }))
        } else {
            Some(Proof::Multiple(MultipleProofs::Jwt(self.proofs.0)))
        };

        CredentialRequest {
            credential: self.credential.0,
            proof,
            credential_response_encryption: self.response_encryption,
        }
    }
}

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
