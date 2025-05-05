//! # Verifiable Credentials
//!
//! This module encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

use anyhow::Context as _;
use credibil_identity::SignerExt;
use credibil_jose::encode_jws;
use serde_json::{Map, Value};

use crate::core::{Kind, OneMany};
use crate::status::StatusClaim;
use crate::vdc::w3c_vc::{
    CredentialStatus, CredentialStatusType, CredentialSubject, VerifiableCredential, W3cVcClaims,
};

/// Generate a W3C `jwt_vc_json` format credential.
#[derive(Debug)]
pub struct W3cVcBuilder<T, I, H, C, S> {
    type_: T,
    issuer: I,
    holder: H,
    claims: C,
    status: Option<StatusClaim>,
    signer: S,
}

/// Builder has no credential configuration.
#[doc(hidden)]
pub struct NoType;
/// Builder has credential configuration.
#[doc(hidden)]
pub struct HasType(Vec<String>);

/// Builder has no issuer.
#[doc(hidden)]
pub struct NoIssuer;
/// Builder has issuer.
#[doc(hidden)]
pub struct HasIssuer(String);

/// Builder has no holder.
#[doc(hidden)]
pub struct NoHolder;
/// Builder has holder.
#[doc(hidden)]
pub struct HasHolder(String);

/// Builder has no claims.
#[doc(hidden)]
pub struct NoClaims;
/// Builder has claims.
#[doc(hidden)]
pub struct HasClaims(Map<String, Value>);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl Default for W3cVcBuilder<NoType, NoIssuer, NoHolder, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl W3cVcBuilder<NoType, NoIssuer, NoHolder, NoClaims, NoSigner> {
    /// Create a new W3C credential builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            type_: NoType,
            issuer: NoIssuer,
            holder: NoHolder,
            claims: NoClaims,
            status: None,
            signer: NoSigner,
        }
    }
}

// Credential configuration
impl<I, H, C, S> W3cVcBuilder<NoType, I, H, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn type_(self, type_: Vec<String>) -> W3cVcBuilder<HasType, I, H, C, S> {
        W3cVcBuilder {
            type_: HasType(type_),
            issuer: self.issuer,
            holder: self.holder,
            claims: self.claims,
            status: self.status,
            signer: self.signer,
        }
    }
}

// Issuer
impl<G, H, C, S> W3cVcBuilder<G, NoIssuer, H, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn issuer(self, issuer: impl Into<String>) -> W3cVcBuilder<G, HasIssuer, H, C, S> {
        W3cVcBuilder {
            type_: self.type_,
            issuer: HasIssuer(issuer.into()),
            holder: self.holder,
            claims: self.claims,
            status: self.status,
            signer: self.signer,
        }
    }
}

// Holder
impl<G, I, C, S> W3cVcBuilder<G, I, NoHolder, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn holder(self, holder: impl Into<String>) -> W3cVcBuilder<G, I, HasHolder, C, S> {
        W3cVcBuilder {
            type_: self.type_,
            issuer: self.issuer,
            holder: HasHolder(holder.into()),
            claims: self.claims,
            status: self.status,
            signer: self.signer,
        }
    }
}

// Claims
impl<G, I, H, S> W3cVcBuilder<G, I, H, NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn claims(self, claims: Map<String, Value>) -> W3cVcBuilder<G, I, H, HasClaims, S> {
        W3cVcBuilder {
            type_: self.type_,
            issuer: self.issuer,
            holder: self.holder,
            claims: HasClaims(claims),
            status: self.status,
            signer: self.signer,
        }
    }
}

// SignerExt
impl<G, I, H, C> W3cVcBuilder<G, I, H, C, NoSigner> {
    /// Set the credential `SignerExt`.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> W3cVcBuilder<G, I, H, C, HasSigner<'_, S>> {
        W3cVcBuilder {
            type_: self.type_,
            issuer: self.issuer,
            holder: self.holder,
            claims: self.claims,
            status: self.status,
            signer: HasSigner(signer),
        }
    }
}

impl<G, I, H, C, S> W3cVcBuilder<G, I, H, C, S> {
    /// Sets the status property.
    #[must_use]
    pub fn status(mut self, status: StatusClaim) -> Self {
        self.status = Some(status);
        self
    }
}

impl<S: SignerExt> W3cVcBuilder<HasType, HasIssuer, HasHolder, HasClaims, HasSigner<'_, S>> {
    /// Build the W3C credential, returning a base64url-encoded JSON JWT.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> anyhow::Result<String> {
        let credential_status = if let Some(status_claim) = self.status {
            Some(OneMany::One(CredentialStatus {
                id: Some(status_claim.status_list.uri.clone()),
                credential_status_type: CredentialStatusType::TokenStatus(status_claim),
            }))
        } else {
            None
        };

        let vc = VerifiableCredential {
            id: Some(format!("{}/credentials/{}", self.issuer.0, uuid::Uuid::new_v4())),
            type_: self.type_.0,
            issuer: Kind::String(self.issuer.0),
            credential_subject: OneMany::One(CredentialSubject {
                id: Some(self.holder.0),
                claims: self.claims.0,
            }),
            credential_status,
            ..VerifiableCredential::default()
        };

        // encode to JWT
        let key = self.signer.0.verification_method().await?;
        encode_jws(&W3cVcClaims::from(vc), &key.try_into()?, self.signer.0)
            .await
            .context("generating `jwt_vc_json` credential")
    }
}
