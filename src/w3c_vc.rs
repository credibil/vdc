//! # Verifiable Credentials
//!
//! This module encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

pub mod proof;
pub mod types;
pub mod vc;
pub mod vp;

use anyhow::anyhow;
use credibil_did::SignerExt;
use credibil_infosec::jose::jws;
use serde_json::{Map, Value};

use crate::core::{Kind, OneMany};
use crate::oid4vci::types::{CredentialConfiguration, CredentialDisplay, FormatProfile};
use crate::w3c_vc::types::{LangString, Language};
use crate::w3c_vc::vc::{CredentialStatus, CredentialSubject, VerifiableCredential, W3cVcClaims};

// pub async fn verify_vc(){

// }

/// Generate a W3C `jwt_vc_json` format credential.
#[derive(Debug)]
pub struct W3cVcBuilder<G, I, H, C, S> {
    config: G,
    issuer: I,
    holder: H,
    claims: C,
    status: Option<OneMany<CredentialStatus>>,
    signer: S,
}

/// Builder has no credential configuration.
#[doc(hidden)]
pub struct NoConfig;
/// Builder has credential configuration.
#[doc(hidden)]
pub struct HasConfig(CredentialConfiguration);

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

impl Default for W3cVcBuilder<NoConfig, NoIssuer, NoHolder, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl W3cVcBuilder<NoConfig, NoIssuer, NoHolder, NoClaims, NoSigner> {
    pub const fn new() -> Self {
        Self {
            config: NoConfig,
            issuer: NoIssuer,
            holder: NoHolder,
            claims: NoClaims,
            status: None,
            signer: NoSigner,
        }
    }
}

// Credential configuration
impl<I, H, C, S> W3cVcBuilder<NoConfig, I, H, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn config(self, cfg: CredentialConfiguration) -> W3cVcBuilder<HasConfig, I, H, C, S> {
        W3cVcBuilder {
            config: HasConfig(cfg),
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
            config: self.config,
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
            config: self.config,
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
            config: self.config,
            issuer: self.issuer,
            holder: self.holder,
            claims: HasClaims(claims),
            status: self.status,
            signer: self.signer,
        }
    }
}

// Signer
impl<G, I, H, C> W3cVcBuilder<G, I, H, C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> W3cVcBuilder<G, I, H, C, HasSigner<'_, S>> {
        W3cVcBuilder {
            config: self.config,
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
    pub fn status(mut self, status: OneMany<CredentialStatus>) -> Self {
        self.status = Some(status);
        self
    }
}

impl<S: SignerExt> W3cVcBuilder<HasConfig, HasIssuer, HasHolder, HasClaims, HasSigner<'_, S>> {
    /// Build the W3C credential, returning a base64url-encoded JSON JWT.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> anyhow::Result<String> {
        let FormatProfile::JwtVcJson {
            credential_definition,
        } = self.config.0.profile
        else {
            return Err(anyhow!("Credential configuration format is invalid"));
        };

        // credential ID
        let id = if let Some(identifier) = credential_definition.type_.get(1) {
            // FIXME: generate credential id
            Some(format!("{}/credentials/{}", self.issuer.0, identifier))
        } else {
            None
        };

        // credential name and description
        let (name, description) =
            self.config.0.display.as_ref().map_or((None, None), |display| create_names(display));

        // subject
        let subject = CredentialSubject {
            id: Some(self.holder.0),
            claims: self.claims.0,
        };

        // create VC
        let vc = VerifiableCredential {
            id,
            type_: OneMany::Many(credential_definition.type_),
            name,
            description,
            issuer: Kind::String(self.issuer.0),
            credential_subject: OneMany::One(subject),
            credential_status: self.status,
            // valid_from: None,
            // valid_until: None,
            ..VerifiableCredential::default()
        };

        let key = self.signer.0.verification_method().await?;

        // encode to JWT
        jws::encode(&W3cVcClaims::from(vc), &key, self.signer.0)
            .await
            .map_err(|e| anyhow!("issue generating `jwt_vc_json` credential: {e}"))
    }
}

// extract language object name and description from  `CredentialDisplay`
fn create_names(display: &[CredentialDisplay]) -> (Option<LangString>, Option<LangString>) {
    let mut name: Option<LangString> = None;
    let mut description: Option<LangString> = None;

    for d in display {
        let n = Language {
            value: d.name.clone(),
            language: d.locale.clone(),
            ..Language::default()
        };

        if let Some(nm) = &mut name {
            nm.add(n);
        } else {
            name = Some(LangString::new_object(n));
        }

        if d.description.is_some() {
            let d = Language {
                value: d.description.clone().unwrap(),
                language: d.locale.clone(),
                ..Language::default()
            };

            if let Some(desc) = &mut description {
                desc.add(d);
            } else {
                description = Some(LangString::new_object(d));
            }
        }
    }

    (name, description)
}
