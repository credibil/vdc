//! # Verifiable Credentials
//!
//! This module encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

pub mod jose;
pub mod proof;
pub mod types;
pub mod vc;
pub mod vp;

use anyhow::anyhow;
use credibil_infosec::Signer;
use credibil_infosec::jose::jws;

use crate::core::{Kind, OneMany};
use crate::oid4vci::types::CredentialDisplay;
use crate::w3c_vc::jose::VcClaims;
use crate::w3c_vc::types::{LangString, Language};
use crate::w3c_vc::vc::{CredentialStatus, CredentialSubject, VerifiableCredential};

/// Generate a W3C `jwt_vc_json` format credential.
#[derive(Debug)]
pub struct W3cVcBuilder<S> {
    vc: VerifiableCredential,
    signer: S,
}

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signer>(pub &'a S);

impl W3cVcBuilder<NoSigner> {
    pub fn new() -> Self {
        Self {
            vc: VerifiableCredential {
                type_: OneMany::One("VerifiableCredential".to_string()),
                ..Default::default()
            },
            signer: NoSigner,
        }
    }
}

impl W3cVcBuilder<NoSigner> {
    /// Set the credential Signer.
    pub fn signer<S: Signer>(self, signer: &'_ S) -> W3cVcBuilder<HasSigner<'_, S>> {
        W3cVcBuilder {
            vc: self.vc,
            signer: HasSigner(signer),
        }
    }
}

impl<S> W3cVcBuilder<S> {
    // /// Sets the `id` property
    // #[must_use]
    // pub fn id(mut self, id: impl Into<String>) -> Self {
    //     self.vc.id = Some(id.into());
    //     self
    // }

    /// Sets the `type_` property
    #[must_use]
    pub fn add_type(mut self, type_: impl Into<String>) -> Self {
        self.vc.type_.add(type_.into());
        self
    }

    /// Sets the `display` property
    #[must_use]
    pub fn display(mut self, display: &[CredentialDisplay]) -> Self {
        let (name, description) = create_names(display);
        if let Some(n) = name {
            self.vc.name = Some(n);
        }

        if let Some(d) = description {
            self.vc.description = Some(d);
        }

        self
    }

    // /// Sets the `name` property
    // #[must_use]
    // pub fn name(mut self, name: LangString) -> Self {
    //     self.vc.name = Some(name);
    //     self
    // }

    // /// Sets the `description` property
    // #[must_use]
    // pub fn description(mut self, description: LangString) -> Self {
    //     self.vc.description = Some(description);
    //     self
    // }

    /// Sets the `issuer` property
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.vc.issuer = Kind::String(issuer.into());
        self
    }

    /// Adds one or more `credential_subject` properties.
    #[must_use]
    pub fn add_subject(mut self, subj: CredentialSubject) -> Self {
        let one_set = match self.vc.credential_subject {
            OneMany::One(one) => {
                if one == CredentialSubject::default() {
                    OneMany::One(subj)
                } else {
                    OneMany::Many(vec![one, subj])
                }
            }
            OneMany::Many(mut set) => {
                set.push(subj);
                OneMany::Many(set)
            }
        };

        self.vc.credential_subject = one_set;
        self
    }

    /// Sets the `credential_status` property.
    #[must_use]
    pub fn status(mut self, status: Option<OneMany<CredentialStatus>>) -> Self {
        self.vc.credential_status = status;
        self
    }
}

impl<S: Signer> W3cVcBuilder<HasSigner<'_, S>> {
    /// Build the W3C credential, returning a base64url-encoded JSON JWT.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> anyhow::Result<String> {
        let mut vc = self.vc;

        // FIXME: generate credential id
        if let Kind::String(issuer) = &vc.issuer {
            if let OneMany::Many(credential_type) = &vc.type_ {
                vc.id = Some(format!("{issuer}/credentials/{}", credential_type[1]));
            }
        }

        let claims = VcClaims::from(vc);
        jws::encode(&claims, self.signer.0)
            .await
            .map_err(|e| anyhow!("issue generating `jwt_vc_json` credential: {e}"))
    }
}

// Extract language object name and description from a `CredentialDisplay`
// vector.
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
