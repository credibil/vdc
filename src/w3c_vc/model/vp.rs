//! # Verifiable Presentations
//!
//! [Verifiable Presentations](https://www.w3.org/TR/vc-data-model/#presentations-0)
//!
//! Specifications:
//! - <https://identity.foundation/presentation-exchange/spec/v2.0.0>
//! - <https://identity.foundation/jwt-vc-presentation-profile>
//! - <https://identity.foundation/claim-format-registry>

use std::str::FromStr;

use anyhow::bail;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::super::model::vc::VerifiableCredential;
use super::super::proof::integrity::Proof;
use crate::core::{Kind, OneMany};

/// A Verifiable Presentation is used to combine and present credentials to a
/// Verifer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct VerifiablePresentation {
    // LATER: add support for @context objects
    #[allow(rustdoc::bare_urls)]
    /// The @context property is used to map property URIs into short-form
    /// aliases. It is an ordered set where the first item is `"https://www.w3.org/2018/credentials/v1"`.
    /// Subsequent items MUST express context information and can be either URIs
    /// or objects. Each URI, if dereferenced, should result in a document
    /// containing machine-readable information about the @context.
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// MAY be used to provide a unique identifier for the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The type property is required and expresses the type of presentation,
    /// such as `VerifiablePresentation`. Consists of `VerifiablePresentation`
    /// and, optionally, a more specific verifiable presentation type.
    /// e.g. `"type": ["VerifiablePresentation",
    /// "CredentialManagerPresentation"]`
    #[serde(rename = "type")]
    pub type_: OneMany<String>,

    /// The verifiableCredential property MUST be constructed from one or more
    /// verifiable credentials, or of data derived from verifiable
    /// credentials in a cryptographically verifiable format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<Vec<Kind<VerifiableCredential>>>,

    /// Holder is a URI for the entity that is generating the presentation.
    /// For example, did:example:ebfeb1f712ebc6f1c276e12ec21.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    /// An embedded proof ensures that the presentation is verifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneMany<Proof>>,
}

impl VerifiablePresentation {
    /// Returns a new [`VerifiablePresentation`] configured with defaults
    ///
    /// # Errors
    ///
    /// Fails with `Error::ServerError` if any of the VP's mandatory fields
    /// are not set.
    pub fn new() -> anyhow::Result<Self> {
        Self::builder().try_into()
    }

    /// Returns a new [`VpBuilder`], which can be used to build a
    /// [`VerifiablePresentation`]
    #[must_use]
    pub fn builder() -> VpBuilder {
        VpBuilder::new()
    }
}

impl TryFrom<VpBuilder> for VerifiablePresentation {
    type Error = anyhow::Error;

    fn try_from(builder: VpBuilder) -> anyhow::Result<Self, Self::Error> {
        builder.build()
    }
}

/// [`VpBuilder`] is used to build a [`VerifiablePresentation`]
#[derive(Clone, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct VpBuilder {
    vp: VerifiablePresentation,
}

impl VpBuilder {
    /// Returns a new [`VpBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let mut builder = Self::default();

        // sensibile defaults
        builder.vp.id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
        builder.vp.context.push(Kind::String("https://www.w3.org/2018/credentials/v1".to_string()));
        builder.vp.type_ = OneMany::One("VerifiablePresentation".to_string());
        builder
    }

    /// Sets the `@context` property
    #[must_use]
    pub fn add_context(mut self, context: Kind<Value>) -> Self {
        self.vp.context.push(context);
        self
    }

    /// Adds a type to the `type` property
    #[must_use]
    pub fn add_type(mut self, type_: impl Into<String>) -> Self {
        let mut vp_type = match self.vp.type_ {
            OneMany::One(t) => vec![t],
            OneMany::Many(t) => t,
        };
        vp_type.push(type_.into());

        self.vp.type_ = OneMany::Many(vp_type);
        self
    }

    /// Adds a `verifiable_credential`
    #[must_use]
    pub fn add_credential(mut self, vc: Kind<VerifiableCredential>) -> Self {
        if let Some(verifiable_credential) = self.vp.verifiable_credential.as_mut() {
            verifiable_credential.push(vc);
        } else {
            self.vp.verifiable_credential = Some(vec![vc]);
        }
        self
    }

    /// Sets the `type_` property
    #[must_use]
    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.vp.holder = Some(holder.into());
        self
    }

    /// Turns this builder into a [`VerifiablePresentation`]
    ///
    /// # Errors
    ///
    /// Fails if any of the VP's mandatory fields are not set.
    pub fn build(self) -> anyhow::Result<VerifiablePresentation> {
        if self.vp.context.len() < 2 {
            bail!("context is required");
        }
        if let OneMany::One(_) = self.vp.type_ {
            bail!("type is required");
        }

        Ok(self.vp)
    }
}

impl FromStr for VerifiablePresentation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        if &s[0..1] != "{" {
            // base64 encoded string
            let dec = Base64UrlUnpadded::decode_vec(s)?;
            return Ok(serde_json::from_slice(dec.as_slice())?);
        }

        // stringified JSON
        Ok(serde_json::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::vc::{CredentialSubject, VerifiableCredential};
    use super::*;

    #[test]
    fn test_vp_build() {
        let vp = base_vp().expect("should build vp");

        // serialize
        let vp_json = serde_json::to_value(&vp).expect("should serialize");

        assert_eq!(
            *vp_json.get("@context").expect("@context should be set"),
            json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ])
        );
        assert_eq!(
            *vp_json.get("type").expect("type should be set"),
            json!(["VerifiablePresentation", "EmployeeIDCredential"])
        );

        assert!(vp.verifiable_credential.is_some());

        let vc_field = vp.verifiable_credential.as_ref().expect("vc should be set");
        let vc = &vc_field[0];
        let vc_json = serde_json::to_value(vc).expect("should serialize");

        assert_eq!(
            *vc_json.get("credentialSubject").expect("credentialSubject should be set"),
            json!({"employeeID":"1234567890","id":"did:example:ebfeb1f712ebc6f1c276e12ec21"})
        );
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        // deserialize
        let vp_de: VerifiablePresentation =
            serde_json::from_value(vp_json).expect("should deserialize");
        assert_eq!(vp_de.context, vp.context);
        assert_eq!(vp_de.type_, vp.type_);
        assert_eq!(vp_de.verifiable_credential, vp.verifiable_credential);
    }

    fn base_vp() -> anyhow::Result<VerifiablePresentation> {
        let mut subj = CredentialSubject::default();
        subj.id = Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_string());
        subj.claims = json!({"employeeID": "1234567890"}).as_object().unwrap().clone();

        let vc = VerifiableCredential::builder()
            .add_context(Kind::String(
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ))
            .id("https://example.com/credentials/3732")
            .add_type("EmployeeIDCredential")
            .issuer("https://example.com/issuers/14")
            .add_subject(subj)
            .build()?;

        VerifiablePresentation::builder()
            .add_context(Kind::String(
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ))
            .add_type("EmployeeIDCredential")
            .add_credential(Kind::Object(vc))
            .build()
    }
}
