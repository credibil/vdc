//! # W3C Verifiable Credentials
//!
//! This module encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

mod issue;
mod present;
mod store;
mod verify;

use std::collections::HashMap;
use std::ops::Deref;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
pub use verify::verify_vp;

pub use self::issue::W3cVcBuilder;
pub use self::present::W3cVpBuilder;
pub use self::store::to_queryable;
use crate::core::{Kind, OneMany};
use crate::status::StatusClaim;

/// `VerifiableCredential` represents a naive implementation of the W3C
/// Verifiable Credential data model v1.1.
/// See <https://www.w3.org/TR/vc-data-model>.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct VerifiableCredential {
    // LATER: add support for @context objects
    /// The @context property is used to map property URIs into short-form
    /// aliases. It is an ordered set where the first item is "`https://www.w3.org/2018/credentials/v1`".
    /// Subsequent items may be composed of any combination of URLs and/or
    /// objects, each processable as a [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context).
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// The id property is OPTIONAL. If present, id property's value MUST be a
    /// single URL, which MAY be dereferenceable. It is RECOMMENDED that the URL
    /// in the id be one which, if dereferenceable, results in a document
    /// containing machine-readable information about the id. For example,
    /// "`http://example.edu/credentials/3732`".
    pub id: Option<String>,

    /// The type property is used to determine whether or not a provided
    /// verifiable credential is appropriate for the intended use-case. It is an
    /// unordered set of terms or URIs (full or relative to @context). It is
    /// RECOMMENDED that each URI, if dereferenced, will result in a
    /// document containing machine-readable information about
    /// the type. Syntactic conveniences, such as JSON-LD, SHOULD be used to
    /// ease developer usage.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The name property expresses the name of the credential. If present, the
    /// value of the name property MUST be a string or a language value object.
    /// Ideally, the name of a credential is concise, human-readable, and could
    /// enable an individual to quickly differentiate one credential from any
    /// other credentials they might hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<LangString>,

    /// The description property conveys specific details about a credential. If
    /// present, the value of the description property MUST be a string or a
    /// language value object. Ideally, the description of a credential is no
    /// more than a few sentences in length and conveys enough information about
    /// the credential to remind an individual of its contents without having to
    /// look through the entirety of the claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LangString>,

    /// A URI or object with an id property. It is RECOMMENDED that the
    /// URI/object id, dereferences to machine-readable information about
    /// the issuer that can be used to verify credential information.
    pub issuer: Kind<Issuer>,

    /// A set of objects containing claims about credential subjects(s).
    pub credential_subject: OneMany<CredentialSubject>,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential becomes valid.
    /// e.g. 2010-01-01T19:23:24Z.
    ///
    /// Note: this is not necessarily the date the credential was issued.
    pub valid_from: Option<DateTime<Utc>>,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential ceases to be valid.
    /// e.g. 2010-06-30T19:23:24Z
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Used to determine the status of the credential, such as whether it is
    /// suspended or revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<OneMany<CredentialStatus>>,

    /// The credentialSchema defines the structure and datatypes of the
    /// credential. Consists of one or more schemas that can be used to
    /// check credential data conformance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneMany<CredentialSchema>>,

    /// One or more cryptographic proofs that can be used to detect tampering
    /// and verify authorship of a credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneMany<Proof>>,

    /// Related resources allow external data to be associated with the
    /// credential and an integrity mechanism to allow a verify to check the
    /// related data has not changed since the credential was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_resource: Option<OneMany<RelatedResource>>,

    /// `RefreshService` can be used to provide a link to the issuer's refresh
    /// service so Holder's can refresh (manually or automatically) an
    /// expired credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<RefreshService>,

    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation
    /// was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<OneMany<Term>>,

    /// Evidence can be included by an issuer to provide the verifier with
    /// additional supporting information in a credential. This could be
    /// used by the verifier to establish the confidence with which it
    /// relies on credential claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<OneMany<Evidence>>,
}

impl VerifiableCredential {
    /// Returns a new [`VerifiableCredential`] configured with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Issuer identifies the issuer of the credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Issuer {
    /// The issuer URI. If dereferenced, it should result in a machine-readable
    /// document that can be used to verify the credential.
    pub id: String,

    /// Issuer-specific fields that may be used to express additional
    /// information about the issuer.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, Value>>,
}

/// `CredentialSubject` holds claims about the subject(s) referenced by the
/// credential. Or, more correctly: a set of objects containing one or more
/// properties related to a subject of the credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSubject {
    /// A URI that uniquely identifies the subject of the claims. if set, it
    /// MUST be the identifier used by others to identify the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claims about the subject.
    #[serde(flatten)]
    pub claims: Map<String, Value>,
}

/// `CredentialStatus` can be used for the discovery of information about the
/// current status of a credential, such as whether it is suspended or revoked.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialStatus {
    /// A URI where credential status information can be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(flatten)]
    pub credential_status_type: CredentialStatusType,
}

/// `CredentialStatusType` are supported credential status methods.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum CredentialStatusType {
    /// A bitstring credential status list method for checking credential
    /// status.
    #[serde(rename = "TokenStatusListEntry", rename_all = "camelCase")]
    TokenStatus(StatusClaim),
}

impl Default for CredentialStatusType {
    fn default() -> Self {
        Self::TokenStatus(StatusClaim::default())
    }
}

/// `CredentialSchema` defines the structure of the credential and the datatypes
/// of each property contained.
///
/// It can be used to verify if credential data is syntatically correct. The
/// precise contents of each data schema is determined by the specific type
/// definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSchema {
    /// A URI identifying the schema file.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential. e.g. "`JsonSchemaValidator2018`"
    #[serde(rename = "type")]
    pub type_: String,
}

/// `RelatedResource` allows external data to be associated with the credential
/// and an integrity mechanism to allow a verifier to check the related data.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct RelatedResource {
    /// The identifier for the resource, typically a URL from which the
    /// resource can be retrieved, or another dereferenceable identifier.
    pub id: String,

    /// The type of media as defined by the
    /// [IANA Media Types registry](https://www.iana.org/assignments/media-types/media-types.xhtml).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// One or more cryptographic digests, as defined by the `hash-expression`
    /// ABNF grammar defined in the Subresource Integrity specification,
    /// [Section 3.5: The integrity attribute](https://www.w3.org/TR/SRI/#the-integrity-attribute).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "digestSRI")]
    pub digest_sri: Option<OneMany<String>>,

    /// One or more cryptographic digests, as defined by the digestMultibase
    /// property in the Verifiable Credential Data Integrity 1.0 specification,
    /// [Section 2.3: Resource Integrity](https://www.w3.org/TR/vc-data-integrity/#resource-integrity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_multibase: Option<OneMany<String>>,
}

/// `RefreshService` can be used to provide a link to the issuer's refresh
/// service so Holder's can refresh (manually or automatically) an expired
/// credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    /// A URI where credential status information can be retrieved.
    pub url: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,

    /// Refresh token to present to the refresh service.
    pub refresh_token: String,
}

/// Term is a single term used in defining the issuers terms of use.
///
/// In aggregate, the termsOfUse property tells the verifier what actions it is
/// required to perform (an obligation), not allowed to perform (a prohibition),
/// or allowed to perform (a permission) if it is to accept the verifiable
/// credential or verifiable presentation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Term {
    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,

    /// A URI where credential policy information can be retrieved.
    pub id: Option<String>,

    /// The policy content specific to the type.
    #[serde(flatten)]
    pub policy: Value,
}

/// Evidence can be included by an issuer to provide the verifier with
/// additional supporting information in a credential.
///
/// This could be used by the verifier to establish the confidence with which it
/// relies on credential claims.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Evidence {
    /// A URL pointing to where more information about this instance of evidence
    /// can be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Type identifies the evidence scheme used for the instance of evidence.
    /// For example, "`DriversLicense`" or "`Passport`".
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A human-readable title for the evidence type.
    pub name: Option<String>,

    /// A human-readable description of the evidence type.
    pub description: Option<String>,

    /// One or more cryptographic digests, as defined by the `hash-expression`
    /// ABNF grammar defined in the Subresource Integrity specification,
    /// [Section 3.5: The integrity attribute](https://www.w3.org/TR/SRI/#the-integrity-attribute).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "digestSRI")]
    pub digest_sri: Option<OneMany<String>>,

    /// One or more cryptographic digests, as defined by the digestMultibase
    /// property in the Verifiable Credential Data Integrity 1.0 specification,
    /// [Section 2.3: Resource Integrity](https://www.w3.org/TR/vc-data-integrity/#resource-integrity).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "digestMultibase")]
    pub digest_multibase: Option<OneMany<String>>,

    /// A list of schema-specific evidence fields.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

/// Claims used for Verifiable Credential issuance when format is
/// "`jwt_vc_json`".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct W3cVcClaims {
    /// The Holder ID the Credential is intended for. Typically, the DID of the
    /// Holder from the Credential's `credentialSubject.id` property.
    ///
    /// For example, "did:example:ebfeb1f712ebc6f1c276e12ec21".
    pub sub: String,

    /// The `issuer` property of the Credential.
    ///
    /// For example, "did:example:123456789abcdefghi#keys-1".
    pub iss: String,

    /// The Credential's issuance date, encoded as a UNIX timestamp.
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The `id` property of the Credential.
    pub jti: String,

    /// The expiration time of the signature, encoded as a UNIX timestamp. This
    /// is NOT the same as the Credential `validUntil`property.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exp: Option<DateTime<Utc>>,

    /// The Credential.
    pub vc: VerifiableCredential,
}

/// Create Verifiable Credential JWT payload from a W3C Verifiable
/// Credential.
impl From<VerifiableCredential> for W3cVcClaims {
    fn from(vc: VerifiableCredential) -> Self {
        let subject = match &vc.credential_subject {
            OneMany::One(sub) => sub,
            OneMany::Many(subs) => &subs[0],
        };

        let issuer_id = match &vc.issuer {
            Kind::String(id) => id,
            Kind::Object(issuer) => &issuer.id,
        };

        Self {
            // TODO: find better way to set sub (shouldn't need to be in vc)
            sub: subject.id.clone().unwrap_or_default(),
            iss: issuer_id.clone(),
            iat: Utc::now(),
            jti: vc.id.clone().unwrap_or_default(),
            exp: None, //vc.valid_until,
            vc,
        }
    }
}

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
    #[serde(rename = "type")]
    pub type_: OneMany<String>,

    /// One or more Verifiable Credentials, or data derived from Verifiable
    /// Credentials in a cryptographically verifiable format.
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

/// To sign, or sign and encrypt the Authorization Response, implementations MAY
/// use JWT Secured Authorization Response Mode for OAuth 2.0
/// ([JARM](https://openid.net/specs/oauth-v2-jarm-final.html)).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct W3cVpClaims {
    /// The `holder` property of the Presentation.
    /// For example, "did:example:123456789abcdefghi".
    pub iss: String,

    /// The `id` property of the Presentation.
    ///
    /// For example, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5".
    pub jti: String,

    /// The `client_id` value from the Verifier's Authorization Request.
    pub aud: String,

    /// The `nonce` value from the Verifier's Authorization Request.
    pub nonce: String,

    /// The time the Presentation was created, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,

    /// The time the Presentation was created, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The time the Presentation will expire, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,

    /// The Verifiable Presentation.
    pub vp: VerifiablePresentation,
}

impl From<VerifiablePresentation> for W3cVpClaims {
    fn from(vp: VerifiablePresentation) -> Self {
        Self {
            iss: vp.holder.clone().unwrap_or_default(),
            jti: vp.id.clone().unwrap_or_default(),
            nbf: Utc::now(),
            iat: Utc::now(),
            exp: Utc::now() + TimeDelta::days(365), // TODO: configure `exp` time
            vp,
            ..Self::default()
        }
    }
}

/// To be verifiable, a credential must contain at least one proof mechanism,
/// and details necessary to evaluate that proof.
///
/// A proof may be external (an enveloping proof) or internal (an embedded
/// proof).
///
/// Enveloping proofs are implemented using JOSE and COSE, while embedded proofs
/// are implemented using the `Proof` object described here.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_field_names)]
pub struct Proof {
    /// An optional identifier for the proof. MUST be a URL, such as a UUID as a
    /// URN e.g. "`urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The specific proof type. MUST map to a URL. Examples include
    /// "`DataIntegrityProof`" and "`Ed25519Signature2020`". The type determines
    /// the other fields required to secure and verify the proof.
    ///
    /// When set to "`DataIntegrityProof`", the `cryptosuite` and the
    /// `proofValue` properties MUST be set.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the cryptosuite property identifies the cryptographic
    /// suite. If subtypes are supported, it MUST be the <https://w3id.org/security#cryptosuiteString>
    /// subtype of string.
    ///
    /// For example, 'ecdsa-rdfc-2019', 'eddsa-2022'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// The reason for the proof. MUST map to a URL. The proof purpose acts as a
    /// safeguard to prevent the proof from being misused.
    pub proof_purpose: String,

    /// Used to verify the proof. MUST map to a URL. For example, a link to a
    /// public key that is used by a verifier during the verification
    /// process. e.g did:example:123456789abcdefghi#keys-1.
    pub verification_method: String,

    /// The date-time the proof was created. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// The date-time the proof expires. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// One or more security domains in which the proof is meant to be used.
    /// MUST be either a string, or a set of strings. SHOULD be used by the
    /// verifier to ensure the proof is used in the correct security domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<OneMany<String>>,

    /// Used to mitigate replay attacks. SHOULD be included if a domain is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Contains the data needed to verify the proof using the
    /// verificationMethod specified. MUST be a MULTIBASE-encoded binary
    /// value.
    pub proof_value: String,

    /// Each value identifies another data integrity proof that MUST verify
    /// before the current proof is processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<OneMany<String>>,

    /// Supplied by the proof creator. Can be used to increase privacy by
    /// decreasing linkability that results from deterministically generated
    /// signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// `Payload` is used to identify the type of proof to be created.
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Payload {
    /// A Verifiable Credential proof encoded as a JWT.
    Vc {
        /// The Credential to create a proof for.
        vc: VerifiableCredential,

        /// The issuance date and time of the Credential.
        issued_at: DateTime<Utc>,
    },

    /// A Verifiable Presentation proof encoded as a JWT.
    Vp {
        /// The Presentation to create a proof for.
        vp: VerifiablePresentation,

        /// The Verifier's OpenID `client_id` (from Presentation request).
        client_id: String,

        /// The Verifier's `nonce` (from Presentation request).
        nonce: String,
    },
}

/// Data type to verify.
pub enum Verify<'a> {
    /// A Verifiable Presentation proof either encoded as a JWT or with an
    /// embedded a Data Integrity Proof.
    Vp(&'a Kind<VerifiablePresentation>),
}

/// `LangString` is a string that has one or more language representations.
///
/// <https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct LangString(Kind<OneMany<Language>>);

impl LangString {
    /// Create a new `LangString` from a simple string.
    #[must_use]
    pub fn new_string(value: &str) -> Self {
        Self(Kind::String(value.to_string()))
    }

    /// Create a new `LangString` from a single language object.
    #[must_use]
    pub const fn new_object(value: Language) -> Self {
        Self(Kind::Object(OneMany::One(value)))
    }

    /// Add a language object to the `LangString`.
    pub fn add(&mut self, value: Language) {
        match &self.0 {
            Kind::String(s) => {
                let existing = Language {
                    value: s.clone(),
                    ..Language::default()
                };
                self.0 = Kind::Object(OneMany::Many(vec![existing, value]));
            }
            Kind::Object(lang_values) => {
                let mut new_values = lang_values.clone();
                new_values.add(value);
                self.0 = Kind::Object(new_values.clone());
            }
        }
    }

    /// Length of the `LangString` is the number of language objects.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.0 {
            Kind::String(_) => 1,
            Kind::Object(lang_values) => lang_values.len(),
        }
    }

    /// Check if the `LangString` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Extract a value for the provided language tag.
    ///
    /// If the language string is a simple string, the value is returned as is.
    /// If the language string is an object, the value for the provided language
    /// tag is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the language tag is not found.
    pub fn value(&self, language: &str) -> anyhow::Result<String> {
        match &self.0 {
            Kind::String(s) => Ok(s.to_string()),
            Kind::Object(lang_values) => match lang_values {
                OneMany::One(lang_value) => {
                    if lang_value.language == Some(language.to_string()) {
                        Ok(lang_value.value.clone())
                    } else {
                        Err(anyhow::anyhow!("Language tag not found"))
                    }
                }
                OneMany::Many(lang_values) => {
                    for lang_value in lang_values {
                        if lang_value.language == Some(language.to_string()) {
                            return Ok(lang_value.value.clone());
                        }
                    }
                    Err(anyhow::anyhow!("Language tag not found"))
                }
            },
        }
    }
}

impl Deref for LangString {
    type Target = Kind<OneMany<Language>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// `Language` is a description of a string in a specific language.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Language {
    /// Value of the string
    #[serde(rename = "@value")]
    pub value: String,

    /// Language-tag as defined in [rfc5646](https://www.rfc-editor.org/rfc/rfc5646)
    ///
    /// A missing language tag implies that the string is in the default language.
    #[serde(rename = "@language")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// Base direction of the text when bidirectional text is displayed.
    #[serde(rename = "@direction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
}

/// Base direction of the text when bidirectional text is displayed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Direction {
    /// Left-to-right
    #[serde(rename = "ltr")]
    Ltr,

    /// Right-to-left
    #[serde(rename = "rtl")]
    Rtl,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[test]
    fn builder() {
        let vc = sample_vc();
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");

        assert_eq!(
            *vc_json.get("@context").expect("@context should be set"),
            json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ])
        );
        assert_eq!(
            *vc_json.get("id").expect("id should be set"),
            json!("https://example.com/credentials/3732")
        );
        assert_eq!(
            *vc_json.get("type").expect("type should be set"),
            json!(["VerifiableCredential", "EmployeeIDCredential"])
        );
        assert_eq!(
            *vc_json.get("credentialSubject").expect("credentialSubject should be set"),
            json!({"employeeId":"1234567890","id":"did:example:ebfeb1f712ebc6f1c276e12ec21"})
        );
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        assert_eq!(
            *vc_json.get("validFrom").expect("validFrom should be set"),
            json!(vc.valid_from)
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.context, vc.context);
        assert_eq!(vc_de.id, vc.id);
        assert_eq!(vc_de.type_, vc.type_);
        assert_eq!(vc_de.credential_subject, vc.credential_subject);
        assert_eq!(vc_de.issuer, vc.issuer);
    }

    #[test]
    fn flexvec() {
        let mut vc = sample_vc();
        vc.credential_schema = Some(OneMany::Many(vec![
            CredentialSchema { ..Default::default() },
            CredentialSchema { ..Default::default() },
        ]));

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert!(vc_json.get("proof").is_none());
        assert_eq!(
            *vc_json.get("credentialSchema").expect("credentialSchema should be set"),
            json!([{"id":"","type":""},{"id":"","type":""}]),
            "Vec with len() > 1 should serialize to array"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.proof, vc.proof, "should deserialize to Vec");
        assert_eq!(
            vc_de.credential_schema, vc.credential_schema,
            "array should deserialize to Vec"
        );
    }

    #[test]
    fn strobj() {
        let mut vc = sample_vc();

        // serialize with just issuer 'id' field set
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        // deserialize from issuer as string,  e.g."issuer":"<value>"
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer);

        let mut issuer = match &vc.issuer {
            Kind::Object(issuer) => issuer.clone(),
            Kind::String(id) => Issuer {
                id: id.clone(),
                ..Issuer::default()
            },
        };
        issuer.extra = Some(HashMap::from([(
            "name".to_string(),
            Value::String("Example University".to_string()),
        )]));
        vc.issuer = Kind::Object(issuer);

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!({"id": "https://example.com/issuers/14", "name": "Example University"}),
            "issuer 'extra' fields should flatten on serialization"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer, "issuer 'extra' fields should be populated");
    }

    fn sample_vc() -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                Kind::String("https://www.w3.org/2018/credentials/v1".to_string()),
                Kind::String("https://www.w3.org/2018/credentials/examples/v1".to_string()),
            ],
            type_: vec!["VerifiableCredential".to_string(), "EmployeeIDCredential".to_string()],
            issuer: Kind::String("https://example.com/issuers/14".to_string()),
            id: Some("https://example.com/credentials/3732".to_string()),
            valid_from: Some(Utc.with_ymd_and_hms(2023, 11, 20, 23, 21, 55).unwrap()),
            credential_subject: OneMany::One(CredentialSubject {
                id: Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_string()),
                claims: json!({"employeeId": "1234567890"})
                    .as_object()
                    .map_or_else(Map::default, Clone::clone),
            }),
            valid_until: Some(Utc.with_ymd_and_hms(2033, 12, 20, 23, 21, 55).unwrap()),

            ..VerifiableCredential::default()
        }
    }

    #[test]
    fn test_vp_build() {
        let vp = base_vp();

        // serialize
        let vp_json = serde_json::to_value(&vp).expect("should serialize");

        assert_eq!(
            *vp_json.get("@context").expect("@context should be set"),
            json!(["https://www.w3.org/2018/credentials/v1"])
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

    fn base_vp() -> VerifiablePresentation {
        let mut subj = CredentialSubject::default();
        subj.id = Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_string());
        subj.claims = json!({"employeeID": "1234567890"}).as_object().unwrap().clone();

        let vc = VerifiableCredential {
            id: Some("https://example.com/credentials/3732".to_string()),
            type_: vec!["VerifiableCredential".to_string(), "EmployeeIDCredential".to_string()],
            issuer: Kind::String("https://example.com/issuers/14".to_string()),
            credential_subject: OneMany::One(subj),
            ..VerifiableCredential::default()
        };

        VerifiablePresentation {
            context: vec![Kind::String("https://www.w3.org/2018/credentials/v1".to_string())],
            type_: OneMany::Many(vec![
                "VerifiablePresentation".to_string(),
                "EmployeeIDCredential".to_string(),
            ]),
            verifiable_credential: Some(vec![Kind::Object(vc)]),
            ..Default::default()
        }
    }

    #[derive(Deserialize, Serialize)]
    struct Info {
        name: LangString,
        description: LangString,
        other: Option<LangString>,
    }

    fn info_sample() -> serde_json::Value {
        json!({
            "name": {
                "@value": "Alice",
                "@language": "en",
            },
            "description": [
                {
                    "@value": "HTML and CSS: Designing and Creating Websites",
                    "@language": "en"
                },
                {
                    "@value": "HTML و CSS: تصميم و إنشاء مواقع الويب",
                    "@language": "ar",
                    "@direction": "rtl"
                }
            ],
            "other": "Just a string"
        })
    }

    #[test]
    fn language_serialization() {
        let json = info_sample();

        let info: Info = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(info.name.value("en").unwrap(), "Alice");

        let serialized = serde_json::to_value(&info).unwrap();
        assert_eq!(json, serialized);
    }

    #[test]
    fn language_value() {
        let json = info_sample();
        let info: Info = serde_json::from_value(json).unwrap();

        assert_eq!(info.name.value("en").unwrap(), "Alice");
        assert_eq!(
            info.other.expect("option should be some").value("en").unwrap(),
            "Just a string"
        );
        info.description.value("es").expect_err("Spanish language tag should not be found");
    }
}
