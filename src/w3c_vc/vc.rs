//! # Verifiable Credentials Data Model

use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::{Kind, OneMany};
use crate::w3c_vc::proof::Proof;
use crate::w3c_vc::types::LangString;

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
    pub type_: OneMany<String>,

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
    ///
    /// # Errors
    ///
    /// Fails with `Error::ServerError` if any of the VC's mandatory fields are
    /// not set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // /// Returns a new [`VcBuilder`], which can be used to build a
    // /// [`VerifiableCredential`]
    // #[must_use]
    // pub fn builder() -> VcBuilder {
    //     VcBuilder::new()
    // }
}

impl crate::dif_exch::Claims for VerifiableCredential {
    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
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
    #[serde(rename = "BitstringStatusListEntry", rename_all = "camelCase")]
    Bitstring(Bitstring),
}

impl Default for CredentialStatusType {
    fn default() -> Self {
        Self::Bitstring(Bitstring {
            status_purpose: StatusPurpose::Revocation,
            status_list_index: 0,
            status_list_credential: String::new(),
            status_size: None,
            status_message: None,
            status_reference: None,
        })
    }
}

/// `Bitstring` is a credential status method.
///
/// [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Bitstring {
    /// The purpose of the status declaration stored in the bitstring.
    pub status_purpose: StatusPurpose,

    /// The position of the status flag in the bitstring.
    pub status_list_index: usize,

    /// A URL to a verifiable credential. When dereferenced, the resulting
    /// VC will have a type property that includes
    /// `BitstringStatusListCredential`.
    pub status_list_credential: String,

    /// The size of the status entry in bits. If not present, the size is
    /// assumed to be 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_size: Option<usize>,

    /// A list of arbitrary status codes and messages for the `Message`
    /// status purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<Vec<StatusMessage>>,

    /// A URL to more information on the status method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<String>,
}

/// `StatusPurpose` defines the purpose of the issuer's credential status
/// information that may be stored on a verifiable credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    /// Used to permanently cancel the validity of a verifiable credential.
    #[default]
    Revocation,
    /// Used to temporarily suspend the validity of a verifiable credential.
    Suspension,
    /// Used to convey an arbitrary message related to the status of the
    /// verifiable credential.
    Message,
}

impl Display for StatusPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revocation => write!(f, "revocation"),
            Self::Suspension => write!(f, "suspension"),
            Self::Message => write!(f, "message"),
        }
    }
}

/// `StatusMessage` is used to convey an arbitrary status code and message
/// for a verifiable credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusMessage {
    /// A string representing the hexadecimal value of the status prefixed
    /// with `0x`.
    pub status: String,

    /// A string used by developers to assist with debugging but should not be
    /// displayed to end users.
    pub message: String,
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
            type_: OneMany::Many(vec![
                "VerifiableCredential".to_string(),
                "EmployeeIDCredential".to_string(),
            ]),
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
}
