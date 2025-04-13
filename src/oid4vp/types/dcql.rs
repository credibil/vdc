//! # Digital Credentials Query Language (DCQL)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// DCQL query for requesting Verifiable Presentations.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlQuery {
    /// Identifies requested Credentials.
    pub credentials: Vec<CredentialQuery>,

    /// Additional constraints on requested Credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// A request for the presentation of a single Queryable.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identifies the Queryable in the response and, if provided, the
    /// constraints in `credential_sets`.
    pub id: String,

    /// The format of the requested Queryable
    pub format: CredentialFormat,

    /// Indicates whether multiple Credentials can be returned for this
    /// Queryable Query. If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Additional properties requested that apply to the metadata of the
    /// Queryable. Properties are specific to Queryable Format Profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetadataQuery>,

    /// Issuer certification authorities or trust frameworks that the Verifier
    /// will accept. Every Queryable returned by the Wallet SHOULD match at
    /// least one of the conditions present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

    /// An array of objects that specifies claims in the requested Queryable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,

    /// Combinations of claims to use when requesting Credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// Contains a request for one or more credentials hat satisfy a particular
/// use case for the Verifier.
///
/// A Queryable Set Query is used when multiple Queryable Queries need to be
/// combined to satisfy the Verifier's requirements.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialSetQuery {
    /// A list of Queryable Query sets, one of which must identify a set of
    /// Credentials that satisfies the query.
    ///
    /// Each value in the array contains a set of Queryable Query identifiers
    /// (`CredentialQuery.id`) pointing to a Queryable Query objects in the
    /// `credentials` array.
    pub options: Vec<Vec<String>>,

    /// Specifies whether this Queryable Set Query entry is required.
    /// Defaults to true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Communicates the purpose of the query to the Wallet. The Wallet may
    /// use this information to show the user the reason for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Value>,
}

/// Claims entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimQuery {
    /// Identifies the claim within the claims array.
    ///
    /// Required when `claim_sets` is present in the Queryable Query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// An array of claims path pointers specifying the path to a claim within
    /// the Queryable.
    pub path: Vec<String>,

    /// The expected values of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

/// Queryable metadata query parameters. Properties are specific to Queryable
/// Format Profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MetadataQuery {
    /// ISO-MDL format credential metadata.
    MsoMdoc {
        /// Allowed value for the doctype of the requested Queryable.
        doctype_value: String,
    },

    /// SD-JWT format credential  metadata.
    SdJwt {
        /// Allowed values when querying for SD-JWT Credentials.
        vct_values: Vec<String>,
    },
}

/// The format of the requested Queryable.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CredentialFormat {
    /// A W3C Verifiable Queryable.
    ///
    /// When this format is specified, Queryable Offer, Authorization Details,
    /// Queryable Request, and Queryable Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD
    /// rules.
    #[serde(rename = "jwt_vc_json")]
    #[default]
    JwtVcJson,

    /// A W3C Verifiable Queryable not  using JSON-LD.
    #[serde(rename = "ldp-vc")]
    LdpVc,

    /// A W3C Verifiable Queryable using JSON-LD.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,

    /// An ISO mDL (ISO.18013-5) mobile driving licence format credential.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,

    /// An IETF SD-JWT format credential.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

/// Represents information that helps to identify an Issuer certification
/// authority or trust framework.
///
/// A Queryable is a match to a Trusted Authorities Query if it matches with
/// one of the values in one of the provided types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedAuthoritiesQuery {
    /// An array of objects that specifies claims in the requested Queryable.
    #[serde(rename = "type")]
    pub type_: Option<Vec<ClaimQuery>>,

    /// Combinations of claims to use when requesting Credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Vec<String>>>,
}

/// The type of information about the Issuer trust framework.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum AuthorityType {
    /// The `KeyIdentifier` of the X.509 `AuthorityKeyIdentifier` as a base64url
    /// encoded string.
    ///
    /// The raw byte representation of this element MUST match with the
    /// `AuthorityKeyIdentifier` element of an X.509 certificate in the
    /// certificate chain present in the credential (e.g., in the header of an
    /// `mdoc` or `SD-JWT`).
    #[serde(rename = "aki")]
    #[default]
    Aki,

    /// The identifier of an ETSI TS Trusted List.
    ///
    /// The trust chain of a matching Queryable MUST contain at least one
    /// X.509 Certificate that matches one of the entries of the Trusted List
    /// or its cascading Trusted Lists.
    #[serde(rename = "etsi_tl")]
    EtsiTl,

    /// An OpenID.Federation Entity Identifier.
    ///
    /// A valid trust path, including the given Entity Identifier, must be
    /// constructible from a matching credential.
    #[serde(rename = "openid_fed")]
    OpenidFed,
}
