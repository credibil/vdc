//! # Digital Credentials Query Language (DCQL)

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid4vci::types::Format;

/// DCQL query for requesting Verifiable Presentations.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlQuery {
    /// Identifies requested Credentials.
    pub credentials: Vec<CredentialQuery>,

    /// Additional constraints on requested Credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}
/// Represents a request for a presentation of one Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identifies the Credential in the response and, if provided, the
    /// constraints in `credential_sets`.
    pub id: String,

    /// The format of the requested Credential
    pub format: Format,

    // /// Additional properties requested that apply to the metadata of the
    // /// Credential. Properties are specific to Credential Format.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub meta: Option<MetadataQuery>,
    //
    /// An array of objects that specifies claims in the requested Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<ClaimsQuery>,

    /// Combinations of claims to use when requesting Credentials. Each set
    /// consists of one or more `claims` identifiers (`ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// Used to request one or more credentials.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialSetQuery {
    /// One or more sets of Credential Query identifiers.
    pub options: Vec<Vec<String>>,

    /// Specifies whether the set of Credentials identified by this query set
    /// is required. Defaults to true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Communicates the purpose of the query to the Wallet. The Wallet may
    /// use this information to show the user the reason for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Value>,
}

/// Claims entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsQuery {
    /// Identifies the claim within the claims array.
    ///
    /// Required when `claim_sets` is present in the Credential Query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// An array of claims path pointers specifying the path to a claim within
    /// the Verifiable Credential.
    pub path: Vec<String>,

    /// The expected values of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}
