//! # Digital Credentials Query Language (DCQL)

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};
// use crate::oid4vp::Result;

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
    pub format: FormatProfile,

    /// Additional properties requested that apply to the metadata of the
    /// Credential. Properties are specific to Credential Format Profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetadataQuery>,

    /// An array of objects that specifies claims in the requested Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,

    /// Combinations of claims to use when requesting Credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
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
pub struct ClaimQuery {
    /// Identifies the claim within the claims array.
    ///
    /// Required when `claim_sets` is present in the Credential Query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// An array of claims path pointers specifying the path to a claim within
    /// the Credential.
    pub path: Vec<String>,

    /// The expected values of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

/// Credential metadata query parameters. Properties are specific to Credential
/// Format Profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum MetadataQuery {
    /// ISO-MDL format credential metadata.
    IsoMdl {
        /// Allowed value for the doctype of the requested Credential.
        doctype_value: String,
    },

    /// SD-JWT format credential  metadata.
    SdJwt {
        /// Allowed values when querying for SD-JWT Credentials.
        vct_values: Vec<String>,
    },
}

/// A generic credential claim.
pub struct Claim {
    /// The path to the claim within the credential.
    pub path: Vec<String>,

    /// The claim's values.
    pub values: Vec<Value>,
}

/// A trait implemented by credentials so they can be queried by DCQL.
pub trait Credential {
    /// Returns the Credential's format.
    fn meta(&self) -> CredentialConfiguration;

    /// Returns the Credential's claims.
    fn claims(&self) -> Vec<Claim>;
}

impl DcqlQuery {
    /// Determines whether the specified credential matches the query.
    pub fn is_match(&self, credential: &impl Credential) -> bool {
        let Some(credential_sets) = &self.credential_sets else {
            return self.credentials.iter().any(|cq| cq.is_match(credential).is_some());
        };

        // a set of Credentials that match to one of the CredentialSetQuery `options`

        // match credential:
        //  - CredentialSetQuery objects where `required` is true/omitted
        //  - any of the other Credential Set Queries.

        for credential_set in credential_sets {
            let mut matched = false;

            for option in &credential_set.options {
                let mut option_matched = true;

                for cq_id in option {
                    if !self.credentials.iter().any(|cq| cq.id == *cq_id) {
                        option_matched = false;
                        break;
                    }
                }

                if option_matched {
                    matched = true;
                    break;
                }
            }

            if !matched {
                return false;
            }
        }

        false
    }
}

impl CredentialQuery {
    /// Determines whether the specified credential matches the query.
    pub fn is_match(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        // format match
        if self.format != credential.meta().profile {
            return None;
        }

        // metadata match
        if let Some(meta) = &self.meta {
            if !meta.is_match(&credential.meta()) {
                return None;
            }
        }

        // claims match
        let claims = self.match_claims(credential)?;

        Some(claims)
    }

    // Find matching claims in the credential.
    fn match_claims(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        // when no claim queries are specified, return all claims
        let Some(claim_queries) = &self.claims else {
            return Some(credential.claims());
        };

        // when no claim sets are specified, return claims matching claim queries
        let Some(claim_sets) = &self.claim_sets else {
            let mut matched = vec![];
            for claim in credential.claims() {
                if claim_queries.iter().any(|cq| cq.matches(&claim)) {
                    matched.push(claim);
                }
            }
            return Some(matched);
        };

        // return the claims specified by the first matched claim set
        for claim_set in claim_sets {
            let mut matched = vec![];

            // find the first matching claim set
            for id in claim_set {
                // get claim query by id
                if let Some(claim_query) =
                    claim_queries.iter().find(|cq| cq.id.as_ref() == Some(id))
                {
                    for claim in credential.claims() {
                        if claim_query.matches(&claim) {
                            matched.push(claim);
                        }
                    }
                }
            }

            if !matched.is_empty() {
                return Some(matched);
            }
        }

        None
    }
}

impl ClaimQuery {
    /// Determine whether the specified claim matches the `ClaimQuery`.
    #[must_use]
    pub fn matches(&self, claim: &Claim) -> bool {
        if self.path == claim.path {
            let Some(values) = &self.values else {
                return true;
            };
            return values.iter().all(|v| claim.values.contains(v));
        }
        false
    }
}

impl MetadataQuery {
    fn is_match(&self, meta: &CredentialConfiguration) -> bool {
        match &self {
            Self::IsoMdl { doctype_value } => {
                if let FormatProfile::IsoMdl { doctype } = &meta.profile {
                    if doctype != doctype_value {
                        return false;
                    }
                }
            }
            Self::SdJwt { vct_values } => {
                if let FormatProfile::DcSdJwt { vct } = &meta.profile {
                    if !vct_values.contains(vct) {
                        return false;
                    }
                }
            }
        }

        true
    }
}
