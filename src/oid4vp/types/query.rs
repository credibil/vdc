//! # Digital Credentials Query Language (DCQL)

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};
// use crate::oid4vp::Result;

/// Implemented by credentials to support DCQL queries.
pub trait Credential {
    /// Returns the Credential's format.
    fn meta(&self) -> &CredentialConfiguration;

    /// Returns the Credential's claims.
    fn claims(&self) -> Vec<Claim>;
}

/// A generic credential claim to use with DCQL queries.
#[derive(Clone, Debug)]
pub struct Claim {
    /// The path to the claim within the credential.
    pub path: Vec<String>,

    /// The claim's values.
    pub values: Vec<Value>,
}

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
    pub format: CredentialFormat,

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
    /// One or more sets of Credential Query identifiers (i.e. `CredentialQuery.id`).
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
#[serde(untagged)]
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

/// The format of the requested Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CredentialFormat {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD
    /// rules.
    #[serde(rename = "jwt_vc_json")]
    #[default]
    JwtVcJson,

    /// A W3C Verifiable Credential not  using JSON-LD.
    #[serde(rename = "ldp-vc")]
    LdpVc,

    /// A W3C Verifiable Credential using JSON-LD.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,

    /// An ISO mDL (ISO.18013-5) mobile driving licence format credential.
    #[serde(rename = "mso_mdoc")]
    IsoMdl,

    /// An IETF SD-JWT format credential.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

impl DcqlQuery {
    /// Determines whether the specified credential matches the query.
    pub fn is_match(&self, credential: &impl Credential) -> bool {
        let Some(credential_sets) = &self.credential_sets else {
            return self.credentials.iter().any(|cq| cq.is_match(credential).is_some());
        };

        // credential must match EVERY set where `required` is true
        'sets: for query_set in credential_sets {
            // TODO: include optional queries
            if !query_set.required.unwrap_or(true) {
                continue;
            }

            // credential must match ONE option
            for option in &query_set.options {
                // match a CredentialQuery in the option set
                for cq_id in option {
                    let Some(cq) = self.credentials.iter().find(|cq| cq.id == *cq_id) else {
                        continue;
                    };
                    if cq.is_match(credential).is_some() {
                        continue 'sets;
                    }
                }
            }

            // credential did not match any option
            return false;
        }

        true
    }
}

impl CredentialQuery {
    /// Determines whether the specified credential matches the query.
    pub fn is_match(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        // format match
        let format = match &credential.meta().profile {
            FormatProfile::IsoMdl { .. } => CredentialFormat::IsoMdl,
            FormatProfile::DcSdJwt { .. } => CredentialFormat::DcSdJwt,
            FormatProfile::JwtVcJson { .. } => CredentialFormat::JwtVcJson,
            _ => return None,
        };
        if self.format != format {
            return None;
        }

        // metadata match
        if let Some(meta) = &self.meta {
            if !meta.is_match(credential.meta()) {
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
        // N.B. every claim query must match at least one claim
        let Some(claim_sets) = &self.claim_sets else {
            return Self::match_claim_queries(claim_queries, credential);
        };

        // find the first claim set where all claim queries are matched
        for claim_set in claim_sets {
            let mut queries = Vec::<ClaimQuery>::new();
            for id in claim_set {
                if let Some(cq) = claim_queries.iter().find(|cq| cq.id.as_ref() == Some(id)) {
                    queries.push(cq.clone());
                }
            }

            if let Some(matched) = Self::match_claim_queries(&queries, credential) {
                return Some(matched);
            }
        }

        None
    }

    fn match_claim_queries(
        queries: &[ClaimQuery], credential: &impl Credential,
    ) -> Option<Vec<Claim>> {
        let mut matched = vec![];

        for cq in queries {
            for claim in credential.claims() {
                if cq.matches(&claim) {
                    matched.push(claim);
                    break;
                }
            }
        }

        if matched.len() == queries.len() {
            return Some(matched);
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

#[cfg(test)]
mod tests {

    use serde_json::json;

    use super::*;
    use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};

    // Request a Credential with the claims `vehicle_holder` and `first_name`
    #[test]
    fn multiple_claims() {
        let query_json = json!({
            "credentials": [{
                "id": "my_credential",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                },
                "claims": [
                    {"path": ["org.iso.7367.1", "vehicle_holder"]},
                    {"path": ["org.iso.18013.5.1", "first_name"]}
                ]
            }]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    // Request multiple Credentials all of which should be returned.
    #[test]
    #[ignore]
    fn multiple_credentials() {
        let query_json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                    ]
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    },
                    "claims": [
                        {"path": ["org.iso.7367.1", "vehicle_holder"]},
                        {"path": ["org.iso.18013.5.1", "first_name"]}
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    // Make a complex query where the Wallet is requested to deliver:
    //  - The `pid` credential
    //  - OR the `other_pid` credential,
    //  - OR both `pid_reduced_cred_1` and `pid_reduced_cred_2`.
    //
    // Additionally, the `nice_to_have` credential may optionally be delivered.
    #[test]
    #[ignore]
    fn complex_query() {
        let query_json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                    ]
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    },
                    "claims": [
                        {"path": ["org.iso.7367.1", "vehicle_holder"]},
                        {"path": ["org.iso.18013.5.1", "first_name"]}
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    // Request an ID and address from any credential.
    #[test]
    #[ignore]
    fn any_credential() {
        let query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": [
                        {
                            "id": "given_name",
                            "path": ["org.iso.18013.5.1", "given_name"]
                        },
                        {
                            "id": "family_name",
                            "path": ["org.iso.18013.5.1", "family_name"]
                        },
                        {
                            "id": "portrait",
                            "path": ["org.iso.18013.5.1", "portrait"]
                        }
                    ]
                },
                {
                    "id": "mdl-address",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": [
                        {
                        "id": "resident_address",
                        "path": ["org.iso.18013.5.1", "resident_address"]
                        },
                        {
                        "id": "resident_country",
                        "path": ["org.iso.18013.5.1", "resident_country"]
                        }
                    ]
                },
                {
                    "id": "photo_card-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.23220.photoid.1"
                    },
                    "claims": [
                        {
                            "id": "given_name",
                            "path": ["org.iso.18013.5.1", "given_name"]
                        },
                        {
                            "id": "family_name",
                            "path": ["org.iso.18013.5.1", "family_name"]
                        },
                        {
                            "id": "portrait",
                            "path": ["org.iso.18013.5.1", "portrait"]
                        }
                    ]
                },
                {
                    "id": "photo_card-address",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.23220.photoid.1"
                    },
                    "claims": [
                        {
                        "id": "resident_address",
                        "path": ["org.iso.18013.5.1", "resident_address"]
                        },
                        {
                        "id": "resident_country",
                        "path": ["org.iso.18013.5.1", "resident_country"]
                        }
                    ]
                }
            ],
            "credential_sets": [
                {
                    "purpose": "Identification",
                    "options": [
                        [ "mdl-id" ],
                        [ "photo_card-id" ]
                    ]
                },
                {
                    "purpose": "Proof of address",
                    "required": false,
                    "options": [
                        [ "mdl-address"],
                        ["photo_card-address" ]
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    // Requests the mandatory claims `last_name` and `date_of_birth`, and
    // either the claim `postal_code`, or, if that is not available, both of
    // the claims `locality` and `region`.
    #[test]
    #[ignore]
    fn alt_claims() {
        let query_json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                    },
                    "claims": [
                        {"id": "a", "path": ["last_name"]},
                        {"id": "b", "path": ["postal_code"]},
                        {"id": "c", "path": ["locality"]},
                        {"id": "d", "path": ["region"]},
                        {"id": "e", "path": ["date_of_birth"]}
                    ],
                    "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    // Requests a credential using specific values for the `last_name` and `postal_code` claims.
    #[test]
    #[ignore]
    fn specific_values() {
        let query_json = json!({
            "credentials": [
                {
                    "id": "my_credential",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                    },
                    "claims": [
                        {
                            "path": ["last_name"],
                            "values": ["Doe"]
                        },
                        {"path": ["first_name"]},
                        {"path": ["address", "street_address"]},
                        {
                            "path": ["postal_code"],
                            "values": ["90210", "90211"]
                        }
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        let credential = vehicle_registration();
        assert!(query.is_match(&credential));
    }

    fn vehicle_registration() -> impl Credential {
        CredentialImpl {
            configuration: CredentialConfiguration {
                profile: FormatProfile::IsoMdl {
                    doctype: "org.iso.7367.1.mVRC".to_string(),
                },
                ..CredentialConfiguration::default()
            },
            claims: vec![
                Claim {
                    path: vec!["org.iso.7367.1".to_string(), "vehicle_holder".to_string()],
                    values: vec![Value::String("Alice Holder".to_string())],
                },
                Claim {
                    path: vec!["org.iso.18013.5.1".to_string(), "first_name".to_string()],
                    values: vec![Value::String("Alice".to_string())],
                },
            ],
        }
    }

    struct CredentialImpl {
        configuration: CredentialConfiguration,
        claims: Vec<Claim>,
    }

    impl Credential for CredentialImpl {
        fn meta(&self) -> &CredentialConfiguration {
            &self.configuration
        }

        fn claims(&self) -> Vec<Claim> {
            self.claims.clone()
        }
    }
}
