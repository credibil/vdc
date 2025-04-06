//! # Digital Credentials Query Language (DCQL)

// use datastore::query::{
//     self, Cursor, DateRange, Lower, MatchOn, MatchSet, Matcher, Pagination, Query, Range, Sort,
//     Upper,
// };
// use crate::oid4vci::types::Credential;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};

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

/// A request for the presentation of a single Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identifies the Credential in the response and, if provided, the
    /// constraints in `credential_sets`.
    pub id: String,

    /// The format of the requested Credential
    pub format: CredentialFormat,

    /// Indicates whether multiple Credentials can be returned for this
    /// Credential Query. If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Additional properties requested that apply to the metadata of the
    /// Credential. Properties are specific to Credential Format Profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetadataQuery>,

    /// Issuer certification authorities or trust frameworks that the Verifier
    /// will accept. Every Credential returned by the Wallet SHOULD match at
    /// least one of the conditions present.
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

    /// An array of objects that specifies claims in the requested Credential.
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
/// A Credential Set Query is used when multiple Credential Queries need to be
/// combined to satisfy the Verifier's requirements.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialSetQuery {
    /// A list of Credential Query sets, one of which must identify a set of
    /// Credentials that satisfies the query.
    ///
    /// Each value in the array contains a set of Credential Query identifiers
    /// (`CredentialQuery.id`) pointing to a Credential Query objects in the
    /// `credentials` array.
    pub options: Vec<Vec<String>>,

    /// Specifies whether this Credential Set Query entry is required.
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
    MsoMdoc {
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
    MsoMdoc,

    /// An IETF SD-JWT format credential.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

/// Represents information that helps to identify an Issuer certification
/// authority or trust framework.
///
/// A Credential is a match to a Trusted Authorities Query if it matches with
/// one of the values in one of the provided types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedAuthoritiesQuery {
    /// An array of objects that specifies claims in the requested Credential.
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
    /// The trust chain of a matching Credential MUST contain at least one
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

impl DcqlQuery {
    /// Execute the query, returning all matching credentials.
    ///
    /// # Errors
    /// TODO: add errors
    pub fn execute<'a, T: Credential>(&self, all_vcs: &'a [T]) -> Result<Vec<&'a T>> {
        let mut matches: Vec<&T> = vec![];

        // Step 2: apply CredentialSetQuery constraints
        if let Some(credential_sets) = &self.credential_sets {
            // find matching VCs for each CredentialSetQuery
            for query_set in credential_sets {
                if !query_set.required.unwrap_or(true) {
                    continue;
                }

                matches.extend(query_set.filter(&self.credentials, all_vcs)?);
            }

            return Ok(matches);
        }

        // Step 1: determine whether credential matches CredentialQuery
        for vc in all_vcs {
            for cq in &self.credentials {
                if cq.is_match(vc).is_some() {
                    matches.push(vc);
                }
            }
        }

        Ok(matches)
    }
}

impl CredentialQuery {
    /// Determines whether the specified credential matches the query.
    pub fn is_match(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        // format match
        let format = match &credential.meta().profile {
            FormatProfile::MsoMdoc { .. } => CredentialFormat::MsoMdoc,
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

impl CredentialSetQuery {
    fn filter<'a, T: Credential>(
        &self, credentials: &[CredentialQuery], all_vcs: &'a [T],
    ) -> Result<Vec<&'a T>> {
        // iterate until we find an `option` where every CredentialQuery is satisfied
        'option: for option in &self.options {
            // match ALL credential queries in the option set
            let mut matches = vec![];

            for cq_id in option {
                // get CredentialQuery
                let Some(cq) = credentials.iter().find(|cq| cq.id == *cq_id) else {
                    return Err(anyhow!("cannot find CredentialQuery matching `id`"));
                };

                // find matching VCs
                let filtered =
                    all_vcs.iter().filter(|vc| cq.is_match(*vc).is_some()).collect::<Vec<&'a T>>();
                if filtered.len() == 0 {
                    continue 'option;
                }

                matches.extend(filtered);
            }

            return Ok(matches);
        }

        Err(anyhow!("no matches"))
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
            Self::MsoMdoc { doctype_value } => {
                if let FormatProfile::MsoMdoc { doctype } = &meta.profile {
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

        // should match the registration VC
        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");

        assert_eq!(res.len(), 1);
    }

    // Request multiple Credentials all of which should be returned.
    #[test]
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

        // should match both identity and registration VCs
        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");

        assert_eq!(res.len(), 2);
    }

    // Make a complex query where the Wallet is requested to deliver:
    //  - The `pid` credential
    //  - OR the `other_pid` credential,
    //  - OR both `pid_reduced_cred_1` and `pid_reduced_cred_2`.
    //
    // Additionally, the `nice_to_have` credential may optionally be delivered.
    #[test]
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
                    "id": "other_pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://othercredentials.example/pid"]
                    },
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                    ]
                },
                {
                    "id": "pid_reduced_cred_1",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                    },
                    "claims": [
                        {"path": ["family_name"]},
                        {"path": ["given_name"]}
                    ]
                },
                {
                    "id": "pid_reduced_cred_2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://cred.example/residence_credential"]
                    },
                    "claims": [
                        {"path": ["postal_code"]},
                        {"path": ["locality"]},
                        {"path": ["region"]}
                    ]
                },
                {
                    "id": "nice_to_have",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://company.example/company_rewards"]
                    },
                    "claims": [
                        {"path": ["rewards_number"]}
                    ]
                }
            ],
            "credential_sets": [
                {
                    "purpose": "Identification",
                    "options": [
                        [ "pid" ],
                        [ "other_pid" ],
                        [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                    ]
                },
                {
                    "purpose": "Show your rewards card",
                    "required": false,
                    "options": [
                        [ "nice_to_have" ]
                    ]
                }
            ]
        });
        let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

        // should match all VCs below
        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");
        assert_eq!(res.len(), 1);

        for vc in res {
            println!("{:?}", vc.configuration)
        }
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

        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");

        assert_eq!(res.len(), 1);
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

        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");

        assert_eq!(res.len(), 0);
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

        let all_vcs = all_vcs();
        let res = query.execute(&all_vcs).expect("should execute");

        assert_eq!(res.len(), 0);
    }

    fn all_vcs() -> Vec<CredentialImpl> {
        vec![
            // identity vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::DcSdJwt {
                        vct: "https://credentials.example.com/identity_credential".to_string(),
                    },
                    ..CredentialConfiguration::default()
                },
                claims: vec![
                    Claim {
                        path: vec!["given_name".to_string()],
                        values: vec![Value::String("Alice".to_string())],
                    },
                    Claim {
                        path: vec!["family_name".to_string()],
                        values: vec![Value::String("Holder".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "street_address".to_string()],
                        values: vec![Value::String("1234 Elm St.".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "postal_code".to_string()],
                        values: vec![Value::String("90210".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "locality".to_string()],
                        values: vec![Value::String("Hollywood".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "region".to_string()],
                        values: vec![Value::String("CA".to_string())],
                    },
                ],
            },
            // other identity vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::DcSdJwt {
                        vct: "https://othercredentials.example/pid".to_string(),
                    },
                    ..CredentialConfiguration::default()
                },
                claims: vec![
                    Claim {
                        path: vec!["given_name".to_string()],
                        values: vec![Value::String("Bob".to_string())],
                    },
                    Claim {
                        path: vec!["family_name".to_string()],
                        values: vec![Value::String("Doe".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "street_address".to_string()],
                        values: vec![Value::String("34 Drake St.".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "postal_code".to_string()],
                        values: vec![Value::String("1010".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "locality".to_string()],
                        values: vec![Value::String("Auckland".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "region".to_string()],
                        values: vec![Value::String("Auckland".to_string())],
                    },
                ],
            },
            // residence vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::DcSdJwt {
                        vct: "https://cred.example/residence_credential".to_string(),
                    },
                    ..CredentialConfiguration::default()
                },
                claims: vec![
                    Claim {
                        path: vec!["address".to_string(), "postal_code".to_string()],
                        values: vec![Value::String("90210".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "locality".to_string()],
                        values: vec![Value::String("Hollywood".to_string())],
                    },
                    Claim {
                        path: vec!["address".to_string(), "region".to_string()],
                        values: vec![Value::String("CA".to_string())],
                    },
                ],
            },
            // rewards vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::DcSdJwt {
                        vct: "https://company.example/company_rewards".to_string(),
                    },
                    ..CredentialConfiguration::default()
                },
                claims: vec![Claim {
                    path: vec!["rewards_number".to_string()],
                    values: vec![Value::String("12345".to_string())],
                }],
            },
            // licence vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::MsoMdoc {
                        doctype: "org.iso.18013.5.1.mDL".to_string(),
                    },
                    ..CredentialConfiguration::default()
                },
                claims: vec![
                    Claim {
                        path: vec!["org.iso.18013.5.1".to_string(), "given_name".to_string()],
                        values: vec![Value::String("Alice".to_string())],
                    },
                    Claim {
                        path: vec!["org.iso.18013.5.1".to_string(), "family_name".to_string()],
                        values: vec![Value::String("Holder".to_string())],
                    },
                    Claim {
                        path: vec!["org.iso.18013.5.1".to_string(), "portrait".to_string()],
                        values: vec![Value::String("path".to_string())],
                    },
                ],
            },
            // registration vc
            CredentialImpl {
                configuration: CredentialConfiguration {
                    profile: FormatProfile::MsoMdoc {
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
            },
        ]
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
