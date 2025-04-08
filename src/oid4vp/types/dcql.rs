//! # Digital Credentials Query Language (DCQL)

// use datastore::query::{
//     self, Cursor, DateRange, Lower, MatchOn, MatchSet, Matcher, Pagination, Query, Range, Sort,
//     Upper,
// };
// use crate::oid4vci::types::Credential;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid4vci::types::FormatProfile;

/// Implemented by credentials to support DCQL queries.
pub trait Credential {
    /// Returns the Credential's format.
    fn meta(&self) -> FormatProfile;

    /// Returns the Credential's claims.
    fn claims(&self) -> Vec<Claim>;
}

/// A generic credential claim to use with DCQL queries.
#[derive(Clone, Debug)]
pub struct Claim {
    /// The path to the claim within the credential.
    pub path: Vec<String>,

    /// The claim's values.
    pub value: Value,
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
    pub trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

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
        // EITHER find matching VCs for each CredentialSetQuery
        if let Some(sets) = &self.credential_sets {
            return sets.iter().try_fold(vec![], |mut matched, query| {
                let vcs = query.execute(&self.credentials, all_vcs)?;
                matched.extend(vcs);
                Ok(matched)
            });
        }

        // OR find matching VCs for each CredentialQuery
        let matched = self.credentials.iter().fold(vec![], |mut matched, query| {
            if let Some(vcs) = query.execute(all_vcs) {
                matched.extend(vcs);
            }
            matched
        });

        Ok(matched)
    }
}

impl CredentialSetQuery {
    /// Execute credential set query.
    fn execute<'a, T: Credential>(
        &self, credentials: &[CredentialQuery], all_vcs: &'a [T],
    ) -> Result<Vec<&'a T>> {
        // iterate until we find an `option` where every CredentialQuery is satisfied
        'next_option: for option in &self.options {
            // match ALL credential queries in the option set
            let mut matches = vec![];

            for cq_id in option {
                // resolve credential query from id
                let Some(cq) = credentials.iter().find(|cq| cq.id == *cq_id) else {
                    return Err(anyhow!("cannot find CredentialQuery with the specified id"));
                };

                // execute credential query
                let Some(vcs) = cq.execute(all_vcs) else {
                    continue 'next_option;
                };
                matches.extend(vcs);
            }

            return Ok(matches);
        }

        if !self.required.unwrap_or(true) {
            return Ok(vec![]);
        }

        Err(anyhow!("no matches"))
    }
}

impl CredentialQuery {
    /// Execute the credential query.
    fn execute<'a, T: Credential>(&self, all_vcs: &'a [T]) -> Option<Vec<&'a T>> {
        if !self.multiple.unwrap_or_default() {
            // return first matching credential
            let matched = all_vcs.iter().find(|vc| self.is_match(*vc).is_some())?;
            return Some(vec![matched]);
        }

        // return all matching credentials
        let matches =
            all_vcs.iter().filter(|vc| self.is_match(*vc).is_some()).collect::<Vec<&'a T>>();
        if matches.is_empty() {
            return None;
        }

        Some(matches)
    }

    /// Determines whether the specified credential matches the query.
    fn is_match(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        // format match
        let format = match &credential.meta() {
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
            if !meta.is_match(&credential.meta()) {
                return None;
            }
        }

        // claims match
        self.match_claims(credential).ok()
    }

    /// Find matching claims in the credential.
    fn match_claims(&self, credential: &impl Credential) -> Result<Vec<Claim>> {
        // when no claim queries are specified, return all claims
        let Some(claims) = &self.claims else {
            return Ok(credential.claims());
        };

        // when no claim sets are specified, return claims matching claim queries
        // N.B. every claim query must match at least one claim
        if let Some(claim_sets) = &self.claim_sets {
            // find the first claim set where all claim queries are matched
            'next_claim_set: for claim_set in claim_sets {
                let mut matches = vec![];

                for cq_id in claim_set {
                    // resolve claim query from id
                    let Some(claim_query) = claims.iter().find(|cq| cq.id.as_ref() == Some(cq_id))
                    else {
                        return Err(anyhow!("cannot find ClaimQuery with the specified id"));
                    };

                    // execute claim query
                    let Some(vcs) = claim_query.execute(credential) else {
                        continue 'next_claim_set;
                    };
                    matches.extend(vcs);
                }

                return Ok(matches);
            }
        }

        // when no claim sets are specified, return claims matching claim queries
        // N.B. every claim query must match at least one claim
        let mut matches = vec![];
        for claim_query in claims {
            if let Some(vcs) = claim_query.execute(credential) {
                matches.extend(vcs);
            }
        }

        Ok(matches)
    }
}

impl MetadataQuery {
    // fn execute(&self, credential: &impl Credential) -> bool {
    // }

    fn is_match(&self, meta: &FormatProfile) -> bool {
        match &self {
            Self::MsoMdoc { doctype_value } => {
                if let FormatProfile::MsoMdoc { doctype } = meta {
                    if doctype != doctype_value {
                        return false;
                    }
                }
            }
            Self::SdJwt { vct_values } => {
                if let FormatProfile::DcSdJwt { vct } = meta {
                    if !vct_values.contains(vct) {
                        return false;
                    }
                }
            }
        }

        true
    }
}

impl ClaimQuery {
    /// Execute claim query to find matching claims
    fn execute(&self, credential: &impl Credential) -> Option<Vec<Claim>> {
        let matches = credential
            .claims()
            .iter()
            .filter(|c| self.is_match(c))
            .cloned()
            .collect::<Vec<Claim>>();

        if matches.is_empty() {
            return None;
        }

        Some(matches)
    }

    /// Determine whether the specified claim matches the `ClaimQuery`.
    #[must_use]
    fn is_match(&self, claim: &Claim) -> bool {
        if self.path != claim.path {
            return false;
        }

        // get query's claim values to match
        let Some(values) = &self.values else {
            return true;
        };

        // every query value must have a corresponding claim value
        values.iter().all(|v| v == &claim.value)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use credibil_infosec::Jws;
    use credibil_infosec::cose::cbor;
    use serde_json::json;

    use super::*;
    use crate::mso_mdoc::{IssuerSigned, MobileSecurityObject};
    use crate::oid4vci::types::FormatProfile;
    use crate::sd_jwt::SdJwtClaims;

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
                    {"path": ["org.iso.18013.5.1", "given_name"]}
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
        assert_eq!(res.len(), 2);
    }

    // Request an ID and address from any credential.
    #[test]
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

        assert_eq!(res.len(), 2);
    }

    // Requests the mandatory claims `last_name` and `date_of_birth`, and
    // either the claim `postal_code`, or, if that is not available, both of
    // the claims `locality` and `region`.
    #[test]
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

        assert_eq!(res.len(), 1);
    }

    // Requests a credential using specific values for the `last_name` and `postal_code` claims.
    #[test]
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
        assert_eq!(res.len(), 1);
    }

    fn all_vcs() -> Vec<CredentialImpl> {
        // load credentials
        let raw = include_bytes!("../../../examples/wallet/data/credentials.json");
        let value: Value = serde_json::from_slice(raw).expect("should deserialize");
        let stored_vcs = value.as_array().expect("should be an array");

        let mut credentials = vec![];

        for vc in stored_vcs {
            let vc = vc.as_object().expect("should be an object");
            let enc_val = vc.values().next().expect("should be a JWT");
            let enc_str = enc_val.as_str().expect("should be a string");

            // decode VC
            if enc_str.starts_with("ey") {
                // base64 encoded JSON object
                let jws = Jws::from_str(enc_str).expect("should be a JWS");
                let credential = match jws.signatures[0].protected.typ.as_str() {
                    "dc+sd-jwt" => from_sd_jwt(enc_str),
                    _ => todo!("unsupported JWT type"),
                };
                credentials.push(credential);
            } else {
                // base64 encoded mdoc
                let credential = from_mso_mdoc(enc_str);
                credentials.push(credential);
            }
        }

        credentials
    }

    fn from_sd_jwt(jws: &str) -> CredentialImpl {
        let mut split = jws.split('~');
        let jws = Jws::from_str(split.next().unwrap()).expect("should be a JWS");
        let sd_jwt: SdJwtClaims = jws.payload().expect("should be a payload");

        // extract claims from disclosures
        let mut claims = vec![];
        while let Some(disclosure) = split.next() {
            let bytes = Base64UrlUnpadded::decode_vec(&disclosure).expect("should decode");
            let value: Value = serde_json::from_slice(&bytes).expect("should be a JSON");
            let disclosure = value.as_array().expect("should be an array");

            let nested =
                unpack_json(vec![disclosure[1].as_str().unwrap().to_string()], &disclosure[2]);
            claims.extend(nested);
        }

        CredentialImpl {
            profile: FormatProfile::DcSdJwt { vct: sd_jwt.vct },
            claims,
        }
    }

    fn unpack_json(path: Vec<String>, value: &serde_json::Value) -> Vec<Claim> {
        match value {
            serde_json::Value::Object(obj) => {
                let mut claims = vec![];

                for (key, value) in obj.iter() {
                    let mut new_path = path.clone();
                    new_path.push(key.to_string());
                    claims.extend(unpack_json(new_path, value));
                }

                claims
            }
            _ => vec![Claim {
                path,
                value: value.clone(),
            }],
        }
    }

    fn from_mso_mdoc(mdoc_str: &str) -> CredentialImpl {
        let mdoc_bytes = Base64UrlUnpadded::decode_vec(mdoc_str).expect("should decode");
        let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes).expect("should deserialize");

        let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
        let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes).expect("should deserialize");

        let mut claims = vec![];

        for (name_space, tags) in &mdoc.name_spaces {
            let mut path = vec![name_space.clone()];
            for tag in tags {
                path.push(tag.element_identifier.clone());
                let nested = unpack_cbor(path.clone(), &tag.element_value);
                claims.extend(nested);
            }
        }

        CredentialImpl {
            profile: FormatProfile::MsoMdoc {
                doctype: mso.doc_type,
            },
            claims,
        }
    }

    fn unpack_cbor(path: Vec<String>, value: &ciborium::Value) -> Vec<Claim> {
        match value {
            ciborium::Value::Map(map) => {
                let mut claims = vec![];

                for (key, value) in map {
                    let mut new_path = path.clone();
                    new_path.push(key.as_text().unwrap().to_string());
                    claims.extend(unpack_cbor(new_path, value));
                }

                claims
            }
            ciborium::Value::Text(txt) => {
                vec![Claim {
                    path,
                    value: serde_json::Value::String(txt.to_string()),
                }]
            }
            _ => todo!(),
        }
    }

    #[derive(Debug)]
    struct CredentialImpl {
        profile: FormatProfile,
        claims: Vec<Claim>,
    }

    impl Credential for CredentialImpl {
        fn meta(&self) -> FormatProfile {
            self.profile.clone()
        }

        fn claims(&self) -> Vec<Claim> {
            self.claims.clone()
        }
    }
}
