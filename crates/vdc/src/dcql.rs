//! # Digital Credentials Query Language (DCQL)

use std::fmt::{Display, Formatter};

use anyhow::{Result, anyhow};
use credibil_core::Kind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::w3c_vc::VerifiableCredential;
use crate::{CredentialDefinition, FormatProfile};

/// DCQL query for requesting Verifiable Presentations.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlQuery {
    /// Identifies requested credentials.
    pub credentials: Vec<CredentialQuery>,

    /// Additional constraints on requested credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    /// Execute the query, returning all matching credentials.
    ///
    /// # Errors
    /// TODO: add errors
    pub fn execute<'a>(&'a self, credentials: &'a [Queryable]) -> Result<Vec<QueryResult<'a>>> {
        // EITHER find matching VCs for each CredentialSetQuery
        if let Some(sets) = &self.credential_sets {
            return sets.iter().try_fold(vec![], |mut matched, query| {
                let results = query.execute(&self.credentials, credentials)?;
                matched.extend(results);
                Ok(matched)
            });
        }

        // OR find matching VCs for each CredentialQuery
        let matched = self.credentials.iter().fold(vec![], |mut matched, query| {
            if let Some(result) = query.execute(credentials) {
                matched.push(result);
            }
            matched
        });

        Ok(matched)
    }
}

/// A request for the presentation of a single credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identifies the credential in the response and, if provided, the
    /// constraints in `credential_sets`.
    pub id: String,

    /// The format of the requested credential
    pub format: RequestedFormat,

    /// Indicates whether multiple credentials can be returned for this
    /// query. Defaults to false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Additional properties requested that apply to the metadata of the
    /// credential. Properties are specific to Credential Format Profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetadataQuery>,

    /// Issuer certification authorities or trust frameworks that the Verifier
    /// will accept. Every credential returned by the Wallet SHOULD match at
    /// least one of the conditions present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

    /// Indicates whether the Verifier requires a Cryptographic Holder Binding
    /// proof. The default value is true, i.e., a Verifiable Presentation with
    /// Cryptographic Holder Binding is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,

    /// An array of objects that specifies claims in the requested credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,

    /// Combinations of claims to use when requesting credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

impl CredentialQuery {
    /// Execute the credential query.
    #[must_use]
    pub fn execute<'a>(&'a self, credentials: &'a [Queryable]) -> Option<QueryResult<'a>> {
        let multiple = self.multiple.unwrap_or_default();

        // return all matching credentials
        let mut matches = vec![];
        for vc in credentials {
            if let Some(claims) = self.is_match(vc) {
                matches.push(Matched {
                    claims,
                    issued: &vc.credential,
                });
                if multiple {
                    break;
                }
            }
        }

        if matches.is_empty() {
            return None;
        }

        Some(QueryResult { query: self, matches })
    }

    /// Determines whether the specified credential matches the query.
    #[must_use]
    pub fn is_match<'a>(&self, queryable: &'a Queryable) -> Option<Vec<&'a Claim>> {
        // format match
        let format = match &queryable.meta {
            FormatProfile::MsoMdoc { .. } => RequestedFormat::MsoMdoc,
            FormatProfile::DcSdJwt { .. } => RequestedFormat::DcSdJwt,
            FormatProfile::JwtVcJson { .. } => RequestedFormat::JwtVcJson,
            _ => return None,
        };
        if self.format != format {
            return None;
        }

        // metadata match
        if self.meta.as_ref().is_some_and(|meta| !meta.execute(queryable)) {
            return None;
        }
        // claims match
        self.match_claims(queryable).ok()
    }

    /// Find matching claims in the credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the referenced claim query cannot be found.
    pub fn match_claims<'a>(&self, credential: &'a Queryable) -> Result<Vec<&'a Claim>> {
        // when no claim queries are specified, return all claims
        let Some(claims) = &self.claims else {
            return Ok(credential.claims.iter().collect());
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

/// Contains a request for one or more credentials that satisfy a particular
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
}

impl CredentialSetQuery {
    /// Execute credential set query.
    ///
    /// # Errors
    ///
    /// Returns an error if the referenced credential query cannot be found.
    pub fn execute<'a>(
        &self, queries: &'a [CredentialQuery], credentials: &'a [Queryable],
    ) -> Result<Vec<QueryResult<'a>>> {
        // iterate until we find an `option` where every CredentialQuery is satisfied
        'next_option: for option in &self.options {
            // match ALL credential queries in the option set
            let mut matches = vec![];

            for cq_id in option {
                // resolve credential query from id
                let Some(cq) = queries.iter().find(|cq| cq.id == *cq_id) else {
                    return Err(anyhow!("cannot find CredentialQuery with the specified id"));
                };

                // execute credential query
                let Some(result) = cq.execute(credentials) else {
                    continue 'next_option;
                };
                matches.push(result);
            }

            return Ok(matches);
        }

        if !self.required.unwrap_or(true) {
            return Ok(vec![]);
        }

        Err(anyhow!("no matches"))
    }
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
    /// the credential.
    pub path: Vec<String>,

    /// The expected values of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,

    /// Equivalent to `IntentToRetain` variable defined in ISO.18013-5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

impl ClaimQuery {
    /// Execute claim query to find matching claims
    #[must_use]
    pub fn execute<'a>(&self, credential: &'a Queryable) -> Option<Vec<&'a Claim>> {
        let matches =
            credential.claims.iter().filter(|c| self.is_match(c)).collect::<Vec<&Claim>>();
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

/// Credential metadata query parameters. Properties are specific to Credential
/// Format Profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MetadataQuery {
    /// ISO-MDL format credential metadata.
    MsoMdoc {
        /// Allowed value for the `doctype` of the requested credential.
        doctype_value: String,
    },

    /// SD-JWT format credential metadata.
    SdJwt {
        /// Allowed `vct` values when querying for SD-JWT Credentials.
        vct_values: Vec<String>,
    },

    /// W3C VC format credential metadata.
    W3cVc {
        /// The fully expanded types after the @context has been applied to the
        /// VC `type` parameter.
        ///
        /// Each top-level array specifies one alternative to match the type
        /// values of the Verifiable Credential against. Each inner array
        /// specifies a set of fully expanded types that MUST be present
        /// in the type property of the Verifiable Credential, regardless
        ///  of order or the presence of additional types.
        ///
        /// For example, the following query
        ///
        /// ```json
        /// "type_values":[
        ///   [
        ///       "https://www.w3.org/2018/credentials#VerifiableCredential",
        ///       "https://example.org/examples#AlumniCredential",
        ///       "https://example.org/examples#BachelorDegree"
        ///   ],
        ///   [
        ///       "https://www.w3.org/2018/credentials#VerifiableCredential",
        ///       "https://example.org/examples#UniversityDegreeCredential"
        ///   ]
        /// ]
        /// ```
        ///
        /// would match a credential with the following type property:
        /// ```json
        /// {
        ///   "@context": [
        ///     "https://www.w3.org/2018/credentials/v1",
        ///     "https://www.w3.org/2018/credentials/examples/v1"
        ///   ],
        ///   "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        ///   ...
        /// }
        /// ```
        type_values: Vec<Vec<String>>,
    },
}

impl MetadataQuery {
    /// Execute the metadata query to determine whether credential matches.
    #[must_use]
    pub fn execute(&self, credential: &Queryable) -> bool {
        match &self {
            Self::MsoMdoc { doctype_value } => {
                if let FormatProfile::MsoMdoc { doctype } = &credential.meta {
                    if doctype == doctype_value {
                        return true;
                    }
                }
            }
            Self::SdJwt { vct_values } => {
                if let FormatProfile::DcSdJwt { vct } = &credential.meta {
                    if vct_values.contains(vct) {
                        return true;
                    }
                }
            }
            Self::W3cVc { type_values } => {
                if let FormatProfile::JwtVcJson {
                    credential_definition,
                } = &credential.meta
                {
                    // all `credential_definition.type` values must be
                    // contained in a single `type_values` set
                    'next_set: for type_value in type_values {
                        for vc_type in &credential_definition.r#type {
                            if !type_value.contains(vc_type) {
                                continue 'next_set;
                            }
                        }
                        // if we get here, `type_values` references
                        // `credential_definition.type` entries
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl Default for MetadataQuery {
    fn default() -> Self {
        Self::W3cVc {
            type_values: vec![vec![]],
        }
    }
}

impl From<&MetadataQuery> for FormatProfile {
    fn from(value: &MetadataQuery) -> Self {
        Self::from(value.clone())
    }
}

impl From<MetadataQuery> for FormatProfile {
    fn from(value: MetadataQuery) -> Self {
        match value {
            MetadataQuery::MsoMdoc { doctype_value } => Self::MsoMdoc {
                doctype: doctype_value,
            },
            MetadataQuery::SdJwt { vct_values } => Self::DcSdJwt {
                vct: vct_values[0].clone(),
            },
            MetadataQuery::W3cVc { type_values } => Self::JwtVcJson {
                credential_definition: CredentialDefinition {
                    context: None,
                    r#type: type_values[0].clone(),
                },
            },
        }
    }
}

/// The format of the requested credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum RequestedFormat {
    /// A W3C Verifiable Credential.
    #[serde(rename = "jwt_vc_json")]
    #[default]
    JwtVcJson,

    /// A W3C Verifiable Credential not using JSON-LD.
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

impl Display for RequestedFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwtVcJson => write!(f, "jwt_vc_json"),
            Self::LdpVc => write!(f, "ldp-vc"),
            Self::JwtVcJsonLd => write!(f, "jwt_vc_json-ld"),
            Self::MsoMdoc => write!(f, "mso_mdoc"),
            Self::DcSdJwt => write!(f, "dc+sd-jwt"),
        }
    }
}

/// Represents information that helps to identify an Issuer certification
/// authority or trust framework.
///
/// A credential is a match to a Trusted Authorities Query if it matches with
/// one of the values in one of the provided types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedAuthoritiesQuery {
    /// An array of objects that specifies claims in the requested credential.
    #[serde(rename = "type")]
    pub r#type: Option<Vec<AuthorityType>>,

    /// Combinations of claims to use when requesting credentials. Each set
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
    /// The trust chain of a matching credential MUST contain at least one
    /// X.509 Certificate that matches one of the entries of the Trusted List
    /// or its cascading Trusted Lists.
    #[serde(rename = "etsi_tl")]
    EtsiTl,

    /// An OpenID.Federation Entity Identifier.
    ///
    /// A valid trust path, including the given Entity Identifier, must be
    /// constructible from a matching credential.
    #[serde(rename = "openid_federation")]
    OpenidFederation,
}

/// Implemented by wallets in order to support DCQL queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Queryable {
    /// The credential's queryable metadata.
    pub meta: FormatProfile,

    /// The credential's claims.
    pub claims: Vec<Claim>,

    /// The credential, as issued.
    pub credential: Kind<VerifiableCredential>,
}

/// A generic credential claim to use with DCQL queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    /// The path to the claim within the credential.
    pub path: Vec<String>,

    /// The claim's values.
    pub value: Value,
}

/// `QueryResult` credentials matching a Credential Query.
#[derive(Clone, Debug)]
pub struct QueryResult<'a> {
    /// Identifies the query the credential is a match for.
    pub query: &'a CredentialQuery,

    /// Additional constraints on requested credentials.
    pub matches: Vec<Matched<'a>>,
}

/// `QueryResult` credentials matching a Credential Query.
#[derive(Clone, Debug)]
pub struct Matched<'a> {
    /// Claims match those requested in the Claims Query.
    pub claims: Vec<&'a Claim>,

    /// The original issued credential.
    pub issued: &'a Kind<VerifiableCredential>,
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::oid4vci::types::{CredentialDefinition, FormatProfile};
    // use crate::oid4vp::query::{Claim, Queryable};

    // #[test]
    // fn to_json() {
    //     let queryable = &Queryable {
    //         profile: FormatProfile::JwtVcJson {
    //             credential_definition: CredentialDefinition {
    //                 context: None,
    //                 r#type: vec![
    //                     "VerifiableCredential".to_string(),
    //                     "EmployeeIDCredential".to_string(),
    //                 ],
    //             },
    //         },
    //         claims: vec![
    //             Claim {
    //                 path: vec!["credentialSubject".to_string(), "employeeId".to_string()],
    //                 value: Value::String("1234567890".to_string()),
    //             },
    //             Claim {
    //                 path: vec!["credentialSubject".to_string(), "family_name".to_string()],
    //                 value: Value::String("Doe".to_string()),
    //             },
    //         ],
    //         issued: Kind::String("jwt_str".to_string()),
    //     };

    //     let json: Value = queryable.try_into().expect("should convert");
    //     dbg!(json);
    // }
}
