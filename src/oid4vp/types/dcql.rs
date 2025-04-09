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

/// Implemented by wallets in order to support DCQL queries.
#[derive(Debug)]
pub struct Credential {
    /// The credential's format profile.
    pub profile: FormatProfile,

    /// The credential's claims.
    pub claims: Vec<Claim>,

    /// The original issued credential.
    pub issued: Value,
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
    pub fn execute<'a>(&self, fetch_vcs: &'a [Credential]) -> Result<Vec<&'a Credential>> {
        // EITHER find matching VCs for each CredentialSetQuery
        if let Some(sets) = &self.credential_sets {
            return sets.iter().try_fold(vec![], |mut matched, query| {
                let vcs = query.execute(&self.credentials, fetch_vcs)?;
                matched.extend(vcs);
                Ok(matched)
            });
        }

        // OR find matching VCs for each CredentialQuery
        let matched = self.credentials.iter().fold(vec![], |mut matched, query| {
            if let Some(vcs) = query.execute(fetch_vcs) {
                matched.extend(vcs);
            }
            matched
        });

        Ok(matched)
    }
}

impl CredentialSetQuery {
    /// Execute credential set query.
    fn execute<'a>(
        &self, credentials: &[CredentialQuery], fetch_vcs: &'a [Credential],
    ) -> Result<Vec<&'a Credential>> {
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
                let Some(vcs) = cq.execute(fetch_vcs) else {
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
    fn execute<'a>(&self, fetch_vcs: &'a [Credential]) -> Option<Vec<&'a Credential>> {
        if !self.multiple.unwrap_or_default() {
            // return first matching credential
            let matched = fetch_vcs.iter().find(|vc| self.is_match(*vc).is_some())?;
            return Some(vec![matched]);
        }

        // return all matching credentials
        let matches = fetch_vcs
            .iter()
            .filter(|vc| self.is_match(*vc).is_some())
            .collect::<Vec<&'a Credential>>();
        if matches.is_empty() {
            return None;
        }

        Some(matches)
    }

    /// Determines whether the specified credential matches the query.
    fn is_match(&self, credential: &Credential) -> Option<Vec<Claim>> {
        // format match
        let format = match &credential.profile {
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
            if !meta.is_match(&credential.profile) {
                return None;
            }
        }

        // claims match
        self.match_claims(credential).ok()
    }

    /// Find matching claims in the credential.
    fn match_claims(&self, credential: &Credential) -> Result<Vec<Claim>> {
        // when no claim queries are specified, return all claims
        let Some(claims) = &self.claims else {
            return Ok(credential.claims.clone());
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
    fn execute(&self, credential: &Credential) -> Option<Vec<Claim>> {
        let matches =
            credential.claims.iter().filter(|c| self.is_match(c)).cloned().collect::<Vec<Claim>>();

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
