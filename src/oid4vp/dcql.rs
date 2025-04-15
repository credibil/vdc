//! #! Querying credentials

use anyhow::{Result, anyhow};

use crate::oid4vci::types::FormatProfile;
use crate::oid4vp::types::{
    Claim, ClaimQuery, CredentialFormat, CredentialQuery, CredentialSetQuery, DcqlQuery,
    MetadataQuery, Queryable,
};

impl DcqlQuery {
    /// Execute the query, returning all matching credentials.
    ///
    /// # Errors
    /// TODO: add errors
    pub fn execute<'a>(&self, fetch_vcs: &'a [Queryable]) -> Result<Vec<&'a Queryable>> {
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
        &self, credentials: &[CredentialQuery], fetch_vcs: &'a [Queryable],
    ) -> Result<Vec<&'a Queryable>> {
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
    fn execute<'a>(&self, fetch_vcs: &'a [Queryable]) -> Option<Vec<&'a Queryable>> {
        if !self.multiple.unwrap_or_default() {
            // return first matching credential
            let matched = fetch_vcs.iter().find(|vc| self.is_match(vc).is_some())?;
            return Some(vec![matched]);
        }

        // return all matching credentials
        let matches = fetch_vcs
            .iter()
            .filter(|vc| self.is_match(vc).is_some())
            .collect::<Vec<&'a Queryable>>();
        if matches.is_empty() {
            return None;
        }

        Some(matches)
    }

    /// Determines whether the specified credential matches the query.
    fn is_match(&self, credential: &Queryable) -> Option<Vec<Claim>> {
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
    fn match_claims(&self, credential: &Queryable) -> Result<Vec<Claim>> {
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
    fn is_match(&self, meta: &FormatProfile) -> bool {
        match &self {
            Self::MsoMdoc { doctype_value } => {
                if let FormatProfile::MsoMdoc { doctype } = meta {
                    if doctype == doctype_value {
                        return true;
                    }
                }
            }
            Self::SdJwt { vct_values } => {
                if let FormatProfile::DcSdJwt { vct } = meta {
                    if vct_values.contains(vct) {
                        return true;
                    }
                }
            }
            Self::W3cVc { type_values } => {
                if let FormatProfile::JwtVcJson {
                    credential_definition,
                } = meta
                {
                    // all `credential_definition.type` values must be
                    // contained in a single `type_values` set
                    'next_set: for type_value in type_values {
                        for vc_type in &credential_definition.type_ {
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

impl ClaimQuery {
    /// Execute claim query to find matching claims
    fn execute(&self, credential: &Queryable) -> Option<Vec<Claim>> {
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
