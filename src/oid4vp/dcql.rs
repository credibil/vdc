//! #! Querying credentials

use anyhow::{Result, anyhow};

use crate::format::FormatProfile;
use crate::oid4vp::types::{
    Claim, ClaimQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, Matched, MetadataQuery,
    QueryResult, Queryable, RequestedFormat,
};

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

impl CredentialSetQuery {
    /// Execute credential set query.
    fn execute<'a>(
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

impl CredentialQuery {
    /// Execute the credential query.
    fn execute<'a>(&'a self, credentials: &'a [Queryable]) -> Option<QueryResult<'a>> {
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
    fn is_match<'a>(&self, queryable: &'a Queryable) -> Option<Vec<&'a Claim>> {
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
        if let Some(meta) = &self.meta {
            if !meta.is_match(&queryable.meta) {
                return None;
            }
        }

        // claims match
        self.match_claims(queryable).ok()
    }

    /// Find matching claims in the credential.
    fn match_claims<'a>(&self, credential: &'a Queryable) -> Result<Vec<&'a Claim>> {
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
    fn execute<'a>(&self, credential: &'a Queryable) -> Option<Vec<&'a Claim>> {
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
