//! # Store

use std::str::FromStr;

use anyhow::Result;
use credibil_binding::Resolver;
use credibil_core::Kind;
use credibil_jose::Jws;
use serde_json::Value;

use crate::dcql::{Claim, Queryable};
use crate::w3c_vc::{CredentialDefinition, VerifiableCredential, W3cVcClaims};
use crate::{FormatProfile, ValidityPeriod};

/// Convert a `w3c` credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub async fn to_queryable(
    issued: impl Into<Kind<VerifiableCredential>>, _resolver: &impl Resolver,
) -> Result<Queryable> {
    let issued = issued.into();

    // FIXME: verify signature

    let (vc, meta) = match &issued {
        Kind::String(encoded) => {
            let jws = Jws::from_str(encoded)?;
            let claims: W3cVcClaims = jws.payload()?;
            let meta = FormatProfile::JwtVcJson {
                credential_definition: CredentialDefinition {
                    context: None,
                    r#type: claims.vc.r#type.clone(),
                },
            };
            (claims.vc, meta)
        }
        Kind::Object(vc) => {
            let meta = FormatProfile::LdpVc {
                credential_definition: CredentialDefinition {
                    context: None,
                    r#type: vc.r#type.clone(),
                },
            };
            (vc.clone(), meta)
        }
    };

    let mut claims = vec![];
    for subj in &vc.credential_subject.to_vec() {
        let value = Value::Object(subj.claims.clone());
        let nested = unpack_claims(vec!["credentialSubject".to_string()], &value);
        claims.extend(nested);
    }

    // Date-times
    let validity = ValidityPeriod {
        valid_from: vc.valid_from,
        valid_until: vc.valid_until,
        issued_at: None, // W3C VC does not have an issued_at field
    };

    Ok(Queryable {
        meta,
        claims,
        credential: issued,
        validity,
    })
}

fn unpack_claims(path: Vec<String>, value: &Value) -> Vec<Claim> {
    match value {
        Value::Object(claims_map) => {
            let mut claims = vec![];

            for (key, value) in claims_map {
                let mut new_path = path.clone();
                new_path.push(key.to_string());
                claims.extend(unpack_claims(new_path, value));
            }

            claims
        }
        _ => vec![Claim { path, value: value.clone() }],
    }
}
