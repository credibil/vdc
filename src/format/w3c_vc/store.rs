//! # Store

use std::str::FromStr;

use anyhow::Result;
use credibil_identity::IdentityResolver;
use credibil_jose::Jws;
use serde_json::Value;

use crate::core::Kind;
use crate::format::FormatProfile;
use crate::format::w3c_vc::{VerifiableCredential, W3cVcClaims};
use crate::oid4vci::types::CredentialDefinition;
use crate::oid4vp::verifier::{Claim, Queryable};

/// Convert a `w3c` credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub async fn to_queryable(
    issued: impl Into<Kind<VerifiableCredential>>, _resolver: &impl IdentityResolver,
) -> Result<Queryable> {
    let issued = issued.into();

    // FIXME: verify signature

    let (vc, meta) = match &issued {
        Kind::String(encoded) => {
            let jws = Jws::from_str(encoded)?;
            let jwt_claims: W3cVcClaims = jws.payload()?;
            let vc = jwt_claims.vc;

            let meta = FormatProfile::JwtVcJson {
                credential_definition: CredentialDefinition {
                    context: None,
                    type_: vc.type_.clone(),
                },
            };

            (vc, meta)
        }
        Kind::Object(vc) => {
            let meta = FormatProfile::LdpVc {
                credential_definition: CredentialDefinition {
                    context: None,
                    type_: vc.type_.clone(),
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

    Ok(Queryable {
        meta,
        claims,
        credential: issued,
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
        _ => vec![Claim {
            path,
            value: value.clone(),
        }],
    }
}
