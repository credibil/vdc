//! # Store

use std::str::FromStr;

use anyhow::Result;
use credibil_infosec::Jws;
use serde_json::Value;

use crate::core::Kind;
use crate::oid4vci::types::{CredentialDefinition, FormatProfile};
use crate::oid4vp::types::{Claim, IssuedFormat, Queryable};
use crate::w3c::{VerifiableCredential, W3cVcClaims};

/// Convert a `w3c` credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub fn to_queryable(vc_kind: Kind<VerifiableCredential>) -> Result<Queryable> {
    let (vc, profile, issued) = match vc_kind {
        Kind::String(encoded) => {
            let jws = Jws::from_str(&encoded)?;
            let jwt_claims: W3cVcClaims = jws.payload()?;
            let vc = jwt_claims.vc;

            let profile = FormatProfile::JwtVcJson {
                credential_definition: CredentialDefinition {
                    context: None,
                    type_: vc.clone().type_.to_vec(),
                },
            };

            (vc, profile, IssuedFormat::JwtVcJson(encoded))
        }
        Kind::Object(vc) => {
            let profile = FormatProfile::LdpVc {
                credential_definition: CredentialDefinition {
                    context: None,
                    type_: vc.clone().type_.to_vec(),
                },
            };
            (vc.clone(), profile, IssuedFormat::LdpVc(vc))
        }
    };

    let mut claims = vec![];

    for subj in &vc.credential_subject.to_vec() {
        let value = Value::Object(subj.claims.clone());
        let nested = unpack_claims(vec!["credentialSubject".to_string()], &value);
        claims.extend(nested);
    }

    Ok(Queryable {
        profile,
        claims,
        issued,
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
