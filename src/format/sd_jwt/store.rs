//! # Store

use std::str::FromStr;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use serde_json::Value;

use crate::core::Kind;
use crate::format::FormatProfile;
use crate::format::sd_jwt::SdJwtClaims;
use crate::oid4vp::types::{Claim, Queryable};

/// Convert a `dc+sd-jwt` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub fn to_queryable(issued: &str) -> Result<Queryable> {
    let mut split = issued.split('~');

    let Some(credential) = split.next() else {
        return Err(anyhow!("missing encoded part"));
    };
    let jws = Jws::from_str(credential)?;

    // extract claims from disclosures
    let mut claims = vec![];
    for issued in split {
        let bytes = Base64UrlUnpadded::decode_vec(issued)?;
        let value: Value = serde_json::from_slice(&bytes)?;

        let Some(disclosure) = value.as_array() else {
            return Err(anyhow!("disclosure is not an array"));
        };
        let Some(root) = disclosure[1].as_str() else {
            return Err(anyhow!("first element in a disclosure should be a string"));
        };

        let nested = unpack_claims(vec![root.to_string()], &disclosure[2]);
        claims.extend(nested);
    }

    let sd_jwt: SdJwtClaims = jws.payload()?;

    Ok(Queryable {
        meta: FormatProfile::DcSdJwt { vct: sd_jwt.vct },
        claims,
        credential: Kind::String(credential.to_string()),
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
