//! # Store

use anyhow::{Result, anyhow};
use credibil_did::DidResolver;
use credibil_infosec::jose::jws;
use credibil_infosec::jose::jwt::Jwt;
use serde_json::Value;

use crate::core::{Kind, did_jwk};
use crate::format::FormatProfile;
use crate::format::sd_jwt::{Disclosure, SdJwtClaims};
use crate::oid4vp::types::{Claim, Queryable};

/// Convert a `dc+sd-jwt` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub async fn to_queryable(issued: &str, resolver: &impl DidResolver) -> Result<Queryable> {
    // decode and verify the sd-jwt
    let (sd_jwt, disclosures) = decode_vc(issued, resolver).await?;

    // unpack disclosures into claims
    let claims = disclosures.iter().fold(vec![], |mut acc, d| {
        acc.extend(unpack_claims(vec![d.name.clone()], &d.value));
        acc
    });

    Ok(Queryable {
        meta: FormatProfile::DcSdJwt {
            vct: sd_jwt.claims.vct,
        },
        claims,
        credential: Kind::String(issued.to_string()),
    })
}

/// Verifies an SD-JWT credential.
///
/// # Errors
///
/// Returns an error if the SD-JWT credential is invalid.
pub async fn decode_vc(
    vc: &str, resolver: &impl DidResolver,
) -> Result<(Jwt<SdJwtClaims>, Vec<Disclosure>)> {
    // extract sd-jwt components
    let split = vc.split('~').collect::<Vec<_>>();
    if split.len() < 2 {
        return Err(anyhow!("invalid sd-jwt"));
    }
    let credential = split[0];
    let disclosures = &split[1..split.len()];

    // verify and decode the sd-jwt:
    //  1. it should be signed by the issuer of the sd-jwt (from the sd-jwt `iss` claim)
    //  2. it should contain a hash of the disclosures
    let resolver = async |kid: String| did_jwk(&kid, resolver).await;
    let sd_jwt: Jwt<SdJwtClaims> = jws::decode(credential, resolver).await?;

    // FIXME: verify sd_jwt is signed by the issuer (from the sd-jwt `iss` claim)
    // println!("sd_jwt kid: {}", sd_jwt.header.kid().unwrap());
    // println!("sd_jwt iss: {}", sd_jwt.claims.iss);

    // verify and extract disclosures
    let mut decoded = vec![];
    for encoded in disclosures {
        let disclosure = Disclosure::from(encoded)?;
        if !sd_jwt.claims.sd.contains(&disclosure.hash()?) {
            return Err(anyhow!("disclosure not in sd-jwt `sd` claim"));
        }
        decoded.push(disclosure);
    }

    Ok((sd_jwt, decoded))
}

fn unpack_claims(path: Vec<String>, value: &Value) -> Vec<Claim> {
    match value {
        Value::Object(map) => map.iter().fold(vec![], |mut acc, (key, value)| {
            let mut new_path = path.clone();
            new_path.push(key.to_string());
            acc.extend(unpack_claims(new_path, value));
            acc
        }),
        _ => vec![Claim {
            path,
            value: value.clone(),
        }],
    }
}
