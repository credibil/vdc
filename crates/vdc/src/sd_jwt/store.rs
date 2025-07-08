//! # Store

use anyhow::{Result, anyhow};
use credibil_binding::Resolver;
use credibil_core::Kind;
use serde_json::Value;

use crate::FormatProfile;
use crate::dcql::{Claim, Queryable};
use crate::sd_jwt::{Disclosure, verify};

/// Convert a `dc+sd-jwt` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub async fn to_queryable(issued: &str, resolver: &impl Resolver) -> Result<Queryable> {
    // extract components of the sd-jwt credential
    let split = issued.split('~').collect::<Vec<_>>();
    if split.len() < 2 {
        return Err(anyhow!("invalid sd-jwt"));
    }
    let credential = split[0];
    let disclosures = &split[1..split.len()];

    // verify the sd-jwt
    let sd_jwt = verify::verify_vc(credential, resolver).await?;

    // unpack and verify disclosures
    let mut claims = vec![];
    for encoded in disclosures {
        let disclosure = Disclosure::from(encoded)?;
        if !sd_jwt.claims.sd.contains(&disclosure.hash()?) {
            return Err(anyhow!("disclosure not in sd-jwt `sd` claim"));
        }
        let path = vec![disclosure.name.clone()];
        claims.extend(unpack_claims(path, &disclosure.value));
    }

    Ok(Queryable {
        meta: FormatProfile::DcSdJwt { vct: sd_jwt.claims.vct },
        claims,
        credential: Kind::String(issued.to_string()),
    })
}

fn unpack_claims(path: Vec<String>, value: &Value) -> Vec<Claim> {
    match value {
        Value::Object(map) => map.iter().fold(vec![], |mut acc, (key, value)| {
            let mut new_path = path.clone();
            new_path.push(key.to_string());
            acc.extend(unpack_claims(new_path, value));
            acc
        }),
        _ => vec![Claim { path, value: value.clone() }],
    }
}
