//! # sd-jwt Verification

use anyhow::{Result, anyhow};
use credibil_did::DidResolver;
use credibil_infosec::jose::jws;
use credibil_infosec::jose::jwt::Jwt;


use crate::core::did_jwk;
use crate::format::sd_jwt::{Disclosure, KbJwtClaims, KeyBinding, SdJwtClaims};
use crate::oid4vp::types::{Claim, RequestObject};





/// Verifies an SD-JWT presentation (KB-JWT, and associated disclosures).
///
/// # Errors
///
/// Returns an error if the SD-JWT presentation is invalid or if verification
/// fails.
pub async fn verify_vp(
    vp: &str, request_object: &RequestObject, resolver: &impl DidResolver,
) -> Result<Vec<Claim>> {
    // extract components of the sd-jwt presentation
    let split = vp.split('~').collect::<Vec<_>>();
    if split.len() < 2 {
        return Err(anyhow!("invalid sd-jwt presentation"));
    }
    let credential = split[0];
    let disclosures = &split[1..split.len() - 1];
    let key_binding = &split[split.len() - 1];

    // verify and unpack the sd-jwt:
    //  1. it should be signed by the issuer of the sd-jwt (from the sd-jwt `iss` claim)
    //  2. it should contain a hash of the disclosures
    let resolver = async |kid: String| did_jwk(&kid, resolver).await;
    let sd_jwt: Jwt<SdJwtClaims> = jws::decode(credential, resolver).await?;

    // verify and unpack the kb-jwt:
    //  1. it should be signed by the holder of the sd-jwt (from the sd-jwt `cnf` claim)
    //  2. it should contain `sd_hash` claim — a hash of the sd-jwt + disclosures
    //  3. the `nonce` should contain the authorization request nonce
    //  4. the `aud` claim should match the client identifier

    // very Holder signature against `cnf` claim of issued credential
    let Some(KeyBinding::Jwk(holder_jwk)) = &sd_jwt.claims.cnf else {
        return Err(anyhow!("sd-jwt `cnf` claim not found"));
    };
    let resolver = async |_| async { Ok(holder_jwk.clone()) }.await;
    let kb_jwt: Jwt<KbJwtClaims> = jws::decode(key_binding, resolver).await?;

    // verify the `sd_hash` claim
    let sd_hash = super::sd_hash(&format!("{credential}~{}", disclosures.join("~")));
    if kb_jwt.claims.sd_hash != sd_hash {
        return Err(anyhow!("kb-jwt `sd_hash` claim is invalid"));
    }
    // verify `nonce` claim
    if kb_jwt.claims.nonce != request_object.nonce {
        return Err(anyhow!("kb-jwt `sd_hash` claim is invalid"));
    }
    // verify `aud` claim
    if kb_jwt.claims.aud != request_object.client_id.to_string() {
        return Err(anyhow!("kb-jwt `sd_hash` claim is invalid"));
    }

    // FIXME: verify disclosures `_sd_alg`

    // unpack each disclosure and verify
    // let dcql_query = &request_object.dcql_query;

    let mut claims = vec![];
    for encoded in disclosures {
        let disclosure = Disclosure::from(encoded)?;
        if !sd_jwt.claims.sd.contains(&disclosure.hash()?) {
            return Err(anyhow!("disclosure not in sd-jwt `sd` claim"));
        }

        let claim = Claim {
            path: vec![disclosure.name.clone()],
            value: disclosure.value.clone(),
        };
        claims.push(claim);
    }

    Ok(claims)
}
