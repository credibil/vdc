//! # sd-jwt Verification

use anyhow::{Result, anyhow};
use credibil_identity::IdentityResolver;
use credibil_jose::{Jwt, decode_jws};
use credibil_status::{StatusListClaims, StatusToken};

use crate::common::did_jwk;
use crate::oid4vp::verifier::{Claim, RequestObject};
use crate::vdc::sd_jwt::{Disclosure, KbJwtClaims, KeyBinding, SdJwtClaims};

/// Verifies an SD-JWT credential.
///
///  1. It should be signed by the issuer (`iss` claim).
///  2. It should contain a hash of the disclosures.
///
/// # Errors
///
/// Returns an error if the SD-JWT credential is invalid.
pub async fn verify_vc(vc: &str, resolver: &impl IdentityResolver) -> Result<Jwt<SdJwtClaims>> {
    let jwk = async |kid: String| did_jwk(&kid, resolver).await;
    let sd_jwt: Jwt<SdJwtClaims> = decode_jws(vc, jwk).await?;

    // FIXME: verify issuer ('iss' claim)

    Ok(sd_jwt)
}

/// Verifies an SD-JWT presentation (KB-JWT, and associated disclosures).
///
/// # Errors
///
/// Returns an error if the SD-JWT presentation is invalid or if verification
/// fails.
pub async fn verify_vp<R>(
    vp: &str, request_object: &RequestObject, resolver: &R,
) -> Result<Vec<Claim>>
where
    R: IdentityResolver + StatusToken,
{
    // extract components of the sd-jwt presentation
    let split = vp.split('~').collect::<Vec<_>>();
    if split.len() < 2 {
        return Err(anyhow!("invalid sd-jwt presentation"));
    }
    let credential = split[0];
    let disclosures = &split[1..split.len() - 1];
    let key_binding = &split[split.len() - 1];

    // verify and unpack the sd-jwt
    let sd_jwt = verify_vc(credential, resolver).await?;

    // ..verify credential's status
    if let Some(status_claim) = &sd_jwt.claims.status {
        // FIXME: move this code  to `StatusList`
        let token = StatusToken::fetch(resolver, &status_claim.status_list.uri).await?;
        let jwk = async |kid: String| did_jwk(&kid, resolver).await;
        let decoded: Jwt<StatusListClaims> = decode_jws(&token, jwk).await?;
        if !decoded.claims.status_list.is_valid(status_claim.status_list.idx)? {
            return Err(anyhow!("credential status is invalid"));
        }
    }

    // verify and unpack the kb-jwt:
    //  1. it should be signed by the holder of the sd-jwt (from the sd-jwt `cnf` claim)
    //  2. it should contain `sd_hash` claim — a hash of the sd-jwt + disclosures
    //  3. the `nonce` should contain the authorization request nonce
    //  4. the `aud` claim should match the client identifier

    // ..verify Holder signature against `cnf` claim of issued credential
    let Some(KeyBinding::Jwk(holder_jwk)) = &sd_jwt.claims.cnf else {
        return Err(anyhow!("sd-jwt `cnf` claim not found"));
    };
    let resolver = async |_| async { Ok(holder_jwk.clone()) }.await;
    let kb_jwt: Jwt<KbJwtClaims> = decode_jws(key_binding, resolver).await?;

    // ..verify the `sd_hash` claim
    let sd_hash = super::sd_hash(&format!("{credential}~{}", disclosures.join("~")));
    if kb_jwt.claims.sd_hash != sd_hash {
        return Err(anyhow!("kb-jwt `sd_hash` claim is invalid"));
    }
    // ..verify `nonce` claim
    if kb_jwt.claims.nonce != request_object.nonce {
        return Err(anyhow!("kb-jwt `nonce` claim is invalid"));
    }
    // ..verify `aud` claim
    if kb_jwt.claims.aud != request_object.client_id.to_string() {
        return Err(anyhow!("kb-jwt `aud` claim is invalid"));
    }

    // FIXME: verify disclosures use `_sd_alg`

    // unpack and verify disclosures
    let mut claims = vec![];
    for encoded in disclosures {
        let disclosure = Disclosure::from(encoded)?;
        if !sd_jwt.claims.sd.contains(&disclosure.hash()?) {
            return Err(anyhow!("disclosure not in sd-jwt `sd` claim"));
        }
        claims.push(Claim {
            path: vec![disclosure.name.clone()],
            value: disclosure.value.clone(),
        });
    }

    Ok(claims)
}
