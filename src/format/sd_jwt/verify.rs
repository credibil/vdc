//! # SD-JWT Verification

use anyhow::{Result, anyhow};
use credibil_did::DidResolver;
use credibil_infosec::jose::jws;
use credibil_infosec::jose::jwt::Jwt;

use crate::core::did_jwk;
use crate::format::sd_jwt::{KbJwtClaims, KeyBinding, SdJwtClaims};

/// Verifies an SD-JWT presentation (KB-JWT, and associated disclosures).
///
/// # Errors
///
/// Returns an error if the SD-JWT presentation is invalid or if verification
/// fails.
pub async fn verify(vp: &str, resolver: &impl DidResolver) -> Result<()> {
    // unpack the kb-jwt and verify
    // <sd-jwt: header.payload.signature>~<disclosure 1>~<disclosure 2>~...~<kb-jwt: header.payload.signature>

    let split = vp.split('~').collect::<Vec<_>>();

    // verify and unpack the sd-jwt:
    //  1. it should be signed by the issuer of the sd-jwt (from the sd-jwt `iss` claim)
    //  2. it should contain a hash of the disclosures
    let resolver = async |kid: String| did_jwk(&kid, resolver).await;
    let jwt = split.first().ok_or_else(|| anyhow!("SD-JWT presentation has no elements"))?;
    let sd_jwt: Jwt<SdJwtClaims> = jws::decode(jwt, resolver).await?;

    // verify and unpack the kb-jwt:
    //  1. it should be signed by the holder of the sd-jwt (from the sd-jwt `cnf` claim)
    //  2. it should contain a hash of the sd-jwt + disclosures
    //  3. the `nonce` should contain the authorization request nonce
    //  4. the `aud` claim should match the client identifier
    let Some(KeyBinding::Jwk(holder_jwk)) = &sd_jwt.claims.cnf else {
        return Err(anyhow!("`cnf` claim not found in SD-JWT"));
    };

    let resolver = async |_| async { Ok(holder_jwk.clone()) }.await;
    let jwt = split.last().ok_or_else(|| anyhow!("Invalid SD-JWT presentation"))?;
    let kb_jwt: Jwt<KbJwtClaims> = jws::decode(jwt, resolver).await?;

    println!("kb_jwt: {kb_jwt:?}");

    let _disclosures = &split[..split.len() - 1];
    let _sd_jwt = split[0];

    // unpack the sd-jwt and verify
    // unpack disclosures and verify against  sd-jwt `_sd` & `_sd_alg`
    // return the disclosures and metadata

    Ok(())
}
