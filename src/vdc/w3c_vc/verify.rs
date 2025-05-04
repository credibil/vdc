//! # W3C Verification

use anyhow::{Result, anyhow};
use credibil_identity::IdentityResolver;
use credibil_jose::{Jwt, decode_jws};

use super::W3cVpClaims;
use crate::core::did_jwk;
use crate::vdc::w3c_vc::store;
use crate::oid4vp::verifier::{Claim, RequestObject};

// /// Verifies an SD-JWT credential.
// ///
// ///  1. It should be signed by the issuer (`iss` claim).
// ///  2. It should contain a hash of the disclosures.
// ///
// /// # Errors
// ///
// /// Returns an error if the SD-JWT credential is invalid.
// pub async fn verify_vc(_vc: &str, _resolver: &impl IdentityResolver) -> Result<Jwt<SdJwtClaims>> {
//     // let jwk = async |kid: String| did_jwk(&kid, resolver).await;
//     // let sd_jwt: Jwt<SdJwtClaims> = decode_jws(vc, jwk).await?;

//     // // FIXME: verify issuer ('iss' claim)

//     // Ok(sd_jwt)
//     todo!()
// }

/// Verifies an SD-JWT presentation (KB-JWT, and associated disclosures).
///
/// # Errors
///
/// Returns an error if the SD-JWT presentation is invalid or if verification
/// fails.
pub async fn verify_vp(
    vp: &str, request_object: &RequestObject, resolver: &impl IdentityResolver,
) -> Result<Vec<Claim>> {
    // verify and unpack jwt:
    //  1. it should be signed by the holder
    //  2. the `nonce` should contain the authorization request nonce
    //  3. the `aud` claim should match the client identifier
    let jwk = async |kid: String| did_jwk(&kid, resolver).await;
    let vp_jwt: Jwt<W3cVpClaims> = decode_jws(vp, jwk).await?;

    // verify claims
    if vp_jwt.claims.aud != request_object.client_id.to_string() {
        return Err(anyhow!("`aud` claim does not match verification request"));
    }
    if vp_jwt.claims.nonce != request_object.nonce {
        return Err(anyhow!("`nonce` claim does not match verification request"));
    }
    // FIXME: verify `iss` claim

    // FIXME: verify credential's status
    // if let Some(status_claim) = &sd_jwt.claims.status {
    //     let jwt = StatusToken::fetch(resolver, &status_claim.status_list.uri).await?;
    //     let status_list = StatusList::from_jwt(&jwt)?;
    //     if !status_list.is_valid(status_claim.status_list.idx)? {
    //         return Err(anyhow!("credential status is invalid"));
    //     }
    // }

    //  unpack claims
    let Some(vcs) = vp_jwt.claims.vp.verifiable_credential else {
        return Ok(vec![]);
    };

    let mut claims = vec![];
    for vc in vcs {
        let c = store::to_queryable(vc, resolver).await?;
        claims.extend(c.claims);
    }

    Ok(claims)
}
