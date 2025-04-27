//! # mdoc Verification

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::DidResolver;

use crate::core::{did_jwk, serde_cbor};
use crate::format::mso_mdoc::{CoseKey, DeviceAuth, DeviceResponse};
use crate::oid4vp::types::{Claim, RequestObject};

/// Verifies an ISO mdoc presentation.
///
/// # Errors
///
/// Returns an error if the presentation is invalid or if verification fails.
pub async fn verify_vp(
    vp: &str, _request_object: &RequestObject, resolver: &impl DidResolver,
) -> Result<Vec<Claim>> {
    // extract components of the mdoc presentation
    let cbor = Base64UrlUnpadded::decode_vec(vp)?;
    let response = serde_cbor::from_slice::<DeviceResponse>(&cbor)?;

    let documents = response.documents.ok_or_else(|| anyhow!("missing documents"))?;
    let Some(doc) = documents.first() else {
        return Err(anyhow!("no document"));
    };

    // authenticate/verify the device response:
    let DeviceAuth::Signature(device_sig) = &doc.device_signed.device_auth else {
        return Err(anyhow!("missing device authentication"));
    };
    let kid_bytes = &device_sig.protected.header.key_id;
    let kid = String::from_utf8_lossy(kid_bytes);
    let verifying_key: CoseKey = did_jwk(&kid, resolver).await?.into();
    device_sig.verify_signature(&[], |sig, tbs| verifying_key.verify(sig, tbs))?;

    // verify the contained mdoc credential
    let issuer_sig = &doc.issuer_signed.issuer_auth;
    let kid_bytes = &issuer_sig.protected.header.key_id;
    let kid = String::from_utf8_lossy(kid_bytes);
    let verifying_key: CoseKey = did_jwk(&kid, resolver).await?.into();
    issuer_sig.verify_signature(&[], |sig, tbs| verifying_key.verify(sig, tbs))?;

    // let Some(mso_bytes) = &doc.issuer_signed.issuer_auth.0.payload else {
    //     return Err(anyhow!("missing MSO payload"));
    // };
    // let mso: DataItem<MobileSecurityObject> = serde_cbor::from_slice(mso_bytes)?;

    // FIXME: verify DeviceSignedItems match IssuerSignedItems
    let mut claims = vec![];
    for (name_space, items) in doc.device_signed.name_spaces.iter() {
        for (identifier, value) in items {
            let claim = Claim {
                path: vec![name_space.to_string(), identifier.to_string()],
                value: serde_json::to_value(value)?,
            };
            claims.push(claim);
        }
    }

    Ok(claims)
}
