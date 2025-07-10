//! # mdoc Identity

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use coset::CoseSign1;
use credibil_binding::{Resolver, resolve_jwk};
use credibil_jose::KeyBinding;

use crate::dcql::Claim;
use crate::mso_mdoc::{CoseKey, DeviceAuth, DeviceResponse, IssuerSigned};
use crate::serde_cbor;

/// Verifies an ISO mdoc presentation.
///
/// # Errors
///
/// Returns an error if the presentation is invalid or if verification fails.
pub async fn verify_vp(vp: &str, resolver: &impl Resolver) -> Result<Vec<Claim>> {
    // extract components of the mdoc presentation
    let cbor = Base64UrlUnpadded::decode_vec(vp)?;
    let response = serde_cbor::from_slice::<DeviceResponse>(&cbor)?;

    // TODO: iterate over all returned documents
    let documents = response.documents.ok_or_else(|| anyhow!("missing documents"))?;
    let Some(doc) = documents.first() else {
        return Err(anyhow!("no document"));
    };

    // authenticate signatures (device response & issued credential)
    let DeviceAuth::Signature(device_sig) = &doc.device_signed.device_auth else {
        return Err(anyhow!("missing device authentication"));
    };
    verify_signature(device_sig, resolver).await?;
    verify_signature(&doc.issuer_signed.issuer_auth, resolver).await?;

    // verify and return presented claims
    let mut claims = vec![];
    for (name_space, items) in doc.device_signed.name_spaces.iter() {
        let Some(issuer_items) = doc.issuer_signed.name_spaces.get(name_space) else {
            return Err(anyhow!("issuer namespace not found"));
        };

        for (identifier, value) in items {
            // verify presented item exists in issuer signed items
            let Some(item) = issuer_items.iter().find(|i| i.element_identifier == *identifier)
            else {
                return Err(anyhow!("issuer signed item not found"));
            };
            if item.element_value != *value {
                return Err(anyhow!("issuer signed item value mismatch"));
            }

            claims.push(Claim {
                path: vec![name_space.to_string(), identifier.to_string()],
                value: serde_json::to_value(value)?,
            });
        }
    }

    Ok(claims)
}

pub async fn verify_signature(signature: &CoseSign1, resolver: &impl Resolver) -> Result<()> {
    let kid_bytes = &signature.protected.header.key_id;
    let kid = String::from_utf8_lossy(kid_bytes);
    let verifying_key: CoseKey = resolve_jwk(&*kid, resolver).await?.into();
    signature.verify_signature(&[], |sig, tbs| verifying_key.verify(sig, tbs))
}

/// Extract the verifying key information from an `mso_mdoc` credential.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub fn key_binding(issued: &str) -> Result<KeyBinding> {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(issued)?;
    let issuer_signed: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes)?;
    let kid = String::from_utf8_lossy(&issuer_signed.issuer_auth.protected.header.key_id);

    Ok(KeyBinding::Kid(kid.to_string()))
}
