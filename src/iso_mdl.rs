//! # Verifiable Credentials
//!
//! This library encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

mod mdoc;
mod mso;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded as Base64, Encoding};
use ciborium::cbor;
use coset::{CoseSign1Builder, HeaderBuilder, iana};
use credibil_infosec::cose::{CoseKey, Tag24};
use credibil_infosec::{Algorithm, Curve, KeyType, Signer};
use mdoc::{IssuerSigned, IssuerSignedItem};
use mso::{DigestIdGenerator, MobileSecurityObject};
use rand::{Rng, rng};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Convert a Credential Dataset to a base64url-encoded, CBOR-encoded, ISO mDL
/// `IssuerSigned` object.
///
/// # Errors
/// // TODO: add errors
pub async fn to_credential(
    dataset: Map<String, Value>, signer: impl Signer,
) -> anyhow::Result<String> {
    // populate mdoc and accompanying MSO
    let mut mdoc = IssuerSigned::new();
    let mut mso = MobileSecurityObject::new();

    for (key, value) in dataset {
        // namespace is a root-level claim
        let Some(name_space) = value.as_object() else {
            return Err(anyhow!("invalid dataset"));
        };

        let mut id_gen = DigestIdGenerator::new();

        // assemble `IssuerSignedItem`s for name space
        for (k, v) in name_space {
            let item = Tag24(IssuerSignedItem {
                digest_id: id_gen.generate(),
                random: rng().random::<[u8; 16]>().into(),
                element_identifier: k.clone(),
                element_value: cbor!(v)?,
            });

            // digest of `IssuerSignedItem` for MSO
            let digest = Sha256::digest(&item.to_vec()?).to_vec();
            mso.value_digests.entry(key.clone()).or_default().insert(item.digest_id, digest);

            // add item to IssuerSigned object
            mdoc.name_spaces.entry(key.clone()).or_default().push(item);
        }
    }

    // add public key to MSO
    mso.device_key_info.device_key = CoseKey {
        kty: KeyType::Okp,
        crv: Curve::Ed25519,
        x: signer.verifying_key().await?,
        y: None,
    };

    // sign
    let mso_bytes = Tag24(mso).to_vec()?;
    let signature = signer.sign(&mso_bytes).await;

    // build COSE_Sign1
    let algorithm = match signer.algorithm() {
        Algorithm::EdDSA => iana::Algorithm::EdDSA,
        Algorithm::ES256K => return Err(anyhow!("unsupported algorithm")),
    };

    let verification_method = signer.verification_method().await?;
    let key_id = verification_method.as_bytes().to_vec();

    let protected = HeaderBuilder::new().algorithm(algorithm).build();
    let unprotected = HeaderBuilder::new().key_id(key_id).build();
    let cose_sign_1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(mso_bytes)
        .signature(signature)
        .build();

    // add COSE_Sign1 to IssuerSigned object
    mdoc.issuer_auth = mso::IssuerAuth(cose_sign_1);

    // encode CBOR -> Base64Url -> return
    Ok(Base64::encode_string(&mdoc.to_vec()?))
}

// #[cfg(test)]
// mod tests {
//     use credibil_infosec::cose::cbor;
//     use serde_json::json;
//     use test_issuer::ProviderImpl;
//     use to_credential;

//     use super::mso::DigestAlgorithm;
//     use super::*;

//     #[tokio::test]
//     async fn roundtrip() {
//         let dataset = json!({
//             "org.iso.18013.5.1.mDL": {
//                 "given_name": "Normal",
//                 "family_name": "Person",
//                 "email": "normal.user@example.com"
//             }
//         });

//         // generate mdl credential
//         let dataset = serde_json::from_value(dataset).unwrap();
//         let provider = ProviderImpl::new();
//         let mdl = to_credential(dataset, provider).await.unwrap();

//         // check credential deserializes back into original mdoc/mso structures
//         let mdoc_bytes = Base64::decode_vec(&mdl).expect("should decode");
//         let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes).expect("should deserialize");

//         let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
//         let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes).expect("should deserialize");

//         assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
//         assert_eq!(mso.device_key_info.device_key.kty, KeyType::Okp);
//     }
// }
