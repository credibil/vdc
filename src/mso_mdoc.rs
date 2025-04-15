//! # ISO mDL-based Credential Format
//!
//! This module provides the implementation of ISO mDL credentials.

mod mdoc;
mod mso;

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::cbor;
use coset::{CoseSign1Builder, HeaderBuilder, iana};
use credibil_did::SignerExt;
use credibil_infosec::cose::{CoseKey, Tag24};
use credibil_infosec::jose::jws::Key;
use credibil_infosec::{Algorithm, Curve, KeyType, Signer};
pub use mdoc::{IssuerSigned, IssuerSignedItem};
pub use mso::{DigestIdGenerator, MobileSecurityObject};
use rand::{Rng, rng};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Generate an ISO mDL `mso_mdoc` format credential.
#[derive(Debug)]
pub struct MsoMdocBuilder<C, S> {
    doctype: String,
    claims: C,
    signer: S,
}

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

/// Builder has no claims.
#[doc(hidden)]
pub struct NoClaims;
/// Builder has claims.
#[doc(hidden)]
pub struct HasClaims(Map<String, Value>);

impl MsoMdocBuilder<NoClaims, NoSigner> {
    pub fn new() -> Self {
        Self {
            doctype: "org.iso.18013.5.1.mDL".to_string(),
            claims: NoClaims,
            signer: NoSigner,
        }
    }
}

impl<C, S> MsoMdocBuilder<C, S> {
    /// Set the claims for the ISO mDL credential.
    pub fn doctype(mut self, doctype: impl Into<String>) -> Self {
        self.doctype = doctype.into();
        self
    }
}

impl<C> MsoMdocBuilder<C, NoSigner> {
    /// Set the credential Signer.
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> MsoMdocBuilder<C, HasSigner<'_, S>> {
        MsoMdocBuilder {
            doctype: self.doctype,
            claims: self.claims,
            signer: HasSigner(signer),
        }
    }
}

impl<S> MsoMdocBuilder<NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    pub fn claims(self, claims: Map<String, Value>) -> MsoMdocBuilder<HasClaims, S> {
        MsoMdocBuilder {
            doctype: self.doctype,
            claims: HasClaims(claims),
            signer: self.signer,
        }
    }
}

impl<S: SignerExt> MsoMdocBuilder<HasClaims, HasSigner<'_, S>> {
    /// Build the ISO mDL credential, returning a base64url-encoded,
    /// CBOR-encoded, ISO mDL.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> anyhow::Result<String> {
        // populate mdoc and accompanying MSO
        let mut mdoc = IssuerSigned::new();
        let mut mso = MobileSecurityObject::new();
        mso.doc_type = self.doctype;

        for (name_space, value) in self.claims.0 {
            // namespace is a root-level claim
            let Some(claims) = value.as_object() else {
                return Err(anyhow!("invalid dataset"));
            };

            let mut id_gen = DigestIdGenerator::new();

            // assemble `IssuerSignedItem`s for name space
            for (k, v) in claims {
                let item = Tag24(IssuerSignedItem {
                    digest_id: id_gen.generate(),
                    random: rng().random::<[u8; 16]>().into(),
                    element_identifier: k.clone(),
                    element_value: cbor!(v)?,
                });

                // digest of `IssuerSignedItem` for MSO
                let digest = Sha256::digest(&item.to_vec()?).to_vec();
                mso.value_digests
                    .entry(name_space.clone())
                    .or_default()
                    .insert(item.digest_id, digest);

                // add item to IssuerSigned object
                mdoc.name_spaces.entry(name_space.clone()).or_default().push(item);
            }
        }

        let signer = self.signer.0;

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

        let Key::KeyId(verification_method) = signer.verification_method().await? else {
            bail!("invalid verification method");
        };
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
        Ok(Base64UrlUnpadded::encode_string(&mdoc.to_vec()?))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use credibil_infosec::cose::cbor;
    use credibil_infosec::{Algorithm, KeyType, Signer};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    use super::mso::DigestAlgorithm;
    use super::{MsoMdocBuilder, *};

    #[tokio::test]
    async fn roundtrip() {
        let claims_json = json!({
            "org.iso.18013.5.1": {
                "given_name": "Normal",
                "family_name": "Person",
                "portrait": "https://example.com/portrait.jpg",
            },
        });
        // let claims_json = json!({
        //     "org.iso.7367.1": {
        //         "vehicle_holder": "Alice Holder",
        //     },
        //     "org.iso.18013.5.1": {
        //         "given_name": "Normal",
        //         "family_name": "Person",
        //         "portrait": "https://example.com/portrait.jpg",
        //     },
        // });
        let claims = claims_json.as_object().unwrap();

        let mdl = MsoMdocBuilder::new()
            .doctype("org.iso.18013.5.1.mDL")
            // .doctype("org.iso.7367.1.mVRC")
            .claims(claims.clone())
            .signer(&Keyring::new())
            .build()
            .await
            .expect("should build");

        // check credential deserializes back into original mdoc/mso structures
        let mdoc_bytes = Base64UrlUnpadded::decode_vec(&mdl).expect("should decode");
        let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes).expect("should deserialize");

        let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
        let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes).expect("should deserialize");

        assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(mso.device_key_info.device_key.kty, KeyType::Okp);
    }

    #[derive(Clone, Debug)]
    pub struct Keyring {
        signing_key: SigningKey,
    }

    impl Keyring {
        pub fn new() -> Self {
            Self {
                signing_key: SigningKey::generate(&mut OsRng),
            }
        }
    }

    impl Signer for Keyring {
        async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            Ok(self.signing_key.sign(msg).to_bytes().to_vec())
        }

        async fn verifying_key(&self) -> Result<Vec<u8>> {
            Ok(self.signing_key.verifying_key().as_bytes().to_vec())
        }

        fn algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }
    }

    impl SignerExt for Keyring {
        async fn verification_method(&self) -> Result<Key> {
            Ok(Key::KeyId("did:example:123#key-1".to_string()))
        }
    }
}
