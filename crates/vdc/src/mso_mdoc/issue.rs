//! # ISO `mso_mdoc` Credential Issuance
//!
//! This module supports issuance of ISO `mso_mdoc` credentials.

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::cbor;
use credibil_identity::SignerExt;
use rand::{Rng, rng};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::mso_mdoc::cose;
pub use crate::mso_mdoc::{
    CoseKey, DigestIdGenerator, IssuerAuth, IssuerSigned, IssuerSignedItem, MobileSecurityObject,
};
use crate::serde_cbor;

/// Generate an ISO mDL `mso_mdoc` format credential.
#[derive(Debug)]
pub struct MdocBuilder<D, K, C, S> {
    doctype: D,
    device_key: K,
    claims: C,
    signer: S,
}

/// Builder has no `doc_type`.
#[doc(hidden)]
pub struct NoDocType;
/// Builder has `doc_type`.
#[doc(hidden)]
pub struct HasDocType(String);

/// Builder has no `doc_type`.
#[doc(hidden)]
pub struct NoDeviceKey;
/// Builder has `doc_type`.
#[doc(hidden)]
pub struct HasDeviceKey(CoseKey);

/// Builder has no claims.
#[doc(hidden)]
pub struct NoClaims;
/// Builder has claims.
#[doc(hidden)]
pub struct HasClaims(Map<String, Value>);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl MdocBuilder<NoDocType, NoDeviceKey, NoClaims, NoSigner> {
    /// Create a new ISO mDL credential builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            doctype: NoDocType,
            device_key: NoDeviceKey,
            claims: NoClaims,
            signer: NoSigner,
        }
    }
}

impl Default for MdocBuilder<NoDocType, NoDeviceKey, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, C, S> MdocBuilder<NoDocType, K, C, S> {
    /// Set the claims for the ISO mDL credential.
    pub fn doctype(self, doctype: impl Into<String>) -> MdocBuilder<HasDocType, K, C, S> {
        MdocBuilder {
            doctype: HasDocType(doctype.into()),
            device_key: self.device_key,
            claims: self.claims,
            signer: self.signer,
        }
    }
}

impl<D, C, S> MdocBuilder<D, NoDeviceKey, C, S> {
    /// Set the claims for the ISO mDL credential.
    pub fn device_key(self, device_key: impl Into<CoseKey>) -> MdocBuilder<D, HasDeviceKey, C, S> {
        MdocBuilder {
            doctype: self.doctype,
            device_key: HasDeviceKey(device_key.into()),
            claims: self.claims,
            signer: self.signer,
        }
    }
}

impl<D, K, S> MdocBuilder<D, K, NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    pub fn claims(self, claims: Map<String, Value>) -> MdocBuilder<D, K, HasClaims, S> {
        MdocBuilder {
            doctype: self.doctype,
            device_key: self.device_key,
            claims: HasClaims(claims),
            signer: self.signer,
        }
    }
}

impl<D, K, C> MdocBuilder<D, K, C, NoSigner> {
    /// Set the credential `SignerExt`.
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> MdocBuilder<D, K, C, HasSigner<'_, S>> {
        MdocBuilder {
            doctype: self.doctype,
            device_key: self.device_key,
            claims: self.claims,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> MdocBuilder<HasDocType, HasDeviceKey, HasClaims, HasSigner<'_, S>> {
    /// Build the ISO mDL credential, returning a base64url-encoded,
    /// CBOR-encoded, ISO mDL.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> anyhow::Result<String> {
        // populate mdoc and accompanying MSO
        let mut mdoc = IssuerSigned::new();
        let mut mso = MobileSecurityObject::new();
        mso.doc_type = self.doctype.0;
        mso.device_key_info.device_key = self.device_key.0;

        for (name_space, value) in self.claims.0 {
            // namespace is a root-level claim
            let Some(claims) = value.as_object() else {
                return Err(anyhow!("invalid dataset"));
            };

            let mut id_gen = DigestIdGenerator::new();

            // assemble `IssuerSignedItem`s for name space
            for (k, v) in claims {
                let item = IssuerSignedItem {
                    digest_id: id_gen.generate(),
                    random: rng().random::<[u8; 16]>().into(),
                    element_identifier: k.clone(),
                    element_value: cbor!(v)?,
                };
                let item_bytes = item.into_bytes();

                // digest of `IssuerSignedItem` for MSO
                let digest = Sha256::digest(&serde_cbor::to_vec(&item_bytes)?).to_vec();
                mso.value_digests
                    .entry(name_space.clone())
                    .or_default()
                    .insert(item_bytes.digest_id, digest);

                // add item to IssuerSigned object
                mdoc.name_spaces.entry(name_space.clone()).or_default().push(item_bytes);
            }
        }

        // sign MSO and attach as `IssuerAuth`
        let mso_bytes = serde_cbor::to_vec(&mso.into_bytes())?;
        mdoc.issuer_auth = IssuerAuth(cose::sign(mso_bytes, self.signer.0).await?);

        // encode CBOR -> Base64Url -> return
        Ok(Base64UrlUnpadded::encode_string(&serde_cbor::to_vec(&mdoc)?))
    }
}

#[cfg(test)]
mod tests {
    use credibil_core::did_jwk;
    use credibil_jose::KeyBinding;
    use serde_json::json;
    use test_utils::issuer::Issuer;
    use test_utils::wallet::Wallet;

    use super::*;
    use crate::mso_mdoc::{DataItem, DigestAlgorithm, KeyType, serde_cbor};

    #[tokio::test]
    async fn build_vc() {
        let wallet = Wallet::new("https://mso_mdoc.io/wallet").await;
        let key_ref = wallet
            .verification_method()
            .await
            .expect("should have key id")
            .try_into()
            .expect("should map key binding to key ref");
        let KeyBinding::Kid(kid) = key_ref else {
            panic!("should have key id");
        };
        let device_jwk = did_jwk(&kid, &wallet).await.expect("should fetch JWK");

        let claims_json = json!({
            "org.iso.18013.5.1": {
                "given_name": "Normal",
                "family_name": "Person",
                "portrait": "https://example.com/portrait.jpg",
            },
        });
        let claims = claims_json.as_object().unwrap();

        let mdoc = MdocBuilder::new()
            .doctype("org.iso.18013.5.1.mDL")
            .device_key(device_jwk)
            .claims(claims.clone())
            .signer(&Issuer::new("https://mso_mdoc.io/issuer").await)
            .build()
            .await
            .expect("should build");

        // check credential deserializes back into original mdoc/mso structures
        let mdoc_bytes = Base64UrlUnpadded::decode_vec(&mdoc).expect("should decode");
        let mdoc: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes).expect("should deserialize");

        let cbor = mdoc.issuer_auth.0.payload.expect("should have payload");
        let mso: DataItem<MobileSecurityObject> =
            serde_cbor::from_slice(&cbor).expect("should deserialize");

        assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(mso.device_key_info.device_key.kty, KeyType::Okp);
    }
}
