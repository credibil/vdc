//! # COSE
//!
//! This module provides types for working with CBOR Object Signing and
//! Encryption (COSE) keys.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::{Value, cbor};
use coset::{
    CoseSign1, CoseSign1Builder, HeaderBuilder, ProtectedHeader, SignatureContext, iana,
    sig_structure_data,
};
use credibil_identity::{Key, SignerExt};
use credibil_jose::PublicKeyJwk;
use credibil_se::PublicKey;
use serde::{Deserialize, Serialize, de, ser};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::mso_mdoc::DataItem;

const KTY: i64 = 1;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

/// Signs the provided payload using the provided signer.
///
/// # Errors
///
/// Returns an error if the signing fails or if the algorithm is unsupported.
pub async fn sign(payload: Vec<u8>, signer: &impl SignerExt) -> Result<CoseSign1> {
    // header
    let algorithm = match signer.algorithm().await? {
        credibil_se::Algorithm::EdDSA => iana::Algorithm::EdDSA,
        credibil_se::Algorithm::Es256K => return Err(anyhow!("unsupported algorithm")),
    };
    let Key::KeyId(key_id) = signer.verification_method().await? else {
        return Err(anyhow!("invalid verification method"));
    };
    let protected = HeaderBuilder::new().algorithm(algorithm).key_id(key_id.into_bytes()).build();

    let sig_data = sig_structure_data(
        SignatureContext::CoseSign1,
        ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        },
        None,
        &[],
        &payload,
    );

    Ok(CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .signature(signer.sign(&sig_data).await)
        .build())
}

/// Implements [`COSE_Key`] as defined in [RFC9052].
///
/// [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoseKey {
    /// Key type
    pub kty: KeyType,

    /// Curve
    pub crv: Curve,

    /// Public key X
    pub x: Vec<u8>,

    /// Public key Y
    pub y: Option<Vec<u8>>,
}

impl CoseKey {
    /// Wraps the `CoseKey` in a [`DataItem`] for serialization to CBOR data
    /// item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
    }

    /// Verify the signature of the provided message using the JWK.
    ///
    /// # Errors
    ///
    /// Will return an error if the signature is invalid, the JWK is invalid, or
    /// the algorithm is unsupported.
    pub fn verify(&self, sig: &[u8], sig_data: &[u8]) -> Result<()> {
        let verifying_key: PublicKey = self.clone().try_into()?;
        match self.crv {
            Curve::Es256K => credibil_se::Algorithm::Es256K.verify(sig_data, sig, &verifying_key),
            Curve::Ed25519 => credibil_se::Algorithm::EdDSA.verify(sig_data, sig, &verifying_key),
            _ => bail!("unsupported DSA curve"),
        }
    }
}

impl TryFrom<CoseKey> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(cose_key: CoseKey) -> Result<Self> {
        match cose_key.crv {
            Curve::Es256K => {
                let y = cose_key.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
                Self::try_from((cose_key.x.as_slice(), y.as_slice()))
                    .map_err(|e| anyhow!("unable to convert to public key: {e}"))
            }
            Curve::Ed25519 => Self::try_from(cose_key.x.as_slice())
                .map_err(|e| anyhow!("unable to convert to public key: {e}")),
            _ => bail!("unsupported DSA curve"),
        }
    }
}

// impl TryInto<PublicKey> for CoseKey {
//     type Error = anyhow::Error;

//     fn try_into(self) -> Result<PublicKey> {
//         match self.crv {
//             Curve::Es256K =>
//                 PublicKey::try_from((self.x.as_slice(), self.y.unwrap_or_default().as_slice()))
//                     .map_err(|e| anyhow!("unable to convert to public key: {e}")),
//             Curve::Ed25519 => PublicKey::try_from(self.x.as_slice())
//                 .map_err(|e| anyhow!("unable to convert to public key: {e}")),
//             _ => bail!("unsupported DSA curve"),
//         }
//     }
// }

impl From<PublicKeyJwk> for CoseKey {
    fn from(jwk: PublicKeyJwk) -> Self {
        let kty = match jwk.kty {
            credibil_se::KeyType::Okp => KeyType::Okp,
            credibil_se::KeyType::Ec => KeyType::Ec,
            credibil_se::KeyType::Oct => todo!("add support for KeyType::Oct"),
        };
        let crv = match jwk.crv {
            credibil_se::Curve::Ed25519 => Curve::Ed25519,
            credibil_se::Curve::Es256K => Curve::Es256K,
            _ => todo!("add support for other curves"),
        };

        let x = Base64UrlUnpadded::decode_vec(&jwk.x).unwrap_or_default();
        let y = jwk.y.as_ref().map(|y| Base64UrlUnpadded::decode_vec(y).unwrap_or_default());

        Self { kty, crv, x, y }
    }
}

impl Serialize for CoseKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = BTreeMap::<i64, Value>::new();
        map.insert(KTY, cbor!(self.kty).map_err(ser::Error::custom)?);
        map.insert(CRV, cbor!(self.crv).map_err(ser::Error::custom)?);
        map.insert(X, self.clone().x.into());
        if let Some(y) = self.clone().y {
            map.insert(Y, y.into());
        }
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // required fields
        let map = BTreeMap::<i64, Value>::deserialize(deserializer)?;
        let kty = map.get(&KTY).ok_or_else(|| de::Error::missing_field("kty"))?;
        let crv = map.get(&CRV).ok_or_else(|| de::Error::missing_field("crv"))?;
        let x = map.get(&X).ok_or_else(|| de::Error::missing_field("x"))?;

        let mut cose_key = Self {
            kty: kty.deserialized().map_err(de::Error::custom)?,
            crv: crv.deserialized().map_err(de::Error::custom)?,
            x: x.as_bytes().cloned().ok_or_else(|| de::Error::custom("x is not bytes"))?,
            y: None,
        };

        // optional fields
        if let Some(y) = map.get(&Y) {
            cose_key.y = y.as_bytes().cloned();
        }

        Ok(cose_key)
    }
}

/// Fully-Specified Algorithms
#[derive(Clone, Debug, Default, Deserialize_repr, Serialize_repr, Eq, PartialEq)]
#[repr(i64)]
pub enum Algorithm {
    /// ECDSA using P-256 curve and SHA-256
    #[default]
    Esp256 = -9,

    /// ECDSA using P-384 curve and SHA-384
    Esp384 = -48,

    /// ECDSA using P-521 curve and SHA-512
    Esp512 = -49,

    /// ECDSA using `BrainpoolP256r1` curve and SHA-256
    Esb256 = -265,

    /// ECDSA using `BrainpoolP320r1` curve and SHA-384
    Esb320 = -266,

    /// ECDSA using `BrainpoolP384r1` curve and SHA-384
    Esb384 = -267,

    /// ECDSA using `BrainpoolP512r1` curve and SHA-512
    Esb512 = -268,

    /// EdDSA using Ed25519 curve
    Ed25519 = -50,

    /// EdDSA using Ed448 curve
    Ed448 = -51,
}

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize_repr, Serialize_repr, Eq, PartialEq)]
#[repr(i64)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    Okp = 1,

    /// Elliptic curve key pair
    Ec = 2,
}

/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize_repr, Serialize_repr, Eq, PartialEq)]
#[repr(i64)]
pub enum Curve {
    /// secp256r1 curve.
    P256 = 1,

    /// X25519 function (encryption) key pairs.
    X25519 = 4,

    /// Ed25519 signature (DSA) key pairs.
    #[default]
    Ed25519 = 6,

    /// secp256k1 curve.
    Es256K = 8,
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;

    const ES256K_CBOR: &str = "a40102200821582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
    const X_HEX: &str = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    const Y_HEX: &str = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";

    #[test]
    fn serialize() {
        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&cose_key, &mut buf).expect("should serialize");

        // deserialize and verify
        let key: CoseKey = ciborium::from_reader(buf.as_slice()).expect("should deserialize");
        assert_eq!(key, cose_key);
    }

    #[test]
    fn deserialize() {
        let bytes = hex::decode(ES256K_CBOR).expect("should decode");
        let key: CoseKey = ciborium::from_reader(bytes.as_slice()).expect("should serialize");

        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        assert_eq!(key, cose_key);
    }
}
