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
use credibil_did::SignerExt;
use credibil_infosec::jose::jws::Key;
use credibil_infosec::{Algorithm, PublicKeyJwk};
use ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize, de, ser};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::format::mso_mdoc::DataItem;

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
    let algorithm = match signer.algorithm() {
        Algorithm::EdDSA => iana::Algorithm::EdDSA,
        Algorithm::ES256K => return Err(anyhow!("unsupported algorithm")),
    };
    let Key::KeyId(key_id) = signer.verification_method().await? else {
        return Err(anyhow!("invalid verification method"));
    };
    let protected = HeaderBuilder::new().algorithm(algorithm).key_id(key_id.into_bytes()).build();

    // `ToBeSigned` data structure
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
        match self.crv {
            Curve::Es256K => self.verify_es256k(sig, sig_data),
            Curve::Ed25519 => self.verify_eddsa(sig, sig_data),
            _ => bail!("unsupported DSA curve"),
        }
    }

    // Verify the signature of the provided message using the ES256K algorithm.
    fn verify_es256k(&self, sig: &[u8], msg: &[u8]) -> Result<()> {
        use ecdsa::{Signature, VerifyingKey};
        use k256::Secp256k1;

        // build verifying key
        let y = self.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut self.x.clone());
        sec1.append(&mut y.clone());

        let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
        let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;
        let normalised = signature.normalize_s().unwrap_or(signature);

        Ok(verifying_key.verify(msg, &normalised)?)
    }

    // Verify the signature of the provided message using the EdDSA algorithm.
    fn verify_eddsa(&self, sig: &[u8], msg: &[u8]) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // build verifying key
        let x_bytes =
            &self.x.clone().try_into().map_err(|_| anyhow!("invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(x_bytes)
            .map_err(|e| anyhow!("unable to build verifying key: {e}"))?;
        let signature =
            Signature::from_slice(sig).map_err(|e| anyhow!("unable to build signature: {e}"))?;

        verifying_key
            .verify(msg, &signature)
            .map_err(|e| anyhow!("unable to verify signature: {e}"))
    }
}

impl From<PublicKeyJwk> for CoseKey {
    fn from(jwk: PublicKeyJwk) -> Self {
        let kty = match jwk.kty {
            credibil_infosec::KeyType::Okp => KeyType::Okp,
            credibil_infosec::KeyType::Ec => KeyType::Ec,
            credibil_infosec::KeyType::Oct => todo!("add support for KeyType::Oct"),
        };
        let crv = match jwk.crv {
            credibil_infosec::Curve::Ed25519 => Curve::Ed25519,
            credibil_infosec::Curve::Es256K => Curve::Es256K,
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
