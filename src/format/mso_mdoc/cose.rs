//! # COSE
//!
//! This module provides types for working with CBOR Object Signing and
//! Encryption (COSE) keys.

use std::collections::BTreeMap;

use ciborium::{Value, cbor};
use serde::{Deserialize, Serialize, de, ser};
use serde_repr::{Deserialize_repr, Serialize_repr};

const KTY: i64 = 1;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

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
            // x: x.deserialized().map_err(de::Error::custom)?.try_into()?,
            y: None,
        };

        // optional fields
        if let Some(y) = map.get(&Y) {
            cose_key.y =
                Some(y.as_bytes().cloned().ok_or_else(|| de::Error::custom("y is not bytes"))?);
            // cose_key.y = Some(y.deserialized().map_err(de::Error::custom)?);
        }

        Ok(cose_key)
    }
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
