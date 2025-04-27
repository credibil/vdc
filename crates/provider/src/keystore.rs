#![allow(unused)]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::document::{CreateOptions, Document};
use credibil_did::{
    DidResolver, DocumentBuilder, KeyPurpose, PublicKeyFormat, SignerExt,
    VerificationMethodBuilder, VmKeyId,
};
use credibil_infosec::jose::jws::Key;
use credibil_infosec::{Algorithm, PublicKeyJwk};
use ed25519_dalek::Signer as _;
use rand_core::OsRng;

#[derive(Clone)]
pub struct Keyring {
    keys: HashMap<String, KeyUse>,
}

impl Keyring {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    pub fn add(&mut self, key_id: impl Into<String>, key: impl Into<KeyUse>) {
        self.keys.insert(key_id.into(), key.into());
    }

    pub fn get(&self, key_id: &str) -> &KeyUse {
        self.keys.get(key_id).expect("should get key")
    }
}

#[derive(Clone)]
pub enum KeyUse {
    Signing(SigningKey),
    Encryption(EncryptionKey),
}

#[derive(Clone)]
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl SigningKey {
    pub fn new() -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.inner.sign(msg).to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> Vec<u8> {
        self.inner.verifying_key().as_bytes().to_vec()
    }

    pub fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    // pub fn public_key(&self) -> x25519_dalek::PublicKey {
    //     let verifying_key = self.signing_key.verifying_key();
    //     x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes())
    // }
}

impl From<SigningKey> for KeyUse {
    fn from(key: SigningKey) -> Self {
        KeyUse::Signing(key)
    }
}

#[derive(Clone)]
pub struct EncryptionKey {
    inner: x25519_dalek::StaticSecret,
}

impl EncryptionKey {
    pub fn new() -> Self {
        Self {
            inner: x25519_dalek::StaticSecret::random_from_rng(&mut OsRng),
        }
    }

    // impl DidOperator for Keyring {
    //     fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
    //         match purpose {
    //             KeyPurpose::VerificationMethod => Some(PublicKeyJwk {
    //                 kty: KeyType::Okp,
    //                 crv: Curve::Ed25519,
    //                 x: Base64UrlUnpadded::encode_string(self.verifying_key.as_bytes()),
    //                 ..PublicKeyJwk::default()
    //             }),
    //             _ => panic!("unsupported purpose"),
    //         }
    //     }
    // }

    pub fn public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.inner.to_bytes())
    }
}
