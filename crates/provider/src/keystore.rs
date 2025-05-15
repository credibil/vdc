#![allow(unused)]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_identity::did::{
    Document, DocumentBuilder, KeyPurpose, PublicKeyFormat, VerificationMethodBuilder, VmKeyId,
};
use credibil_identity::{IdentityResolver, Key, SignerExt};
use credibil_jose::PublicKeyJwk;
use credibil_se::{Algorithm, Curve, PublicKey};
use ed25519_dalek::Signer as _;
use rand_core::OsRng;
use test_kms::Keyring as BaseKeyring;

#[derive(Clone)]
pub struct Keyring {
    keys: BaseKeyring,
}

impl Keyring {
    pub async fn new(owner: &str) -> anyhow::Result<Self> {
        Ok(Self { keys: BaseKeyring::new(owner).await? })
    }

    pub async fn add(&mut self, key_id: impl ToString, key: KeyUse) -> anyhow::Result<()> {
        let curve = match key {
            KeyUse::Signing => Curve::Ed25519,
            KeyUse::Encryption => Curve::X25519,
        };
        self.keys.add(&curve, key_id).await
    }

    pub async fn verifying_key_jwk(&self, key_id: impl ToString) -> anyhow::Result<PublicKeyJwk> {
        let key = self.keys.verifying_key(key_id).await?;
        PublicKeyJwk::from_bytes(&key)
    }

    pub async fn verifying_key(&self, key_id: impl ToString) -> anyhow::Result<Vec<u8>> {
        self.keys.verifying_key(key_id).await
    }

    pub async fn sign(&self, key_id: impl ToString, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.keys.sign(key_id, msg).await
    }
}

#[derive(Clone)]
pub enum KeyUse {
    Signing,
    Encryption,
}
