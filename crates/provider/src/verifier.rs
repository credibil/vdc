#![allow(dead_code)]

use anyhow::Result;
use credibil_did::{DidResolver, Document};
use credibil_infosec::{self, Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use credibil_vc::BlockStore;

use crate::blockstore::Mockstore;
use crate::keystore::Keyring;

pub const VERIFIER_ID: &str = "http://localhost:8080";

pub mod data {
    pub const VERIFIER: &[u8] = include_bytes!("../data/verifier/verifier.json");
}

#[derive(Clone, Debug)]
pub struct Verifier {
    keyring: Keyring,
    blockstore: Mockstore,
}

impl Verifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            blockstore: Mockstore::new(),
        }
    }
}

impl DidResolver for Verifier {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        self.keyring.resolve(url).await
    }
}

impl Signer for Verifier {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.keyring.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key().await
    }

    fn algorithm(&self) -> Algorithm {
        self.keyring.algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        self.keyring.verification_method().await
    }
}

impl Receiver for Verifier {
    fn key_id(&self) -> String {
        todo!()
    }

    async fn shared_secret(&self, _sender_public: PublicKey) -> Result<SharedSecret> {
        todo!()
    }
}

impl BlockStore for Verifier {
    async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        self.blockstore.put(owner, partition, key, block).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.blockstore.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        self.blockstore.delete(owner, partition, key).await
    }

    async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}
