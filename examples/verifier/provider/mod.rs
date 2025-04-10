#![allow(dead_code)]

#[path = "../../blockstore/mod.rs"]
mod block_store;
#[path = "../../kms/mod.rs"]
mod kms;

use anyhow::Result;
use blockstore::InMemoryBlockstore;
use credibil_did::{DidResolver, Document};
use credibil_infosec::{self, Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use kms::Keyring;

pub const VERIFIER_ID: &str = "http://localhost:8080";

#[derive(Clone, Debug)]
pub struct ProviderImpl {
    keyring: Keyring,
    blockstore: InMemoryBlockstore<64>,
}

impl ProviderImpl {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            blockstore: InMemoryBlockstore::<64>::new(),
        }
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        self.keyring.resolve(url).await
    }
}

impl Signer for ProviderImpl {
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

impl Receiver for ProviderImpl {
    fn key_id(&self) -> String {
        todo!()
    }

    async fn shared_secret(&self, _sender_public: PublicKey) -> Result<SharedSecret> {
        todo!()
    }
}
