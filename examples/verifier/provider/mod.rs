#![allow(dead_code)]

#[path = "../../blockstore/mod.rs"]
mod blockstore;
#[path = "../../kms/mod.rs"]
mod kms;

use anyhow::Result;
use credibil_did::{DidResolver, Document};
use credibil_infosec::{self, Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use credibil_vc::BlockStore;

use self::blockstore::Mockstore;
use self::kms::Keyring;

pub const VERIFIER_ID: &str = "http://localhost:8080";

#[derive(Clone, Debug)]
pub struct ProviderImpl {
    keyring: Keyring,
    blockstore: Mockstore,
}

impl ProviderImpl {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            blockstore: Mockstore::new(),
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

impl BlockStore for ProviderImpl {
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
