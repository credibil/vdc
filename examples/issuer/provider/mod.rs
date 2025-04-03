#![allow(dead_code)]

#[path = "../../blockstore/mod.rs"]
mod block_store;
#[path = "../../kms/mod.rs"]
mod kms;

use std::sync::Arc;

use anyhow::Result;
use blockstore::InMemoryBlockstore;
use credibil_did::{DidResolver, Document};
use credibil_infosec::Signer;
use credibil_infosec::jose::jwa::Algorithm;
use credibil_vc::status::issuer::Status;
use kms::Keyring;

pub const ISSUER_ID: &str = "http://credibil.io";
pub const NORMAL: &str = "normal_user";
pub const PENDING: &str = "pending_user";

#[derive(Clone, Debug)]
pub struct ProviderImpl {
    keyring: Keyring,
    blockstore: Arc<InMemoryBlockstore<64>>,
}

impl ProviderImpl {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            blockstore: Arc::new(InMemoryBlockstore::<64>::new()),
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

impl Status for ProviderImpl {}
