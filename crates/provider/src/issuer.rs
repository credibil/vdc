#![allow(unused)]

use anyhow::Result;
use credibil_did::{DidResolver, Document};
use credibil_infosec::{Algorithm, Signer};
use credibil_vc::BlockStore;
use credibil_vc::status::issuer::Status;

use crate::blockstore::Mockstore;
use crate::keystore::Keyring;

pub const ISSUER_ID: &str = "http://credibil.io";
pub const BOB_ID: &str = "bob";
pub const CAROL_ID: &str = "carol";

pub mod data {
    pub const CLIENT: &[u8] = include_bytes!("../data/issuer/client.json");
    pub const ISSUER: &[u8] = include_bytes!("../data/issuer/issuer.json");
    pub const SERVER: &[u8] = include_bytes!("../data/issuer/server.json");
    pub const NORMAL_USER: &[u8] = include_bytes!("../data/issuer/normal-user.json");
    pub const PENDING_USER: &[u8] = include_bytes!("../data/issuer/pending-user.json");
}

#[derive(Clone, Debug)]
pub struct Issuer {
    keyring: Keyring,
    blockstore: Mockstore,
}

impl Issuer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            blockstore: Mockstore::new(),
        }
    }
}

impl DidResolver for Issuer {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        self.keyring.resolve(url).await
    }
}

impl Signer for Issuer {
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

impl BlockStore for Issuer {
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

impl Status for Issuer {}
