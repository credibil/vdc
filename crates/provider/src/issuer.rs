#![allow(unused)]

use anyhow::Result;
use credibil_did::{DidResolver, Document, SignerExt};
use credibil_infosec::jose::jws::Key;
use credibil_infosec::{Algorithm, Signer};
use credibil_vc::BlockStore;
use credibil_vc::status::issuer::Status;

use crate::blockstore::Mockstore;
use crate::identity::Identity;

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

#[derive(Clone)]
pub struct Issuer {
    identity: Identity,
    blockstore: Mockstore,
}

impl Issuer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity: Identity::new(),
            blockstore: Mockstore::new(),
        }
    }
}

impl DidResolver for Issuer {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        self.identity.resolve(url).await
    }
}

impl Signer for Issuer {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.identity.verifying_key().await
    }

    fn algorithm(&self) -> Algorithm {
        self.identity.algorithm()
    }
}

impl SignerExt for Issuer {
    async fn verification_method(&self) -> Result<Key> {
        self.identity.verification_method().await
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
