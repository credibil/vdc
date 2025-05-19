use anyhow::Result;
use credibil_core::blockstore::BlockStore;
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_se::{Algorithm, Signer};

use crate::blockstore::Mockstore;
use crate::identity::DidIdentity;

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
    identity: DidIdentity,
    blockstore: Mockstore,
}

impl Issuer {
    #[must_use]
    pub async fn new(owner: &str) -> Self {
        Self {
            identity: DidIdentity::new(owner).await,
            blockstore: Mockstore::new(),
        }
    }
}

impl IdentityResolver for Issuer {
    async fn resolve(&self, url: &str) -> anyhow::Result<Identity> {
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

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(self.identity.algorithm())
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
