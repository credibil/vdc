use anyhow::Result;
use credibil_core::blockstore::BlockStore;
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_se::{Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use credibil_status::StatusToken;

use crate::blockstore::Mockstore;
use crate::identity::DidIdentity;

pub const VERIFIER_ID: &str = "http://localhost:8080";

pub mod data {
    pub const VERIFIER: &[u8] = include_bytes!("../data/verifier/verifier.json");
}

#[derive(Clone)]
pub struct Verifier {
    identity: DidIdentity,
    blockstore: Mockstore,
}

impl Verifier {
    #[must_use]
    pub async fn new(owner: &str) -> Self {
        Self {
            identity: DidIdentity::new(owner).await,
            blockstore: Mockstore::new(),
        }
    }
}

impl IdentityResolver for Verifier {
    async fn resolve(&self, url: &str) -> anyhow::Result<Identity> {
        self.identity.resolve(url).await
    }
}

impl Signer for Verifier {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.identity.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.identity.algorithm().await
    }
}

impl SignerExt for Verifier {
    async fn verification_method(&self) -> Result<Key> {
        self.identity.verification_method().await
    }
}

impl Receiver for Verifier {
    async fn key_id(&self) -> Result<String> {
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

impl StatusToken for Verifier {
    async fn fetch(&self, uri: &str) -> Result<String> {
        let Some(block) = BlockStore::get(self, "owner", "STATUSTOKEN", uri).await? else {
            return Err(anyhow::anyhow!("could not find status token"));
        };
        Ok(serde_json::from_slice(&block)?)
    }
}
