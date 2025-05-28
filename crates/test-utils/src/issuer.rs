use anyhow::Result;
use credibil_core::blockstore::BlockStore;
use credibil_identity::did::Document;
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_se::{Algorithm, Signer};

use crate::blockstore::Mockstore;
use crate::identity::DidIdentity;

const ISSUER_METADATA: &[u8] = include_bytes!("../data/issuer-metadata.json");
const SERVER_METADATA: &[u8] = include_bytes!("../data/server-metadata.json");
const NORMAL_USER: &[u8] = include_bytes!("../data/normal-user.json");
const PENDING_USER: &[u8] = include_bytes!("../data/pending-user.json");
const CLIENT: &[u8] = include_bytes!("../data/client.json");

#[derive(Clone)]
pub struct Issuer {
    blockstore: Mockstore,
    identity: DidIdentity,
}

impl Issuer {
    #[must_use]
    pub async fn new(issuer_id: &str) -> Self {
        let blockstore = Mockstore::open();
        blockstore.put("owner", "ISSUER", issuer_id, ISSUER_METADATA).await.unwrap();
        blockstore.put("owner", "SERVER", issuer_id, SERVER_METADATA).await.unwrap();
        blockstore.put("owner", "SUBJECT", "normal_user", NORMAL_USER).await.unwrap();
        blockstore.put("owner", "SUBJECT", "pending_user", PENDING_USER).await.unwrap();
        blockstore.put("owner", "CLIENT", "http://localhost:8082", CLIENT).await.unwrap();

        Self {
            blockstore,
            identity: DidIdentity::new(issuer_id).await,
        }
    }

    pub async fn did(&self) -> Result<Document> {
        self.identity.document(&self.identity.owner).await
    }
}

impl IdentityResolver for Issuer {
    async fn resolve(&self, url: &str) -> Result<Identity> {
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
        self.identity.algorithm().await
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
