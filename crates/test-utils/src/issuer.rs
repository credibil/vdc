use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_identity::did::Document;
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_se::{Algorithm, Signer};

use crate::datastore::Store;
use crate::identity::DidIdentity;

const ISSUER_METADATA: &[u8] = include_bytes!("../data/issuer-metadata.json");
const SERVER_METADATA: &[u8] = include_bytes!("../data/server-metadata.json");
const NORMAL_USER: &[u8] = include_bytes!("../data/normal-user.json");
const PENDING_USER: &[u8] = include_bytes!("../data/pending-user.json");
const CLIENT: &[u8] = include_bytes!("../data/client.json");

#[derive(Clone)]
pub struct Issuer {
    datastore: Store,
    identity: DidIdentity,
}

impl Issuer {
    #[must_use]
    pub async fn new(issuer_id: &str) -> Self {
        let datastore = Store::open();
        datastore.put("owner", "ISSUER", issuer_id, ISSUER_METADATA).await.unwrap();
        datastore.put("owner", "SERVER", issuer_id, SERVER_METADATA).await.unwrap();
        datastore.put("owner", "SUBJECT", "normal_user", NORMAL_USER).await.unwrap();
        datastore.put("owner", "SUBJECT", "pending_user", PENDING_USER).await.unwrap();
        datastore.put("owner", "CLIENT", "http://localhost:8082", CLIENT).await.unwrap();

        Self {
            datastore,
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

impl Datastore for Issuer {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        self.datastore.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.datastore.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        self.datastore.delete(owner, partition, key).await
    }

    async fn get_all(
        &self, owner: &str, partition: &str,
    ) -> impl Iterator<Item = (String, Vec<u8>)> {
        self.datastore.get_all(owner, partition).await
    }
}
