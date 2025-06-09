use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_ecc::{Algorithm, Signer};
use credibil_identity::did::Document;
use credibil_identity::{Identity, IdentityResolver, Signature, VerifyBy};

use crate::datastore::Store;
use crate::identity::DidIdentity;

const ISSUER_METADATA: &[u8] = include_bytes!("../data/issuer-metadata.json");
const SERVER_METADATA: &[u8] = include_bytes!("../data/server-metadata.json");
const NORMAL_USER: &[u8] = include_bytes!("../data/normal-user.json");
const PENDING_USER: &[u8] = include_bytes!("../data/pending-user.json");
const CLIENT_METADATA: &[u8] = include_bytes!("../data/client-metadata.json");
const METADATA: &str = "METADATA";
const ISSUER: &str = "ISSUER";
const SERVER: &str = "SERVER";
const SUBJECT: &str = "SUBJECT";

#[derive(Clone)]
pub struct Issuer {
    // datastore: Store,
    identity: DidIdentity,
}

impl Issuer {
    #[must_use]
    pub async fn new(issuer: &str) -> Self {
        let datastore = Store;
        datastore.put(issuer, METADATA, ISSUER, ISSUER_METADATA).await.unwrap();
        datastore.put(issuer, METADATA, SERVER, SERVER_METADATA).await.unwrap();
        datastore.put(issuer, METADATA, "http://localhost:8082", CLIENT_METADATA).await.unwrap();
        datastore.put(issuer, SUBJECT, "normal_user", NORMAL_USER).await.unwrap();
        datastore.put(issuer, SUBJECT, "pending_user", PENDING_USER).await.unwrap();

        Self {
            // datastore,
            identity: DidIdentity::new(issuer).await,
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

impl Signature for Issuer {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.identity.verification_method().await
    }
}

impl Datastore for Issuer {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        Store.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Store.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        Store.delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Store.get_all(owner, partition).await
    }
}
