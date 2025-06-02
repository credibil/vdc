use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_identity::did::Document;
use credibil_identity::se::{Algorithm, PublicKey, Receiver, SharedSecret, Signer};
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};

use crate::datastore::Store;
use crate::identity::DidIdentity;

const VERIFIER_METADATA: &[u8] = include_bytes!("../data/verifier-metadata.json");

#[derive(Clone)]
pub struct Verifier {
    identity: DidIdentity,
    datastore: Store,
}

impl Verifier {
    #[must_use]
    pub async fn new(verifier_id: &str) -> Self {
        let datastore = Store::open();
        datastore.put("owner", "VERIFIER", verifier_id, VERIFIER_METADATA).await.unwrap();

        Self {
            datastore,
            identity: DidIdentity::new(verifier_id).await,
        }
    }

    pub async fn did(&self) -> Result<Document> {
        self.identity.document(&self.identity.owner).await
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

impl Datastore for Verifier {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        self.datastore.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.datastore.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        self.datastore.delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        self.datastore.get_all(owner, partition).await
    }
}
