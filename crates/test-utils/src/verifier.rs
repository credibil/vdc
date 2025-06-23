use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_ecc::{Algorithm, PublicKey, Signer};
use credibil_proof::{Resolver, Signature, VerifyBy};

use crate::identity::Identity;
use crate::store::Store;

const VERIFIER_METADATA: &[u8] = include_bytes!("../data/verifier-metadata.json");
const METADATA: &str = "METADATA";
const VERIFIER: &str = "VERIFIER";

#[derive(Clone)]
pub struct Verifier {
    identity: Identity,
}

impl Verifier {
    #[must_use]
    pub async fn new(verifier: &str) -> Self {
        let datastore = Store;
        datastore.put(verifier, METADATA, VERIFIER, VERIFIER_METADATA).await.unwrap();

        let identity = Identity::new(verifier).await;

        Self { identity }
    }
}

impl Resolver for Verifier {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        self.identity.resolve(url).await
    }
}

impl Signer for Verifier {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.signer.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.identity.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.identity.signer.algorithm().await
    }
}

impl Signature for Verifier {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.identity.verification_method().await
    }
}

impl Datastore for Verifier {
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
