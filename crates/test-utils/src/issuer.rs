use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_ecc::{Algorithm, Entry, Keyring, Signer};
use credibil_proof::ecc::Curve::Ed25519;
use credibil_proof::{Resolver, Signature, VerifyBy};

use crate::datastore::Store;
use crate::identity::Identity;
use crate::vault::KeyVault as Vault;

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
    signer: Entry,
    identity: Identity,
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

        let signer =
            Keyring::generate(&Vault, issuer, "signing", Ed25519).await.expect("should generate");
        let identity = Identity::new(issuer, &signer).await;

        Self { signer, identity }
    }
}

impl Resolver for Issuer {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        self.identity.resolve(url).await
    }
}

impl Signer for Issuer {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signer.sign(msg).await)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
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
