use anyhow::Result;
use credibil_core::datastore::Datastore;
use credibil_ecc::Curve::Ed25519;
use credibil_ecc::{Algorithm, Entry, Keyring, Signer};
use credibil_identity::{Identity, IdentityResolver, Signature, VerifyBy};

use crate::datastore::Store;
use crate::identity::DidIdentity;
use crate::vault::KeyVault as Vault;

const VERIFIER_METADATA: &[u8] = include_bytes!("../data/verifier-metadata.json");
const METADATA: &str = "METADATA";
const VERIFIER: &str = "VERIFIER";

#[derive(Clone)]
pub struct Verifier {
    signer: Entry,
    identity: DidIdentity,
}

impl Verifier {
    #[must_use]
    pub async fn new(verifier: &str) -> Self {
        let datastore = Store::open();
        datastore.put(verifier, METADATA, VERIFIER, VERIFIER_METADATA).await.unwrap();

        let signer =
            Keyring::generate(&Vault, verifier, "signing", Ed25519).await.expect("should generate");
        let identity = DidIdentity::new(verifier, &signer).await;

        Self { signer, identity }
    }
}

impl IdentityResolver for Verifier {
    async fn resolve(&self, url: &str) -> Result<Identity> {
        self.identity.resolve(url).await
    }
}

impl Signer for Verifier {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.signer.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.signer.algorithm().await
    }
}

impl Signature for Verifier {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.signer.verification_method().await
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
