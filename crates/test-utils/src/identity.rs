use anyhow::{Result, anyhow};
use credibil_core::datastore::Datastore;
use credibil_identity::did::{self, Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_identity::ecc::Curve::Ed25519;
use credibil_identity::ecc::{Algorithm, Keyring, Signer};
use credibil_identity::jose::PublicKeyJwk;
use credibil_identity::{Identity, IdentityResolver, Signature, VerifyBy};

use crate::datastore::Store;
use crate::vault::KeyVault as Vault;

#[derive(Clone)]
pub struct DidIdentity {
    pub owner: String,
}

impl DidIdentity {
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let signer =
            Keyring::generate(&Vault, owner, "signing", Ed25519).await.expect("should generate");
        let key_bytes = signer.verifying_key().await.expect("should get key");
        let jwk = PublicKeyJwk::from_bytes(&key_bytes).expect("should convert");

        // generate a did:web document
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);

        let identity = Self {
            owner: owner.to_string(),
        };
        did::web::create(owner, builder, &identity).await.expect("should create");

        identity
    }

    pub async fn document(&self, url: &str) -> Result<Document> {
        did::web::document(url, self).await
    }
}

impl IdentityResolver for DidIdentity {
    async fn resolve(&self, url: &str) -> Result<Identity> {
        let doc = match self.document(url).await {
            Ok(doc) => doc,
            Err(_) => {
                let url = url.replace("https", "http");
                let resp = reqwest::get(url).await.map_err(|e| anyhow!("fetching: {e}"))?;
                resp.json::<Document>().await.map_err(|e| anyhow!("{e}"))?
            }
        };
        Ok(Identity::DidDocument(doc))
    }
}

impl Signer for DidIdentity {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let signer = Keyring::entry(&Vault, &self.owner, "signing").await?;
        Ok(signer.sign(msg).await)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let signer = Keyring::entry(&Vault, &self.owner, "signing").await?;
        signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for DidIdentity {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let doc = self.document(&self.owner).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }
}

impl Datastore for DidIdentity {
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
