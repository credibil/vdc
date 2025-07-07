use std::thread;

use anyhow::{Result, anyhow};
use credibil_proof::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_proof::ecc::Curve::Ed25519;
use credibil_proof::ecc::{Entry, Keyring, Signer};
use credibil_proof::jose::PublicKeyJwk;
use credibil_proof::{Client, DocumentRequest, Proof, VerifyBy};

use crate::resources::KeyVault;
use crate::resources::store::Datastore;

#[derive(Clone)]
pub struct Identity<'a> {
    pub owner: &'a str,
    signer: Entry,
}

impl<'a> Identity<'a> {
    /// Create a new identity for the specified owner.
    pub async fn new(owner: &'a str) -> Result<Self> {
        // fetch (or generate) the signing key
        let signer = match Keyring::entry(&KeyVault, owner, "signing").await {
            Ok(entry) => entry,
            Err(_) => Keyring::generate(&KeyVault, owner, "signing", Ed25519).await?,
        };

        // generate a did:web document
        let verifying_key = signer.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        credibil_proof::create(owner, builder, &Datastore).await?;

        Ok(Self { owner, signer })
    }

    #[must_use]
    pub const fn signer(&self) -> &Entry {
        &self.signer
    }

    pub async fn verification_method(&self) -> Result<VerifyBy> {
        let request = DocumentRequest {
            url: format!("{}/.well-known/did.json", self.owner),
        };
        let document =
            Client::new(Datastore).request(request).owner(self.owner).await.map(|r| r.0.clone())?;
        let Some(vm) = &document.verification_method.as_ref().and_then(|v| v.first()) else {
            return Err(anyhow!("no verification method found"));
        };
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }

    pub async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let document = if thread::current().name() == Some("tokio-runtime-worker") {
            // in a tokio runtime (-> running in a web server)
            reqwest::get(url.replace("https", "http")).await?.json::<Document>().await?
        } else {
            // not in a tokio runtime (-> running in a test)
            let request = DocumentRequest { url: url.to_string() };
            Client::new(Datastore).request(request).owner(self.owner).await.map(|r| r.0.clone())?
        };
        Ok(serde_json::to_vec(&document)?)
    }
}

impl Proof for Datastore {
    async fn put(&self, owner: &str, document: &Document) -> Result<()> {
        let data = serde_json::to_vec(document)?;
        self.put(owner, "proof", &document.id, &data).await
    }

    async fn get(&self, owner: &str, key: &str) -> Result<Option<Document>> {
        let Some(data) = self.get(owner, "proof", key).await? else {
            return Err(anyhow!("could not find proof"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn delete(&self, owner: &str, key: &str) -> Result<()> {
        self.delete(owner, "proof", key).await
    }

    async fn get_all(&self, owner: &str) -> Result<Vec<(String, Document)>> {
        self.get_all(owner, "proof")
            .await?
            .iter()
            .map(|(k, v)| Ok((k.to_string(), serde_json::from_slice(v)?)))
            .collect()
    }
}
