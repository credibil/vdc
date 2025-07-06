use std::thread;

use anyhow::Result;
use credibil_proof::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_proof::ecc::Curve::Ed25519;
use credibil_proof::ecc::{Entry, Keyring, Signer};
use credibil_proof::jose::PublicKeyJwk;
use credibil_proof::{Client, DocumentRequest, VerifyBy};

use crate::store::Store;

#[derive(Clone)]
pub struct Identity<'a> {
    pub owner: &'a str,
    signer: Entry,
}

impl<'a> Identity<'a> {
    /// Create a new identity for the specified owner.
    ///
    /// # Errors
    /// Returns an error if the key generation fails or if the JWK conversion fails.
    pub async fn new(owner: &'a str) -> Result<Self> {
        let signer = if let Ok(entry) = Keyring::entry(&Store, owner, "signing").await {
            entry
        } else {
            Keyring::generate(&Store, owner, "signing", Ed25519).await?
        };

        // create a new keyring and add a signing key.
        let key = signer.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&key.to_bytes())?;

        // generate a did:web document
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        credibil_proof::create(owner, builder, &Store).await?;

        Ok(Self { owner, signer })
    }

    /// Returns the signer's key entry.
    ///
    /// # Errors
    /// Returns an error if the key entry cannot be found.
    #[must_use]
    pub const fn signer(&self) -> &Entry {
        &self.signer
    }

    pub async fn verification_method(&self) -> Result<VerifyBy> {
        let request = DocumentRequest {
            url: format!("{}/.well-known/did.json", self.owner),
        };
        let document =
            Client::new(Store).request(request).owner(self.owner).await.map(|r| r.0.clone())?;
        let vm = &document.verification_method.as_ref().unwrap()[0];
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }

    pub async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let doc = self.document(url).await?;
        serde_json::to_vec(&doc).map_err(|e| e.into())
    }

    async fn document(&self, url: &str) -> Result<Document> {
        // not in a tokio runtime == running in a test
        if thread::current().name() != Some("tokio-runtime-worker") {
            let request = DocumentRequest { url: url.to_string() };
            let client = Client::new(Store);
            return client.request(request).owner(self.owner).await.map(|r| r.0.clone());
        }

        // in a tokio runtime: assume web server is running
        let resp = reqwest::get(url.replace("https", "http")).await?;
        Ok(resp.json::<Document>().await?)
    }
}
