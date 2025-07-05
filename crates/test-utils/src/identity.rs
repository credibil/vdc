use std::thread;

use anyhow::Result;
use credibil_proof::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_proof::ecc::Curve::Ed25519;
use credibil_proof::ecc::{Entry, Keyring, Signer};
use credibil_proof::jose::PublicKeyJwk;
use credibil_proof::{Client, DocumentRequest, VerifyBy};

use crate::store::Store;

#[derive(Clone)]
pub struct Identity {
    pub signer: Entry,
    owner: String,
}

impl Identity {
    pub async fn new(owner: &str) -> Self {
        let signer =
            Keyring::generate(&Store, owner, "signing", Ed25519).await.expect("should generate");
        let key = signer.verifying_key().await.expect("should get key");
        let jwk = PublicKeyJwk::from_bytes(&key.to_bytes()).expect("should convert");

        // generate a did:web document
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        credibil_proof::create(owner, builder, &Store).await.expect("should create");

        Self {
            signer,
            owner: owner.to_string(),
        }
    }

    pub async fn document(&self, url: &str) -> Result<Document> {
        // not in a tokio runtime == running in a test
        if thread::current().name() != Some("tokio-runtime-worker") {
            let request = DocumentRequest { url: url.to_string() };
            let client = Client::new(Store);
            return client.request(request).owner(&self.owner).await.map(|r| r.0.clone());
        }

        // in a tokio runtime: assume web server is running
        let resp = reqwest::get(url.replace("https", "http")).await?;
        Ok(resp.json::<Document>().await?)
    }

    pub async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let doc = self.document(url).await?;
        serde_json::to_vec(&doc).map_err(|e| e.into())
    }

    pub async fn verification_method(&self) -> Result<VerifyBy> {
        let doc = self.document(&format!("{}/.well-known/did.json", self.owner)).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }
}
