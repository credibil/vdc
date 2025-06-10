use std::thread;

use anyhow::Result;
use credibil_identity::did::{self, Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_identity::ecc::{Entry, Signer};
use credibil_identity::jose::PublicKeyJwk;
use credibil_identity::{Identity, VerifyBy};

use crate::datastore::Store;

#[derive(Clone)]
pub struct DidIdentity {
    pub owner: String,
}

impl DidIdentity {
    pub async fn new(owner: &str, signer: &Entry) -> Self {
        let key_bytes = signer.verifying_key().await.expect("should get key");
        let jwk = PublicKeyJwk::from_bytes(&key_bytes).expect("should convert");

        // generate a did:web document
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        did::web::create(owner, builder, &Store).await.expect("should create");

        Self {
            owner: owner.to_string(),
        }
    }

    pub async fn document(&self, url: &str) -> Result<Document> {
        // not in a tokio runtime == running in a test
        if thread::current().name() != Some("tokio-runtime-worker") {
            let request = did::DocumentRequest { url: url.to_string() };
            return did::handle("owner", request, &Store).await.map(|r| r.0.clone());
        }

        // in a tokio runtime: assume web server is running
        let resp = reqwest::get(url.replace("https", "http")).await?;
        Ok(resp.json::<Document>().await?)
    }

    pub async fn resolve(&self, url: &str) -> Result<Identity> {
        let doc = self.document(url).await?;
        Ok(Identity::DidDocument(doc))
    }

    pub async fn verification_method(&self) -> Result<VerifyBy> {
        let doc = self.document(&format!("{}/.well-known/did.json", self.owner)).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }
}
