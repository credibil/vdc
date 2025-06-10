use anyhow::{Result, anyhow};
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
        let request = did::DocumentRequest { url: url.to_string() };
        let doc = match did::handle("owner", request, &Store).await {
            Ok(response) => response.0.clone(),
            Err(_) => {
                let url = url.replace("https", "http");
                let resp = reqwest::get(url).await.map_err(|e| anyhow!("fetching: {e}"))?;
                resp.json::<Document>().await.map_err(|e| anyhow!("{e}"))?
            }
        };

        Ok(doc)
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
