use anyhow::{Result, anyhow, bail};
use credibil_identity::Identity::DidDocument;
use credibil_identity::did::{self, Document, DocumentBuilder};
use credibil_identity::jose::PublicKeyJwk;
use credibil_identity::se::{Algorithm, Curve, Signer};
use credibil_identity::{IdentityResolver, Key, SignerExt};
use test_kms::Keyring;

use crate::blockstore::Mockstore;

#[derive(Clone)]
pub struct DidIdentity {
    pub owner: String,
    keyring: Keyring,
}

impl DidIdentity {
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = Keyring::new(owner).await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "signer").await.expect("keyring created");
        let key_bytes = keyring.verifying_key("signer").await.expect("key bytes");
        let verifying_key = PublicKeyJwk::from_bytes(&key_bytes).expect("verifying key");

        // generate a did:web document
        let did = did::web::default_did(owner).expect("should create DID");
        let document = DocumentBuilder::new(&did)
            .add_verifying_key(&verifying_key, true)
            .expect("should add verifying key")
            .build();
        let doc_bytes = serde_json::to_vec(&document).expect("should serialize");

        // save to global blockstore
        Mockstore::open().put(owner, "DID", owner, &doc_bytes).await.expect("should put");

        Self {
            owner: owner.to_string(),
            keyring,
        }
    }

    pub async fn document(&self, url: &str) -> Result<Document> {
        let url = url.trim_end_matches("/did.json");
        let owner = url;
        let Some(doc_bytes) = Mockstore::open().get(owner, "DID", url).await? else {
            bail!("document not found");
        };
        serde_json::from_slice(&doc_bytes).map_err(Into::into)
    }
}

impl IdentityResolver for DidIdentity {
    async fn resolve(&self, url: &str) -> Result<credibil_identity::Identity> {
        let doc = match self.document(url).await {
            Ok(doc) => doc,
            Err(_) => {
                let url = url.replace("https", "http");
                let resp = reqwest::get(url).await.map_err(|e| anyhow!("{e}"))?;
                resp.json::<Document>().await.map_err(|e| anyhow!("{e}"))?
            }
        };

        Ok(DidDocument(doc))
    }
}

impl Signer for DidIdentity {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.keyring.sign("signer", msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key("signer").await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl SignerExt for DidIdentity {
    async fn verification_method(&self) -> Result<Key> {
        let doc = self.document(&self.owner).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }
}
