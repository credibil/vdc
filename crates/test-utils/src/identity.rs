use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, bail};
use credibil_identity::Identity::DidDocument;
use credibil_identity::did::{self, Document, DocumentBuilder};
use credibil_identity::{IdentityResolver, Key, SignerExt};
use credibil_jose::PublicKeyJwk;
use credibil_se::{Algorithm, Curve, Signer};

static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct DidIdentity {
    pub url: String,
    keyring: test_kms::Keyring,
}

impl DidIdentity {
    // Generate a DID-based Identity.
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = test_kms::Keyring::new(owner).await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "signer").await.expect("keyring created");
        let key_bytes = keyring.verifying_key("signer").await.expect("key bytes");
        let verifying_key = PublicKeyJwk::from_bytes(&key_bytes).expect("verifying key");

        // generate a did:web document
        let url = format!("https://credibil.io/{}", uuid::Uuid::new_v4());
        let did = did::web::default_did(&url).expect("should construct DID");

        let document = DocumentBuilder::new(&did)
            .add_verifying_key(&verifying_key, true)
            .expect("should add verifying key")
            .build();
        DID_STORE.lock().expect("should lock").insert(url.clone(), document);

        Self { url, keyring }
    }
}

impl IdentityResolver for DidIdentity {
    async fn resolve(&self, url: &str) -> anyhow::Result<credibil_identity::Identity> {
        let key = url.trim_end_matches("/did.json");
        let store = DID_STORE.lock().expect("should lock");
        let Some(doc) = store.get(key).cloned() else {
            bail!("document not found");
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
        let store = DID_STORE.lock().expect("should lock");
        let Some(doc) = store.get(&self.url).cloned() else {
            bail!("document not found");
        };
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }
}
