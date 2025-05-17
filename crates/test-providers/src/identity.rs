use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, bail};
use credibil_identity::did::{self, Document, DocumentBuilder};
use credibil_identity::{Identity, Key};
use credibil_se::Algorithm;

use crate::keystore::{KeyUse, Keyring};

static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct DidIdentity {
    pub url: String,
    keyring: Keyring,
}

impl DidIdentity {
    // Generate a DID-based Identity.
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = Keyring::new(owner).await.expect("keyring created");
        keyring.add("signer", KeyUse::Signing).await.expect("signing key added");
        let verifying_key =
            keyring.verifying_key_jwk("signer").await.expect("JWK verifying key derived");

        // generate a did:web document
        let url = format!("https://credibil.io/{}", uuid::Uuid::new_v4());
        let did = did::web::default_did(&url).expect("should construct DID");

        let document = DocumentBuilder::new(&did)
            .add_verifying_key(&verifying_key, true)
            .expect("should add verifying key")
            .build();
        DID_STORE.lock().expect("should lock").insert(url.clone(), document);

        Self {
            url,
            keyring: keyring.clone(),
        }
    }

    pub async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.keyring.sign("signer", msg).await
    }

    pub async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key("signer").await
    }

    pub fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    pub async fn verification_method(&self) -> Result<Key> {
        let Identity::DidDocument(doc) = self.resolve(&self.url).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }

    pub async fn resolve(&self, url: &str) -> Result<Identity> {
        let key = url.trim_end_matches("/did.json");
        let store = DID_STORE.lock().expect("should lock");
        let Some(doc) = store.get(key).cloned() else {
            bail!("document not found");
        };
        Ok(Identity::DidDocument(doc))
    }
}
