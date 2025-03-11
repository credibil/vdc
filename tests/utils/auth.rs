use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::document::{CreateOptions, Document};
use credibil_did::{DidKey, DidOperator, DidResolver, DidWeb, KeyPurpose};
use credibil_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk, Signer};
use credibil_vc::core::generate;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;

static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone, Debug)]
pub struct Keyring {
    url: String,
    signing_key: SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    // public_key: x25519_dalek::PublicKey,
}

pub enum DidMethod {
    Key,
    Web,
}

impl Keyring {
    pub fn did_web() -> Self {
        Self::new(DidMethod::Web)
    }

    pub fn did_key() -> Self {
        Self::new(DidMethod::Web)
    }

    pub fn new(method: DidMethod) -> Self {
        // generate key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        // let public_key = x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());

        let url = format!("https://credibil.io/{}", generate::uri_token());

        let keyring = Self {
            url: url.clone(),
            signing_key,
            verifying_key,
        };

        // generate did:web document
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let document = match method {
            DidMethod::Key => DidKey::create(&keyring, options).expect("should create"),
            DidMethod::Web => DidWeb::create(&url, &keyring, options).expect("should create"),
        };

        DID_STORE.lock().expect("should lock").insert(url, document);

        keyring
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    async fn verification_method(&self) -> Result<String> {
        let store = DID_STORE.lock().expect("should lock");
        let doc = store.get(&self.url).unwrap();
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(vm.id.clone())
    }
}

impl DidOperator for Keyring {
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
        match purpose {
            KeyPurpose::VerificationMethod => Some(PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(self.verifying_key.as_bytes()),
                ..PublicKeyJwk::default()
            }),
            _ => panic!("unsupported purpose"),
        }
    }
}

impl DidResolver for Keyring {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        let key = url.strip_suffix("/did.json").unwrap();
        let store = DID_STORE.lock().expect("should lock");
        store.get(key).cloned().ok_or_else(|| anyhow!("document not found"))
    }
}
