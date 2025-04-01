#![allow(unused)]

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
    did: String,
    signing_key: SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

enum DidMethod {
    Key,
    Web,
}

impl Keyring {
    pub fn new() -> Self {
        Self::new_web()
    }

    pub fn new_web() -> Self {
        Self::generate(DidMethod::Web)
    }

    pub fn new_key() -> Self {
        Self::generate(DidMethod::Key)
    }

    fn generate(method: DidMethod) -> Self {
        // generate key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let url = format!("https://credibil.io/{}", generate::uri_token());

        let mut keyring = Self {
            url: url.clone(),
            did: String::new(),
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

        keyring.did = document.id.clone();
        DID_STORE.lock().expect("should lock").insert(url, document);

        keyring
    }

    pub fn did(&self) -> String {
        self.did.clone()
    }

    pub fn public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.verifying_key.to_montgomery().to_bytes())
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
