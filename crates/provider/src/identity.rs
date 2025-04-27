#![allow(unused)]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_identity::{Key, Identity, IdentityResolver, SignerExt};
use credibil_identity::did::{
    self, Document, DocumentBuilder, KeyPurpose, PublicKeyFormat,
    VerificationMethodBuilder, VmKeyId,
};
use credibil_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk};
use credibil_vc::core::generate;
use credibil_vc::format::w3c::verify;

use crate::blockstore::Mockstore;
use crate::keystore::{self, KeyUse, Keyring, SigningKey};

static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct DidIdentity {
    pub url: String,
    keyring: Keyring,
}

impl DidIdentity {
    // Generate a DID-based Identity.
    pub fn new() -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = Keyring::new();
        let signing_key = SigningKey::new();

        let verifying_key = PublicKeyJwk::from_bytes(&signing_key.verifying_key())
            .expect("should convert verifying key to JWK");
        keyring.add("signer", signing_key);

        // generate a did:web document
        let url = format!("https://credibil.io/{}", generate::uri_token());
        let did = did::web::default_did(&url).expect("should construct DID");

        let vk = PublicKeyJwk::from_bytes(&signing_key.verifying_key())
            .expect("should convert verifying key to JWK");
        
        let mut keyring = Keyring::new();
        keyring.add("signer", signing_key);

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
        let KeyUse::Signing(signer) = self.keyring.get("signer") else {
            return Err(anyhow!("signer not found"));
        };
        Ok(signer.sign(msg))
    }

    pub async fn verifying_key(&self) -> Result<Vec<u8>> {
        let KeyUse::Signing(signer) = self.keyring.get("signer") else {
            return Err(anyhow!("signer not found"));
        };
        Ok(signer.verifying_key())
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
