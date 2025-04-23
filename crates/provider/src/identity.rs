#![allow(unused)]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::document::{CreateOptions, Document};
use credibil_did::{
    DidResolver, DocumentBuilder, KeyPurpose, PublicKeyFormat, SignerExt,
    VerificationMethodBuilder, VmKeyId,
};
use credibil_infosec::jose::jws::Key;
use credibil_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk};
use credibil_vc::core::generate;

use crate::blockstore::Mockstore;
use crate::keystore::{self, KeyUse, Keyring, SigningKey};

static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct Identity {
    pub url: String,
    keyring: Keyring,
}

impl Identity {
    // Generate a DID-based Identity.
    pub fn new() -> Self {
        // create a new keyring and add a signing key.
        let signing_key = SigningKey::new();

        // generate a did:web document
        let url = format!("https://credibil.io/{}", generate::uri_token());
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;
        // let document = DidWeb::create(&url, &keyring, options).expect("should create");

        let did = credibil_did::web::default_did(&url).expect("should construct DID");

        let vk = PublicKeyJwk::from_bytes(&signing_key.verifying_key())
            .expect("should convert verifying key to JWK");
        
        let mut keyring = Keyring::new();
        keyring.add("signer", signing_key);

        let document = DocumentBuilder::new(&did)
            .add_verifying_key(&vk, true)
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
        let doc = self.resolve(&self.url).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }

    pub async fn resolve(&self, url: &str) -> Result<Document> {
        let key = url.trim_end_matches("/did.json");
        let store = DID_STORE.lock().expect("should lock");
        store.get(key).cloned().ok_or_else(|| anyhow!("document not found"))
    }
}

// impl DidOperator for Keyring {
//     fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
//         let KeyUse::Signing(signer) = self.get("signer") else {
//             panic!("signer not found");
//         };

//         match purpose {
//             KeyPurpose::VerificationMethod => Some(PublicKeyJwk {
//                 kty: KeyType::Okp,
//                 crv: Curve::Ed25519,
//                 x: Base64UrlUnpadded::encode_string(&signer.verifying_key()),
//                 ..PublicKeyJwk::default()
//             }),
//             _ => panic!("unsupported purpose"),
//         }
//     }
// }
