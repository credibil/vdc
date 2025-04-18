#![allow(unused)]

use std::str::FromStr;

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::{DidResolver, Document};
use credibil_infosec::cose::cbor;
use credibil_infosec::{Algorithm, Jws, Signer};
use credibil_vc::format::FormatProfile;
use credibil_vc::format::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use credibil_vc::format::sd_jwt::SdJwtClaims;
use credibil_vc::oid4vci::types::Credential;
use credibil_vc::oid4vp::types::{Claim, Queryable};
use serde_json::Value;

use crate::blockstore::Mockstore;
use crate::keystore::Keyring;

#[derive(Clone, Debug)]
pub struct Wallet {
    keyring: Keyring,
    // blockstore: Mockstore,
    store: Vec<Queryable>,
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            // blockstore: Mockstore::new(),
            store: Vec::new(),
        }
    }

    // Add a credential to the store.
    pub fn add(&mut self, queryable: Queryable) {
        self.store.push(queryable);
    }

    pub fn fetch(&self) -> &[Queryable] {
        &self.store
    }
}

impl DidResolver for Wallet {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        self.keyring.resolve(url).await
    }
}

impl Signer for Wallet {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.keyring.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key().await
    }

    fn algorithm(&self) -> Algorithm {
        self.keyring.algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        self.keyring.verification_method().await
    }
}
