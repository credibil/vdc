#![allow(unused)]

use std::str::FromStr;

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_jose::{Algorithm, Jws, Signer};
use credibil_vc::core::serde_cbor;
use credibil_vc::format::FormatProfile;
use credibil_vc::format::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use credibil_vc::format::sd_jwt::SdJwtClaims;
use credibil_vc::oid4vci::types::Credential;
use credibil_vc::oid4vp::types::{Claim, Queryable};
use serde_json::Value;

use crate::blockstore::Mockstore;
use crate::identity::DidIdentity;

#[derive(Clone)]
pub struct Wallet {
    identity: DidIdentity,
    // blockstore: Mockstore,
    store: Vec<Queryable>,
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            identity: DidIdentity::new(),
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

impl IdentityResolver for Wallet {
    async fn resolve(&self, url: &str) -> anyhow::Result<Identity> {
        self.identity.resolve(url).await
    }
}

impl Signer for Wallet {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.identity.verifying_key().await
    }

    fn algorithm(&self) -> Algorithm {
        self.identity.algorithm()
    }
}

impl SignerExt for Wallet {
    async fn verification_method(&self) -> Result<Key> {
        self.identity.verification_method().await
    }
}
