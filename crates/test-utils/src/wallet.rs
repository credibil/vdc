use anyhow::Result;
use credibil_identity::{Algorithm, Identity, IdentityResolver, Key, Signer, SignerExt};
use credibil_vdc::Queryable;

use crate::identity::DidIdentity;

#[derive(Clone)]
pub struct Wallet {
    identity: DidIdentity,
    // blockstore: Mockstore,
    store: Vec<Queryable>,
}

impl Wallet {
    pub async fn new(owner: &str) -> Self {
        Self {
            identity: DidIdentity::new(owner).await,
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

    async fn algorithm(&self) -> Result<Algorithm> {
        self.identity.algorithm().await
    }
}

impl SignerExt for Wallet {
    async fn verification_method(&self) -> Result<Key> {
        self.identity.verification_method().await
    }
}
