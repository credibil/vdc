//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::future::Future;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use credibil_did::DidResolver;
pub use credibil_infosec::Signer;
use serde::{Deserialize, Serialize};

use crate::BlockStore;
use crate::oid4vp::types::{Verifier, Wallet};

/// Verifier Provider trait.
pub trait Provider: Metadata + StateStore + Signer + DidResolver + Clone {}

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where T: Metadata + StateStore + Signer + DidResolver + Clone {}

/// The `Metadata` trait is used by implementers to provide `Verifier` (client)
/// metadata to the library.
pub trait Metadata: Send + Sync {
    /// Verifier (Client) metadata for the specified verifier.
    fn verifier(&self, verifier_id: &str) -> impl Future<Output = Result<Verifier>> + Send;

    /// Wallet (Authorization Server) metadata.
    fn wallet(&self, wallet_id: &str) -> impl Future<Output = Result<Wallet>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(&self, verifier: &Verifier) -> impl Future<Output = Result<Verifier>> + Send;
}

/// `StateStore` is used to store and retrieve server state between requests.
pub trait StateStore: Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data using the provided key.
    fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> impl Future<Output = Result<T>> + Send;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}

const WALLET: &str = "WALLET";
const VERIFIER: &str = "VERIFIER";
const STATE: &str = "STATE";

impl<T: BlockStore> Metadata for T {
    async fn verifier(&self, verifier_id: &str) -> Result<Verifier> {
        let Some(block) = BlockStore::get(self, "owner", VERIFIER, verifier_id).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn wallet(&self, wallet_id: &str) -> Result<Wallet> {
        let Some(block) = BlockStore::get(self, "owner", WALLET, wallet_id).await? else {
            return Err(anyhow!("could not find issuer"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn register(&self, verifier: &Verifier) -> Result<Verifier> {
        let mut verifier = verifier.clone();
        verifier.oauth.client_id = uuid::Uuid::new_v4().to_string();

        let block = serde_json::to_vec(&verifier)?;
        BlockStore::put(self, "owner", VERIFIER, &verifier.oauth.client_id, &block).await?;
        Ok(verifier)
    }
}

impl<T: BlockStore> StateStore for T {
    #[allow(unused)]
    async fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> Result<()> {
        let state = serde_json::to_vec(&state)?;
        BlockStore::delete(self, "owner", STATE, key).await?;
        BlockStore::put(self, "owner", STATE, key, &state).await
    }

    async fn get<S>(&self, key: &str) -> Result<S>
    where
        S: for<'a> Deserialize<'a>,
    {
        let Some(block) = BlockStore::get(self, "owner", STATE, key).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        BlockStore::delete(self, "owner", STATE, key).await
    }
}
