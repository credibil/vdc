//! # Status Store Provider

use std::future::Future;

use anyhow::Result;
use credibil_core::blockstore::BlockStore;

/// Verifier Provider trait.
pub trait Provider: StatusStore + Clone {}

const STATUSTOKEN: &str = "STATUSTOKEN";

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where T: StatusStore + Clone {}

/// `StatusStore` is used to store and retrieve Status Tokens.
pub trait StatusStore: Send + Sync {
    /// Store the Status Token using the provided key.
    fn put(&self, uri: &str, token: &str) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve the specified Status Token.
    fn get(&self, uri: &str) -> impl Future<Output = Result<Option<String>>> + Send;
}

impl<T: BlockStore> StatusStore for T {
    #[allow(unused)]
    async fn put(&self, uri: &str, token: &str) -> Result<()> {
        let data = serde_json::to_vec(token)?;
        BlockStore::delete(self, "owner", STATUSTOKEN, uri).await?;
        BlockStore::put(self, "owner", STATUSTOKEN, uri, &data).await
    }

    async fn get(&self, uri: &str) -> Result<Option<String>> {
        let Some(block) = BlockStore::get(self, "owner", STATUSTOKEN, uri).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&block)?))
    }
}
