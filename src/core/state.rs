//! # State
//!
//! State is used to persist request information between steps in a flow.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::blockstore::BlockStore;

const STATE: &str = "STATE";

/// The `StateStore` trait is implemented to provide concrete storage and
/// retrieval of retrieve server state between requests.
pub trait StateStore: Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data using the provided key.
    fn get<T>(&self, key: &str) -> impl Future<Output = Result<T>> + Send
    where
        T: for<'de> Deserialize<'de>;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
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
        S: for<'de> Deserialize<'de>,
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
