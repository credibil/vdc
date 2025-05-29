//! # Status Store Provider

use std::future::Future;

use anyhow::Result;
use credibil_core::datastore::Datastore;

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

/// `StatusToken` is used to store and retrieve Status Tokens.
pub trait StatusToken: Send + Sync {
    /// Fetch the specified status list.
    fn fetch(&self, uri: &str) -> impl Future<Output = Result<String>> + Send;
}

impl<T: Datastore> StatusStore for T {
    #[allow(unused)]
    async fn put(&self, uri: &str, token: &str) -> Result<()> {
        let data = serde_json::to_vec(token)?;
        Datastore::delete(self, "owner", STATUSTOKEN, uri).await?;
        Datastore::put(self, "owner", STATUSTOKEN, uri, data).await
    }

    async fn get(&self, uri: &str) -> Result<Option<String>> {
        let Some(block) = Datastore::get(self, "owner", STATUSTOKEN, uri).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&block)?))
    }
}

impl<T: Datastore> StatusToken for T {
    async fn fetch(&self, uri: &str) -> Result<String> {
        let Some(block) = Datastore::get(self, "owner", STATUSTOKEN, uri).await? else {
            return Err(anyhow::anyhow!("could not find status token"));
        };
        Ok(serde_json::from_slice(&block)?)
    }
}
