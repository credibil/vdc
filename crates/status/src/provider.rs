//! # Status Store Provider

use std::future::Future;
use std::str::FromStr;

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
    fn put(&self, owner: &str, id: &str, token: &str) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve the specified Status Token.
    fn get(&self, owner: &str, id: &str) -> impl Future<Output = Result<Option<String>>> + Send;
}

/// `StatusToken` is used to store and retrieve Status Tokens.
pub trait StatusToken: Send + Sync {
    /// Fetch the specified status list.
    fn fetch(&self, uri: &str) -> impl Future<Output = Result<String>> + Send;
}

impl<T: Datastore> StatusStore for T {
    #[allow(unused)]
    async fn put(&self, owner: &str, id: &str, token: &str) -> Result<()> {
        let data = serde_json::to_vec(token)?;
        Datastore::put(self, owner, STATUSTOKEN, id, &data).await
    }

    async fn get(&self, owner: &str, id: &str) -> Result<Option<String>> {
        let Some(data) = Datastore::get(self, owner, STATUSTOKEN, id).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&data)?))
    }
}

impl<T: Datastore> StatusToken for T {
    async fn fetch(&self, uri: &str) -> Result<String> {
        let http_uri =
            http::Uri::from_str(uri).map_err(|_| anyhow::anyhow!("invalid status token URI"))?;
        let Some(scheme) = http_uri.scheme_str() else {
            return Err(anyhow::anyhow!("invalid scheme"));
        };
        let Some(authority) = http_uri.authority() else {
            return Err(anyhow::anyhow!("invalid  authority"));
        };
        let owner = format!("{scheme}://{authority}");

        let Some(data) = Datastore::get(self, &owner, STATUSTOKEN, uri).await? else {
            return Err(anyhow::anyhow!("could not find status token"));
        };
        Ok(serde_json::from_slice(&data)?)
    }
}
