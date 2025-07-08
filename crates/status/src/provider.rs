//! # Status Store Provider

use std::future::Future;

use anyhow::Result;
// use credibil_core::datastore::Datastore;

/// Verifier Provider trait.
pub trait Provider: StatusStore + Clone {}

pub const STATUSTOKEN: &str = "statustoken";

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
