//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::future::Future;

use anyhow::Result;
use chrono::{DateTime, Utc};
use credibil_did::{DidResolver, SignerExt};
use serde::{Deserialize, Serialize};

use crate::oid4vp::types::{Verifier, Wallet};

/// Verifier Provider trait.
pub trait Provider: Metadata + StateStore + SignerExt + DidResolver + Clone {}

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
