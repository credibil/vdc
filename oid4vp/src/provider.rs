//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::future::Future;

use anyhow::{Result, anyhow};
use credibil_core::datastore::Datastore;
pub use credibil_core::state::StateStore;
pub use credibil_proof::{Resolver, Signature};
pub use credibil_status::StatusToken;

use crate::types::VerifierMetadata;

/// Verifier Provider trait.
pub trait Provider: Metadata + StateStore + Signature + Resolver + StatusToken + Clone {}

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where T: Metadata + StateStore + Signature + Resolver + StatusToken + Clone {}

/// The `Metadata` trait is used by implementers to provide `Verifier` (client)
/// metadata to the library.
pub trait Metadata: Send + Sync {
    /// Verifier (Client) metadata for the specified verifier.
    fn verifier(&self, owner: &str) -> impl Future<Output = Result<VerifierMetadata>> + Send;

    // /// Wallet (Authorization Server) metadata.
    // fn wallet(&self, wallet_id: &str) -> impl Future<Output = Result<Wallet>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(
        &self, owner: &str, verifier: &VerifierMetadata,
    ) -> impl Future<Output = Result<VerifierMetadata>> + Send;
}

const METADATA: &str = "metadata";
const VERIFIER: &str = "VERIFIER";

impl<T: Datastore> Metadata for T {
    async fn verifier(&self, owner: &str) -> Result<VerifierMetadata> {
        let Some(data) = Datastore::get(self, owner, METADATA, VERIFIER).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn register(&self, owner: &str, verifier: &VerifierMetadata) -> Result<VerifierMetadata> {
        let mut verifier = verifier.clone();
        verifier.oauth.client_id = uuid::Uuid::new_v4().to_string();

        let data = serde_json::to_vec(&verifier)?;
        Datastore::put(self, owner, VERIFIER, &verifier.oauth.client_id, &data).await?;
        Ok(verifier)
    }
}
