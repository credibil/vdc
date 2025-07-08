//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::future::Future;

use anyhow::Result;
pub use credibil_binding::{Resolver, Signature};
pub use credibil_core::state::StateStore;
pub use credibil_status::StatusToken;

use crate::types::VerifierMetadata;

/// Verifier Provider trait.
pub trait Provider: Metadata + StateStore + Signature + Resolver + StatusToken + Clone {}

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
