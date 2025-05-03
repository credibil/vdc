//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::future::Future;

use anyhow::{Result, anyhow};
use credibil_identity::IdentityResolver;
pub use credibil_identity::SignerExt;

use crate::blockstore::BlockStore;
use crate::oid4vp::verifier::{Verifier, Wallet};
pub use crate::state::StateStore;
use crate::token_status::StatusToken;

/// Verifier Provider trait.
pub trait Provider:
    Metadata + StateStore + SignerExt + IdentityResolver + StatusToken + Clone
{
}

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where
    T: Metadata + StateStore + SignerExt + IdentityResolver + StatusToken + Clone
{
}

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

const WALLET: &str = "WALLET";
const VERIFIER: &str = "VERIFIER";

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
