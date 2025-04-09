//! An API for the issuance and verification of Verifiable Credentials based on
//! the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
//! and [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! specifications.
//!
//! # Feature Flags
//!
//! There is no default feature. The following features are available:
//!
//! * `issuer` - Enables the issuer API.
//! * `verifier` - Enables the verifier API.

#[cfg(feature = "issuer")]
pub mod oid4vci;

#[cfg(feature = "verifier")]
pub mod oid4vp;

pub mod core;
pub mod dif_exch;
pub mod mso_mdoc;
pub mod oauth;
pub mod sd_jwt;
pub mod status;
pub mod w3c_vc;

/// Re-export DID resolution
pub mod did {
    pub use credibil_did::*;
}

/// Re-export cryptographic types and functions
pub mod infosec {
    pub use credibil_infosec::*;
}

/// Re-export basic types
pub use crate::core::{Kind, OneMany, urlencode};

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Sized + Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(
        &self, owner: &str, partition: &str, cid: &str, data: &[u8],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(
        &self, owner: &str, partition: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}
