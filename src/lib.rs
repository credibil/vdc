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

pub mod oauth;
pub mod vdc;

mod core;

/// Re-export DID resolution
pub mod identity {
    pub use credibil_identity::*;
}

/// Re-export cryptographic types and functions
pub mod jose {
    pub use credibil_jose::*;
}

// /// Re-export basic types
// pub use crate::core::{Kind, OneMany, blockstore, did_jwk, generate, http, serde_cbor, urlencode};
pub use crate::core::*;
