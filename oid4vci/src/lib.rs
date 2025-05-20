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

pub mod issuer;
pub mod oauth;
pub mod pkce;
pub mod provider;
pub mod wallet;

mod common;
mod error;
mod handlers;
mod state;

/// Re-export proofs
pub mod proof {
    pub use credibil_vdc::w3c_vc::{Payload, Verify, W3cVcClaims};
}

/// Re-export `credibil_identity` modules for convenience.
pub mod identity {
    pub use credibil_identity::*;
}
/// Re-export `credibil_jose` modules for convenience.
pub mod jose {
    pub use credibil_jose::*;
}

use serde::{Deserialize, Serialize};

pub use self::error::Error;
pub use self::handlers::*;
pub use self::issuer::*;

/// The JWT `typ` header parameter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum JwtType {
    /// General purpose JWT type.
    #[default]
    #[serde(rename = "jwt")]
    Jwt,

    /// JWT `typ` for Wallet's Proof of possession of key material.
    #[serde(rename = "oid4vci-proof+jwt")]
    ProofJwt,
}

impl From<JwtType> for String {
    fn from(t: JwtType) -> Self {
        From::from(&t)
    }
}

impl From<&JwtType> for String {
    fn from(t: &JwtType) -> Self {
        match t {
            JwtType::Jwt => "jwt".to_string(),
            JwtType::ProofJwt => "oid4vci-proof+jwt".to_string(),
        }
    }
}

impl std::fmt::Display for JwtType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = self.into();
        write!(f, "{s}")
    }
}
