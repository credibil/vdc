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

pub mod oauth;
pub mod provider;
pub mod types;
pub mod vp_token;

mod common;
mod error;
mod handlers;
mod state;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub use self::error::Error;
pub use self::handlers::*;
pub use self::types::*;

/// Re-export `credibil_identity` modules for convenience.
pub mod identity {
    pub use credibil_identity::*;
}
/// Re-export `credibil_jose` modules for convenience.
pub mod jose {
    pub use credibil_jose::*;
}

/// The JWS `typ` header parameter.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum JwtType {
    /// General purpose JWT type.
    #[default]
    #[serde(rename = "jwt")]
    Jwt,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    OauthAuthzReqJwt,
}

impl From<JwtType> for String {
    fn from(t: JwtType) -> Self {
        match t {
            JwtType::Jwt => "jwt".to_string(),
            JwtType::OauthAuthzReqJwt => "oauth-authz-req+jwt".to_string(),
        }
    }
}

impl Display for JwtType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = self.clone().into();
        write!(f, "{s}")
    }
}
