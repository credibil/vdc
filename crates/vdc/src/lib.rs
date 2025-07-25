//! # Verifiable Digital Credential
//!
//! This module provides the implementations for supported Credential formats.

pub mod dcql;
pub mod mso_mdoc;
pub mod sd_jwt;
pub mod serde_cbor;
pub mod w3c_vc;

mod generate;

use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};

pub use self::dcql::*;
pub use self::mso_mdoc::MdocBuilder;
pub use self::sd_jwt::SdJwtVcBuilder;
use self::w3c_vc::CredentialDefinition;
pub use self::w3c_vc::W3cVcBuilder;

/// Format Profile defines supported Credential data models. Each profile
/// defines a specific set of parameters or claims used to support a particular
/// format.
///
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles>
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "format")]
pub enum FormatProfile {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD
    /// rules.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson {
        /// The detailed description of the W3C Credential type.
        credential_definition: CredentialDefinition,
    },

    /// A W3C Verifiable Credential not  using JSON-LD.
    #[serde(rename = "ldp-vc")]
    LdpVc {
        /// The detailed description of the W3C Credential type.
        credential_definition: CredentialDefinition,
    },

    /// A W3C Verifiable Credential using JSON-LD.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd {
        /// The detailed description of the W3C Credential type.
        credential_definition: CredentialDefinition,
    },

    /// An ISO mDL (ISO.18013-5) mobile driving licence format credential.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc {
        /// The credential type.
        doctype: String,
    },

    /// An IETF SD-JWT format credential.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt {
        /// The SD-JWT VC type identifier.
        vct: String,
    },
}

impl Default for FormatProfile {
    fn default() -> Self {
        Self::JwtVcJson { credential_definition: CredentialDefinition::default() }
    }
}

impl Display for FormatProfile {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::JwtVcJson { .. } => write!(f, "jwt_vc_json"),
            Self::LdpVc { .. } => write!(f, "ldp_vc"),
            Self::JwtVcJsonLd { .. } => write!(f, "jwt_vc_json-ld"),
            Self::MsoMdoc { .. } => write!(f, "mso_mdoc"),
            Self::DcSdJwt { .. } => write!(f, "dc+sd-jwt"),
        }
    }
}
