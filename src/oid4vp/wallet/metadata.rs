//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

use std::fmt::Debug;

use credibil_jose::Algorithm;
use credibil_jose::jwe::{AlgAlgorithm, EncAlgorithm};
use serde::{Deserialize, Serialize};

use crate::oauth::OAuthServer;
use crate::oid4vp::{ClientIdPrefix, VpFormat};

/// Request to retrieve the Verifier's client metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetadataRequest {
    /// The Verifier's Client Identifier for which the configuration is to be
    /// returned.
    #[serde(default)]
    pub client_id: String,
}

/// OAuth 2.0 Authorization Server metadata.
///
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Wallet {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Supported JWE methods  for when the Wallet requires an encrypted
    /// Authorization Response.
    pub presentation_definition_uri_supported: bool,

    /// A list of key value pairs, where the key identifies a Credential format
    /// supported by the Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats_supported: Option<Vec<VpFormat>>,

    /// Client Identifier prefixes the Wallet supports. Defaults to
    /// `pre-registered`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,

    /// When the Client Identifier Prefix permits signed Request Objects, the
    /// Wallet SHOULD list supported cryptographic algorithms for securing the
    /// Request Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<Algorithm>>,

    // /// Supported JWS algorithms for JARM. The none algorithm, i.e. a plain
    // /// JWT, is forbidden. If the client doesn’t have a JWS algorithm
    // /// registered for JARM and requests a JWT-secured response_mode the
    // /// default algorithm is RS256.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub authorization_signing_alg_values_supported: Option<Vec<String>>,
    //
    /// Supported JWE algorithms for when the Wallet requires an encrypted
    /// Authorization Response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encryption_alg_values_supported: Option<Vec<AlgAlgorithm>>,

    /// Supported JWE methods for when the Wallet requires an encrypted
    /// Authorization Response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encryption_enc_values_supported: Option<Vec<EncAlgorithm>>,
}
