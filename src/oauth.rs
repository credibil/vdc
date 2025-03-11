//! # OAuth 2.0 Types
//!
//! Types for OAuth 2.0 clients and servers.

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::invalid;
use crate::oid4vci::Error;

/// OAuth 2 client metadata used for registering clients of the issuance and
/// wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthClient {
    /// ID of the registered client.
    pub client_id: String,

    /// Time at which the client identifier was issued, as Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,

    /// OAuth 2.0 client secret string. If issued, this MUST be unique for each
    /// `client_id` and SHOULD be unique for multiple instances of a client
    /// using the same `client_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Required if `client_secret` is issued. Time at which the client secret
    /// will expire (Unix time) or 0 if it will not expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,

    /// Redirection URIs for use in authorization code redirect-based flows.
    /// As required by RFC6749, clients using flows with redirection MUST
    /// register their redirection URI values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,

    /// Client's authentication method for the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuth>,

    /// OAuth 2.0 grant types the client can use at the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<GrantType>>,

    /// OAuth 2.0 response types the client can use at the authorization
    /// endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<ResponseType>>,

    /// Human-readable name of the client shown to the end-user during
    /// authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL of a web page providing information about the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL string that references a logo for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// A space-separated list of scope values the client can use when
    /// requesting access tokens. Semantics of scope values are service
    /// specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Ways to contact people responsible for the client, typically email
    /// addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,

    /// URL pointing to a human-readable terms of service document for the
    /// client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL pointing to a human-readable privacy policy for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL referencing the client's JSON Web Key (JWK) Set [RFC7517] document,
    /// containing the client's public keys. MUST NOT both be set if the`jwks`
    /// parameter is set.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set [RFC7517], containing the client's public
    /// keys. MUST be a JSON object containing a valid JWK Set. MUST NOT be
    /// set if the `jwks_uri` parameter is set.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,

    /// A unique identifier string (e.g., a Universally Unique Identifier
    /// (UUID)) assigned by the client developer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// A version identifier string for the client software identified by
    /// `software_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// Indicates whether the only means of initiating an authorization request
    /// the client is allowed to use is PAR. If omitted, the default value is
    /// false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    /// Credential Offer Endpoint of for Wallets. If the Credential Issuer is
    /// unable to perform discovery of the Wallet's Credential Offer Endpoint,
    /// the following custom URL scheme is used: `openid-credential-offer://`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,
}

impl OAuthClient {
    /// Create a new Client with the specified client ID.
    #[must_use]
    pub fn new(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            ..Self::default()
        }
    }
}

impl Display for OAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let Ok(s) = serde_json::to_string(self) else {
            return Err(fmt::Error);
        };
        write!(f, "{s}")
    }
}

impl FromStr for OAuthClient {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(res) = serde_json::from_str(s) else {
            return Err(invalid!("failed to parse Verifier"));
        };
        Ok(res)
    }
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthServer {
    /// The authorization server's issuer identifier (URL). MUST be identical to
    /// the issuer identifier value in the well-known URI:
    /// `{issuer}/.well-known/oauth-authorization-server`.
    pub issuer: String,

    /// URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: String,

    /// URL of the authorization server's token endpoint.
    pub token_endpoint: String,

    /// URL of the authorization server's JWK Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// URL of the authorization server's Dynamic Client Registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// List of scope values the authorization server supports. RECOMMENDED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// List of `response_type` values the authorization server supports.
    pub response_types_supported: Vec<ResponseType>,

    /// A list of `response_mode` values the authorization server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<ResponseMode>>,

    /// A list of grant types supported. Values are the same as the Dynamic
    /// Client Registration `grant_types`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<GrantType>>,

    /// A list of client authentication methods supported by the token endpoint.
    /// The same as those used with the `grant_types` parameter defined by the
    /// OAuth 2.0 Dynamic Client Registration Protocol specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<TokenEndpointAuth>>,

    /// A list of the JWS algorithms supported by the token endpoint for the
    /// signature on the JWT used to authenticate the client at the endpoint
    /// for the `private_key_jwt` and `client_secret_jwt` authentication
    /// methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<TokenEndpointAuthSigningAlg>>,

    /// URL to information developers might need when using the authorization
    /// server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Languages supported for the user interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// URL provided to the person registering a client regarding how the
    /// authorization server's data may be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// URL provided to the person registering the client to read about the
    /// authorization server's terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    /// URL of the authorization server's revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// A list of client authentication methods supported by this revocation
    /// endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the revocation endpoint for
    /// the signature on the JWT used to authenticate the client at the
    /// endpoint for the `private_key_jwt` and `client_secret_jwt`
    /// authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL of the authorization server's introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// A list of client authentication methods supported by this introspection
    /// endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// A list of the JWS algorithms supported by the introspection endpoint for
    /// the signature on the JWT used to authenticate the client at the
    /// endpoint for the `private_key_jwt` and `client_secret_jwt`
    /// authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// Proof Key for Code Exchange (PKCE) code challenge methods supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<CodeChallengeMethod>>,

    /// Metadata values MAY also be provided as a `signed_metadata` value, which
    /// is a JSON Web Token (JWT) that asserts metadata values about the
    /// authorization server as a bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// The URL of the pushed authorization request endpoint at which a client
    /// can post an authorization request to exchange for a `request_uri` value
    /// usable at the authorization server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// Indicates whether the authorization server accepts authorization request
    /// data only via PAR. If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
}

/// Grant Types supported by the Authorization Server.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum GrantType {
    /// The OAuth 2.0 Grant Type for Authorization Code Flow.
    #[serde(rename = "authorization_code")]
    AuthorizationCode,

    /// The OAuth 2.0 Grant Type for Pre-Authorized Code Flow.
    #[default]
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
}

/// Response types supported by the authorization endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ResponseType {
    /// Authorization Code flow response.
    #[default]
    #[serde(rename = "code")]
    Code,

    /// Verifiable Presentation Token response.
    #[serde(rename = "vp_token")]
    VpToken,

    /// ID Token response for SIOPv2
    #[serde(rename = "id_token vp_token")]
    IdToken,
}

impl From<String> for ResponseType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "code" => Self::Code,
            _ => Self::default(),
        }
    }
}

impl From<&str> for ResponseType {
    fn from(s: &str) -> Self {
        match s {
            "code" => Self::Code,
            _ => Self::default(),
        }
    }
}

/// Response modes supported by the authorization server.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Authorization Code flow response.
    #[default]
    Query,

    /// JWT Secured Authorization Response Mode
    Jarm,
}

/// Supported authentication methods for the token endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuth {
    /// The client is public and does not have a secret
    #[default]
    None,

    /// JWT Profile for OAuth 2.0 Client Authentication and Authorization
    /// Grants [RFC7523].
    ///
    /// [RFC7523]: (https://www.rfc-editor.org/rfc/rfc7523.html)
    ClientSecretJwt,

    /// The client uses JWT for client authentication.
    PrivateKeyJwt,
    //
    // /// The client uses RFC6749 HTTP POST
    // ClientSecretPost,
    //
    // /// The client uses HTTP Basic.
    // ClientSecretBasic,
}

/// JWS algorithms supported by the token endpoint for the signature on the JWT
/// used to authenticate the client at the endpoint for `private_key_jwt` and
/// `client_secret_jwt` authentication methods.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum TokenEndpointAuthSigningAlg {
    /// Algorithm for the secp256k1 curve
    #[serde(rename = "ES256K")]
    ES256K,

    /// Algorithm for the Ed25519 curve
    #[default]
    #[serde(rename = "EdDSA")]
    EdDSA,
}

/// Proof Key for Code Exchange (PKCE) code challenge methods supported.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// The S256 code challenge method.
    #[default]
    S256,
}

impl From<&str> for CodeChallengeMethod {
    fn from(s: &str) -> Self {
        match s {
            "S256" => Self::S256,
            _ => Self::default(),
        }
    }
}

impl From<String> for CodeChallengeMethod {
    fn from(s: String) -> Self {
        match s.as_str() {
            "S256" => Self::S256,
            _ => Self::default(),
        }
    }
}
