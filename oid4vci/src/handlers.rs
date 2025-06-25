//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

mod authorize;
mod create_offer;
mod credential;
mod credential_offer;
mod deferred;
mod metadata;
mod nonce;
mod notification;
mod par;
mod register;
mod server;
mod token;

use http::HeaderMap;
use http::header::ACCEPT_LANGUAGE;

pub use crate::error::Error;

/// Result type for `OpenID` for Verifiable Credential Issuance.
pub type Result<T> = anyhow::Result<T, Error>;

/// Credential request headers.
pub type CredentialHeaders = AuthorizationHeader;

/// Deferred Credential request headers.
pub type DeferredHeaders = AuthorizationHeader;

/// Registration request headers.
pub type MetadataHeaders = LanguageHeader;

/// Notification request headers.
pub type NotificationHeaders = AuthorizationHeader;

/// Registration request headers.
pub type RegistrationHeaders = AuthorizationHeader;

/// An authorization-only header for use by handlers that soley require
/// authorization.
#[derive(Clone, Debug)]
pub struct AuthorizationHeader {
    /// The authorization header (access token).
    pub authorization: String,
}

/// An language-only header for use by handlers that soley require
/// the `accept-language` header.
#[derive(Clone, Debug)]
pub struct LanguageHeader {
    /// The `accept-language` header.
    pub accept_language: Option<String>,
}

impl From<HeaderMap> for LanguageHeader {
    fn from(headers: HeaderMap) -> Self {
        let accept_language =
            headers.get(ACCEPT_LANGUAGE).map(|h| h.to_str().ok().unwrap_or("en").to_string());
        Self { accept_language }
    }
}
