use anyhow::Result;
// use base64ct::{Base64UrlUnpadded, Encoding};
// use chrono::Utc;
use credibil_infosec::Signer;

// use sha2::{Digest, Sha256};

// use crate::format::sd_jwt::{Disclosure, JwtType, KbJwtClaims};
use crate::oid4vp::types::Matched;
// use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct DeviceResponseBuilder<M, C, S> {
    matched: M,
    client_id: C,
    nonce: Option<String>,
    signer: S,
}

/// Builder has no claims.
#[doc(hidden)]
pub struct NoMatched;
/// Builder has claims.
#[doc(hidden)]
pub struct HasMatched<'a>(&'a Matched<'a>);

/// Builder has no issuer.
#[doc(hidden)]
pub struct NoClientIdentifier;
/// Builder has issuer.
#[doc(hidden)]
pub struct HasClientIdentifier(String);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signer>(pub &'a S);

impl Default for DeviceResponseBuilder<NoMatched, NoClientIdentifier, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceResponseBuilder<NoMatched, NoClientIdentifier, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            matched: NoMatched,
            client_id: NoClientIdentifier,
            nonce: None,
            signer: NoSigner,
        }
    }
}

// Credentials to include in the presentation
impl<'a, C, S> DeviceResponseBuilder<NoMatched, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn matched(self, matched: &'a Matched) -> DeviceResponseBuilder<HasMatched<'a>, C, S> {
        DeviceResponseBuilder {
            matched: HasMatched(matched),
            client_id: self.client_id,
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<M, S> DeviceResponseBuilder<M, NoClientIdentifier, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn client_id(self, client_id: String) -> DeviceResponseBuilder<M, HasClientIdentifier, S> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: HasClientIdentifier(client_id),
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<M, C, S> DeviceResponseBuilder<M, C, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

// Signer
impl<M, C> DeviceResponseBuilder<M, C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &'_ S) -> DeviceResponseBuilder<M, C, HasSigner<'_, S>> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<S: Signer> DeviceResponseBuilder<HasMatched<'_>, HasClientIdentifier, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;

        // build presentation

        // encrypt Authorization Response Object using the Verifier Metadata
        // from the Authorization Request Object

        todo!()
    }
}
