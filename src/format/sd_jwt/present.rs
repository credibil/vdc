//! # SD-JWT Presentation

use anyhow::{Result, anyhow};
use chrono::Utc;
use credibil_did::SignerExt;
use credibil_infosec::Jws;

use crate::format::sd_jwt::{Disclosure, JwtType, KbJwtClaims};
use crate::oid4vp::types::Matched;
use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct SdJwtVpBuilder<C, V, S> {
    matched: C,
    client_id: V,
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
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl Default for SdJwtVpBuilder<NoMatched, NoClientIdentifier, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl SdJwtVpBuilder<NoMatched, NoClientIdentifier, NoSigner> {
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
impl<'a, V, S> SdJwtVpBuilder<NoMatched, V, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn matched(self, matched: &'a Matched) -> SdJwtVpBuilder<HasMatched<'a>, V, S> {
        SdJwtVpBuilder {
            matched: HasMatched(matched),
            client_id: self.client_id,
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<C, S> SdJwtVpBuilder<C, NoClientIdentifier, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn client_id(
        self, client_id: impl Into<String>,
    ) -> SdJwtVpBuilder<C, HasClientIdentifier, S> {
        SdJwtVpBuilder {
            matched: self.matched,
            client_id: HasClientIdentifier(client_id.into()),
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<C, V, S> SdJwtVpBuilder<C, V, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

// SignerExt
impl<C, V> SdJwtVpBuilder<C, V, NoSigner> {
    /// Set the credential `SignerExt`.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> SdJwtVpBuilder<C, V, HasSigner<'_, S>> {
        SdJwtVpBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> SdJwtVpBuilder<HasMatched<'_>, HasClientIdentifier, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;

        // issued SD-JWT (including disclosures)
        let Some(credential) = matched.issued.as_str() else {
            return Err(anyhow!("Invalid issued claim type"));
        };

        // unpack disclosures
        let split = credential.split('~').collect::<Vec<_>>();
        if split.len() < 2 {
            return Err(anyhow!("invalid sd-jwt credential"));
        }

        let mut unpacked = vec![];
        for encoded in &split[1..split.len()] {
            unpacked.push(Disclosure::from(encoded)?);
        }

        // select disclosures to include in the presentation
        let mut selected = vec![];
        for claim in &matched.claims {
            let Some(disclosure) =
                unpacked.iter().find(|d| d.name == claim.path[claim.path.len() - 1])
            else {
                return Err(anyhow!("disclosure not found"));
            };

            selected.push(disclosure.encode()?);
        }

        // key binding JWT
        let sd = format!("{credential}~{}", selected.join("~"));

        let claims = KbJwtClaims {
            nonce: self.nonce.unwrap_or_default(),
            aud: self.client_id.0,
            iat: Utc::now(),
            sd_hash: super::sd_hash(&sd),
        };

        let kb_jwt = Jws::builder()
            .typ(JwtType::KbJwt)
            .payload(claims)
            .key_ref(&self.signer.0.verification_method().await?)
            .add_signer(self.signer.0)
            .build()
            .await
            .map_err(|e| server!("issue signing KB-JWT: {e}"))?
            .to_string();

        // assemble
        let presentation = format!("{sd}~{kb_jwt}");
        Ok(presentation)
    }
}
