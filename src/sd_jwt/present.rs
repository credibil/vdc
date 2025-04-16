use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use credibil_infosec::{Jws, Signer};
use sha2::{Digest, Sha256};

use crate::oid4vp::types::Selected;
use crate::sd_jwt::{Disclosure, JwtType, KbJwtClaims};
use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct SdJwtVpBuilder<C, V, S> {
    selected: C,
    verifier: V,
    nonce: Option<String>,
    signer: S,
}

/// Builder has no claims.
#[doc(hidden)]
pub struct NoSelected;
/// Builder has claims.
#[doc(hidden)]
pub struct HasSelected<'a>(Selected<'a>);

/// Builder has no issuer.
#[doc(hidden)]
pub struct NoVerifier;
/// Builder has issuer.
#[doc(hidden)]
pub struct HasVerifier(String);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signer>(pub &'a S);

impl Default for SdJwtVpBuilder<NoSelected, NoVerifier, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl SdJwtVpBuilder<NoSelected, NoVerifier, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: NoSelected,
            verifier: NoVerifier,
            nonce: None,
            signer: NoSigner,
        }
    }
}

// Credentials to include in the presentation
impl<V, S> SdJwtVpBuilder<NoSelected, V, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn selected(self, selected: Selected) -> SdJwtVpBuilder<HasSelected, V, S> {
        SdJwtVpBuilder {
            selected: HasSelected(selected),
            verifier: self.verifier,
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<C, S> SdJwtVpBuilder<C, NoVerifier, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn verifier(self, verifier: impl Into<String>) -> SdJwtVpBuilder<C, HasVerifier, S> {
        SdJwtVpBuilder {
            selected: self.selected,
            verifier: HasVerifier(verifier.into()),
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

// Signer
impl<C, V> SdJwtVpBuilder<C, V, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &'_ S) -> SdJwtVpBuilder<C, V, HasSigner<'_, S>> {
        SdJwtVpBuilder {
            selected: self.selected,
            verifier: self.verifier,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<'a, S: Signer> SdJwtVpBuilder<HasSelected<'a>, HasVerifier, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let selected = self.selected.0;

        // 1. issued SD-JWT
        let Some(credential) = selected.credential.as_str() else {
            return Err(anyhow!("Invalid issued claim type"));
        };

        // 2. disclosures
        let mut disclosures = vec![];
        for claim in &selected.claims {
            let disclosure =
                Disclosure::new(&claim.path[claim.path.len() - 1], claim.value.clone());
            disclosures.push(disclosure.encoded()?);
        }

        // 3. key binding JWT
        let sd = format!("{credential}~{}", disclosures.join("~"));
        let sd_hash = Sha256::digest(&sd);

        let claims = KbJwtClaims {
            nonce: self.nonce.unwrap_or_default(),
            aud: self.verifier.0,
            iat: Utc::now(),
            sd_hash: Base64UrlUnpadded::encode_string(sd_hash.as_slice()),
        };

        let kb_jwt = Jws::builder()
            .typ(JwtType::KbJwt)
            .payload(claims)
            .add_signer(self.signer.0)
            .build()
            .await
            .map_err(|e| server!("issue signing SD-JWT: {e}"))?
            .to_string();

        // assemble
        let presentation = format!("{sd}~{kb_jwt}");
        Ok(presentation)
    }
}
