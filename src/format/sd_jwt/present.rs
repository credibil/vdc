//! # SD-JWT Presentation

use anyhow::{Result, anyhow};
use chrono::Utc;
use credibil_identity::SignerExt;
use credibil_jose::Jws;

use crate::format::sd_jwt::{Disclosure, JwtType, KbJwtClaims};
use crate::oid4vp::types::Matched;
use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct SdJwtVpBuilder<M, C, S> {
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
pub struct NoClientId;
/// Builder has issuer.
#[doc(hidden)]
pub struct HasClientId(String);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl Default for SdJwtVpBuilder<NoMatched, NoClientId, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl SdJwtVpBuilder<NoMatched, NoClientId, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            matched: NoMatched,
            client_id: NoClientId,
            nonce: None,
            signer: NoSigner,
        }
    }
}

// Credentials to include in the presentation
impl<'a, C, S> SdJwtVpBuilder<NoMatched, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn matched(self, matched: &'a Matched) -> SdJwtVpBuilder<HasMatched<'a>, C, S> {
        SdJwtVpBuilder {
            matched: HasMatched(matched),
            client_id: self.client_id,
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<M, S> SdJwtVpBuilder<M, NoClientId, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn client_id(self, client_id: impl Into<String>) -> SdJwtVpBuilder<M, HasClientId, S> {
        SdJwtVpBuilder {
            matched: self.matched,
            client_id: HasClientId(client_id.into()),
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<M, C, S> SdJwtVpBuilder<M, C, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

// SignerExt
impl<M, C> SdJwtVpBuilder<M, C, NoSigner> {
    /// Set the credential `SignerExt`.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> SdJwtVpBuilder<M, C, HasSigner<'_, S>> {
        SdJwtVpBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> SdJwtVpBuilder<HasMatched<'_>, HasClientId, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;

        // issued SD-JWT (including disclosures)
        let Some(sd_jwt) = matched.issued.as_str() else {
            return Err(anyhow!("issued credential is invalid"));
        };

        // unpack disclosures
        let mut split = sd_jwt.split('~');
        let credential = split.next().ok_or_else(|| anyhow!("missing issuer-signed JWT"))?;
        let disclosures = split.map(Disclosure::from).collect::<Result<Vec<_>>>()?;

        // select disclosures to include in the presentation
        let mut selected = vec![];
        for claim in &matched.claims {
            let Some(disclosure) =
                disclosures.iter().find(|d| d.name == claim.path[claim.path.len() - 1])
            else {
                return Err(anyhow!("disclosure not found"));
            };
            selected.push(disclosure.encode()?);
        }

        let sd = format!("{credential}~{}", selected.join("~"));

        // key binding JWT
        let key_ref = self.signer.0.verification_method().await?.try_into()?;
        let kb_jwt = Jws::builder()
            .typ(JwtType::KbJwt)
            .payload(KbJwtClaims {
                nonce: self.nonce.unwrap_or_default(),
                aud: self.client_id.0,
                iat: Utc::now(),
                sd_hash: super::sd_hash(&sd),
            })
            .key_ref(&key_ref)
            .add_signer(self.signer.0)
            .build()
            .await
            .map_err(|e| server!("issue signing KB-JWT: {e}"))?
            .to_string();

        // assemble presentation
        Ok(format!("{sd}~{kb_jwt}"))
    }
}
