//! # W3C-VC Presentation

use anyhow::{Result, anyhow};
// use chrono::Utc;
use credibil_identity::SignerExt;

// use credibil_jose::Jws;
use crate::oid4vp::types::Matched;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct W3cVpBuilder<M, C, S> {
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

impl Default for W3cVpBuilder<NoMatched, NoClientId, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl W3cVpBuilder<NoMatched, NoClientId, NoSigner> {
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
impl<'a, C, S> W3cVpBuilder<NoMatched, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn matched(self, matched: &'a Matched) -> W3cVpBuilder<HasMatched<'a>, C, S> {
        W3cVpBuilder {
            matched: HasMatched(matched),
            client_id: self.client_id,
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<M, S> W3cVpBuilder<M, NoClientId, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn client_id(self, client_id: impl Into<String>) -> W3cVpBuilder<M, HasClientId, S> {
        W3cVpBuilder {
            matched: self.matched,
            client_id: HasClientId(client_id.into()),
            nonce: self.nonce,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<M, C, S> W3cVpBuilder<M, C, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

// SignerExt
impl<M, C> W3cVpBuilder<M, C, NoSigner> {
    /// Set the credential `SignerExt`.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> W3cVpBuilder<M, C, HasSigner<'_, S>> {
        W3cVpBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> W3cVpBuilder<HasMatched<'_>, HasClientId, HasSigner<'_, S>> {
    /// Build the W3C-VC presentation.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;

        // issued W3C-VC (including disclosures)
        let Some(credential) = matched.issued.as_str() else {
            return Err(anyhow!("Invalid issued claim type"));
        };

        dbg!(&credential);
        dbg!(self.client_id.0);

        // unpack

        // select disclosures to include in the presentation
        // let mut selected = vec![];
        // for claim in &matched.claims {

        //     selected.push(disclosure.encode()?);
        // }

        // let key = self.signer.0.verification_method().await?;
        // let key_ref = key.try_into()?;
        // let kb_jwt = Jws::builder()
        //     .typ(JwtType::KbJwt)
        //     .payload(claims)
        //     .key_ref(&key_ref)
        //     .add_signer(self.signer.0)
        //     .build()
        //     .await
        //     .map_err(|e| server!("issue signing KB-JWT: {e}"))?
        //     .to_string();

        // // assemble presentation
        // Ok(format!("{sd}~{kb_jwt}"))

        todo!()
    }
}
