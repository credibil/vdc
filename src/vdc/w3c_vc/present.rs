//! # W3C-VC Presentation

use anyhow::{Context as _, Result, anyhow};
use credibil_core::{Kind, OneMany};
use credibil_identity::{Key, SignerExt};
use credibil_jose::encode_jws;

use crate::oid4vp::verifier::Matched;
use crate::vdc::w3c_vc::{VerifiablePresentation, W3cVpClaims};

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
    /// Build the presentation.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;

        let Key::KeyId(kid) = self.signer.0.verification_method().await? else {
            return Err(anyhow!("failed to get verification method"));
        };
        let (holder_did, _) =
            kid.split_once('#').ok_or_else(|| anyhow!("failed to parse key id"))?;

        let vp = VerifiablePresentation {
            context: vec![Kind::String("https://www.w3.org/2018/credentials/v1".to_string())],
            id: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            r#type: OneMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(vec![matched.issued.clone()]),
            holder: Some(holder_did.to_string()),
            ..Default::default()
        };

        let mut vp_claims: W3cVpClaims = vp.into();
        vp_claims.aud = self.client_id.0;
        vp_claims.nonce = self.nonce.unwrap_or_default();

        let key = self.signer.0.verification_method().await?;
        encode_jws(&vp_claims, &key.try_into()?, self.signer.0)
            .await
            .context("generating `jwt_vc_json` credential")
    }
}
