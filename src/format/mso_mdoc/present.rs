//! # ISO `mso_mdoc` Credential Presentation
//!
//! This module supports presentation of ISO `mso_mdoc` credentials.

use anyhow::{Result, anyhow};
use base64ct::{Base64Unpadded, Encoding};
use coset::{CoseSign1Builder, HeaderBuilder, iana};
use credibil_did::SignerExt;
use credibil_infosec::Algorithm;
use credibil_infosec::jose::jws::Key;
use sha2::{Digest, Sha256};

use crate::Kind;
use crate::core::serde_cbor;
use crate::format::mso_mdoc::{
    CipherSuite, CoseKey, Curve, DataItem, DeviceAuth, DeviceAuthentication, DeviceEngagement,
    DeviceNameSpaces, DeviceResponse, DeviceSignature, DeviceSigned, Document, IssuerSigned,
    KeyType, OpenID4VPDCAPIHandover, OpenID4VPDCAPIHandoverInfo, ResponseStatus, Security,
    SessionTranscript, VersionString,
};
use crate::oid4vp::types::Matched;

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
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

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
    pub fn signer<S: SignerExt>(
        self, signer: &'_ S,
    ) -> DeviceResponseBuilder<M, C, HasSigner<'_, S>> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> DeviceResponseBuilder<HasMatched<'_>, HasClientIdentifier, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    #[allow(clippy::unused_async)]
    pub async fn build(self) -> Result<String> {
        let matched = self.matched.0;
        println!("matched: {matched:?}");

        let client_id = self.client_id.0;
        println!("client_id: {client_id:?}");

        let Kind::String(issued) = &self.matched.0.issued else {
            return Err(anyhow::anyhow!("mso_mdoc credential is not a string"));
        };

        let decoded = Base64Unpadded::decode_vec(issued)?;
        let issuer_signed: IssuerSigned = serde_cbor::from_slice(&decoded)?;

        // signature
        let signer = self.signer.0;

        let device_key = CoseKey {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: signer.verifying_key().await?,
            y: None,
        };

        let de = DeviceEngagement {
            version: VersionString::One,
            security: Security(CipherSuite::Suite1, device_key.into_bytes()),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        let reader_key = CoseKey {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: signer.verifying_key().await?,
            y: None,
        };

        let info = OpenID4VPDCAPIHandoverInfo(
            "Origin".to_string(),
            "nonce".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
        let info_hash = Sha256::digest(&serde_cbor::to_vec(&info.into_bytes())?).to_vec();
        let handover = OpenID4VPDCAPIHandover("OpenID4VPDCAPIHandover".to_string(), info_hash);

        let device_authn = DeviceAuthentication(
            "DeviceAuthentication",
            SessionTranscript(de.into_bytes(), reader_key.into_bytes(), handover),
            "DocType".to_string(),
            DataItem(DeviceNameSpaces::new()),
        );

        let device_authentication_bytes = serde_cbor::to_vec(&device_authn.into_bytes())?;
        let signature = signer.sign(&device_authentication_bytes).await;

        // build COSE_Sign1
        let algorithm = match signer.algorithm() {
            Algorithm::EdDSA => iana::Algorithm::EdDSA,
            Algorithm::ES256K => return Err(anyhow!("unsupported algorithm")),
        };

        let Key::KeyId(key_id) = signer.verification_method().await? else {
            return Err(anyhow!("invalid verification method"));
        };

        let protected = HeaderBuilder::new().algorithm(algorithm).build();
        let unprotected = HeaderBuilder::new().key_id(key_id.into_bytes()).build();
        let cose_sign_1 = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .signature(signature)
            .build();

        // build presentation
        let doc = Document {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            issuer_signed,
            device_signed: DeviceSigned {
                name_spaces: DataItem(DeviceNameSpaces::new()),
                device_auth: DeviceAuth::Signature(DeviceSignature(cose_sign_1)),
            },
            errors: None,
        };

        let response = DeviceResponse {
            version: VersionString::One,
            documents: Some(vec![doc]),
            document_errors: None,
            status: ResponseStatus::Ok,
        };

        println!("device_response: {response:?}");

        // FIXME: encrypt Authorization Response Object using the Verifier
        //        Metadata from the Authorization Request Object

        todo!()
    }
}
