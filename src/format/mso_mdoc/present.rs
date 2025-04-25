//! # ISO `mso_mdoc` Credential Presentation
//!
//! This module supports presentation of ISO `mso_mdoc` credentials.

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use coset::{CoseSign1Builder, HeaderBuilder, iana};
use credibil_did::SignerExt;
use credibil_infosec::Algorithm;
use credibil_infosec::jose::jws::Key;
use sha2::{Digest, Sha256};

use crate::Kind;
use crate::core::{generate, serde_cbor};
use crate::format::mso_mdoc::{
    DataItem, DeviceAuth, DeviceAuthentication, DeviceNameSpaces, DeviceResponse, DeviceSignature,
    DeviceSigned, DeviceSignedItems, Document, Handover, IssuerSigned, MobileSecurityObject,
    OID4VPHandover, ResponseStatus, SessionTranscript, VersionString,
};
use crate::oid4vp::types::Matched;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct DeviceResponseBuilder<M, C, N, U, S> {
    matched: M,
    client_id: C,
    nonce: N,
    response_uri: U,
    signer: S,
}

/// Builder has no claims.
#[doc(hidden)]
pub struct NoMatched;
/// Builder has claims.
#[doc(hidden)]
pub struct HasMatched<'a>(&'a Matched<'a>);

/// Builder has no client identifier.
#[doc(hidden)]
pub struct NoClientId;
/// Builder has client_id.
#[doc(hidden)]
pub struct HasClientId(String);

/// Builder has no nonce.
#[doc(hidden)]
pub struct NoNonce;
/// Builder has nonce.
#[doc(hidden)]
pub struct HasNonce(String);

/// Builder has no response_uri.
#[doc(hidden)]
pub struct NoResponseUri;
/// Builder has response_uri.
#[doc(hidden)]
pub struct HasResponseUri(String);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl Default for DeviceResponseBuilder<NoMatched, NoClientId, NoNonce, NoResponseUri, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceResponseBuilder<NoMatched, NoClientId, NoNonce, NoResponseUri, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            matched: NoMatched,
            client_id: NoClientId,
            nonce: NoNonce,
            response_uri: NoResponseUri,
            signer: NoSigner,
        }
    }
}

// Credentials to include in the presentation
impl<'a, C, N, U, S> DeviceResponseBuilder<NoMatched, C, N, U, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn matched(
        self, matched: &'a Matched,
    ) -> DeviceResponseBuilder<HasMatched<'a>, C, N, U, S> {
        DeviceResponseBuilder {
            matched: HasMatched(matched),
            client_id: self.client_id,
            nonce: self.nonce,
            response_uri: self.response_uri,
            signer: self.signer,
        }
    }
}

// Credentials to include in the presentation
impl<M, N, U, S> DeviceResponseBuilder<M, NoClientId, N, U, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn client_id(
        self, client_id: impl Into<String>,
    ) -> DeviceResponseBuilder<M, HasClientId, N, U, S> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: HasClientId(client_id.into()),
            nonce: self.nonce,
            response_uri: self.response_uri,
            signer: self.signer,
        }
    }
}

impl<M, C, U, S> DeviceResponseBuilder<M, C, NoNonce, U, S> {
    /// Set the `nonce` provided in the Authorization Request Object.
    #[must_use]
    pub fn nonce(self, nonce: impl Into<String>) -> DeviceResponseBuilder<M, C, HasNonce, U, S> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: HasNonce(nonce.into()),
            response_uri: self.response_uri,
            signer: self.signer,
        }
    }
}

impl<M, C, N, S> DeviceResponseBuilder<M, C, N, NoResponseUri, S> {
    /// Set the `nonce` provided in the Authorization Request Object.
    #[must_use]
    pub fn response_uri(
        self, nonce: impl Into<String>,
    ) -> DeviceResponseBuilder<M, C, N, HasResponseUri, S> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            response_uri: HasResponseUri(nonce.into()),
            signer: self.signer,
        }
    }
}

// Signer
impl<M, C, N, U> DeviceResponseBuilder<M, C, N, U, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: SignerExt>(
        self, signer: &'_ S,
    ) -> DeviceResponseBuilder<M, C, N, U, HasSigner<'_, S>> {
        DeviceResponseBuilder {
            matched: self.matched,
            client_id: self.client_id,
            nonce: self.nonce,
            response_uri: self.response_uri,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt>
    DeviceResponseBuilder<HasMatched<'_>, HasClientId, HasNonce, HasResponseUri, HasSigner<'_, S>>
{
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
    ///
    /// # Errors
    /// TODO: Document errors
    #[allow(clippy::unused_async)]
    pub async fn build(self) -> Result<String> {
        // extract mdoc and mso from the issued credential
        let Kind::String(issued) = &self.matched.0.issued else {
            return Err(anyhow::anyhow!("`mso_mdoc` credential is not a string"));
        };
        let mdoc_bytes = Base64UrlUnpadded::decode_vec(issued)?;
        let issuer_signed: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes)?;

        let Some(mso_bytes) = &issuer_signed.issuer_auth.0.payload else {
            return Err(anyhow!("`mso` does not contain a payload"));
        };
        let mso: DataItem<MobileSecurityObject> = serde_cbor::from_slice(mso_bytes)?;

        // select claims from the issued credential and convert to device signed items
        let mut device_name_spaces = DeviceNameSpaces::new();
        for (name_space, issuer_items) in &issuer_signed.name_spaces {
            println!("namespace: {name_space}",);

            let mut device_signed_items = DeviceSignedItems::new();
            for item in issuer_items {
                device_signed_items
                    .insert(item.element_identifier.clone(), item.element_value.clone());
            }
            device_name_spaces.entry(name_space.clone()).or_default().push(device_signed_items);
        }

        // device signature
        // ..handover
        let mdoc_nonce = generate::nonce();
        let client_id_hash =
            Sha256::digest(&serde_cbor::to_vec(&[self.client_id.0, mdoc_nonce.clone()])?).to_vec();
        let response_uri_hash =
            Sha256::digest(&serde_cbor::to_vec(&[self.response_uri.0, mdoc_nonce])?).to_vec();
        let handover = OID4VPHandover(client_id_hash, response_uri_hash, self.nonce.0);

        // ..device auth
        let device_authn = DeviceAuthentication(
            "DeviceAuthentication",
            SessionTranscript(None, None, Handover::Oid4Vp(handover)),
            mso.doc_type.clone(),
            DataItem(device_name_spaces),
        );

        // ..COSE_Sign1
        let signer = self.signer.0;
        let device_authn_bytes = serde_cbor::to_vec(&device_authn.into_bytes())?;
        let signature = signer.sign(&device_authn_bytes).await;

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

        // presentation
        let doc = Document {
            doc_type: mso.doc_type.clone(),
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

        // FIXME: encrypt Authorization Response Object using the Verifier
        //        Metadata from the Authorization Request Object

        // encode CBOR -> Base64Url -> return
        Ok(Base64UrlUnpadded::encode_string(&serde_cbor::to_vec(&response)?))
    }
}

// let info = OpenID4VPDCAPIHandoverInfo(
//     self.client_id.0.clone(),
//     self.nonce.unwrap_or_default(),
//     vec![1, 2, 3, 4, 5, 6, 7, 8],
// );
// let info_hash = Sha256::digest(&serde_cbor::to_vec(&info.into_bytes())?).to_vec();
// let handover = OpenID4VPDCAPIHandover("OpenID4VPDCAPIHandover".to_string(), info_hash);

#[cfg(test)]
mod tests {
    use provider::issuer::Issuer;
    use serde_json::{Value, json};

    use super::*;
    use crate::format::mso_mdoc::MsoMdocBuilder;
    use crate::oid4vp::types::Claim;

    #[tokio::test]
    async fn build_vp() {
        let issued = build_vc().await;

        let given_name = &Claim {
            path: vec!["org.iso.18013.5.1".to_string(), "given_name".to_string()],
            value: Value::String("Normal".to_string()),
        };
        let family_name = &Claim {
            path: vec!["org.iso.18013.5.1".to_string(), "family_name".to_string()],
            value: Value::String("Person".to_string()),
        };
        let portrait = &Claim {
            path: vec!["org.iso.18013.5.1".to_string(), "portrait".to_string()],
            value: Value::String("https://example.com/portrait.jpg".to_string()),
        };

        let matched = Matched {
            claims: vec![given_name, family_name, portrait],
            issued: &Kind::String(issued),
        };

        let mdl = DeviceResponseBuilder::new()
            .matched(&matched)
            .client_id("client_id")
            .nonce("nonce")
            .response_uri("https://example.com/response")
            .signer(&Issuer::new())
            .build()
            .await
            .expect("should build");

        dbg!(mdl);

        // check credential deserializes back into original mdoc/mso structures
        // let mdoc_bytes = Base64UrlUnpadded::decode_vec(&mdl).expect("should decode");
        // let mdoc: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes).expect("should deserialize");

        // let _mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
        // let mso: DataItem<MobileSecurityObject> =
        //     serde_cbor::from_slice(&mso_bytes).expect("should deserialize");

        // assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
        // assert_eq!(mso.device_key_info.device_key.kty, KeyType::Okp);
    }

    async fn build_vc() -> String {
        let claims_json = json!({
            "org.iso.18013.5.1": {
                "given_name": "Normal",
                "family_name": "Person",
                "portrait": "https://example.com/portrait.jpg",
            },
        });
        let claims = claims_json.as_object().unwrap();

        MsoMdocBuilder::new()
            .doctype("org.iso.18013.5.1.mDL")
            .claims(claims.clone())
            .signer(&Issuer::new())
            .build()
            .await
            .expect("should build")

        // check credential deserializes back into original mdoc/mso structures
        // let mdoc_bytes = Base64UrlUnpadded::decode_vec(&mdl).expect("should decode");
        // let mdoc: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes).expect("should deserialize");

        // let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
        // let mso: DataItem<MobileSecurityObject> =
        //     serde_cbor::from_slice(&mso_bytes).expect("should deserialize");
    }
}
