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
            DataItem(device_name_spaces.clone()),
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
                name_spaces: DataItem(device_name_spaces),
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

        // encode CBOR -> Base64Url -> return
        Ok(Base64UrlUnpadded::encode_string(&serde_cbor::to_vec(&response)?))

        // FIXME: encrypt Authorization Response Object using the Verifier
        //        Metadata from the Authorization Request Object
    }
}

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

        let response = DeviceResponseBuilder::new()
            .matched(&matched)
            .client_id("client_id")
            .nonce("nonce")
            .response_uri("https://example.com/response")
            .signer(&Issuer::new())
            .build()
            .await
            .expect("should build");

        // check credential deserializes back into original mdoc/mso structures
        let cbor = Base64UrlUnpadded::decode_vec(&response).expect("should decode");
        let mdoc = serde_cbor::from_slice::<DeviceResponse>(&cbor).unwrap();

        let documents = mdoc.documents.expect("should have documents");
        assert_eq!(documents[0].doc_type, "org.iso.18013.5.1.mDL");
        assert!(&documents[0].device_signed.name_spaces.get("org.iso.18013.5.1").is_some());
    }

    #[test]
    fn vp_token() {
        const VP_TOKEN: &str = "o2ZzdGF0dXMAZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGRldmljZVNpZ25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAZIIUI8retZS5btJ9TGyaMt7j1nQm1DUy5FyG_98yKOOWNOtizwY41CipQOMGZ5d7Plh722-YQrSCpZTNBIYjxmpuYW1lU3BhY2Vz2BhBoGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCYDCCAlwwggIBoAMCAQICCkdSCck8KAChX_8wCgYIKoZIzj0EAwIwRTELMAkGA1UEBhMCVVMxKTAnBgNVBAMMIElTTzE4MDEzLTUgVGVzdCBDZXJ0aWZpY2F0ZSBJQUNBMQswCQYDVQQIDAJOWTAeFw0yNDA0MjgyMTAyMjNaFw0yNTA3MjkyMTAyMjNaMEQxCzAJBgNVBAYTAlVTMSgwJgYDVQQDDB9JU08xODAxMy01IFRlc3QgQ2VydGlmaWNhdGUgRFNDMQswCQYDVQQIDAJOWTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDdOFaKr9WxgpFWlzF8VmfchBvTwC1oH1MaP685sHKGmreQPVsqbSlHABGTWPrcnbhlPbQLrDsZH03ggndfjw7yjgdkwgdYwHQYDVR0OBBYEFGUpDcssvlnvVrvfRW1P-KRafe5aMB8GA1UdIwQYMBaAFEz_lSXgZZtQ7BxDClpyjcQbTTrPMA4GA1UdDwEB_wQEAwIHgDAdBgNVHREEFjAUgRJleGFtcGxlQGlzb21kbC5jb20wHQYDVR0SBBYwFIESZXhhbXBsZUBpc29tZGwuY29tMC8GA1UdHwQoMCYwJKAioCCGHmh0dHBzOi8vZXhhbXBsZS5jb20vSVNPbURMLmNybDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoGCCqGSM49BAMCA0kAMEYCIQCvw8wYtoDlQlBzqMYF6U0KXK1fFC5f0NETmKktxq-jWQIhAKOIt0zsjXCO2TJvtCa81HQDOoDOCvc4Tp5jzp4rW7VDWQK62BhZArWmZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGrAFggJU2b_85ISFXlEQWLKnOZVmRs1xSzYsZwWe0Z1Nju4yUBWCC6jOuodOY0wsyiy1cVQZ1trp9MdS40ma6NoiqSCw3i_AJYINNVwMahFR_eg3WdYKd_mlT7jcpBlUo4efrVfaljh1qUA1gg18RTMj2oZ361MmmRKRskRJxLZr8U8y8BjYePiE0MDrIEWCBAXKSrlBnPKnWZ5ovf0-tH6yS-_fLq0jtlV6lo_m2xkAVYIChjHaujPFotPAVarU6OS9bOUGJM2i8Su0QHcGd8LUIqBlggEPSlRSQU3qO8WGlhdybrFvOED7ClhKoXNnaz7iEYYG0HWCBdHiKvThj-f0ujtxCpB-rDOr2j5K6Dus7A4wlVA1FesghYIOcFkpH5fl3zQDlmzrt0uOqp37_3RYcsl11ju8WBF0Q0CVggRxt5r6QHia1VtAc2pWWASpR-FtxUWwSriOJRAA3xUNwKWCBJKSm9xIOQawO8CVvCxg_B-1LOrUU_syVoouJRsC2cXm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIFfRF0B86kxJpllzlXbiSPjaamzG1FL6ZOL9VKkdPecLIlgglApkmUibrqPDNOcJi0q0zSbX440venAe0K1Xrn3X70BnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2l2YWxpZEZyb23AdDIwMjQtMDQtMjhUMjE6MDI6MjVaanZhbGlkVW50aWzAdDIwMjQtMDUtMDhUMjE6MDI6MjRaZnNpZ25lZMB0MjAyNC0wNC0yOFQyMTowMjoyNFpYQNMckHB3uEeFbz7re-heKVBrD6L9MiAQBk5IRhF1U9cfIq5lanDt5cnWBOEEV77VxJXDF-pbja-murf1S_9ymnxqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGL2BhZCDukaGRpZ2VzdElEBWZyYW5kb21QZWUgWBRENQw29qWDPQ9duHFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdGxlbGVtZW50VmFsdWVZB-3_2P_gABBKRklGAAEBAAAAAAAAAP_iAihJQ0NfUFJPRklMRQABAQAAAhgAAAAABDAAAG1udHJSR0IgWFlaIAAAAAAAAAAAAAAAAGFjc3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAD21gABAAAAANMtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACWRlc2MAAADwAAAAdHJYWVoAAAFkAAAAFGdYWVoAAAF4AAAAFGJYWVoAAAGMAAAAFHJUUkMAAAGgAAAAKGdUUkMAAAGgAAAAKGJUUkMAAAGgAAAAKHd0cHQAAAHIAAAAFGNwcnQAAAHcAAAAPG1sdWMAAAAAAAAAAQAAAAxlblVTAAAAWAAAABwAcwBSAEcAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWFlaIAAAAAAAAG-iAAA49QAAA5BYWVogAAAAAAAAYpkAALeFAAAY2lhZWiAAAAAAAAAkoAAAD4QAALbPcGFyYQAAAAAABAAAAAJmZgAA8qcAAA1ZAAAT0AAAClsAAAAAAAAAAFhZWiAAAAAAAAD21gABAAAAANMtbWx1YwAAAAAAAAABAAAADGVuVVMAAAAgAAAAHABHAG8AbwBnAGwAZQAgAEkAbgBjAC4AIAAyADAAMQA2_9sAQwAQCwwODAoQDg0OEhEQExgoGhgWFhgxIyUdKDozPTw5Mzg3QEhcTkBEV0U3OFBtUVdfYmdoZz5NcXlwZHhcZWdj_9sAQwEREhIYFRgvGhovY0I4QmNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj_8AAEQgAsAB5AwEiAAIRAQMRAf_EABoAAAMBAQEBAAAAAAAAAAAAAAADBAUGBwH_xAAuEAACAgEDAgQFAwUAAAAAAAAAAwQTIwUUM0NTJGNzgwEGFTSjFkSTJTVRVbP_xAAWAQEBAQAAAAAAAAAAAAAAAAAAAwT_xAAWEQEBAQAAAAAAAAAAAAAAAAAAAxP_2gAMAwEAAhEDEQA_AOXAAJJGgAAABbUKtAaBLulH3er_AMAUgS7oLQKgAAAAAAAAAUNFDQAU0aSygFW2tFNACqoBQVAA31WhaHqhb5QDVNG9IltBvKSF6m2gKilQSKAAAAAAAVKariCS2pRLFVa0BsWA2U06OL8uKGwFVGyoNWTGb8uK6RB-nJR2Q0K5OSV8r4srTLlaM2K2pp6CSz1WqqBk4OVpbYuXpCukb09VraldLlMuerayvKaEkHEVErVFSuIJAAAJAAACCVyl-lqIJXKakAKydHFUaiiCKXqDUaNACQLaiCps_wApRfUNqKiDYKUqpSjnNUgVWnZGXqkW1QHBtxAobP8AumiovKGU0AAJAAACWVyl8VtRBK5RoVk6iLPVUXqnq7pySmqG1WqtUFdHZKlDbcpxsBrWtUo62q2KFVVo205eU2UrFaKiz225ZQHWkrcpKprW9X2irL1QPPtUxSmqFReIq17-6SvVFKxKDLUAABIAKGgKaovVFtUKV6VpqRVVNqCsksWB5RsqqVFqqG1CpXEGplqyz1KU2o6ipqov37fdUcvoyvH2nZcqqgINqpsXzW5SD6Wq3q-kbMBVUVShoGXFgVNxcRe23lUrKNqFNbU1VQHn09Tfqjbe6NGz8rbaiUMtQAoAkUNFDQGqL4sqppANUFZN7dNxYrSWe1o2LxCpUW0NRugtVbUdGclFgSt1iOo2rWqVlygFtTWjWylK5W1eqNqxBUSCrbeLKDVctvK0qIJ89UDK1uIqOS1ltuqN_iIBsqUpspre60UGAoAABQ0UADRooAN6K3wo1Uq0y4De6X1KaGps6XVaX905eLFVbbumqNlVTf3VvuhVqDeUlUqriaNtJAacl82yvFKV2jo5UqpTWt6RwcqVupTZTeqVSqUKACrKA90BQAAAFTQa0U1tQSsWICqLxGzAymDA4i9TaiSrrYsBVQ1WlqV1SCBPVVlNRUpXdCptQNDddoFKJDL17FpbWtOIby4jsvmOUprdr2srTl21N5alFUqoAKthitU1VQpqmqKpFAABJfKitUrEogqL_dt7pK1Vv2vSCqVXKoqaprWi4vw-Pw-OP4ZWcZuxYqm2ta3iUBlwDZ2BAqA2LFU3unZRVeFUSVYMXS2tNmLoylF6lVDbQqFKUog1TVFQFeaKn6ztcSuU5eVKbPbbaBqQLVaXKn9VuIy9ZUpUVXSaXym1QIsXtK_KY2vKqlKi9pQSKUq3FaKbuoGJtqhrVVKNTVIDVcSsX_IqkxlKU1WUq2vmilNUpuVXEX7qL_q_ygKbF2EVTeW3lJWxWxek06iVFtlKge60xpTW7prcoGNlVlN5U9X0tSlN8U3lFaxGUnS4vd5SVsXaqiylcTQNlWWBteqo6iB9qo4PS57d_l_Kd4rixEmqQaZc-VixGo3iOcnyuq0kMuUEBX9XbK_ajVW9VWVrcQ1srwFSv4mlUjVVStUytxKyt9UwZTbdUa3zTUbFlaXo2XqmDFU1rcRVJfKardKy4jeVKVKVi5fNOSlKaqVUdGrS27VTQMufaqeFoawqVUprVGWSH__Z2BhYW6RoZGlnZXN0SUQIZnJhbmRvbVC0gDHM3xUFKaiFRu1DAnUXcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVl2QPsajE5OTAtMDEtMDHYGFhTpGhkaWdlc3RJRAdmcmFuZG9tUNPRb_Jle7E5D-hepAv3TxVxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVlQWxpY2XYGFhbpGhkaWdlc3RJRAFmcmFuZG9tUPKBXZijF1d3_R04NtJz7C1xZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyMC0wMS0wMdgYWFykaGRpZ2VzdElEAGZyYW5kb21QgHykf2kk9Y9_jhM0BAAitHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNS0wMS0wMdgYWFSkaGRpZ2VzdElECWZyYW5kb21QulAkqm6fqkRXlxcbNvrUc3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGjYGFhbpGhkaWdlc3RJRARmcmFuZG9tUOTooDeEwCnlGLbbzY-ver5xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZWhBQkNEMTIzNNgYWFWkaGRpZ2VzdElECmZyYW5kb21Q_ctRuMUlAkselcS8sFjbJHFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYlVT2BhYW6RoZGlnZXN0SUQGZnJhbmRvbVC_I_4SIn8VRu_qWxcclHpNcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR5bGVsZW1lbnRWYWx1ZWZOWSxVU0HYGFjvpGhkaWdlc3RJRAJmcmFuZG9tUFoPu1Ae76m2ftDBo8H1DU9xZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZYKjamlzc3VlX2RhdGXZA-xqMjAyMC0wMS0wMWtleHBpcnlfZGF0ZdkD7GoyMDI1LTAxLTAxdXZlaGljbGVfY2F0ZWdvcnlfY29kZWFCo2ppc3N1ZV9kYXRl2QPsajIwMjAtMDEtMDFrZXhwaXJ5X2RhdGXZA-xqMjAyNS0wMS0wMXV2ZWhpY2xlX2NhdGVnb3J5X2NvZGViQkXYGFhdpGhkaWdlc3RJRANmcmFuZG9tUADrjtIGo37dMzctfKHT9J1xZWxlbWVudElkZW50aWZpZXJ2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbmxlbGVtZW50VmFsdWVjVVNB";
        let cbor = Base64UrlUnpadded::decode_vec(VP_TOKEN).expect("should decode");
        let _device_response = serde_cbor::from_slice::<DeviceResponse>(&cbor).unwrap();
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
