// use anyhow::{Result, anyhow};
// use base64ct::{Base64UrlUnpadded, Encoding};
// use chrono::Utc;
// use credibil_infosec::{Jws, Signer};
// use sha2::{Digest, Sha256};

// use crate::oid4vp::IssuedFormat;
// use crate::oid4vp::types::Queryable;
// use crate::format::sd_jwt::{Disclosure, JwtType, KbJwtClaims};
// use crate::server;

// /// Generate an IETF `dc+sd-jwt` format credential.
// #[derive(Debug)]
// pub struct DeviceResponseBuilder<Q, V, S> {
//     queryable: Q,
//     verifier: V,
//     nonce: Option<String>,
//     signer: S,
// }

// /// Builder has no claims.
// #[doc(hidden)]
// pub struct NoQueryable;
// /// Builder has claims.
// #[doc(hidden)]
// pub struct HasQueryable(Queryable);

// /// Builder has no issuer.
// #[doc(hidden)]
// pub struct NoVerifier;
// /// Builder has issuer.
// #[doc(hidden)]
// pub struct HasVerifier(String);

// /// Builder has no signer.
// #[doc(hidden)]
// pub struct NoSigner;
// /// Builder state has a signer.
// #[doc(hidden)]
// pub struct HasSigner<'a, S: Signer>(pub &'a S);

// impl Default for DeviceResponseBuilder<NoQueryable, NoVerifier, NoSigner> {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl DeviceResponseBuilder<NoQueryable, NoVerifier, NoSigner> {
//     /// Create a new builder.
//     #[must_use]
//     pub const fn new() -> Self {
//         Self {
//             queryable: NoQueryable,
//             verifier: NoVerifier,
//             nonce: None,
//             signer: NoSigner,
//         }
//     }
// }

// // Credentials to include in the presentation
// impl<V, S> DeviceResponseBuilder<NoQueryable, V, S> {
//     /// Set the claims for the ISO mDL credential.
//     #[must_use]
//     pub fn queryable(self, queryable: Queryable) -> DeviceResponseBuilder<HasQueryable, V, S> {
//         DeviceResponseBuilder {
//             queryable: HasQueryable(queryable),
//             verifier: self.verifier,
//             nonce: self.nonce,
//             signer: self.signer,
//         }
//     }
// }

// // Credentials to include in the presentation
// impl<Q, S> DeviceResponseBuilder<Q, HasVerifier, S> {
//     /// Set the claims for the ISO mDL credential.
//     #[must_use]
//     pub fn verifier(self, verifier: String) -> Self {
//         Self {
//             queryable: self.queryable,
//             verifier: HasVerifier(verifier),
//             nonce: self.nonce,
//             signer: self.signer,
//         }
//     }
// }

// // Optional fields
// impl<Q, V, S> DeviceResponseBuilder<Q, V, S> {
//     /// Set the credential Holder.
//     #[must_use]
//     pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
//         self.nonce = Some(nonce.into());
//         self
//     }
// }

// // Signer
// impl<Q, V> DeviceResponseBuilder<Q, V, NoSigner> {
//     /// Set the credential Signer.
//     #[must_use]
//     pub fn signer<S: Signer>(self, signer: &'_ S) -> DeviceResponseBuilder<Q, V, HasSigner<'_, S>> {
//         DeviceResponseBuilder {
//             queryable: self.queryable,
//             verifier: self.verifier,
//             nonce: self.nonce,
//             signer: HasSigner(signer),
//         }
//     }
// }

// impl<S: Signer> DeviceResponseBuilder<HasQueryable, HasVerifier, HasSigner<'_, S>> {
//     /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
//     /// with the format: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>`.
//     ///
//     /// # Errors
//     /// TODO: Document errors
//     pub async fn build(self) -> Result<String> {
//         let queryable = self.queryable.0;

//         // 1. issued SD-JWT
//         let IssuedFormat::DcSdJwt(issued) = queryable.issued else {
//             return Err(anyhow!("Invalid issued claim type"));
//         };

//         // 2. disclosures
//         let mut disclosures = vec![];
//         for claim in &queryable.claims {
//             let disclosure =
//                 Disclosure::new(&claim.path[claim.path.len() - 1], claim.value.clone());
//             disclosures.push(disclosure.encoded()?);
//         }

//         // 3. key binding JWT
//         let sd = format!("{issued}~{}", disclosures.join("~"));
//         let sd_hash = Sha256::digest(&sd);

//         let claims = KbJwtClaims {
//             nonce: self.nonce.unwrap_or_default(),
//             aud: self.verifier.0,
//             iat: Utc::now(),
//             sd_hash: Base64UrlUnpadded::encode_string(sd_hash.as_slice()),
//         };

//         let kb_jwt = Jws::builder()
//             .typ(JwtType::KbJwt)
//             .payload(claims)
//             .add_signer(self.signer.0)
//             .build()
//             .await
//             .map_err(|e| server!("issue signing SD-JWT: {e}"))?
//             .to_string();

//         // assemble
//         let presentation = format!("{sd}~{kb_jwt}");
//         Ok(presentation)
//     }
// }
