//! # IETF SD-JWT-based Credential Format
//!
//! This module provides the implementation of SD-JWT-based Verifiable
//! Credentials (SD-JWT VC).
//!
//! Encompasses data formats as well as validation and processing rules to
//! express Verifiable Credentials with JSON payloads with and without
//! selective disclosure based on the SD-JWT [I-D.ietf-oauth-sd-jwt-vc] format.
//!
//! [I-D.ietf-oauth-sd-jwt-vc]: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-17.html

use anyhow::Result;
use chrono::Utc;
use credibil_did::PublicKeyJwk;
use credibil_infosec::{Jws, Signer};
use serde_json::{Map, Value};

use crate::format::sd_jwt::{Disclosure, JwtType, KeyBinding, SdJwtClaims};
use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct SdJwtVcBuilder<V, I, K, C, S> {
    vct: V,
    issuer: I,
    key_binding: K,
    claims: C,
    holder: Option<String>,
    // status: Option<OneMany<CredentialStatus>>,
    signer: S,
}

/// Builder has no credential configuration.
#[doc(hidden)]
pub struct NoVct;
/// Builder has credential configuration.
#[doc(hidden)]
pub struct Vct(String);

/// Builder has no issuer.
#[doc(hidden)]
pub struct NoIssuer;
/// Builder has issuer.
#[doc(hidden)]
pub struct HasIssuer(String);

/// Builder has no key_binding.
#[doc(hidden)]
pub struct NoKeyBinding;
/// Builder has key_binding.
#[doc(hidden)]
pub struct HasKeyBinding(PublicKeyJwk);

/// Builder has no claims.
#[doc(hidden)]
pub struct NoClaims;
/// Builder has claims.
#[doc(hidden)]
pub struct HasClaims(Map<String, Value>);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signer>(pub &'a S);

impl Default for SdJwtVcBuilder<NoVct, NoIssuer, NoKeyBinding, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl SdJwtVcBuilder<NoVct, NoIssuer, NoKeyBinding, NoClaims, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vct: NoVct,
            issuer: NoIssuer,
            key_binding: NoKeyBinding,
            claims: NoClaims,
            holder: None,
            signer: NoSigner,
        }
    }
}

// Credential configuration
impl<I, K, C, S> SdJwtVcBuilder<NoVct, I, K, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn vct(self, vct: impl Into<String>) -> SdJwtVcBuilder<Vct, I, K, C, S> {
        SdJwtVcBuilder {
            vct: Vct(vct.into()),
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Issuer
impl<V, K, C, S> SdJwtVcBuilder<V, NoIssuer, K, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn issuer(self, issuer: impl Into<String>) -> SdJwtVcBuilder<V, HasIssuer, K, C, S> {
        SdJwtVcBuilder {
            vct: self.vct,
            issuer: HasIssuer(issuer.into()),
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// KeyBinding
impl<V, I, C, S> SdJwtVcBuilder<V, I, NoKeyBinding, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn key_binding(
        self, key_binding: PublicKeyJwk,
    ) -> SdJwtVcBuilder<V, I, HasKeyBinding, C, S> {
        SdJwtVcBuilder {
            vct: self.vct,
            issuer: self.issuer,
            key_binding: HasKeyBinding(key_binding),
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Claims
impl<V, I, K, S> SdJwtVcBuilder<V, I, K, NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn claims(self, claims: Map<String, Value>) -> SdJwtVcBuilder<V, I, K, HasClaims, S> {
        SdJwtVcBuilder {
            vct: self.vct,
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: HasClaims(claims),
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<V, I, K, C, S> SdJwtVcBuilder<V, I, K, C, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }
}

// Signer
impl<V, I, K, C> SdJwtVcBuilder<V, I, K, C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &'_ S) -> SdJwtVcBuilder<V, I, K, C, HasSigner<'_, S>> {
        SdJwtVcBuilder {
            vct: self.vct,
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: HasSigner(signer),
        }
    }
}

impl<S: Signer> SdJwtVcBuilder<Vct, HasIssuer, HasKeyBinding, HasClaims, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~`
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let mut disclosures = vec![];
        let mut sd_hashes = vec![];

        // TODO: create disclosure for nested claims
        // create disclosures
        for (name, value) in self.claims.0 {
            let disclosure = Disclosure::new(name, value);
            disclosures.push(disclosure.encoded()?);
            sd_hashes.push(disclosure.hashed()?);
        }

        // create JWT (and sign)
        let claims = SdJwtClaims {
            sd: sd_hashes.clone(),
            iss: self.issuer.0,
            iat: Some(Utc::now()),
            // exp: Some(Utc::now()),
            vct: self.vct.0,
            sd_alg: Some("sha-256".to_string()),
            cnf: Some(KeyBinding::Jwk(self.key_binding.0)),
            // status: None,
            sub: self.holder,
            ..SdJwtClaims::default()
        };

        let jws = Jws::builder()
            .typ(JwtType::SdJwt)
            .payload(claims)
            .add_signer(self.signer.0)
            .build()
            .await
            .map_err(|e| server!("issue signing SD-JWT: {e}"))?
            .to_string();

        // concatenate disclosures
        let sd_jwt = format!("{jws}~{}", disclosures.join("~"));

        Ok(sd_jwt)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use credibil_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk, Signer};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    use super::SdJwtVcBuilder;

    #[tokio::test]
    async fn test_claims() {
        // create claims
        let claims_json = json!({
            "given_name": "Alice",
            "family_name": "Holder",
            "address": {
                "street_address": "123 Elm St",
                "locality": "Hollywood",
                "region": "CA",
                "postal_code": "90210",
                "country": "USA"
            },
            "birthdate": "2000-01-01"
        });
        let claims = claims_json.as_object().unwrap();

        let jwk = PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: "x".to_string(),
            ..PublicKeyJwk::default()
        };

        // serialize to SD-JWT
        let sd_jwt = SdJwtVcBuilder::new()
            .vct("https://credentials.example.com/identity_credential")
            .issuer("https://example.com")
            .key_binding(jwk)
            .claims(claims.clone())
            .signer(&Keyring::new())
            .build()
            .await
            .expect("should build");

        println!("{sd_jwt}");
    }

    #[derive(Clone, Debug)]
    pub struct Keyring {
        signing_key: SigningKey,
    }

    impl Keyring {
        pub fn new() -> Self {
            Self {
                signing_key: SigningKey::generate(&mut OsRng),
            }
        }
    }

    impl Signer for Keyring {
        async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            Ok(self.signing_key.sign(msg).to_bytes().to_vec())
        }

        async fn verifying_key(&self) -> Result<Vec<u8>> {
            Ok(self.signing_key.verifying_key().as_bytes().to_vec())
        }

        fn algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }

        async fn verification_method(&self) -> Result<String> {
            Ok("did:example:123#key-1".to_string())
        }
    }
}
