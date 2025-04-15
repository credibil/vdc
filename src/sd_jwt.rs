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

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use credibil_did::SignerExt;
use credibil_infosec::{Jws, PublicKeyJwk};
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::oid4vci::JwtType;
use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};
use crate::server;

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct DcSdJwtBuilder<G, I, K, C, S> {
    config: G,
    issuer: I,
    key_binding: K,
    claims: C,
    holder: Option<String>,
    // status: Option<OneMany<CredentialStatus>>,
    signer: S,
}

/// Builder has no credential configuration.
#[doc(hidden)]
pub struct NoConfig;
/// Builder has credential configuration.
#[doc(hidden)]
pub struct HasConfig(CredentialConfiguration);

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
pub struct HasSigner<'a, S: SignerExt>(pub &'a S);

impl Default for DcSdJwtBuilder<NoConfig, NoIssuer, NoKeyBinding, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DcSdJwtBuilder<NoConfig, NoIssuer, NoKeyBinding, NoClaims, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: NoConfig,
            issuer: NoIssuer,
            key_binding: NoKeyBinding,
            claims: NoClaims,
            holder: None,
            signer: NoSigner,
        }
    }
}

// Credential configuration
impl<I, K, C, S> DcSdJwtBuilder<NoConfig, I, K, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn config(self, cfg: CredentialConfiguration) -> DcSdJwtBuilder<HasConfig, I, K, C, S> {
        DcSdJwtBuilder {
            config: HasConfig(cfg),
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Issuer
impl<G, K, C, S> DcSdJwtBuilder<G, NoIssuer, K, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn issuer(self, issuer: impl Into<String>) -> DcSdJwtBuilder<G, HasIssuer, K, C, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: HasIssuer(issuer.into()),
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// KeyBinding
impl<G, I, C, S> DcSdJwtBuilder<G, I, NoKeyBinding, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn key_binding(
        self, key_binding: PublicKeyJwk,
    ) -> DcSdJwtBuilder<G, I, HasKeyBinding, C, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            key_binding: HasKeyBinding(key_binding),
            claims: self.claims,
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Claims
impl<G, I, K, S> DcSdJwtBuilder<G, I, K, NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn claims(self, claims: Map<String, Value>) -> DcSdJwtBuilder<G, I, K, HasClaims, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: HasClaims(claims),
            holder: self.holder,
            signer: self.signer,
        }
    }
}

// Optional fields
impl<G, I, K, C, S> DcSdJwtBuilder<G, I, K, C, S> {
    /// Set the credential Holder.
    #[must_use]
    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }
}

// Signer
impl<G, I, K, C> DcSdJwtBuilder<G, I, K, C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: SignerExt>(self, signer: &'_ S) -> DcSdJwtBuilder<G, I, K, C, HasSigner<'_, S>> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            key_binding: self.key_binding,
            claims: self.claims,
            holder: self.holder,
            signer: HasSigner(signer),
        }
    }
}

impl<S: SignerExt> DcSdJwtBuilder<HasConfig, HasIssuer, HasKeyBinding, HasClaims, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~`
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn build(self) -> Result<String> {
        let FormatProfile::DcSdJwt { vct } = self.config.0.profile else {
            return Err(anyhow!("Credential configuration format is invalid"));
        };

        // for each disclosure:
        //  1. construct an array ["<b64 Salt>","<Claim Name>","<Claim Value>"].
        //  2. JSON-encode the array.
        //  3. base64url-encode the JSON array.
        let mut disclosures = vec![];
        let mut sd_hashes = vec![];
        for (name, value) in self.claims.0 {
            let salt = Base64UrlUnpadded::encode_string(&rng().random::<[u8; 16]>());
            let sd_json = serde_json::to_vec(&json!([salt, name, value]))?;
            let disclosure = Base64UrlUnpadded::encode_string(&sd_json);
            let sd_hash = Base64UrlUnpadded::encode_string(Sha256::digest(&disclosure).as_slice());

            disclosures.push(disclosure);
            sd_hashes.push(sd_hash);
        }

        // create JWT (and sign)
        let claims = SdJwtClaims {
            sd: sd_hashes.clone(),
            iss: self.issuer.0,
            iat: Some(Utc::now()),
            // exp: Some(Utc::now()),
            vct,
            sd_alg: Some("sha-256".to_string()),
            cnf: Some(Binding::Jwk(self.key_binding.0)),
            // status: None,
            sub: self.holder,

            ..SdJwtClaims::default()
        };

        let key_id = self.signer.0.verification_method().await.map_err(|e| {
            server!("issue getting verification method: {e}")
        })?;

        let jws = Jws::builder()
            .typ(JwtType::SdJwt)
            .payload(claims)
            .key_ref(&key_id)
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
/// Claims that can be included in the payload of SD-JWT VCs.
#[serde(default)]
pub struct SdJwtClaims {
    /// Digests of selective disclosure claims. Each digest is a hash (using
    /// `_sd_alg` hashing algortith) of the base65url-encoded Disclosure.
    #[serde(rename = "_sd")]
    pub sd: Vec<String>,

    /// Algorithm used to generate `_sd` digests. A default of `sha-256` is
    /// used when not set.
    #[serde(rename = "_sd_alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sd_alg: Option<String>,

    /// The type of Verifiable Credential represented.
    /// For example, `https://credentials.example.com/identity_credential`
    pub vct: String,

    /// VCT integrity metadata.
    #[serde(rename = "vct#integrity")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct_integrity: Option<String>,

    /// The Issuer (as a URI) of the Verifiable Credential.
    pub iss: String,

    /// The time of issuance of the Verifiable Credential.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<DateTime<Utc>>,

    /// The time before which the Verifiable Credential must not be accepted
    /// before validating.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<DateTime<Utc>>,

    /// The expiry time of the Verifiable Credential after which it is no longer
    /// valid.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<DateTime<Utc>>,

    /// The identifier of the Subject of the Verifiable Credential. The Issuer
    /// MAY use it to provide the Subject identifier known by the Issuer. There
    /// is no requirement for a binding to exist between sub and cnf claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Contains a public key associated with the key binding (as presented to
    /// the Issuer via proof-of-possession of key material) in order to provide
    /// confirmation of cryptographic Key Binding.
    ///
    /// The Key Binding JWT in the SD-JWT presentation must be secured by the
    /// key identified in this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Binding>,

    /// The information on how to read the status of the Verifiable Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// The type of binding between the SD-JWT and the public key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// The public key is bound to the SD-JWT using a JWK.
    Jwk(PublicKeyJwk),
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use credibil_did::SignerExt;
    use credibil_infosec::{jose::jws::Key, Algorithm, Curve, KeyType, PublicKeyJwk, Signer};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    use super::DcSdJwtBuilder;
    use crate::oid4vci::types::{CredentialConfiguration, FormatProfile};

    #[tokio::test]
    async fn test_claims() {
        let cfg = CredentialConfiguration {
            profile: FormatProfile::DcSdJwt {
                vct: "https://company.example/company_rewards".to_string(),
            },
            ..CredentialConfiguration::default()
        };

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
        let jwt = DcSdJwtBuilder::new()
            .config(cfg)
            .issuer("https://example.com")
            .key_binding(jwk)
            .claims(claims.clone())
            .signer(&Keyring::new())
            .build()
            .await
            .expect("should build");

        println!("{jwt}");
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
    }

    impl SignerExt for Keyring {
        async fn verification_method(&self) -> Result<Key> {
            Ok(Key::KeyId("did:example:123#key-1".to_string()))
        }
    }
}
