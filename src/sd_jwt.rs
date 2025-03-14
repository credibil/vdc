//! # SD-JWT-based Verifiable Credentials (SD-JWT VC)
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
use credibil_did::PublicKeyJwk;
use credibil_infosec::Signer;
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::oid4vci::types::{CredentialConfiguration, Format};

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct DcSdJwtBuilder<G, I, H, C, S> {
    config: G,
    issuer: I,
    holder: H,
    claims: C,
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

/// Builder has no holder.
#[doc(hidden)]
pub struct NoHolder;
/// Builder has holder.
#[doc(hidden)]
pub struct HasHolder(String);

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

impl Default for DcSdJwtBuilder<NoConfig, NoIssuer, NoHolder, NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DcSdJwtBuilder<NoConfig, NoIssuer, NoHolder, NoClaims, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: NoConfig,
            issuer: NoIssuer,
            holder: NoHolder,
            claims: NoClaims,
            signer: NoSigner,
        }
    }
}

// Credential configuration
impl<I, H, C, S> DcSdJwtBuilder<NoConfig, I, H, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn config(self, cfg: CredentialConfiguration) -> DcSdJwtBuilder<HasConfig, I, H, C, S> {
        DcSdJwtBuilder {
            config: HasConfig(cfg),
            issuer: self.issuer,
            holder: self.holder,
            claims: self.claims,
            signer: self.signer,
        }
    }
}

// Issuer
impl<G, H, C, S> DcSdJwtBuilder<G, NoIssuer, H, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn issuer(self, issuer: impl Into<String>) -> DcSdJwtBuilder<G, HasIssuer, H, C, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: HasIssuer(issuer.into()),
            holder: self.holder,
            claims: self.claims,
            signer: self.signer,
        }
    }
}

// Holder
impl<G, I, C, S> DcSdJwtBuilder<G, I, NoHolder, C, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn holder(self, holder: impl Into<String>) -> DcSdJwtBuilder<G, I, HasHolder, C, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            holder: HasHolder(holder.into()),
            claims: self.claims,
            signer: self.signer,
        }
    }
}

// Claims
impl<G, I, H, S> DcSdJwtBuilder<G, I, H, NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn claims(self, claims: Map<String, Value>) -> DcSdJwtBuilder<G, I, H, HasClaims, S> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            holder: self.holder,
            claims: HasClaims(claims),
            signer: self.signer,
        }
    }
}

// Signer
impl<G, I, H, C> DcSdJwtBuilder<G, I, H, C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &'_ S) -> DcSdJwtBuilder<G, I, H, C, HasSigner<'_, S>> {
        DcSdJwtBuilder {
            config: self.config,
            issuer: self.issuer,
            holder: self.holder,
            claims: self.claims,
            signer: HasSigner(signer),
        }
    }
}

impl<S: Signer> DcSdJwtBuilder<HasConfig, HasIssuer, HasHolder, HasClaims, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT
    /// with the format `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~`
    ///
    /// # Errors
    /// TODO: Document errors
    pub fn build(self) -> Result<String> {
        let Format::DcSdJwt(sd_jwt) = self.config.0.format else {
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
        let vc_claims = SdJwtVcClaims {
            sd: sd_hashes.clone(),
            vct: sd_jwt.vct,
            iss: self.issuer.0,
            nbf: Some(Utc::now()),
            exp: Some(Utc::now()),
            // cnf: Some(self.signer.0.verifying_key()),
            status: None,
            sub: Some(self.holder.0),
            iat: Some(Utc::now()),

            ..SdJwtVcClaims::default()
        };

        let jwt = serde_json::to_string(&vc_claims)?;

        // concatenate disclosures
        let sd_jwt = format!("{jwt}~{}", disclosures.join("~"));

        Ok(sd_jwt)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
/// Claims that can be included in the payload of SD-JWT VCs.
pub struct SdJwtVcClaims {
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

    /// Contains a public key associated with the Holder (as presented to the
    /// Issuer via proof-of-possession of key material) in order to provide
    /// confirmation of cryptographic Key Binding.
    ///
    /// The Key Binding JWT in the SD-JWT presentation must be secured by the
    /// key identified in this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<PublicKeyJwk>,

    /// The information on how to read the status of the Verifiable Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use credibil_infosec::{Algorithm, Signer};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    use super::DcSdJwtBuilder;
    use crate::oid4vci::types::{CredentialConfiguration, Format, ProfileSdJwt};

    #[test]
    fn test_claims() {
        let cfg = CredentialConfiguration {
            format: Format::DcSdJwt(ProfileSdJwt {
                vct: "https://credentials.example.com/identity_credential".to_string(),
            }),
            ..CredentialConfiguration::default()
        };

        // create claims
        let claims_json = json!({
            "name": "Alice",
            "age": 25
        });
        let claims = claims_json.as_object().unwrap();

        // serialize to SD-JWT
        let x = DcSdJwtBuilder::new()
            .config(cfg)
            .issuer("https://example.com")
            .holder("did:example:123")
            .claims(claims.clone())
            .signer(&Keyring::new())
            .build();
        println!("x: {:?}", x);
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
            unimplemented!()
        }
    }
}
