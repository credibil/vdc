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

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use credibil_did::PublicKeyJwk;
use credibil_infosec::Signer;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Generate an IETF `dc+sd-jwt` format credential.
#[derive(Debug)]
pub struct DcSdJwtBuilder<C, S> {
    claims: C,
    signer: S,
}

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signer>(pub &'a S);

/// Builder has no claims.
#[doc(hidden)]
pub struct NoClaims;
/// Builder has claims.
#[doc(hidden)]
pub struct HasClaims(Map<String, Value>);

impl Default for DcSdJwtBuilder<NoClaims, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DcSdJwtBuilder<NoClaims, NoSigner> {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            claims: NoClaims,
            signer: NoSigner,
        }
    }
}

impl<C> DcSdJwtBuilder<C, NoSigner> {
    /// Set the credential Signer.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &'_ S) -> DcSdJwtBuilder<C, HasSigner<'_, S>> {
        DcSdJwtBuilder {
            claims: self.claims,
            signer: HasSigner(signer),
        }
    }
}

impl<S> DcSdJwtBuilder<NoClaims, S> {
    /// Set the claims for the ISO mDL credential.
    #[must_use]
    pub fn claims(self, claims: Map<String, Value>) -> DcSdJwtBuilder<HasClaims, S> {
        DcSdJwtBuilder {
            claims: HasClaims(claims),
            signer: self.signer,
        }
    }
}

impl<S: Signer> DcSdJwtBuilder<HasClaims, HasSigner<'_, S>> {
    /// Build the SD-JWT credential, returning a base64url-encoded, JSON SD-JWT.
    ///
    /// # Errors
    /// TODO: Document errors
    pub fn build(self) -> anyhow::Result<String> {
        // Disclosure:
        //  1. Construct an array ["<b64 Salt>","<Claim Name>","<Claim Value>"].
        //  2. JSON-encode the array.
        //  3. base64url-encode the JSON array.

        // create disclosures
        let mut disclosures = vec![];
        for (name, value) in self.claims.0 {
            let salt_bytes = rand::rng().random::<[u8; 32]>();
            let as_json = serde_json::to_vec(&json!([
                Base64UrlUnpadded::encode_string(&salt_bytes),
                name,
                value
            ]))?;
            disclosures.push(Base64UrlUnpadded::encode_string(&as_json));
        }

        println!("disclosures: {disclosures:?}");

        todo!()
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

/// Object property disclosure.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Disclosure {
    /// The salt consists of a minimum of 128 bits of cryptographically secure
    /// random data, base64url-encoded. It must only be revealed to the Holder.
    pub salt: String,

    /// The name of the claim to be disclosed, as it would appear in a regular JWT.
    pub claim_name: String,

    /// The value of the claim to be disclosed.
    pub claim_value: Value,
}

#[cfg(test)]
mod tests {

    // use super::*;

    #[test]
    fn test_claims() {

        // create VC

        // serialize to SD-JWT
    }
}
