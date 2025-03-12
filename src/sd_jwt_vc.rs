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

use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use credibil_did::PublicKeyJwk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Disclosure:
//  1. Construct an array ["<b64 Salt>","<Claim Name>","<Claim Value>"].
//  2. JSON-encode the array.
//  3. base64url-encode the JSON array.
//
// SD-JWT with Disclosures: <Issuer-signed JWT>~<b64 Disclosure 1>~<b64 Disclosure N>~

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
