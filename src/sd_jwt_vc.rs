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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
/// Claims that can be included in the payload of SD-JWT VCs.
pub struct SdJwtVcClaims {
    /// The Issuer (as a URI) of the Verifiable Credential.
    pub iss: String,

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

    /// Contains the confirmation method of Key Binding. The Key Binding JWT in
    /// the presentation of the SD-JWT MUST be secured by the key identified in
    /// this claim.
    ///
    /// OPTIONAL unless cryptographic Key Binding is to be supported, in which
    /// case it is REQUIRED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<PublicKeyJwk>,

    /// The identifier of the Subject of the Verifiable Credential. The Issuer
    /// MAY use it to provide the Subject identifier known by the Issuer. There
    /// is no requirement for a binding to exist between sub and cnf claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    ///  The time of issuance of the Verifiable Credential.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<DateTime<Utc>>,

    /// The type of Verifiable Credential represented.
    /// For example, `https://credentials.example.com/identity_credential`
    pub vct: String,

    /// VCT integrity metadata.
    #[serde(rename = "vct#integrity")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct_integrity: Option<String>,

    /// The information on how to read the status of the Verifiable Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}
