//! Bitstring-based status list validation errors.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard error codes for bitstring-based status list validation.
///
/// The standard calls for returning strongly typed errors when a verifier
/// attempts to validate a verifiable credential against a published status
/// list.
///
/// [Processing Errors](https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors)
#[derive(Error, Debug, Deserialize)]
pub enum Error {
    /// Retrievel of the status list failed.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-128", "code": -128, "title": "status retrieval error", "detail": "{0}"}}"#)]
    Retrieval(String),

    /// Validation of the status entry failed.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-129", "code": -129, "title": "status verification error", "detail": "{0}"}}"#)]
    Verification(String),

    /// The status list length does not satisfy the minimum length required for
    /// herd privacy.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-130", "code": -130, "title": "status list length error", "detail": "{0}"}}"#)]
    ListLength(String),

    /// The index into the status list is larger than the length of the list.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-67", "code": -67, "title": "range error", "detail": "{0}"}}"#)]
    Range(String),
}

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerdeError;

        let Ok(error) = serde_json::from_str::<ValidationError>(&self.to_string()) else {
            return Err(SerdeError::custom("failed to serialize error"));
        };
        error.serialize(serializer)
    }
}

impl Error {
    /// Transform error to `ValidationError` compatible json format.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.to_string()).unwrap_or_default()
    }
}

/// Error response for bitstring status list validation.
///
/// [Processing Errors](https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors)
/// [RFC 9457: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
#[derive(Deserialize, Serialize)]
pub struct ValidationError {
    /// Type of error in URL format.
    ///
    /// The type value of the error object MUST be a URL that starts with the
    /// value `https://www.w3.org/ns/credentials/status-list#` and ends with the
    /// value in the section listed below.
    #[serde(rename = "type")]
    pub type_: String,

    /// Integer code
    ///
    /// The code value MUST be the integer code described in the specification.
    pub code: i32,

    /// Title
    ///
    /// The title value SHOULD provide a short but specific human-readable
    /// string for the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Detail
    ///
    /// The detail value SHOULD provide a longer human-readable string for the
    /// error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
