//! # `OpenID` Errors
//!
//! This module defines errors for `OpenID` for Verifiable Credential Issuance
//! and Verifiable Presentations.

// TODO: add support for "client-state" in error responses.
// TODO: use custom serialisation for Err enum.

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::core::urlencode;

/// `OpenID` error codes for  for Verifiable Credential Issuance and
/// Presentation.
#[derive(Error, Debug, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value, repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the client, or is
    /// otherwise malformed.
    #[error(r#"{{"error": "invalid_request", "error_description": "{0}"}}"#)]
    InvalidRequest(String),

    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    #[error(r#"{{"error": "unsupported_response_type", "error_description": "{0}"}}"#)]
    UnsupportedResponseType(String),

    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    #[error(r#"{{"error": "server_error", "error_description": "{0}"}}"#)]
    ServerError(String),

    /// The Wallet does not support any of the formats requested by the
    /// Verifier, such as those included in the `vp_formats` registration
    /// parameter.
    #[error(r#"{{"error": "vp_formats_not_supported", "error_description": "{0}"}}"#)]
    VpFormatsNotSupported(String),

    /// The Presentation Definition URL cannot be reached.
    #[error(r#"{{"error": "invalid_presentation_definition_uri", "error_description": "{0}"}}"#)]
    InvalidPresentationDefinitionUri(String),

    /// The Presentation Definition URL can be reached, but the specified
    /// `presentation_definition` cannot be found at the URL.
    #[error(
        r#"{{"error": "invalid_presentation_definition_reference", "error_description": "{0}"}}"#
    )]
    InvalidPresentationDefinitionReference(String),

    /// The Wallet appears to be unavailable and therefore unable to respond to
    /// the request.
    /// Use when the User Agent cannot invoke the Wallet and another component
    /// receives the request while the End-User wishes to continue the journey
    /// on the Verifier website.
    #[error(r#"{{"error": "wallet_unavailable", "error_description": "{0}"}}"#)]
    WalletUnavailable(String),
}

/// Error response for `OpenID` for Verifiable Credentials.
#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct OidError {
    /// Error code.
    pub error: String,

    /// Error description.
    pub error_description: String,

    /// Optional client-state parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// A fresh `c_nonce` to use when retrying Proof submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// The expiry time of the `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerdeError;

        let Ok(error) = serde_json::from_str::<OidError>(&self.to_string()) else {
            return Err(SerdeError::custom("issue deserializing Err"));
        };
        error.serialize(serializer)
    }
}

impl Error {
    /// Transfrom error to `OpenID` compatible json format.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.to_string()).unwrap_or_default()
    }

    /// Transfrom error to `OpenID` compatible query string format.
    /// Does not include `c_nonce` as this is not required for in query
    /// string responses.
    #[must_use]
    pub fn to_querystring(&self) -> String {
        urlencode::to_string(&self).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn err_json() {
        let err = Error::InvalidRequest("bad request".to_string());
        let ser: Value = serde_json::from_str(&err.to_string()).unwrap();
        assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn err_querystring() {
        let err = Error::InvalidRequest("Invalid request description".to_string());
        let ser = urlencode::to_string(&err).unwrap();
        assert_eq!(ser, "error=invalid_request&error_description=Invalid%20request%20description");
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn err_serialize() {
        let err = Error::InvalidRequest("bad request".to_string());
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
    }
}
