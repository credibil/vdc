//! # `OpenID` Errors
//!
//! This module defines errors for `OpenID` for Verifiable Credential Issuance
//! and Verifiable Presentations.

// TODO: add support for "client-state" in error responses.
// TODO: use custom serialisation for Err enum.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::urlencode;

/// `OpenID` error codes for  for Verifiable Credential Issuance and
/// Presentation.
#[derive(Error, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error", content = "error_description")]
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
    /// Verifier, such as those included in the `vp_format_supported` registration
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

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<Self>() {
            Some(Self::InvalidRequest(e)) => Self::InvalidRequest(format!("{err}: {e}")),
            Some(Self::UnsupportedResponseType(e)) => {
                Self::UnsupportedResponseType(format!("{err}: {e}"))
            }
            Some(Self::ServerError(e)) => Self::ServerError(format!("{err}: {e}")),
            Some(Self::VpFormatsNotSupported(e)) => {
                Self::VpFormatsNotSupported(format!("{err}: {e}"))
            }
            Some(Self::InvalidPresentationDefinitionUri(e)) => {
                Self::InvalidPresentationDefinitionUri(format!("{err}: {e}"))
            }
            Some(Self::InvalidPresentationDefinitionReference(e)) => {
                Self::InvalidPresentationDefinitionReference(format!("{err}: {e}"))
            }
            Some(Self::WalletUnavailable(e)) => Self::WalletUnavailable(format!("{err}: {e}")),
            None => {
                let source = err.source().map_or_else(String::new, ToString::to_string);
                Self::ServerError(format!("{err}: {source}"))
            }
        }
    }
}

/// Construct an `Error::InvalidRequest` error from a string or existing error
/// value.
macro_rules! invalid {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::oid4vp::Error::InvalidRequest(format!($fmt, $($arg)*))
    };
     ($err:expr $(,)?) => {
        $crate::oid4vp::Error::InvalidRequest(format!($err))
    };
}
pub(crate) use invalid;

#[cfg(test)]
mod test {
    use anyhow::{Context, Result, anyhow};
    use serde_json::{Value, json};

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn oid4vp_context() {
        let err = oid4vp_error().unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"{"error": "invalid_request", "error_description": "request context: some invalid request"}"#
        );
    }
    fn oid4vp_error() -> Result<(), Error> {
        Err(Error::InvalidRequest("some invalid request".to_string())).context("request context")?
    }

    #[test]
    fn anyhow_context() {
        let err = anyhow_error().unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"{"error": "server_error", "error_description": "error context: one-off error"}"#
        );
    }
    fn anyhow_error() -> Result<(), Error> {
        Err(anyhow!("one-off error")).context("error context")?
    }

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
