//! # `OpenID` Errors
//!
//! This module defines errors for `OpenID` for Verifiable Credential Issuance
//! and Verifiable Presentations.

// TODO: add support for "client-state" in error responses.
// TODO: use custom serialisation for Err enum.

use serde::{Deserialize, Serialize};
use thiserror::Error;

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

    // #[error(r#"{{"error": "test"}}"#)]
    // Test,
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
                let stack = err.chain().fold(String::new(), |cause, e| format!("{cause} -> {e}"));
                let stack = stack.trim_start_matches(" -> ").to_string();
                Self::ServerError(stack)
            }
            // Some(Self::Test) => Self::Test,
        }
    }
}

/// Construct an `Error::InvalidRequest` error from a string or existing error
/// value.
macro_rules! invalid {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::InvalidRequest(format!($fmt, $($arg)*))
    };
     ($err:expr $(,)?) => {
        $crate::Error::InvalidRequest(format!($err))
    };
}
pub(crate) use invalid;

#[cfg(test)]
mod test {
    use anyhow::{Context, Result, anyhow};
    use serde_json::{Value, json};

    use super::*;

    // #[test]
    // fn test_context() {
    //     let result = Err::<(), Error>(Error::Test).context("request context");
    //     let err = result.unwrap_err();
    //     println!("Error: {}", err);
    // }

    // Test that error details are retuned as json.
    #[test]
    fn oid4vp_context() {
        let result = Err::<(), Error>(Error::InvalidRequest("invalid request".to_string()))
            .context("request context");
        let err: Error = result.unwrap_err().into();

        assert_eq!(
            err.to_string(),
            r#"{"error": "invalid_request", "error_description": "request context: invalid request"}"#
        );
    }

    #[test]
    fn anyhow_context() {
        let result = Err::<(), anyhow::Error>(anyhow!("one-off error")).context("error context");
        let err: Error = result.unwrap_err().into();

        assert_eq!(
            err.to_string(),
            r#"{"error": "server_error", "error_description": "error context -> one-off error"}"#
        );
    }

    #[test]
    fn serde_context() {
        let result: Result<Value, anyhow::Error> =
            serde_json::from_str(r#"{"foo": "bar""#).context("error context");
        let err: Error = result.unwrap_err().into();

        assert_eq!(
            err.to_string(),
            r#"{"error": "server_error", "error_description": "error context -> EOF while parsing an object at line 1 column 13"}"#
        );
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn querystring() {
        let err = Error::InvalidRequest("Invalid request description".to_string());
        let ser = serde_urlencoded::to_string(&err).unwrap();
        assert_eq!(ser, "error=invalid_request&error_description=Invalid+request+description");
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn json() {
        let err = Error::InvalidRequest("bad request".to_string());
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
    }
}
