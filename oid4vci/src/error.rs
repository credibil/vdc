//! # `OpenID4VCI` Errors
//!
//! This module defines errors for `OpenID` for Verifiable Credential Issuance
//! and Verifiable Presentations.

// TODO: add support for "client-state" in error responses.
// TODO: use custom serialisation for Err enum.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `OpenID` error codes for  for Verifiable Credential Issuance and
/// Presentation.
#[derive(Error, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error", content = "error_description")]
pub enum Error {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value, repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the client, or is
    /// otherwise malformed.
    #[error(r#"{{"error": "invalid_request", "error_description": "{0}"}}"#)]
    InvalidRequest(String),

    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method).
    ///
    /// The client tried to send a Token Request with a Pre-Authorized Code
    /// without Client ID but the Authorization Server does not support
    /// anonymous access.
    ///
    /// For Verifiable Presentations:
    ///
    /// `client_metadata` or `client_metadata_uri` is set, but the Wallet
    /// recognizes Client Identifier and already knows metadata associated
    /// with it.
    ///
    /// Verifier's pre-registered metadata has been found based on the Client
    /// Identifier, but `client_metadata` parameter is also set.
    #[error(r#"{{"error": "invalid_client", "error_description": "{0}"}}"#)]
    InvalidClient(String),

    /// The provided authorization grant (e.g., authorization code,
    /// pre-authorized_code) or refresh token is invalid, expired, revoked,
    /// does not match the redirection URI used in the authorization
    /// request, or was issued to another client.
    ///
    /// The Authorization Server expects a PIN in the pre-authorized flow but
    /// the client provides the wrong PIN.
    #[error(r#"{{"error": "invalid_grant", "error_description": "{0}"}}"#)]
    InvalidGrant(String),

    /// The client is not authorized to request an authorization code using this
    /// method.
    #[error(r#"{{"error": "unauthorized_client", "error_description": "{0}"}}"#)]
    UnauthorizedClient(String),

    /// The authorization grant type is not supported by the authorization
    /// server.
    #[error(r#"{{"error": "unsupported_grant_type", "error_description": "{0}"}}"#)]
    UnsupportedGrantType(String),

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope
    /// granted.
    #[error(r#"{{"error": "invalid_scope", "error_description": "{0}"}}"#)]
    InvalidScope(String),

    /// Unknown authorization details type or authorization details not
    /// conforming to the respective type definition
    #[error(r#"{{"error": "invalid_authorization_details", "error_description": "{0}"}}"#)]
    InvalidAuthorizationDetails(String),

    /// The resource owner or authorization server denied the request.
    #[error(r#"{{"error": "access_denied", "error_description": "{0}"}}"#)]
    AccessDenied(String),

    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    #[error(r#"{{"error": "unsupported_response_type", "error_description": "{0}"}}"#)]
    UnsupportedResponseType(String),

    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    #[error(r#"{{"error": "server_error", "error_description": "{0}"}}"#)]
    ServerError(String),

    /// The authorization server is unable to handle the request due to
    /// temporary overloading or maintenance.
    #[error(r#"{{"error": "temporarily_unavailable", "error_description": "{0}"}}"#)]
    TemporarilyUnavailable(String),

    /// The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same
    /// parameter, or is otherwise malformed.
    #[error(r#"{{"error": "invalid_credential_request", "error_description": "{0}"}}"#)]
    InvalidCredentialRequest(String),

    /// Requested credential type is not supported.
    #[error(r#"{{"error": "unsupported_credential_type", "error_description": "{0}"}}"#)]
    UnsupportedCredentialType(String),

    /// Requested credential format is not supported.
    #[error(r#"{{"error": "unsupported_credential_format", "error_description": "{0}"}}"#)]
    UnsupportedCredentialFormat(String),

    /// Credential Request did not contain a proof, or proof was invalid, i.e.
    /// it was not bound to a Credential Issuer provided `c_nonce`.
    #[allow(missing_docs)]
    #[error(r#"{{"error": "invalid_proof", "error_description": "{0}"}}"#)]
    InvalidProof(String),

    /// The proof or proofs parameter in the Credential Request uses an invalid
    /// nonce: at least one of the key proofs contains an invalid `c_nonce`
    /// value. The wallet should retrieve a new `c_nonce` value.
    #[allow(missing_docs)]
    #[error(r#"{{"error": "invalid_nonce", "error_description": "{0}"}}"#)]
    InvalidNonce(String),

    /// This error occurs when the encryption parameters in the Credential
    /// Request are either invalid or missing. In the latter case, it
    /// indicates that the Credential Issuer requires the Credential
    /// Response to be sent encrypted, but the Credential Request does not
    /// contain the necessary encryption parameters.
    #[error(r#"{{"error": "invalid_encryption_parameters", "error_description": "{0}"}}"#)]
    InvalidEncryptionParameters(String),

    /// The Credential Request has not been accepted by the Credential Issuer.
    #[error(r#"{{"error": "credential_request_denied", "error_description": "{0}"}}"#)]
    CredentialRequestDenied(String),

    /// The Credential issuance is still pending. The error response SHOULD also
    /// contain the interval member, determining the minimum amount of time
    /// in seconds that the Wallet needs to wait before providing a new
    /// request to the Deferred Credential Endpoint. If interval member is
    /// missing or its value is not provided, the Wallet MUST use 5 as the
    /// default value.
    #[error(r#"{{"error": "issuance_pending", "interval": {0}}}"#)]
    IssuancePending(i64),

    /// The Deferred Credential Request contains an invalid `transaction_id`.
    /// This error occurs when the `transaction_id` was not issued by the
    /// respective Credential Issuer or it was already used to obtain the
    /// Credential.
    #[error(r#"{{"error": "invalid_transaction_id", "error_description": "{0}"}}"#)]
    InvalidTransactionId(String),
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<Self>() {
            Some(Self::InvalidRequest(e)) => Self::InvalidRequest(format!("{err}: {e}")),
            Some(Self::InvalidClient(e)) => Self::InvalidClient(format!("{err}: {e}")),
            Some(Self::InvalidGrant(e)) => Self::InvalidGrant(format!("{err}: {e}")),
            Some(Self::UnauthorizedClient(e)) => Self::UnauthorizedClient(format!("{err}: {e}")),
            Some(Self::UnsupportedGrantType(e)) => {
                Self::UnsupportedGrantType(format!("{err}: {e}"))
            }
            Some(Self::InvalidScope(e)) => Self::InvalidScope(format!("{err}: {e}")),
            Some(Self::InvalidAuthorizationDetails(e)) => {
                Self::InvalidAuthorizationDetails(format!("{err}: {e}"))
            }
            Some(Self::AccessDenied(e)) => Self::AccessDenied(format!("{err}: {e}")),
            Some(Self::UnsupportedResponseType(e)) => {
                Self::UnsupportedResponseType(format!("{err}: {e}"))
            }
            Some(Self::ServerError(e)) => Self::ServerError(format!("{err}: {e}")),

            Some(Self::TemporarilyUnavailable(e)) => {
                Self::TemporarilyUnavailable(format!("{err}: {e}"))
            }
            Some(Self::InvalidCredentialRequest(e)) => {
                Self::InvalidCredentialRequest(format!("{err}: {e}"))
            }
            Some(Self::UnsupportedCredentialType(e)) => {
                Self::UnsupportedCredentialType(format!("{err}: {e}"))
            }
            Some(Self::UnsupportedCredentialFormat(e)) => {
                Self::UnsupportedCredentialFormat(format!("{err}: {e}"))
            }
            Some(Self::InvalidProof(e)) => Self::InvalidProof(format!("{err}: {e}")),
            Some(Self::InvalidNonce(e)) => Self::InvalidNonce(format!("{err}: {e}")),
            Some(Self::InvalidEncryptionParameters(e)) => {
                Self::InvalidEncryptionParameters(format!("{err}: {e}"))
            }
            Some(Self::CredentialRequestDenied(e)) => {
                Self::CredentialRequestDenied(format!("{err}: {e}"))
            }
            Some(Self::IssuancePending(i)) => Self::IssuancePending(*i),
            Some(Self::InvalidTransactionId(e)) => {
                Self::InvalidTransactionId(format!("{err}: {e}"))
            }
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
        $crate::Error::InvalidRequest(format!($fmt, $($arg)*))
    };
     ($err:expr $(,)?) => {
        $crate::Error::InvalidRequest(format!($err))
    };
}
pub(crate) use invalid;

/// Construct an `Error::ServerError` error from a string or existing error
/// value.
macro_rules! server {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::ServerError(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::ServerError($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::Error::ServerError(format!($err))
    };
}
pub(crate) use server;

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    // Test that the error details are returned as an http query string.
    #[test]
    fn querystring() {
        let err = invalid!("Invalid request description");
        let ser = serde_urlencoded::to_string(&err).unwrap();
        assert_eq!(ser, "error=invalid_request&error_description=Invalid+request+description");
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn json() {
        let err = invalid!("bad request");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
    }
}
