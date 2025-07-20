//! # Token Status Errors

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `OpenID` error codes for  for Verifiable Credential Issuance and
/// Presentation.
#[derive(Error, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "error", content = "error_description")]
pub enum Error {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value, repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the client, or is
    /// otherwise malformed.
    #[error(r#"{{"error": "invalid_request", "error_description": "{0}"}}"#)]
    InvalidRequest(String),

    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    #[error(r#"{{"error": "server_error", "error_description": "{0}"}}"#)]
    ServerError(String),
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<Self>() {
            Some(Self::InvalidRequest(e)) => Self::InvalidRequest(format!("{err}: {e}")),
            Some(Self::ServerError(e)) => Self::ServerError(format!("{err}: {e}")),
            None => {
                let stack = err.chain().map(|cause| format!(" -> {cause}")).collect::<String>();
                Self::ServerError(stack)
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
