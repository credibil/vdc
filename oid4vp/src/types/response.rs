use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The [`AuthorizationResponse`] object is used by Wallets to send a VP Token
/// to the Verifier who initiated the verification process.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    /// The VP Token returned by the Wallet.
    pub vp_token: HashMap<String, Vec<String>>,

    /// The client state value from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// FIXME: align serialization/deserialization with spec
impl AuthorizationResponse {
    /// Create a `application/x-www-form-urlencoded` string of the
    /// `AuthorizationResponse` suitable for use in an HTML form post.
    ///
    /// # Errors
    ///
    /// Will return an error if any nested objects cannot be serialized and
    /// URL-encoded.
    pub fn form_encode(&self) -> anyhow::Result<Vec<(String, String)>> {
        credibil_encoding::form_encode(self)
    }

    /// Create a `AuthorizationResponse` from a
    /// `application/x-www-form-urlencoded` string.
    ///
    /// Suitable for
    /// use in a verifier's response endpoint that receives a form post before
    /// passing the `AuthorizationResponse` to the `response` handler.
    ///
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be deserialized from
    /// URL-encoded JSON strings.
    pub fn form_decode(form: &[(String, String)]) -> anyhow::Result<Self> {
        credibil_encoding::form_decode(form)
    }
}

impl Display for AuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = credibil_encoding::url_encode(self).map_err(|_e| fmt::Error)?;
        write!(f, "{s}")
    }
}

impl FromStr for AuthorizationResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        credibil_encoding::url_decode(s)
    }
}

/// Authorization Response object is used to return a `redirect_uri` to
/// the Wallet following successful processing of the presentation submission.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubmissionResponse {
    /// When the redirect parameter is used the Wallet MUST send the User Agent
    /// to the provided URI. The redirect URI allows the Verifier to
    /// continue the interaction with the End-User on the device where the
    /// Wallet resides after the Wallet has sent the Authorization Response.
    /// It especially enables the Verifier to prevent session fixation
    /// attacks.
    ///
    /// The URI — an absolute URI — is chosen by the Verifier. It MUST include a
    /// fresh, cryptographically random number to ensure only the receiver
    /// of the redirect can fetch and process the Authorization Response.
    /// The number could be added as a path component or a parameter to the
    /// URL. It is RECOMMENDED to use a cryptographic random value of 128
    /// bits or more.
    ///
    /// # Example
    ///
    /// ```http
    /// redirect_uri": "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"
    /// ```
    /// If the response does not contain a parameter, the Wallet is not required
    /// to perform any further steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// A cryptographically random number with sufficient entropy used to link
    /// the Authorization Response to the Authorization Request. The
    /// `response_code` is returned to the Verifier when the Wallet follows
    /// the redirect in the `redirect_uri` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,

    /// The identifier for use when retrieving the verified, deserialized
    /// VP token data.
    pub vp_data_id: String,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn form_encode() {
        let request = AuthorizationResponse {
            vp_token: HashMap::from([("my_credential".to_string(), vec!["eyJ.etc".to_string()])]),
            state: None,
        };

        let encoded = request.form_encode().expect("should encode");
        assert_eq!(
            encoded,
            vec![(
                "vp_token".to_string(),
                "%7B%22my_credential%22%3A%5B%22eyJ.etc%22%5D%7D".to_string()
            )]
        );

        let decoded = AuthorizationResponse::form_decode(&encoded).expect("should decode");
        assert_eq!(request, decoded);
    }
}
