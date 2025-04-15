use std::collections::HashMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::Kind;
use crate::w3c_vc::vp::VerifiablePresentation;

/// Authorization Response request object is used by Wallets to send a VP Token
/// and Presentation Submission to the Verifier who initiated the verification.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorzationResponse {
    /// The VP Token returned by the Wallet.
    pub vp_token: HashMap<String, Vec<Kind<VerifiablePresentation>>>,

    /// The client state value from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// FIXME: align serialization/deserialization with spec
impl AuthorzationResponse {
    /// Create a `application/x-www-form-urlencoded` string of the
    /// `AuthorzationResponse` suitable for use in an HTML form post.
    ///
    /// # Errors
    ///
    /// Will return an error if any nested objects cannot be serialized and
    /// URL-encoded.
    pub fn form_encode(&self) -> anyhow::Result<String> {
        let mut encoder = form_urlencoded::Serializer::new(String::new());

        encoder.append_pair("vp_token", &serde_json::to_string(&self.vp_token)?);

        if let Some(state) = &self.state {
            encoder.append_pair("state", state);
        }

        Ok(encoder.finish())
    }

    /// Create a `AuthorzationResponse` from a
    /// `application/x-www-form-urlencoded` string.
    ///
    /// Suitable for
    /// use in a verifier's response endpoint that receives a form post before
    /// passing the `AuthorzationResponse` to the `response` handler.
    ///
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be deserialized from
    /// URL-encoded JSON strings.
    pub fn form_decode(form: &str) -> anyhow::Result<Self> {
        let mut req = Self::default();
        let decoded = form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>();

        if let Some(vp_token) = decoded.get("vp_token") {
            req.vp_token = serde_json::from_str(vp_token)?;
        }
        req.state = decoded.get("state").cloned();

        Ok(req)
    }
}

/// Authorization Response object is used to return a `redirect_uri` to
/// the Wallet following successful processing of the presentation submission.
#[derive(Debug, Deserialize, Serialize)]
pub struct RedirectResponse {
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
    pub redirect_uri: Option<String>,

    /// A cryptographically random number with sufficient entropy used to link
    /// the Authorization Response to the Authorization Request. The
    /// `response_code` is returned to the Verifier when the Wallet follows
    /// the redirect in the `redirect_uri` parameter.
    pub response_code: Option<String>,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::core::Kind;

    #[test]
    fn form_encode() {
        let request = AuthorzationResponse {
            vp_token: HashMap::from([(
                "my_credential".to_string(),
                vec![Kind::String("eyJ.etc".to_string())],
            )]),
            state: None,
        };

        let encoded = request.form_encode().expect("should encode");
        assert_eq!(encoded, "vp_token=%7B%22my_credential%22%3A%5B%22eyJ.etc%22%5D%7D");

        let decoded = AuthorzationResponse::form_decode(&encoded).expect("should decode");
        assert_eq!(request, decoded);
    }
}
