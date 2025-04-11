use std::collections::HashMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::{Kind, OneMany};
use crate::dif_exch::PresentationSubmission;
use crate::w3c_vc::vp::VerifiablePresentation;

/// Authorization Response request object is used by Wallets to send a VP Token
/// and Presentation Submission to the Verifier who initiated the verification.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorzationResponse {
    /// The VP Token returned by the Wallet.
    #[serde(flatten)]
    pub vp_token: VpToken,

    /// The client state value from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// `VpToken` is used to return a Verifiable Presentation to the Verifier.
///
/// The variant used is dependent on the type of query used in the
/// Authorization Request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum VpToken {
    /// The VP token is JSON-encoded and containing a Verifiable
    /// Presentation for each Credential Query. The key is the ID of the
    /// Credential Query.
    Dcql {
        /// One or more Verifiable Presentations as base64url encoded strings
        /// and/or JSON objects. The VP format determines the encoding.
        vp_token: HashMap<String, Vec<Kind<VerifiablePresentation>>>,
    },

    /// The presentation is a DIF Presentation Exchange in response to a DIF
    /// Presentation Exchange request.
    DifExch {
        /// One or more Verifiable Presentations as base64url encoded strings
        /// and/or JSON objects. The VP format determines the encoding.
        vp_token: OneMany<Kind<VerifiablePresentation>>,

        /// Mappings between the requested Verifiable Credentials and their
        /// location within the returned VP Token.
        presentation_submission: PresentationSubmission,
    },
}

impl Default for VpToken {
    fn default() -> Self {
        Self::Dcql {
            vp_token: HashMap::new(),
        }
    }
}

impl AuthorzationResponse {
    /// Create a `HashMap` representation of the `AuthorzationResponse` suitable for
    /// use in an HTML form post.
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be serialized and
    /// URL-encoded.
    pub fn form_encode(&self) -> anyhow::Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        if let VpToken::DifExch {
            vp_token,
            presentation_submission,
        } = &self.vp_token
        {
            let as_json = serde_json::to_string(vp_token)?;
            map.insert("vp_token".to_string(), urlencoding::encode(&as_json).to_string());

            let as_json = serde_json::to_string(presentation_submission)?;
            map.insert(
                "presentation_submission".to_string(),
                urlencoding::encode(&as_json).to_string(),
            );
        }

        if let Some(state) = &self.state {
            map.insert("state".to_string(), state.into());
        }
        
        Ok(map)
    }

    /// Create a `AuthorzationResponse` from a `HashMap` representation.
    ///
    /// Suitable for
    /// use in a verifier's response endpoint that receives a form post before
    /// passing the `AuthorzationResponse` to the `response` handler.
    ///
    /// # Errors
    /// Will return an error if any nested objects cannot be deserialized from
    /// URL-encoded JSON strings.
    pub fn form_decode(map: &HashMap<String, String>) -> anyhow::Result<Self> {
        let mut req = Self::default();
        if let Some(vp_token) = map.get("vp_token") {
            let decoded = urlencoding::decode(vp_token)?;
            let vp_token: OneMany<Kind<VerifiablePresentation>> = serde_json::from_str(&decoded)?;

            let Some(presentation_submission) = map.get("presentation_submission") else {
                return Err(anyhow::anyhow!("presentation_submission not found"));
            };
            let decoded = urlencoding::decode(presentation_submission)?;
            let presentation_submission: PresentationSubmission = serde_json::from_str(&decoded)?;

            req.vp_token = VpToken::DifExch {
                vp_token,
                presentation_submission,
            };
        }

        if let Some(state) = map.get("state") {
            req.state = Some(state.to_string());
        }
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
