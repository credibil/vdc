//! # `OpenID` for Verifiable Presentations (`OpenID4VP`)

mod request;
mod response;

use std::collections::HashMap;
use std::fmt::Debug;

pub use request::*;
pub use response::*;
use serde::{Deserialize, Serialize};

use crate::oauth::{OAuthClient, OAuthServer};

/// Request to retrieve the Verifier's  client metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetadataRequest {
    /// The Verifier's Client Identifier for which the configuration is to be
    /// returned.
    #[serde(default)]
    pub client_id: String,
}

/// Response containing the Verifier's client metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataResponse {
    /// The Client metadata for the specified Verifier.
    #[serde(flatten)]
    pub client: Verifier,
}

/// Used to define the format and proof types of Verifiable Presentations and
/// Verifiable Credentials that a Verifier supports.
///
/// Deployments can extend the formats supported, provided Issuers, Holders and
/// Verifiers all understand the new format.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#alternative_credential_formats>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VpFormat {
    /// Algorithms supported by the format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,

    /// Proof types supported by the format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<Vec<String>>,
}

/// OAuth 2 client metadata used for registering clients of the issuance and
/// wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Verifier {
    /// OAuth 2.0 Client
    #[serde(flatten)]
    pub oauth: OAuthClient,

    /// An object defining the formats and proof types of Verifiable
    /// Presentations and Verifiable Credentials that a Verifier supports.
    /// For specific values that can be used.
    ///
    /// # Example
    ///
    /// ```json
    /// "jwt_vc_json": {
    ///     "proof_type": [
    ///         "JsonWebSignature2020"
    ///     ]
    /// }
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<HashMap<Format, VpFormat>>,
}

/// The `OpenID4VCI` specification defines commonly used [Credential Format
/// Profiles] to support.  The profiles define Credential format specific
/// parameters or claims used to support a particular format.
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Format {
    /// W3C Verifiable Credential.
    #[serde(rename = "jwt_vp_json")]
    JwtVpJson,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Wallet {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Specifies whether the Wallet supports the transfer of
    /// `presentation_definition` by reference, with true indicating support.
    /// If omitted, the default value is true.
    pub presentation_definition_uri_supported: bool,

    /// A list of key value pairs, where the key identifies a Credential format
    /// supported by the Wallet.
    pub vp_formats_supported: Option<HashMap<String, VpFormat>>,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::core::Kind;
    use crate::dif_exch::{DescriptorMap, PathNested, PresentationSubmission};

    #[test]
    fn response_request_form_encode() {
        let request = ResponseRequest {
            vp_token: Some(vec![Kind::String("eyJ.etc".to_string())]),
            presentation_submission: Some(PresentationSubmission {
                id: "07b0d07c-f51e-4909-a1ab-d35e2cef20b0".to_string(),
                definition_id: "4b93b6aa-2157-4458-80ff-ffcefa3ff3b0".to_string(),
                descriptor_map: vec![DescriptorMap {
                    id: "employment".to_string(),
                    format: "jwt_vc_json".to_string(),
                    path: "$".to_string(),
                    path_nested: PathNested {
                        format: "jwt_vc_json".to_string(),
                        path: "$.verifiableCredential[0]".to_string(),
                    },
                }],
            }),
            state: Some("Z2VVKkglOWt-MkNDbX5VN05RRFI4ZkZeT01ZelEzQG8".to_string()),
        };
        let map = request.form_encode().expect("should condense to hashmap");
        assert_snapshot!("response_request_form_encoded", &map, {
            "." => insta::sorted_redaction(),
        });
        let req = ResponseRequest::form_decode(&map).expect("should expand from hashmap");
        assert_snapshot!("response_request_form_decoded", &req);
    }
}
