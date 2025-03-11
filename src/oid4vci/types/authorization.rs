use std::fmt::{self, Debug};
use std::str::FromStr;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use super::ClaimsDescription;
use crate::core::urlencode;
use crate::oauth;
use crate::oid4vci::types::Format;

/// An Authorization Request type.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorizationRequest {
    /// A URI referencing the authorization request previously stored at the PAR
    /// endpoint.
    Uri(RequestUri),

    /// An Authorization Request object.
    Object(RequestObject),
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

impl fmt::Display for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = urlencode::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{s}")
    }
}

impl FromStr for AuthorizationRequest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('=') && s.contains('&') {
            Ok(urlencode::from_str(s)?)
        } else {
            Ok(Self::Object(serde_json::from_str(s)?))
        }
    }
}

/// `AuthorizationRequest` requires a custom deserializer because the default
/// deserializer cannot readily distinguish between `RequestObject` and
/// `RequestUri`.
impl<'de> de::Deserialize<'de> for AuthorizationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RequestVisitor;

        impl<'de> Visitor<'de> for RequestVisitor {
            type Value = AuthorizationRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("AuthorizationRequest")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut obj: RequestObject = RequestObject::default();
                let mut uri: RequestUri = RequestUri::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // RequestObject
                        "response_type" => {
                            obj.response_type = map.next_value::<oauth::ResponseType>()?;
                        }
                        "client_id" => obj.client_id = map.next_value::<String>()?,
                        "redirect_uri" => obj.redirect_uri = Some(map.next_value::<String>()?),
                        "state" => obj.state = Some(map.next_value::<String>()?),
                        "code_challenge" => obj.code_challenge = map.next_value::<String>()?,
                        "code_challenge_method" => {
                            obj.code_challenge_method =
                                map.next_value::<oauth::CodeChallengeMethod>()?;
                        }
                        "authorization_details" => {
                            obj.authorization_details =
                                Some(map.next_value::<Vec<AuthorizationDetail>>()?);
                        }
                        "scope" => obj.scope = Some(map.next_value::<String>()?),
                        "resource" => obj.resource = Some(map.next_value::<String>()?),
                        "subject_id" => obj.subject_id = map.next_value::<String>()?,
                        "wallet_issuer" => obj.wallet_issuer = Some(map.next_value::<String>()?),
                        "user_hint" => obj.user_hint = Some(map.next_value::<String>()?),
                        "issuer_state" => obj.issuer_state = Some(map.next_value::<String>()?),

                        // RequestUri
                        "request_uri" => uri.request_uri = map.next_value::<String>()?,
                        _ => {}
                    }
                }

                if uri.request_uri.is_empty() {
                    Ok(AuthorizationRequest::Object(obj))
                } else {
                    Ok(AuthorizationRequest::Uri(uri))
                }
            }
        }

        deserializer.deserialize_map(RequestVisitor)
    }
}

/// Authorization Response as defined in [RFC6749].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationResponse {
    /// Authorization code.
    pub code: String,

    /// Client state. An opaque value used by the client to maintain state
    /// between the request and callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// The client's redirection endpoint from the Authorization request.
    pub redirect_uri: String,
}

/// Grant Types the Credential Issuer's Authorization Server is prepared to
/// process for this credential offer.
///
/// The Credential Issuer can obtain user information to turn into a Verifiable
/// Credential using user authentication and consent at the Credential Issuer's
/// Authorization Endpoint (Authorization Code Flow) or using out of bound
/// mechanisms outside of the issuance flow (Pre-Authorized Code Flow).
///
/// When multiple grants are present, it's at the Wallet's discretion which one
/// to use.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Grants {
    /// Authorization Code Grant Type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-Authorized Code Grant Type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

/// The Authorization Code Grant Type contains parameters used by the Wallet
/// when requesting the Authorization Code Flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    /// Issuer state is used to link an Authorization Request to the Offer
    /// context. If the Wallet uses the Authorization Code Flow, it MUST
    /// include it in the Authorization Request using the `issuer_state`
    /// parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,

    /// To be used by the Wallet to identify the Authorization Server to use
    /// with this grant type when `authorization_servers` parameter in the
    /// Credential Issuer metadata has multiple entries. MUST NOT be used
    /// otherwise. The value of this parameter MUST match with one of the
    /// values in the Credential Issuer `authorization_servers` metadata
    /// property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// The Pre-Authorized Code Grant Type contains parameters used by the Wallet
/// when using the Pre-Authorized Code Flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    /// The code representing the Issuer's authorization for the Wallet to
    /// obtain Credentials of the type specified in the offer. This code
    /// MUST be short lived and single-use. If the Wallet decides to use the
    /// Pre-Authorized Code Flow, this parameter MUST be include
    /// in the subsequent Token Request with the Pre-Authorized Code Flow.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// The `tx_code` specifies whether the Authorization Server expects
    /// presentation of a Transaction Code by the End-User along with the
    /// Token Request in a Pre-Authorized Code Flow.
    ///
    /// The Transaction Code binds the Pre-Authorized Code to a certain
    /// transaction
    // to prevent replay of this code by an attacker that, for example, scanned the
    /// QR code while standing behind the legitimate End-User.
    ///
    /// It is RECOMMENDED to send the Transaction Code via a separate channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,

    /// To be used by the Wallet to identify the Authorization Server to use
    /// with this grant type when `authorization_servers` parameter in the
    /// Credential Issuer metadata has multiple entries. MUST NOT be used
    /// otherwise. The value of this parameter MUST match with one of the
    /// values in the Credential Issuer `authorization_servers` metadata
    /// property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// Specifies whether the Authorization Server expects presentation of a
/// Transaction Code by the End-User along with the Token Request in a
/// Pre-Authorized Code Flow.
///
/// If the Authorization Server does not expect a Transaction Code, this object
/// is absent; this is the default.
///
/// The Transaction Code is used to bind the Pre-Authorized Code to a
/// transaction to prevent replay of the code by an attacker that, for example,
/// scanned the QR code while standing behind the legitimate End-User. It is
/// RECOMMENDED to send the Transaction Code via a separate channel. If the
/// Wallet decides to use the Pre-Authorized Code Flow, the Transaction Code
/// value MUST be sent in the `tx_code` parameter with the respective
/// Token Request as defined in Section 6.1. If no length or description is
/// given, this object may be empty, indicating that a Transaction Code is
/// required.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxCode {
    /// Specifies the input character set. Possible values are "numeric" (only
    /// digits) and "text" (any characters). The default is "numeric".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,

    /// Specifies the length of the Transaction Code. This helps the Wallet to
    /// render the input screen and improve the user experience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i32>,

    /// Guidance for the Holder of the Wallet on how to obtain the Transaction
    /// Code, e.g., describing over which communication channel it is
    /// delivered. The Wallet is RECOMMENDED to display this description
    /// next to the Transaction Code input screen to improve the user
    /// experience. The length of the string MUST NOT exceed 300 characters.
    /// The description does not support internationalization, however
    /// the Issuer MAY detect the Holder's language by previous communication or
    /// an HTTP Accept-Language header within an HTTP GET request for a
    /// Credential Offer URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A URI referencing the authorization request previously stored at the PAR
/// endpoint.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestUri {
    /// The URI of the authorization request.
    pub request_uri: String,
}

/// An Authorization Request is an OAuth 2.0 Authorization Request as defined in
/// section 4.1.1 of [RFC6749], which requests to grant access to the Credential
/// Endpoint.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestObject {
    /// Authorization Server's response type.
    pub response_type: oauth::ResponseType,

    /// OAuth 2.0 Client ID used by the Wallet.
    pub client_id: String,

    /// The client's redirection endpoint as previously established during the
    /// client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Client state is used by the client to maintain state between the request
    /// and callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// PKCE code challenge, used to prevent authorization code interception
    /// attacks and mitigate the need for client secrets.
    pub code_challenge: String,

    /// PKCE code challenge method. Must be "S256".
    pub code_challenge_method: oauth::CodeChallengeMethod,

    /// Authorization Details may used to convey the details about credentials
    /// the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// Credential Issuers MAY support requesting authorization to issue a
    /// credential using OAuth 2.0 scope values.
    ///
    /// A scope value and its mapping to a credential type is defined by the
    /// Issuer. A description of scope value semantics or machine readable
    /// definitions could be defined in Issuer metadata. For example,
    /// mapping a scope value to an authorization details object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The Credential Issuer's identifier to allow the Authorization Server to
    /// differentiate between Issuers. [RFC8707]: The target resource to which
    /// access is being requested. MUST be an absolute URI.
    ///
    /// [RFC8707]: (https://www.rfc-editor.org/rfc/rfc8707)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    // TODO: replace `subject_id` with support for authentication
    // <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>
    /// A Holder identifier provided by the Wallet. It must have meaning to the
    /// Credential Issuer in order that credentialSubject claims can be
    /// populated.
    pub subject_id: String,

    /// The Wallet's `OpenID` Connect issuer URL. The Credential Issuer can use
    /// the discovery process as defined in [SIOPv2] to determine the Wallet's
    /// capabilities and endpoints. RECOMMENDED in Dynamic Credential Requests.
    ///
    /// [SIOPv2]: (https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_issuer: Option<String>,

    /// An opaque user hint the Wallet MAY use in subsequent callbacks to
    /// optimize the user's experience. RECOMMENDED in Dynamic Credential
    /// Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_hint: Option<String>,

    /// Identifies a pre-existing Credential Issuer processing context. A value
    /// for this parameter may be passed in the Credential Offer to the
    /// Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Authorization Details is used to convey the details about the Credentials
/// the Wallet wants to obtain.
/// See <https://www.rfc-editor.org/rfc/rfc9396.html>
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDetail {
    /// Type determines the authorization details type. MUST be
    /// "`openid_credential`".
    #[serde(rename = "type")]
    pub type_: AuthorizationDetailType,

    /// Identifies credential to authorize for issuance using either
    /// `credential_configuration_id` or a supported credential `format`.
    #[serde(flatten)]
    pub credential: AuthorizationCredential,

    // TODO: integrate locations
    /// If the Credential Issuer metadata contains an `authorization_servers`
    /// parameter, the authorization detail's locations field MUST be set to
    /// the Credential Issuer Identifier.
    ///
    /// # Example
    ///
    /// ```text
    /// "locations": [
    ///     "https://credential-issuer.example.com"
    ///  ]
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,

    /// Claims is used to define requested claims the Wallet wants to be
    /// included in the issued Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsDescription>>,
}

/// Authorization detail type (we only support `openid_credential`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationDetailType {
    /// OpenID Credential authorization detail type.
    #[default]
    #[serde(rename = "openid_credential")]
    OpenIdCredential,
}

/// Means used to identifiy a Credential's type when requesting a Credential.
#[derive(Clone, Debug, Deserialize, Serialize, Eq)]
#[serde(untagged)]
pub enum AuthorizationCredential {
    /// Identifes the credential to authorize by `credential_configuration_id`.
    ConfigurationId {
        /// The unique identifier of the Credential being requested in the
        /// `credential_configurations_supported` map in  Issuer Metadata.
        credential_configuration_id: String,
    },

    /// Identifies the credential to authorize using format-specific parameters.
    /// The requested format should resolve to a single supported credential in
    /// the `credential_configurations_supported` map in the Issuer Metadata.
    Format(Format),
}

impl Default for AuthorizationCredential {
    fn default() -> Self {
        Self::ConfigurationId {
            credential_configuration_id: String::new(),
        }
    }
}

/// `PartialEq` for `AuthorizationCredential` checks for equivalence using
/// `credential_configuration_id` or `format`, ecluding claims.
impl PartialEq for AuthorizationCredential {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::ConfigurationId {
                credential_configuration_id,
                ..
            } => {
                let Self::ConfigurationId {
                    credential_configuration_id: other_id,
                    ..
                } = &other
                else {
                    return false;
                };
                credential_configuration_id == other_id
            }
            Self::Format(format) => {
                let Self::Format(other_format) = &other else {
                    return false;
                };
                format == other_format
            }
        }
    }
}

/// Pushed Authorization Request (PAR) response as defined in [RFC9126].
///
/// [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationRequest {
    /// The authorization request posted.
    #[serde(flatten)]
    pub request: RequestObject,

    /// Client identity assertion using JWT instead of credentials to
    /// authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub client_assertion: Option<ClientAssertion>,
}

/// Client identity assertion.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "client_assertion_type")]
pub enum ClientAssertion {
    /// OAuth 2.0 Client Assertion using JWT Bearer Token.
    /// See <https://blog.logto.io/client-assertion-in-client-authn>
    #[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
    JwtBearer {
        /// The client's JWT assertion.
        client_assertion: String,
    },
}

/// Pushed Authorization Request (PAR) response as defined in [RFC9126].
///
/// [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
    /// The request URI corresponding to the authorization request posted. This
    /// URI is a single-use reference to the respective request data in the
    /// subsequent authorization request.
    pub request_uri: String,

    /// The lifetime of the request URI in seconds. Typically a relatively short
    /// duration (e.g., between 5 and 600 seconds).
    pub expires_in: i64,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::core::urlencode;
    use crate::oauth;
    use crate::oid4vci::types::{ClaimsDescription, CredentialDefinition, ProfileW3c};

    #[test]
    fn authorization_configuration_id() {
        let request = AuthorizationRequest::Object(RequestObject {
            response_type: oauth::ResponseType::Code,
            client_id: "1234".to_string(),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            state: Some("1234".to_string()),
            code_challenge: "1234".to_string(),
            code_challenge_method: oauth::CodeChallengeMethod::S256,
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: AuthorizationCredential::ConfigurationId {
                    credential_configuration_id: "EmployeeID_JWT".to_string(),
                },
                claims: Some(vec![
                    ClaimsDescription {
                        path: vec!["given_name".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec!["family_name".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec!["email".to_string()],
                        ..ClaimsDescription::default()
                    },
                ]),
                locations: None,
            }]),
            subject_id: "1234".to_string(),
            wallet_issuer: Some("1234".to_string()),

            ..RequestObject::default()
        });

        assert_snapshot!("authorization_configuration_id", request, {
            ".authorization_details" => "[authorization_details]",
        });

        let AuthorizationRequest::Object(object) = &request else {
            panic!("should be an object request");
        };
        assert_snapshot!("authorization_details", object.authorization_details, {
            "[].credential_definition.credentialSubject" => insta::sorted_redaction(),
        });

        let serialized = request.to_string();
        let deserialized = AuthorizationRequest::from_str(&serialized).expect("should parse");
        assert_eq!(request, deserialized);
    }

    #[test]
    fn authorization_format() {
        let request = AuthorizationRequest::Object(RequestObject {
            response_type: oauth::ResponseType::Code,
            client_id: "1234".to_string(),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            state: Some("1234".to_string()),
            code_challenge: "1234".to_string(),
            code_challenge_method: oauth::CodeChallengeMethod::S256,
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: AuthorizationCredential::Format(Format::JwtVcJson(ProfileW3c {
                    credential_definition: CredentialDefinition {
                        type_: vec![
                            "VerifiableCredential".to_string(),
                            "EmployeeIDCredential".to_string(),
                        ],
                        ..CredentialDefinition::default()
                    },
                })),

                ..AuthorizationDetail::default()
            }]),
            subject_id: "1234".to_string(),
            wallet_issuer: Some("1234".to_string()),

            ..RequestObject::default()
        });

        let serialized = urlencode::to_string(&request).expect("should serialize to string");
        assert_snapshot!("authorization_format", &serialized, {
            ".code" => "[code]",
        });

        let deserialized: AuthorizationRequest =
            urlencode::from_str(&serialized).expect("should deserialize from string");
        assert_eq!(request, deserialized);
    }
}
