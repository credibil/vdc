use std::collections::HashMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::oid4vci::types::{AuthorizationCredential, AuthorizationDetail, ClientAssertion};

/// Upon receiving a successful Authorization Response, a Token Request is made
/// as defined in [RFC6749] with extensions to support the Pre-Authorized Code
/// Flow.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TokenRequest {
    /// OAuth 2.0 Client ID used by the Wallet.
    ///
    /// REQUIRED if the client is not authenticating with the authorization
    /// server. An unauthenticated client MUST send its `client_id` to
    /// prevent itself from inadvertently accepting a code intended for a
    /// client with a different `client_id`.  This protects the client from
    /// substitution of the authentication code.
    ///
    /// For the Pre-Authorized Code Grant Type, authentication of the Client is
    /// OPTIONAL, as described in Section 3.2.1 of OAuth 2.0 [RFC6749], and,
    /// consequently, the `client_id` parameter is only needed when a form
    /// of Client Authentication that relies on this parameter is used.
    pub client_id: Option<String>,

    /// Authorization grant type.
    #[serde(flatten)]
    pub grant_type: TokenGrantType,

    /// Authorization Details is used to convey the details about the
    /// Credentials the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// Client identity assertion using JWT instead of credentials to
    /// authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub client_assertion: Option<ClientAssertion>,
}

impl TokenRequest {
    /// Create an `application/x-www-form-urlencoded` representation of the
    /// `TokenRequest` suitable for use in an HTML form post.
    ///
    /// # Errors
    ///
    /// Will return an error if any of the object-type fields cannot be
    /// serialized to JSON and URL-encoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_encode(&self) -> anyhow::Result<String> {
        let mut encoder = form_urlencoded::Serializer::new(String::new());

        if let Some(client_id) = &self.client_id {
            encoder.append_pair("client_id", client_id);
        }
        match &self.grant_type {
            TokenGrantType::AuthorizationCode {
                code,
                redirect_uri,
                code_verifier,
            } => {
                encoder.append_pair("code", code);
                if let Some(redirect_uri) = redirect_uri {
                    encoder.append_pair("redirect_uri", redirect_uri);
                }
                if let Some(code_verifier) = code_verifier {
                    encoder.append_pair("code_verifier", code_verifier);
                }
            }
            TokenGrantType::PreAuthorizedCode {
                pre_authorized_code,
                tx_code,
            } => {
                encoder.append_pair("pre-authorized_code", pre_authorized_code);
                if let Some(tx_code) = tx_code {
                    encoder.append_pair("tx_code", tx_code);
                }
            }
        }
        if let Some(authorization_details) = &self.authorization_details {
            let as_json = serde_json::to_string(authorization_details)?;
            encoder.append_pair("authorization_details", &as_json);
        }
        if let Some(client_assertion) = &self.client_assertion {
            encoder.append_pair(
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            );
            let ClientAssertion::JwtBearer { client_assertion } = client_assertion;
            encoder.append_pair("client_assertion", client_assertion);
        }

        Ok(encoder.finish())
    }

    /// Create a `TokenRequest` from a `HashMap` representation. Suitable for
    /// use in an issuer's token endpoint that receives an HTML form post.
    ///
    /// # Errors
    /// Will return an error if any of the object-type fields, assumed to be
    /// URL-encoded JSON, cannot be decoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_decode(form: &str) -> anyhow::Result<Self> {
        let decoded = form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>();

        let mut req = Self {
            client_id: decoded.get("client_id").cloned(),
            ..Self::default()
        };

        if let Some(code) = decoded.get("code") {
            req.grant_type = TokenGrantType::AuthorizationCode {
                code: code.clone(),
                redirect_uri: decoded.get("redirect_uri").cloned(),
                code_verifier: decoded.get("code_verifier").cloned(),
            };
        } else if let Some(pre_authorized_code) = decoded.get("pre-authorized_code") {
            req.grant_type = TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: pre_authorized_code.clone(),
                tx_code: decoded.get("tx_code").cloned(),
            };
        }
        if let Some(authorization_details) = decoded.get("authorization_details") {
            req.authorization_details = Some(serde_json::from_str(authorization_details)?);
        }
        if let Some(client_assertion) = decoded.get("client_assertion") {
            if let Some(client_assertion_type) = decoded.get("client_assertion_type") {
                if client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                {
                    req.client_assertion = Some(ClientAssertion::JwtBearer {
                        client_assertion: client_assertion.clone(),
                    });
                }
            }
        }

        Ok(req)
    }
}

/// Token authorization grant types.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "grant_type")]
pub enum TokenGrantType {
    /// Attributes required for the Authorization Code grant type.
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        /// The authorization code received from the authorization server when
        /// the Wallet use the Authorization Code Flow.
        code: String,

        /// The client's redirection endpoint if `redirect_uri` was included in
        /// the authorization request.
        /// REQUIRED if the `redirect_uri` parameter was included in the
        /// authorization request; values MUST be identical.
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_uri: Option<String>,

        /// PKCE code verifier provided by the Wallet when using the
        /// Authorization Code Flow. MUST be able to verify the
        /// `code_challenge` provided in the authorization request.
        #[serde(skip_serializing_if = "Option::is_none")]
        code_verifier: Option<String>,
    },

    /// Attributes required for the Pre-Authorized Code grant type
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        /// The pre-authorized code provided to the Wallet in a Credential
        /// Offer.
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,

        /// The Transaction Code provided to the user during the Credential
        /// Offer process. Must be present if `tx_code` was set to true
        /// in the Credential Offer.
        #[serde(skip_serializing_if = "Option::is_none")]
        tx_code: Option<String>,
    },
}

impl Default for TokenGrantType {
    fn default() -> Self {
        Self::AuthorizationCode {
            code: String::new(),
            redirect_uri: None,
            code_verifier: None,
        }
    }
}

/// Token Response as defined in [RFC6749].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    /// An OAuth 2.0 Access Token that can subsequently be used to request one
    /// or more Credentials.
    pub access_token: String,

    /// The type of the token issued. Must be "`Bearer`".
    pub token_type: TokenType,

    /// The lifetime in seconds of the access token.
    pub expires_in: i64,

    /// REQUIRED when `authorization_details` parameter is used to request
    /// issuance of a certain Credential type. MUST NOT be used otherwise.
    ///
    /// The Authorization Details `credential_identifiers` parameter may be
    /// populated for use in subsequent Credential Requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizedDetail>>,
}

/// Access token type as defined in [RFC6749]. Per the specification, the only
/// value allowed is "`Bearer`".
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// The only valid value is "`Bearer`".
    #[default]
    Bearer,
}

/// Authorization Details object specifically for use in successful Access Token
/// responses ([`TokenResponse`]).
///
/// It wraps the `AuthorizationDetail` struct and adds `credential_identifiers`
/// parameter for use in Credential requests.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedDetail {
    /// Reuse (and flatten) the existing [`AuthorizationDetail`] object used in
    /// authorization requests.
    #[serde(flatten)]
    pub authorization_detail: AuthorizationDetail,

    /// Credential Identifiers uniquely identify Credential Datasets that can
    /// be issued. Each Dataset corresponds to a Credential Configuration in the
    /// `credential_configurations_supported` parameter of the Credential
    /// Issuer metadata. The Wallet MUST use these identifiers in Credential
    /// Requests.
    pub credential_identifiers: Vec<String>,
}

impl From<AuthorizationDetail> for AuthorizedDetail {
    fn from(authorization_detail: AuthorizationDetail) -> Self {
        Self {
            authorization_detail,
            credential_identifiers: Vec::new(),
        }
    }
}

impl AuthorizedDetail {
    /// Get the `credential_configuration_id` from the `AuthorizationDetail`
    /// object.
    #[must_use]
    pub fn credential_configuration_id(&self) -> Option<&str> {
        match &self.authorization_detail.credential {
            AuthorizationCredential::ConfigurationId {
                credential_configuration_id,
            } => Some(credential_configuration_id.as_str()),
            AuthorizationCredential::FormatProfile(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::oid4vci::types::{
        AuthorizationCredential, AuthorizationDetailType, ClaimsDescription,
    };

    #[test]
    fn form_encoding() {
        let request = TokenRequest {
            client_id: Some("1234".to_string()),
            grant_type: TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: "WQHhDmQ3ZygxyOPlBjunlA".to_string(),
                tx_code: Some("111222".to_string()),
            },
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: AuthorizationCredential::ConfigurationId {
                    credential_configuration_id: "EmployeeID_W3C_VC".to_string(),
                },
                claims: Some(vec![
                    ClaimsDescription {
                        path: vec!["credentialSubject".to_string(), "given_name".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec!["credentialSubject".to_string(), "family_name".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec!["credentialSubject".to_string(), "email".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec!["credentialSubject".to_string(), "address".to_string()],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec![
                            "credentialSubject".to_string(),
                            "address".to_string(),
                            "street_address".to_string(),
                        ],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec![
                            "credentialSubject".to_string(),
                            "address".to_string(),
                            "locality".to_string(),
                        ],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec![
                            "credentialSubject".to_string(),
                            "address".to_string(),
                            "region".to_string(),
                        ],
                        ..ClaimsDescription::default()
                    },
                    ClaimsDescription {
                        path: vec![
                            "credentialSubject".to_string(),
                            "address".to_string(),
                            "country".to_string(),
                        ],
                        ..ClaimsDescription::default()
                    },
                ]),
                locations: Some(vec!["https://example.com".to_string()]),
            }]),
            client_assertion: Some(ClientAssertion::JwtBearer {
                client_assertion: "Ezie91o7DuPsA2PCLOtRUg".to_string(),
            }),
        };

        let encoded = request.form_encode().expect("should encode");
        assert!(encoded.contains("client_id=1234"));
        assert!(encoded.contains("&pre-authorized_code=WQHhDmQ3ZygxyOPlBjunlA"));
        assert!(encoded.contains("&authorization_details=%5B%7B%22"));

        let decoded = TokenRequest::form_decode(&encoded).expect("should decode");
        assert_eq!(request, decoded);
    }
}
