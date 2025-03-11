use std::collections::HashMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::oid4vci::types::{AuthorizationCredential, AuthorizationDetail, ClientAssertion};

/// Upon receiving a successful Authorization Response, a Token Request is made
/// as defined in [RFC6749] with extensions to support the Pre-Authorized Code
/// Flow.
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
    /// Create a `HashMap` representation of the `TokenRequest` suitable for
    /// use in an HTML form post.
    ///
    /// # Errors
    ///
    /// Will return an error if any of the object-type fields cannot be
    /// serialized to JSON and URL-encoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_encode(&self) -> anyhow::Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        // if !self.credential_issuer.is_empty() {
        //     map.insert("credential_issuer".to_string(), self.credential_issuer.clone());
        // }
        if let Some(client_id) = &self.client_id {
            map.insert("client_id".to_string(), client_id.clone());
        }
        match &self.grant_type {
            TokenGrantType::AuthorizationCode {
                code,
                redirect_uri,
                code_verifier,
            } => {
                map.insert("code".to_string(), code.clone());
                if let Some(redirect_uri) = redirect_uri {
                    map.insert("redirect_uri".to_string(), redirect_uri.clone());
                }
                if let Some(code_verifier) = code_verifier {
                    map.insert("code_verifier".to_string(), code_verifier.clone());
                }
            }
            TokenGrantType::PreAuthorizedCode {
                pre_authorized_code,
                tx_code,
            } => {
                map.insert("pre-authorized_code".to_string(), pre_authorized_code.clone());
                if let Some(tx_code) = tx_code {
                    map.insert("tx_code".to_string(), tx_code.clone());
                }
            }
        }
        if let Some(authorization_details) = &self.authorization_details {
            let as_json = serde_json::to_string(authorization_details)?;
            map.insert(
                "authorization_details".to_string(),
                urlencoding::encode(&as_json).to_string(),
            );
        }
        if let Some(client_assertion) = &self.client_assertion {
            map.insert(
                "client_assertion_type".to_string(),
                urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    .into(),
            );
            let ClientAssertion::JwtBearer { client_assertion } = client_assertion;
            map.insert("client_assertion".to_string(), client_assertion.clone());
        }
        Ok(map)
    }

    /// Create a `TokenRequest` from a `HashMap` representation. Suitable for
    /// use in an issuer's token endpoint that receives an HTML form post.
    ///
    /// # Errors
    /// Will return an error if any of the object-type fields, assumed to be
    /// URL-encoded JSON, cannot be decoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_decode(map: &HashMap<String, String>) -> anyhow::Result<Self> {
        let mut req = Self::default();
        // if let Some(credential_issuer) = map.get("credential_issuer") {
        //     req.credential_issuer.clone_from(credential_issuer);
        // }
        if let Some(client_id) = map.get("client_id") {
            req.client_id = Some(client_id.clone());
        }
        if let Some(code) = map.get("code") {
            let redirect_uri = map.get("redirect_uri").cloned();
            let code_verifier = map.get("code_verifier").cloned();
            req.grant_type = TokenGrantType::AuthorizationCode {
                code: code.clone(),
                redirect_uri,
                code_verifier,
            };
        } else if let Some(pre_authorized_code) = map.get("pre-authorized_code") {
            let tx_code = map.get("tx_code").cloned();
            req.grant_type = TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: pre_authorized_code.clone(),
                tx_code,
            };
        }
        if let Some(authorization_details) = map.get("authorization_details") {
            let authorization_details =
                serde_json::from_str(&urlencoding::decode(authorization_details)?)?;
            req.authorization_details = Some(authorization_details);
        }
        if let Some(client_assertion) = map.get("client_assertion") {
            if let Some(client_assertion_type) = map.get("client_assertion_type") {
                let decoded = urlencoding::decode(client_assertion_type)?;
                if decoded == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
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
            AuthorizationCredential::Format(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::oid4vci::types::{
        AuthorizationCredential, AuthorizationDetailType, ClaimsDescription,
    };

    #[test]
    fn token_request_form_encoding() {
        let request = TokenRequest {
            client_id: Some("1234".to_string()),
            grant_type: TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: "WQHhDmQ3ZygxyOPlBjunlA".to_string(),
                tx_code: Some("111222".to_string()),
            },
            authorization_details: Some(vec![AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: AuthorizationCredential::ConfigurationId {
                    credential_configuration_id: "EmployeeID_JWT".to_string(),
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

        let map = request.form_encode().expect("should condense to hashmap");
        let req = TokenRequest::form_decode(&map).expect("should expand from hashmap");
        assert_snapshot!("token_request_form_encoding", &req, {
            ".authorization_details[].credential_definition.type_" => insta::sorted_redaction(),
            ".authorization_details[].credential_definition.credentialSubject" => insta::sorted_redaction(),
            ".authorization_details[].credential_definition.credentialSubject.address" => insta::sorted_redaction(),
        });
    }
}
