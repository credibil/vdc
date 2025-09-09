use std::fmt::Debug;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::types::{AuthorizationDefinition, AuthorizationDetail, ClientAssertion};

impl TokenRequest {
    /// Create a new `TokenRequestBuilder`.
    #[must_use]
    pub fn builder() -> TokenRequestBuilder<NoGrant> {
        TokenRequestBuilder::new()
    }
}

/// Build a Token Request.
#[derive(Debug)]
pub struct TokenRequestBuilder<G> {
    client_id: Option<String>,
    grant_type: G,
    authorization_details: Option<Vec<AuthorizationDetail>>,
    client_assertion: Option<ClientAssertion>,
}

impl Default for TokenRequestBuilder<NoGrant> {
    fn default() -> Self {
        Self {
            client_id: None,
            grant_type: NoGrant,
            authorization_details: None,
            client_assertion: None,
        }
    }
}

/// No credential configuration id is set.
#[doc(hidden)]
pub struct NoGrant;
/// At least one credential configuration id is specifiedset.
#[doc(hidden)]
pub struct Grant(TokenGrantType);

impl TokenRequestBuilder<NoGrant> {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify a grant to include in the offer.
    #[must_use]
    pub fn grant_type(self, grant_type: TokenGrantType) -> TokenRequestBuilder<Grant> {
        TokenRequestBuilder {
            client_id: self.client_id,
            grant_type: Grant(grant_type),
            authorization_details: self.authorization_details,
            client_assertion: self.client_assertion,
        }
    }
}

impl<G> TokenRequestBuilder<G> {
    /// Specify the Wallet's Client ID.
    ///
    /// This is required if the client is not authenticating with the
    /// authorization server. For the Pre-Authorized Code Grant Type,
    /// client authentication is optional.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Specify Authorization Details when needing to request a specific
    /// credential configuration.
    #[must_use]
    pub fn with_authorization_detail(mut self, authorization_detail: AuthorizationDetail) -> Self {
        self.authorization_details.get_or_insert_with(Vec::new).push(authorization_detail);
        self
    }
}

impl TokenRequestBuilder<Grant> {
    /// Build the Create Offer request.
    #[must_use]
    pub fn build(self) -> TokenRequest {
        TokenRequest {
            client_id: self.client_id,
            grant_type: self.grant_type.0,
            authorization_details: self.authorization_details,
            client_assertion: self.client_assertion,
        }
    }
}

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
    pub fn form_encode(&self) -> Result<Vec<(String, String)>> {
        credibil_encoding::form_encode(self)
    }

    /// Create a `TokenRequest` from a `x-www-form-urlencoded` form.
    ///
    /// # Errors
    ///
    /// Will return an error if any of the object-type fields, assumed to be
    /// URL-encoded JSON, cannot be decoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_decode(form: &[(String, String)]) -> Result<Self> {
        credibil_encoding::form_decode(form)
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
        Self::AuthorizationCode { code: String::new(), redirect_uri: None, code_verifier: None }
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
        Self { authorization_detail, credential_identifiers: Vec::new() }
    }
}

impl AuthorizedDetail {
    /// Get the `credential_configuration_id` from the `AuthorizationDetail`
    /// object.
    #[must_use]
    pub const fn credential_configuration_id(&self) -> Option<&str> {
        match &self.authorization_detail.credential {
            AuthorizationDefinition::ConfigurationId { credential_configuration_id } => {
                Some(credential_configuration_id.as_str())
            }
            AuthorizationDefinition::FormatProfile(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::{AuthorizationDetailType, ClaimsDescription};

    #[test]
    fn form_encoding() {
        let request = TokenRequest {
            client_id: Some("1234".to_string()),
            grant_type: TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: "WQHhDmQ3ZygxyOPlBjunlA".to_string(),
                tx_code: Some("111222".to_string()),
            },
            authorization_details: Some(vec![AuthorizationDetail {
                r#type: AuthorizationDetailType::OpenIdCredential,
                credential: AuthorizationDefinition::ConfigurationId {
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
        assert!(encoded.contains(&("client_id".to_string(), "1234".to_string())));
        assert!(
            encoded.contains(&(
                "pre-authorized_code".to_string(),
                "WQHhDmQ3ZygxyOPlBjunlA".to_string()
            ))
        );
        assert!(
            encoded
                .contains(&("client_assertion".to_string(), "Ezie91o7DuPsA2PCLOtRUg".to_string()))
        );

        let decoded = TokenRequest::form_decode(&encoded).expect("should decode");
        assert_eq!(request, decoded);
    }
}
