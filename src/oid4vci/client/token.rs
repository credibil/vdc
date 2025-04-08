//! # Token Request Builder

use crate::oid4vci::types::{AuthorizationDetail, ClientAssertion, TokenGrantType, TokenRequest};

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
