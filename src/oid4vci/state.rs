//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::oauth::CodeChallengeMethod;
use crate::oid4vci::types::{AuthorizedDetail, CredentialOffer, CredentialRequest, RequestObject};
use crate::w3c_vc::model::VerifiableCredential;

/// State is used to persist request information between issuance steps in the
/// Credential issuance process.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    /// Stage holds data relevant to the current state of the issuance process.
    /// This data is used by subsequent step(s) to verify Wallet interactions,
    /// including credential issuance.
    pub stage: Stage,

    /// Time state should expire.
    pub expires_at: DateTime<Utc>,
}

impl State {
    /// Determines whether state has expired or not.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

/// State stages.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Stage {
    /// Unauthorized state.
    #[default]
    Unauthorized,

    /// Holds a Credential Offer awaiting retrieval by the Wallet. The Wallet
    /// has been sent a unique URL it can use to retrieve the offer.
    Pending(CredentialOffer),

    /// Holds pre-authorized offer data as presented to the Wallet. This data is
    /// used when validating the Wallet's request for an access token.
    Offered(Offer),

    /// Holds a Pushed Authorization Request awaiting retrieval by the Wallet.
    PushedAuthorization(PushedAuthorization),

    /// Holds authorization data in cases where the Wallet requests and is
    /// granted authorization to request credential issuance. As with
    /// `PreAuthorized` state, this data is used when validating the
    /// Wallet's request for an access token.
    Authorized(Authorization),

    /// Holds information about the access token and corresponding credentials
    /// the Wallet is authorized to request.
    Validated(Token),

    /// Issued Credential state.
    Issued(Credential),

    /// Deferred issuance state.
    Deferred(Deferrance),
}

/// Pre-authorization state from the `create_offer` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Offer {
    /// A list of `authorization_details` entries referencing credentials the
    /// Wallet is authorized to request.
    pub details: Option<Vec<AuthorizedDetail>>,

    /// Transaction code sent to the holder to use (if present)when requesting
    /// an access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// Authorization state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Authorization {
    /// The `client_id` of the Wallet requesting issuance.
    pub client_id: String,

    /// The `redirect_uri` of the Wallet requesting issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// PKCE code challenge from the Authorization Request.
    pub code_challenge: String,

    /// PKCE code challenge method from the Authorization Request.
    pub code_challenge_method: CodeChallengeMethod,

    /// A list of authorized `scope` or `authorization_details` entries along
    /// with credential metadata and dataset identifiers.
    pub details: Vec<AuthorizedDetail>,
}

/// Pushed Authorization Request state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PushedAuthorization {
    /// The Authorization Request pushed to the PAR endpoint.
    pub request: RequestObject,

    /// The time the request URI should expire at.
    pub expires_at: DateTime<Utc>,
}

/// Token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// A list `authorization_details` entries including credential
    /// identifiers.
    pub details: Vec<AuthorizedDetail>,
}

/// Issued Credential state (for Notification endpoint).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Credential {
    /// The issued credential.
    pub credential: VerifiableCredential,
}

/// Deferred issuance state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Deferrance {
    /// Used to identify a Deferred Issuance transaction. Is used as the
    /// state persistence key.
    pub transaction_id: String,

    /// Save the Credential request when issuance is deferred.
    pub credential_request: CredentialRequest,
}

/// Expire enum.
pub enum Expire {
    /// Authorized state expiration.
    Authorized,
    /// Access state expiration.
    Access,
    // /// Nonce state expiration.
    // Nonce,
}

impl Expire {
    /// Duration of the state.
    #[must_use]
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::Authorized => TimeDelta::try_minutes(5).unwrap_or_default(),
            Self::Access => TimeDelta::try_minutes(15).unwrap_or_default(),
            // Self::Nonce => TimeDelta::try_minutes(10).unwrap_or_default(),
        }
    }
}
