//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use crate::oauth::CodeChallengeMethod;
use crate::oid4vci::types::{AuthorizedDetail, CredentialRequest};

/// Pre-authorization state from the `create_offer` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Offered {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

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
pub struct Authorized {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    pub subject_id: String,

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

/// Token state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    pub subject_id: String,

    /// The access token.
    #[allow(clippy::struct_field_names)]
    pub access_token: String,

    /// A list `authorization_details` entries including credential
    /// identifiers.
    pub authorized_details: Vec<AuthorizedDetail>,
}

// /// Issued Credential state (for Notification endpoint).
// #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
// pub struct Issued {
//     /// The issued credential.
//     pub credential: VerifiableCredential,
// }

/// Deferred issuance state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Deferred {
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
