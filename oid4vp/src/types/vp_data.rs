//! # VP Data Endpoint Types

use credibil_vdc::Queryable;
use serde::{Deserialize, Serialize};

/// The [`AuthorizationResponse`] object is used by Wallets to send a VP Token
/// to the Verifier who initiated the verification process.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VpDataRequest {
    /// The `vp_data_id` pointing to VP token data temporarily saved in state
    /// on successful conclusion of an authorization (presentation).
    pub vp_data_id: String,
}

/// Authorization Response object is used to return a `redirect_uri` to
/// the Wallet following successful processing of the presentation submission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpDataResponse {
    /// Verified, deserialized VP token data saved in temporarily in state.
    pub vp_data: Vec<Queryable>,
}
