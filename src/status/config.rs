//! # Configurations for status lists
//!
//! Types and traits for working with status lists configurations.

use serde::{Deserialize, Serialize};

use crate::format::w3c_vc::{StatusMessage, StatusPurpose};

/// Configuration for a status list for a credential.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ListConfig {
    /// Type of status
    pub purpose: StatusPurpose,

    /// List identifier.
    pub list: usize,

    /// Number of values used to represent the status.
    ///
    /// Should be 1 for [`Purpose::Revocation`] or [`Purpose::Suspension`]. For
    /// [`Purpose::Message`] this will be the number of possible arbitrary
    /// status messages.
    pub size: usize,

    /// Status messages.
    ///
    /// Valid for [`Purpose::Message`] only. Number of entries will be equal to
    /// [size].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<StatusMessage>>,

    /// URL to reference information for the status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Configuration for the possible statuses a credential type can have.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialStatusConfig {
    /// Credential type.
    pub credential_type: String,

    /// Configurations for the statuses this credential type can have.
    pub status_list: Option<Vec<ListConfig>>,
}
