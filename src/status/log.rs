//! # Log
//!
//! Types and traits for keeping a log of credentials issued and their current
//! statuses. This is independent of the method used to publish the status.

use serde::{Deserialize, Serialize};

use crate::core::vc::StatusPurpose;

/// Entry in a log of issued credentials and their current status.
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct StatusLogEntry {
    /// Credential identifier.
    pub credential_id: String,

    /// Holder identifier.
    ///
    /// For some implementations this may be an identifer of the holder
    /// themselves, or it could be an indexed claim that is used to identify
    /// the credential without storing the holder's identifier directly.
    pub subject_id: String,

    /// Current status(es) of the credential.
    pub status: Vec<StatusValue>,
}

/// Status value for a credential and the lookup identifier in a published
/// status list.
#[derive(Debug, Deserialize, Serialize)]
pub struct StatusValue {
    /// Type of status.
    pub purpose: StatusPurpose,

    /// Identifier in the status list.
    ///
    /// For example, in a bitstring list this would be the index of the first
    /// bit in the bitstring that represents the status of this credential.
    pub list_index: usize,

    /// Status value.
    ///
    /// For [`StatusPurpose::Revocation`] or [`StatusPurpose::Suspension`] this
    /// will be 0 as false or 1 as true. For [`StatusPurpose::Message`] this
    /// will resolve to the index of the message in the list of messages.
    pub value: u8,
}
