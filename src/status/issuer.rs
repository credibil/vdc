//! # Status (Issuer)
//!
//! Traits and types for managing the publication of a credential status as an
//! issuer.

use std::future::Future;

use super::provider;
pub use crate::core::OneMany;
pub use crate::w3c_vc::model::CredentialStatus;

/// The `Status` trait specifies how status information can be looked up for a
/// credential.
pub trait Status: Send + Sync {
    /// Returns information on how to look up the status of a credential.
    ///
    /// A default implementation is provided that just returns `None` for cases
    /// where the issuer will not be providing a status endpoint.
    fn status(
        &self, _subject_id: &str, _credential_identifier: &str,
    ) -> impl Future<Output = provider::Result<Option<OneMany<CredentialStatus>>>> + Send {
        async { Ok(None) }
    }
}
