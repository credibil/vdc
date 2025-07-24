//! # Wallet Provider

use anyhow::Result;
pub use credibil_binding::{Resolver, Signature};
pub use credibil_core::state::StateStore;

/// Wallet Provider trait.
pub trait Provider: UrlResolver + StateStore + Signature + Resolver + Clone {}

/// [`UrlResolver`] is used to proxy the resolution of an HTTP URL.
pub trait UrlResolver: Send + Sync {
    /// Resolve the URL to public material key such as a DID Document or
    /// X509 certificate.
    ///
    /// The default implementation is a no-op since for some methods, such as
    /// `did:key`, the URL contains sufficient information to verify the
    /// signature of an identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be resolved.
    fn resolve<T>(&self, url: &str) -> impl Future<Output = Result<T>> + Send
    where
        T: serde::de::DeserializeOwned + Send;
}
