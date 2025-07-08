//! # Provider Traits
//!
//! This module defines the `Provider` trait and its associated traits, which
//! can be implemented by library users to provide metadata, state management,
//! and subject information for the credential issuance process.
//!
//! The default implementation only requires library users to implement the
//! `Datastore` trait, which is used to store and retrieve data. Users can
//! implement the other traits as needed.

use std::future::Future;

use anyhow::Result;
pub use credibil_binding::{Resolver, Signature};
pub use credibil_core::state::StateStore;
pub use credibil_status::StatusStore;

use crate::types::{ClientMetadata, Dataset, IssuerMetadata, ServerMetadata};

/// Issuer Provider trait.
pub trait Provider:
    Metadata + Subject + StateStore + Signature + Resolver + StatusStore + Clone
{
}

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where
    T: Metadata + Subject + StateStore + Signature + Resolver + StatusStore + Clone
{
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait Metadata: Send + Sync {
    /// Client (wallet) metadata for the specified issuance client.
    fn client(
        &self, owner: &str, client_id: &str,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;

    /// Credential Issuer metadata for the specified issuer.
    fn issuer(&self, owner: &str) -> impl Future<Output = Result<IssuerMetadata>> + Send;

    /// Authorization Server metadata for the specified issuer/server.
    fn server(&self, owner: &str) -> impl Future<Output = Result<ServerMetadata>> + Send;

    /// Used to dynamically register OAuth 2.0 clients with the authorization
    /// server.
    fn register(
        &self, owner: &str, client: &ClientMetadata,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;
}

/// The Subject trait specifies how the library expects issuance subject (user)
/// information to be provided by implementers.
pub trait Subject: Send + Sync {
    /// Authorize issuance of the credential specified by
    /// `credential_configuration_id`. Returns a one or more
    /// `credential_identifier`s the subject (holder) is authorized to
    /// request.
    fn authorize(
        &self, owner: &str, subject_id: &str, credential_configuration_id: &str,
    ) -> impl Future<Output = Result<Vec<String>>> + Send;

    /// Returns a populated `Dataset` object for the given subject (holder) and
    /// credential definition.
    fn dataset(
        &self, owner: &str, subject_id: &str, credential_identifier: &str,
    ) -> impl Future<Output = Result<Dataset>> + Send;
}
