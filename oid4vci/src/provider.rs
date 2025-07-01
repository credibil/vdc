//! # Provider Traits
//!
//! This module defines the `Provider` trait and its associated traits, which
//! can be implemented by library users to provide metadata, state management,
//! and subject information for the credential issuance process.
//!
//! The default implementation only requires library users to implement the
//! `Datastore` trait, which is used to store and retrieve data. Users can
//! implement the other traits as needed.

use std::collections::HashMap;
use std::future::Future;

use anyhow::{Result, anyhow};
use credibil_core::datastore::Datastore;
pub use credibil_core::state::StateStore;
pub use credibil_proof::{Resolver, Signature};
pub use credibil_status::StatusStore;

use crate::types::{ClientMetadata, Dataset, IssuerMetadata, ServerMetadata};

const METADATA: &str = "metadata";
const ISSUER: &str = "issuer";
const SERVER: &str = "server";
const SUBJECT: &str = "subject";

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

impl<T: Datastore> Metadata for T {
    async fn client(&self, owner: &str, client_id: &str) -> Result<ClientMetadata> {
        let Some(data) = Datastore::get(self, owner, METADATA, client_id).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn issuer(&self, owner: &str) -> Result<IssuerMetadata> {
        let Some(data) = Datastore::get(self, owner, METADATA, ISSUER).await? else {
            return Err(anyhow!("could not find issuer metadata"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn server(&self, owner: &str) -> Result<ServerMetadata> {
        let Some(data) = Datastore::get(self, owner, METADATA, SERVER).await? else {
            return Err(anyhow!("could not find server metadata"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn register(&self, owner: &str, client: &ClientMetadata) -> Result<ClientMetadata> {
        let mut client = client.clone();
        client.oauth.client_id = uuid::Uuid::new_v4().to_string();

        let data = serde_json::to_vec(&client)?;
        Datastore::put(self, owner, METADATA, &client.oauth.client_id, &data).await?;
        Ok(client)
    }
}

impl<T: Datastore> Subject for T {
    async fn authorize(
        &self, owner: &str, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        let Some(data) = Datastore::get(self, owner, SUBJECT, subject_id).await? else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        let datasets: HashMap<String, Dataset> = serde_json::from_slice(&data)?;

        // find dataset identifiers for the provided subject & credential
        let identifiers = datasets
            .iter()
            .filter(|(_, ds)| ds.credential_configuration_id == credential_configuration_id)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        if identifiers.is_empty() {
            return Err(anyhow!("no matching dataset for subject/credential"));
        }

        Ok(identifiers)
    }

    async fn dataset(
        &self, owner: &str, subject_id: &str, credential_identifier: &str,
    ) -> Result<Dataset> {
        let Some(data) = Datastore::get(self, owner, SUBJECT, subject_id).await? else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        let datasets: HashMap<String, Dataset> = serde_json::from_slice(&data)?;

        let Some(dataset) = datasets.get(credential_identifier) else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        Ok(dataset.clone())
    }
}
