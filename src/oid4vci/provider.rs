//! # Provider Traits
//!
//! This module defines the `Provider` trait and its associated traits, which
//! can be implemented by library users to provide metadata, state management,
//! and subject information for the credential issuance process.
//!
//! The default implementation only requires library users to implement the
//! `BlockStore` trait, which is used to store and retrieve data. Users can
//! implement the other traits as needed.

use std::collections::HashMap;
use std::future::Future;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use credibil_did::DidResolver;
use credibil_infosec::Signer;
use serde::{Deserialize, Serialize};

use crate::BlockStore;
use crate::oid4vci::types::{Client, Dataset, Issuer, Server};
use crate::status::issuer::Status;

/// Issuer Provider trait.
pub trait Provider:
    Metadata + Subject + StateStore + Signer + DidResolver + Status + Clone
{
}

/// A blanket implementation for `Provider` trait so that any type implementing
/// the required super traits is considered a `Provider`.
impl<T> Provider for T where
    T: Metadata + Subject + StateStore + Signer + DidResolver + Status + Clone
{
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait Metadata: Send + Sync {
    /// Client (wallet) metadata for the specified issuance client.
    fn client(&self, client_id: &str) -> impl Future<Output = Result<Client>> + Send;

    /// Credential Issuer metadata for the specified issuer.
    fn issuer(&self, credential_issuer: &str) -> impl Future<Output = Result<Issuer>> + Send;

    /// Authorization Server metadata for the specified issuer/server.
    fn server(&self, issuer: &str) -> impl Future<Output = Result<Server>> + Send;

    /// Used to dynamically register OAuth 2.0 clients with the authorization
    /// server.
    fn register(&self, client: &Client) -> impl Future<Output = Result<Client>> + Send;
}

/// `StateStore` is used to store and retrieve server state between requests.
pub trait StateStore: Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve data using the provided key.
    fn get<T>(&self, key: &str) -> impl Future<Output = Result<T>> + Send
    where
        T: for<'a> Deserialize<'a>;

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}

/// The Subject trait specifies how the library expects issuance subject (user)
/// information to be provided by implementers.
pub trait Subject: Send + Sync {
    /// Authorize issuance of the credential specified by
    /// `credential_configuration_id`. Returns a one or more
    /// `credential_identifier`s the subject (holder) is authorized to
    /// request.
    fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> impl Future<Output = Result<Vec<String>>> + Send;

    /// Returns a populated `Dataset` object for the given subject (holder) and
    /// credential definition.
    fn dataset(
        &self, subject_id: &str, credential_identifier: &str,
    ) -> impl Future<Output = Result<Dataset>> + Send;
}

const ISSUER: &str = "ISSUER";
const SERVER: &str = "SERVER";
const CLIENT: &str = "CLIENT";
const STATE: &str = "STATE";

impl<T: BlockStore> Metadata for T {
    async fn client(&self, client_id: &str) -> Result<Client> {
        let Some(block) = BlockStore::get(self, "owner", CLIENT, client_id).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn issuer(&self, credential_issuer: &str) -> Result<Issuer> {
        let Some(block) = BlockStore::get(self, "owner", ISSUER, credential_issuer).await? else {
            return Err(anyhow!("could not find issuer"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn server(&self, issuer: &str) -> Result<Server> {
        let Some(block) = BlockStore::get(self, "owner", SERVER, issuer).await? else {
            return Err(anyhow!("could not find server for issuer"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        let mut client = client.clone();
        client.oauth.client_id = uuid::Uuid::new_v4().to_string();

        let block = serde_json::to_vec(&client)?;
        BlockStore::put(self, "owner", CLIENT, &client.oauth.client_id, &block).await?;
        Ok(client.clone())
    }
}

impl<T: BlockStore> StateStore for T {
    #[allow(unused)]
    async fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> Result<()> {
        let state = serde_json::to_vec(&state)?;
        BlockStore::delete(self, "owner", STATE, key).await?;
        BlockStore::put(self, "owner", STATE, key, &state).await
    }

    async fn get<S>(&self, key: &str) -> Result<S>
    where
        S: for<'a> Deserialize<'a>,
    {
        let Some(block) = BlockStore::get(self, "owner", STATE, key).await? else {
            return Err(anyhow!("could not find client"));
        };
        Ok(serde_json::from_slice(&block)?)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        BlockStore::delete(self, "owner", STATE, key).await
    }
}

impl<T: BlockStore> Subject for T {
    async fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        let Some(block) = BlockStore::get(self, "owner", "SUBJECT", subject_id).await? else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        let datasets: HashMap<String, Dataset> = serde_json::from_slice(&block)?;

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

    async fn dataset(&self, subject_id: &str, credential_identifier: &str) -> Result<Dataset> {
        let Some(block) = BlockStore::get(self, "owner", "SUBJECT", subject_id).await? else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        let datasets: HashMap<String, Dataset> = serde_json::from_slice(&block)?;

        let Some(dataset) = datasets.get(credential_identifier) else {
            return Err(anyhow!("could not find dataset for subject"));
        };
        Ok(dataset.clone())
    }
}
