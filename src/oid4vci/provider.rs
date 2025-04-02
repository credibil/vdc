//! # `OpenID` for Verifiable Credential Issuance

use std::future::Future;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use credibil_did::DidResolver;
use credibil_infosec::Signer;
use serde::Serialize;
use serde::de::Deserialize;

use crate::BlockStore;
use crate::oid4vci::types::{Client, Dataset, Issuer, Server};
use crate::status::issuer::Status;

/// Issuer Provider trait.
pub trait Provider:
    Metadata + Subject + StateStore + Signer + DidResolver + Status + Clone
{
}

impl<T> Provider for T where
    T: Metadata + Subject + StateStore + Signer + DidResolver + Status + Clone
{
}
impl<T> Metadata for T where T: BlockStore {}
impl<T> StateStore for T where T: BlockStore {}
// impl<T> Subject for T where T: BlockStore {}

const ISSUER: &str = "ISSUER";
const SERVER: &str = "SERVER";
const CLIENT: &str = "CLIENT";
const STATE: &str = "STATE";

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait Metadata: BlockStore + Send + Sync {
    /// Client (wallet) metadata for the specified issuance client.
    fn client(&self, client_id: &str) -> impl Future<Output = Result<Client>> + Send {
        async {
            let Some(block) = BlockStore::get(self, "owner", CLIENT, client_id).await? else {
                return Err(anyhow!("could not find client"));
            };
            Ok(serde_json::from_slice(&block)?)
        }
    }

    /// Credential Issuer metadata for the specified issuer.
    fn issuer(&self, credential_issuer: &str) -> impl Future<Output = Result<Issuer>> + Send {
        async {
            let Some(block) = BlockStore::get(self, "owner", ISSUER, credential_issuer).await?
            else {
                return Err(anyhow!("could not find issuer"));
            };
            Ok(serde_json::from_slice(&block)?)
        }
    }

    /// Authorization Server metadata for the specified issuer/server.
    fn server(&self, issuer: &str) -> impl Future<Output = Result<Server>> + Send {
        async {
            let Some(block) = BlockStore::get(self, "owner", SERVER, issuer).await? else {
                return Err(anyhow!("could not find server for issuer"));
            };
            Ok(serde_json::from_slice(&block)?)
        }
    }

    /// Used to dynamically register OAuth 2.0 clients with the authorization
    /// server.
    fn register(&self, client: &Client) -> impl Future<Output = Result<Client>> + Send {
        async {
            let mut client = client.clone();
            client.oauth.client_id = uuid::Uuid::new_v4().to_string();

            let block = serde_json::to_vec(&client)?;
            BlockStore::put(self, "owner", CLIENT, &client.oauth.client_id, &block).await?;
            Ok(client.clone())
        }
    }
}

/// `StateStore` is used to store and retrieve server state between requests.
pub trait StateStore: BlockStore + Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    #[allow(unused)]
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send {
        async move {
            let state = serde_json::to_vec(&state)?;
            BlockStore::delete(self, "owner", STATE, key).await?;
            BlockStore::put(self, "owner", STATE, key, &state).await
        }
    }

    /// Retrieve data using the provided key.
    fn get<T>(&self, key: &str) -> impl Future<Output = Result<T>> + Send
    where
        T: for<'a> Deserialize<'a>,
    {
        async {
            let Some(block) = BlockStore::get(self, "owner", STATE, key).await? else {
                return Err(anyhow!("could not find client"));
            };
            Ok(serde_json::from_slice(&block)?)
        }
    }

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send {
        BlockStore::delete(self, "owner", STATE, key)
    }
}

/// The Subject trait specifies how the library expects issuance subject (user)
/// information to be provided by implementers.
pub trait Subject: BlockStore + Send + Sync {
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
