//! # `OpenID` for Verifiable Credential Issuance

use std::future::Future;

use anyhow::Result;
use chrono::{DateTime, Utc};
use credibil_did::DidResolver;
use credibil_infosec::Signer;
use serde::Serialize;
use serde::de::Deserialize;

use crate::oid4vci::types::{Client, Dataset, Issuer, Server};
use crate::status::issuer::Status;

/// Issuer Provider trait.
pub trait Provider:
    Metadata + Subject + StateStore + Signer + DidResolver + Status + Clone
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

/// `StateStore` is used to store and retrieve server state between requests.
pub trait StateStore: Send + Sync {
    /// Store state using the provided key. The expiry parameter indicates
    /// when data can be expunged from the state store.
    fn put(
        &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    // fn put(
    //     &self, key: &str, state: impl Serialize + Send, expiry: DateTime<Utc>,
    // ) -> impl Future<Output = Result<()>> + Send {
    //     async { store::put(owner, "STATE", entry, self).await }
    //     async { BlockStore::put(owner, "STATE", entry, self).await }
    // }

    /// Retrieve data using the provided key.
    fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> impl Future<Output = Result<T>> + Send;

    // fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> impl Future<Output = Result<T>> + Send {
    //     async { store::get(owner, "STATE", message_cid, self).await }
    //}

    /// Remove data using the key provided.
    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;

    // fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send{
    //     async { store::delete(owner, "STATE", message_cid, self).await }
    // }
}
