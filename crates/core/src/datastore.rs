//! # Datastore

use anyhow::Result;

/// `Datastore` is used by implementers to provide data storage
/// capability.
pub trait Datastore: Sized + Send + Sync {
    /// Store a data item in the underlying item store.
    fn put(
        &self, owner: &str, partition: &str, key: &str, data: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single item from the underlying store, returning `None` if
    /// no match was found.
    fn get(
        &self, owner: &str, partition: &str, key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Delete the specified data item.
    fn delete(
        &self, owner: &str, partition: &str, key: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Fetches all matching items from the underlying store.
    fn get_all(
        &self, owner: &str, partition: &str,
    ) -> impl Future<Output = Result<Vec<(String, Vec<u8>)>>> + Send;

    // /// Stores data items in the underlying store.
    // fn put_many(
    //     &self, owner: &str, partition: &str, key: &str, data: &[u8],
    // ) -> impl Future<Output = Result<()>> + Send;

    // /// Fetches specified items from the underlying store.
    // fn get_many(
    //     &self, owner: &str, partition: &str, key: &[&str],
    // ) -> impl Future<Output = Result<Block>> + Send;

    // /// Delete items for the owner/partition.
    // fn delete_many(
    //     &self, owner: &str, partition: &str, cids:&[&str],
    // ) -> impl Future<Output = Result<()>> + Send;
}
