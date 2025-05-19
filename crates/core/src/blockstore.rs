//! # Block Store

use cid::Cid;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Sized + Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(
        &self, owner: &str, partition: &str, cid: &str, data: &[u8],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all blocks for the owner/partition.
    fn purge(
        &self, owner: &str, partition: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[derive(Serialize, Deserialize)]
struct Identitifier<'a>(&'a str, &'a str, &'a str);
const RAW: u64 = 0x55;

/// Generates a unique CID for the given owner, partition, and key.
///
/// # Errors
///
/// Returns an error if the serialization of the identifier fails.
pub fn unique_cid(owner: &str, partition: &str, key: &str) -> anyhow::Result<Cid> {
    let id = Identitifier(owner, partition, key);
    let mut buf = Vec::new();
    ciborium::into_writer(&id, &mut buf)?;
    let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(RAW, hash))
}
