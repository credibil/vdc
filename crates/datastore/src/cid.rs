//! Content Identifier (CID) utilities.

// use std::io::Read;

use anyhow::Result;
use cid::Cid;
// use futures::executor::block_on;
use multihash_codetable::MultihashDigest;
use serde::Serialize;

// use crate::{BlockStore, ipfs};

const RAW: u64 = 0x55;
// const DAG_CBOR: u64 = 0x71;

/// Compute a CID from provided payload, serialized to CBOR.
///
/// # Errors
///
/// Fails when the payload cannot be serialized to CBOR.
pub fn from_value<T: Serialize>(payload: &T) -> Result<String> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)?;
    let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(RAW, hash).to_string())
}

// /// Compute a CID for the provided data reader.
// ///
// /// # Errors
// ///
// /// Fails when there is an issue processing the provided data using the
// /// mock [`BlockStore`].
// pub fn from_reader(reader: impl Read) -> Result<(String, usize)> {
//     // use the default storage algorithm to compute CID and size
//     block_on(async { ipfs::import("owner", "record_id", "data_cid", reader, &MockStore).await })
// }

// struct MockStore;
// impl BlockStore for MockStore {
//     async fn put(&self, _: &str, _: &str, _: &str, _: &[u8]) -> anyhow::Result<()> {
//         Ok(())
//     }

//     async fn get(&self, _: &str, _: &str, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
//         unimplemented!("MockStore::get")
//     }

//     async fn delete(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
//         unimplemented!("MockStore::delete")
//     }

//     async fn purge(&self, _: &str, _: &str) -> anyhow::Result<()> {
//         unimplemented!("MockStore::purge")
//     }
// }
