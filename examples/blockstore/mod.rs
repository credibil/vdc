//! # In-Memory Blockstore

use std::sync::LazyLock;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use cid::Cid;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

// static START: Once = Once::new();
static BLOCKSTORE: LazyLock<InMemoryBlockstore<64>> = LazyLock::new(InMemoryBlockstore::new);

#[derive(Clone, Debug)]
pub struct Mockstore;

impl Mockstore {
    pub fn new() -> Self {
        Self {}
    }

    pub fn dump(&self) {
        println!("Blockstore: {:?}", BLOCKSTORE);
    }

    pub async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        let cid = unique_cid(owner, partition, key)?;
        BLOCKSTORE.put_keyed(&cid, block).await.map_err(Into::into)
    }

    pub async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cid = unique_cid(owner, partition, key)?;
        let Some(bytes) = BLOCKSTORE.get(&cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    pub async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let cid = unique_cid(owner, partition, key)?;
        Ok(BLOCKSTORE.remove(&cid).await?)
    }

    pub async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Serialize, Deserialize)]
struct Identitifier<'a>(&'a str, &'a str, &'a str);
const RAW: u64 = 0x55;

fn unique_cid(owner: &str, partition: &str, key: &str) -> anyhow::Result<Cid> {
    let id = Identitifier(owner, partition, key);
    let mut buf = Vec::new();
    ciborium::into_writer(&id, &mut buf)?;
    let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(RAW, hash))
}
