//! # In-Memory Blockstore

use std::sync::LazyLock;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use credibil_core::blockstore::unique_cid;

// static START: Once = Once::new();
static BLOCKSTORE: LazyLock<InMemoryBlockstore<64>> = LazyLock::new(InMemoryBlockstore::new);

#[derive(Clone, Debug)]
pub struct Mockstore;

impl Mockstore {
    pub fn open() -> Self {
        Self {}
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
}
