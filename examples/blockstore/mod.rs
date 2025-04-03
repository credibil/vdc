use anyhow::Result;
use blockstore::Blockstore as _;
use cid::Cid;
use credibil_vc::BlockStore;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

use super::ProviderImpl;

const RAW: u64 = 0x55;

#[derive(Serialize, Deserialize)]
struct Identitifier<'a> {
    owner: &'a str,
    partition: &'a str,
    key: &'a str,
}

impl<'a> Identitifier<'a> {
    fn new(owner: &'a str, partition: &'a str, key: &'a str) -> Self {
        Self {
            owner,
            partition,
            key,
        }
    }

    fn to_cid(&self) -> anyhow::Result<Cid> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash))
    }
}

impl BlockStore for ProviderImpl {
    async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        self.blockstore.put_keyed(&cid, block).await.map_err(Into::into)
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        let Some(bytes) = self.blockstore.get(&cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        Ok(self.blockstore.remove(&cid).await?)
    }

    async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}
