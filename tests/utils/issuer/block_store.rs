use std::str::FromStr;

use anyhow::Result;
use blockstore::Blockstore as _;
use credibil_dwn::provider::BlockStore;

use super::ProviderImpl;

impl BlockStore for ProviderImpl {
    async fn put(&self, owner: &str, partition: &str, cid: &str, block: &[u8]) -> Result<()> {
        // convert libipld CID to blockstore CID
        let block_cid = cid::Cid::from_str(cid)?;
        self.blockstore.put_keyed(&block_cid, block).await.map_err(Into::into)
    }

    async fn get(&self, owner: &str, partition: &str, cid: &str) -> Result<Option<Vec<u8>>> {
        // convert libipld CID to blockstore CID
        let block_cid = cid::Cid::try_from(cid)?;
        let Some(bytes) = self.blockstore.get(&block_cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    async fn delete(&self, owner: &str, partition: &str, cid: &str) -> Result<()> {
        let cid = cid::Cid::from_str(cid)?;
        self.blockstore.remove(&cid).await?;
        Ok(())
    }

    async fn purge(&self, owner: &str, partition: &str) -> Result<()> {
        unimplemented!()
    }
}
