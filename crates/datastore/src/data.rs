//! Data record handling.

use std::io::{Cursor, Read, Write};

use anyhow::{Result, anyhow};
use ipld_core::ipld::Ipld;

use crate::{BlockStore, ipfs};

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 30000;

/// Put a data record into the block store.
pub async fn put(
    owner: &str, partition: &str, data_cid: &str, reader: impl Read, store: &impl BlockStore,
) -> Result<(String, usize)> {
    ipfs::import(owner, partition, data_cid, reader, store).await
}

/// Get a data record from the block store.
pub async fn get(
    owner: &str, partition: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<Option<Cursor<Vec<u8>>>> {
    let Some(bytes) = store.get(owner, partition, data_cid).await? else {
        return Ok(None);
    };

    // the root blook contains a list of links to data blocks
    let Ipld::List(links) = ipfs::decode_block(&bytes)? else {
        return Ok(None);
    };

    // TODO: optimize by streaming the data blocks as fetched
    // fetch each data block
    let mut buf = Cursor::new(vec![]);

    for link in links {
        // get data block
        let Ipld::Link(link_cid) = link else {
            return Err(anyhow!("invalid link"));
        };
        let Some(bytes) = store.get(owner, partition, &link_cid.to_string()).await? else {
            return Ok(None);
        };

        // get data block's payload
        let ipld_bytes = ipfs::decode_block(&bytes)?;
        let Ipld::Bytes(bytes) = ipld_bytes else {
            return Ok(None);
        };

        buf.write_all(&bytes)?;
    }

    buf.set_position(0);
    Ok(Some(buf))
}

pub async fn delete(
    owner: &str, partition: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<()> {
    store.delete(owner, partition, data_cid).await
}
