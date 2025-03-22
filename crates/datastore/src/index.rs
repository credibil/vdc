//! # Index Store
//!
//! The index store is responsible for storing and retrieving message indexes.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound::{self, Excluded, Included, Unbounded};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::query::Query;
use crate::store::{Document, Storable};
use crate::{BlockStore, cid, ipfs};

const NULL: char = '\u{100000}'; // u8 = 0x00;
const MAX: char = '\u{10ffff}'; // u8 = 0x7E;

/// Insert an entry's queryable fields into indexes.
pub async fn insert(
    owner: &str, partition: &str, entry: &impl Storable, store: &impl BlockStore,
) -> Result<()> {
    let message_cid = entry.document().cid()?;

    let fields = &entry.indexes();
    let all_indexes = IndexesBuilder::new().owner(owner).partition(partition).store(store).build();

    // remove the previous index entries for message
    delete(owner, partition, &message_cid, store).await?;

    for (field, value) in fields {
        let mut index = all_indexes.get(field).await?;
        index.insert(
            value,
            IndexItem {
                fields: fields.clone(),
                message_cid: message_cid.clone(),
            },
        );
        all_indexes.put(index).await?;
    }

    // add reverse lookup to use when message is updated or deleted
    let mut index = all_indexes.get("message_cid").await?;
    index.items.insert(
        message_cid.clone(),
        IndexItem {
            fields: fields.clone(),
            message_cid,
        },
    );
    all_indexes.put(index).await?;

    Ok(())
}

/// Query an index for matching entries.
pub async fn query(
    owner: &str, partition: &str, query: &Query, store: &impl BlockStore,
) -> Result<Vec<IndexItem>> {
    let indexes = IndexesBuilder::new().owner(owner).partition(partition).store(store).build();

    if query.is_concise() {
        return indexes.query_concise(query).await;
    }
    indexes.query_full(query).await
}

/// Delete entry specified by `message_cid` from indexes.
pub async fn delete(
    owner: &str, partition: &str, message_cid: &str, store: &impl BlockStore,
) -> Result<()> {
    let indexes = IndexesBuilder::new().owner(owner).partition(partition).store(store).build();

    // if this is an update, remove the previous message indexes
    let messages = indexes.get("message_cid").await?;
    if let Some(item) = messages.items.get(message_cid) {
        for (field, value) in &item.fields {
            let mut index = indexes.get(field).await?;
            let x = index.remove(value, message_cid);
            indexes.put(index).await?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct Cid(String);

/// Indexes store.
pub struct Indexes<'a, S: BlockStore> {
    owner: &'a str,
    partition: &'a str,
    store: &'a S,
}

impl<S: BlockStore> Indexes<'_, S> {
    /// Get an index.
    pub async fn get(&self, field: &str) -> Result<Index> {
        let index_cid = cid::from_value(&Cid(format!("{}-{}", self.owner, field)))?;

        // get the index block or return empty index
        let Some(data) = self.store.get(self.owner, self.partition, &index_cid).await? else {
            return Ok(Index::new(field));
        };
        ipfs::decode_block(&data)
    }

    /// Update an index.
    pub async fn put(&self, index: Index) -> Result<()> {
        let index_cid = cid::from_value(&Cid(format!("{}-{}", self.owner, index.field)))?;

        // update the index block
        self.store.delete(self.owner, self.partition, &index_cid).await?;
        self.store.put(self.owner, self.partition, &index_cid, &ipfs::encode_block(&index)?).await
    }

    // This query strategy is used when the filter contains a property that
    // leads to a concise, or small, set of results that can be sorted and
    // paged in memory.
    //
    // This strategy is employed when the filter contains one of `record_id`,
    // `context_id`, `protocol_path`, `parent_id`, or `schema`.
    async fn query_concise(&self, query: &Query) -> Result<Vec<IndexItem>> {
        let mut matches = HashSet::new();
        let mut results = BTreeMap::new();

        let sort_field = query.sort.to_string();

        // match sets are 'OR-ed' together
        for match_set in &query.match_sets {
            // choose the best index to use for this MatchSet
            let Some((field, value)) = &match_set.index else {
                continue;
            };

            let index = self.get(field).await?;

            // 1. use the index to find candidate matches
            // 2. compare each entry against the current filter
            'next_item: for item in index.matches(value.clone()) {
                // short circuit when previously matched
                if matches.contains(&item.message_cid) {
                    continue;
                }

                // a set of matchers are 'AND-ed' together
                for matcher in &match_set.inner {
                    let Some(index_value) = item.fields.get(&matcher.field) else {
                        continue 'next_item;
                    };
                    if !matcher.is_match(index_value)? {
                        continue 'next_item;
                    }
                }

                matches.insert(item.message_cid.clone());

                // sort results as we collect using `message_cid` as a tie-breaker
                let sort_key = format!("{}{}", &item.fields[&sort_field], item.message_cid);
                results.insert(sort_key, item.clone());
            }
        }

        // collect results in sorted order
        let mut items = if query.sort.is_ascending() {
            results.values().cloned().collect::<Vec<IndexItem>>()
        } else {
            results.values().rev().cloned().collect::<Vec<IndexItem>>()
        };

        // paginate results
        if let Some(pagination) = &query.pagination {
            let limit = pagination.limit.unwrap_or(items.len());
            let start = pagination.cursor.as_ref().map_or(0, |cursor| {
                items.iter().position(|item| item.message_cid == cursor.message_cid).unwrap_or(0)
            });

            let mut end = start + limit + 1;
            if end > items.len() {
                end = items.len();
            }
            items = items[start..end].to_vec();
        }

        Ok(items)
    }

    // This query strategy is used when the filter will return a larger set of
    // results.
    async fn query_full(&self, query: &Query) -> Result<Vec<IndexItem>> {
        let mut items = Vec::new();
        let mut matches = HashSet::new();

        let (limit, cursor) =
            query.pagination.as_ref().map_or((None, None), |p| (p.limit, p.cursor.as_ref()));

        // the location in the index to begin querying from
        let start_key =
            cursor.map_or(Unbounded, |c| Included(format!("{}{NULL}{}", c.value, c.message_cid)));
        let index = self.get(&query.sort.to_string()).await?;

        // starting from `start_key`, select matching index items until limit
        for (value, item) in index.lower_bound(start_key) {
            // stop when page limit + 1 is reached
            if let Some(lim) = limit {
                if items.len() == lim + 1 {
                    break;
                }
            }

            if matches.contains(&item.message_cid) {
                continue;
            }

            if query.match_sets.is_empty() {
                matches.insert(item.message_cid.clone());
                items.push(item.clone());
                continue;
            }

            // match sets are 'OR-ed' together
            'next_set: for match_set in &query.match_sets {
                // a set of matchers are 'AND-ed' together
                for matcher in &match_set.inner {
                    let Some(index_value) = item.fields.get(&matcher.field) else {
                        continue 'next_set;
                    };
                    if !matcher.is_match(index_value)? {
                        continue 'next_set;
                    }
                }
                matches.insert(item.message_cid.clone());
                items.push(item.clone());
            }
        }

        Ok(items)
    }
}

/// `Index` wraps a physical index, providing helper methods.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    field: String,
    items: BTreeMap<String, IndexItem>,
}

/// Represents an index entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexItem {
    /// The CID pointing to the indexed message.
    pub message_cid: String,

    /// The fields indexed for the message.
    pub fields: HashMap<String, String>,
}

impl Index {
    fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            items: BTreeMap::new(),
        }
    }

    fn insert(&mut self, value: &str, item: IndexItem) {
        let key = format!("{value}{NULL}{}", item.message_cid);
        self.items.insert(key, item);
    }

    fn remove(&mut self, value: &str, message_cid: &str) -> Option<IndexItem> {
        let key = format!("{value}{NULL}{message_cid}");
        self.items.remove(&key)
    }

    fn lower_bound(&self, lower: Bound<String>) -> Range<String, IndexItem> {
        self.items.range((lower, Unbounded))
    }

    fn matches(&self, value: String) -> Vec<&IndexItem> {
        let index = &self.items;
        let upper = format!("{value}{MAX}");
        index.range((Excluded(value), Excluded(upper))).map(|(_, item)| item).collect()
    }
}

struct IndexesBuilder<O, P, S> {
    owner: O,
    partition: P,
    indexes: Option<BTreeMap<String, String>>,
    store: S,
}

/// Store has been set on IndexesBuilder.
#[doc(hidden)]
struct Owner<'a>(&'a str);
/// Store not set on IndexesBuilder.
#[doc(hidden)]
struct NoOwner;

/// Partition has been set on IndexesBuilder.
#[doc(hidden)]
struct Partition<'a>(&'a str);
/// Partition not set on IndexesBuilder.
#[doc(hidden)]
struct NoPartition;

/// Store has been set on IndexesBuilder.
#[doc(hidden)]
struct Store<'a, S: BlockStore>(&'a S);
/// Store not set on IndexesBuilder.
#[doc(hidden)]
struct NoStore;

impl IndexesBuilder<NoOwner, NoPartition, NoStore> {
    const fn new() -> Self {
        Self {
            owner: NoOwner,
            partition: NoPartition,
            indexes: None,
            store: NoStore,
        }
    }
}

impl<P, S> IndexesBuilder<NoOwner, P, S> {
    fn owner(self, owner: &str) -> IndexesBuilder<Owner, P, S> {
        IndexesBuilder {
            owner: Owner(owner),
            partition: self.partition,
            indexes: None,
            store: self.store,
        }
    }
}

impl<O, S> IndexesBuilder<O, NoPartition, S> {
    fn partition(self, partition: &str) -> IndexesBuilder<O, Partition, S> {
        IndexesBuilder {
            owner: self.owner,
            partition: Partition(partition),
            indexes: None,
            store: self.store,
        }
    }
}

impl<O, P> IndexesBuilder<O, P, NoStore> {
    fn store<S: BlockStore>(self, store: &S) -> IndexesBuilder<O, P, Store<'_, S>> {
        IndexesBuilder {
            owner: self.owner,
            partition: self.partition,
            indexes: self.indexes,
            store: Store(store),
        }
    }
}

impl<'a, S: BlockStore> IndexesBuilder<Owner<'a>, Partition<'a>, Store<'a, S>> {
    fn build(self) -> Indexes<'a, S> {
        Indexes {
            owner: self.owner.0,
            partition: self.partition.0,
            store: self.store.0,
        }
    }
}

// #[cfg(test)]
// mod tests {

//     use std::io::Cursor;
//     use std::str::FromStr;

//     use anyhow::Result;
//     use blockstore::{Blockstore as _, InMemoryBlockstore};
//     use rand::RngCore;
//     use test_node::keystore;

//     use super::*;
//     use crate::client::protocols::{ConfigureBuilder, Definition};
//     use crate::client::records::{Data, WriteBuilder};
//     use crate::store::{ProtocolsQueryBuilder, RecordsFilter, RecordsQueryBuilder};

//     const PARTITION: &str = "TEST";

//     #[tokio::test]
//     async fn query_records() {
//         let block_store = BlockStoreImpl::new();
//         let alice = keystore::new_keyring();

//         let mut data = [0u8; 10];
//         rand::thread_rng().fill_bytes(&mut data);
//         let stream = Cursor::new(data.to_vec());

//         let write = WriteBuilder::new()
//             .data(Data::Stream(stream.clone()))
//             .published(true)
//             .sign(&alice)
//             .build()
//             .await
//             .unwrap();

//         // add message
//         let message_cid = write.cid().unwrap();
//         let block = ipfs::encode_block(&write).unwrap();
//         block_store.put(&alice.did, PARTITION, &message_cid, &block).await.unwrap();

//         // update indexes
//         super::insert(&alice.did, PARTITION, &write, &block_store).await.unwrap();

//         // execute query
//         let query = RecordsQueryBuilder::new()
//             .add_filter(
//                 RecordsFilter::new()
//                     // .add_author(&alice.did)
//                     // .data_size(Range::new().gt(8)),
//                     .record_id(write.record_id),
//             )
//             .build();

//         let items = super::query(&alice.did, PARTITION, &query, &block_store).await.unwrap();
//     }

//     #[tokio::test]
//     async fn query_protocols() {
//         let block_store = BlockStoreImpl::new();
//         let alice = keystore::new_keyring();

//         let configure = ConfigureBuilder::new()
//             .definition(Definition::new("http://minimal.xyz"))
//             .sign(&alice)
//             .build()
//             .await
//             .expect("should build");

//         // add message
//         let message_cid = configure.cid().unwrap();
//         let block = ipfs::encode_block(&configure).unwrap();
//         block_store.put(&alice.did, PARTITION, &message_cid, &block).await.unwrap();

//         // update indexes
//         super::insert(&alice.did, PARTITION, &configure, &block_store).await.unwrap();

//         // execute query
//         let query = ProtocolsQueryBuilder::new().protocol("http://minimal.xyz").build();
//         let items = super::query(&alice.did, PARTITION, &query, &block_store).await.unwrap();
//     }

//     struct BlockStoreImpl {
//         blockstore: InMemoryBlockstore<64>,
//     }

//     impl BlockStoreImpl {
//         pub fn new() -> Self {
//             Self {
//                 blockstore: InMemoryBlockstore::<64>::new(),
//             }
//         }
//     }

//     impl BlockStore for BlockStoreImpl {
//         async fn put(&self, owner: &str, partition: &str, cid: &str, data: &[u8]) -> Result<()> {
//             // convert libipld CID to blockstore CID
//             let block_cid = ::cid::Cid::from_str(cid)?;
//             self.blockstore.put_keyed(&block_cid, data).await.map_err(Into::into)
//         }

//         async fn get(&self, owner: &str, partition: &str, cid: &str) -> Result<Option<Vec<u8>>> {
//             // convert libipld CID to blockstore CID
//             let block_cid = ::cid::Cid::try_from(cid)?;
//             let Some(bytes) = self.blockstore.get(&block_cid).await? else {
//                 return Ok(None);
//             };
//             Ok(Some(bytes))
//         }

//         async fn delete(&self, owner: &str, partition: &str, cid: &str) -> Result<()> {
//             let cid = ::cid::Cid::from_str(cid)?;
//             self.blockstore.remove(&cid).await?;
//             Ok(())
//         }

//         async fn purge(&self, owner: &str, partition: &str) -> Result<()> {
//             unimplemented!()
//         }
//     }
// }
