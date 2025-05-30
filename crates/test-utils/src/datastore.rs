//! # In-Memory Datastore

use std::sync::LazyLock;

use anyhow::Result;
use dashmap::DashMap;

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct Store;

impl Store {
    pub fn open() -> Self {
        Self {}
    }

    pub async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.insert(key, data.to_vec());
        Ok(())
    }

    pub async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = STORE.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    pub async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.remove(&key);
        Ok(())
    }

    pub async fn get_all(
        &self, owner: &str, partition: &str,
    ) -> impl Iterator<Item = (String, Vec<u8>)> {
        STORE
            .iter()
            .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
            .map(|r| (r.key().to_string(), r.value().clone()))
    }
}
