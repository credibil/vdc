//! # In-Memory Datastore

use std::sync::LazyLock;

use anyhow::Result;
use dashmap::DashMap;

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct Datastore;

impl Datastore {
    pub async fn put(owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        STORE.insert(format!("{owner}-{partition}-{key}"), data.to_vec());
        Ok(())
    }

    pub async fn get(owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = STORE.get(&format!("{owner}-{partition}-{key}")) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    pub async fn delete(owner: &str, partition: &str, key: &str) -> Result<()> {
        STORE.remove(&format!("{owner}-{partition}-{key}"));
        Ok(())
    }

    pub async fn get_all(owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let all = STORE
            .iter()
            .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
            .map(|r| (r.key().to_string(), r.value().clone()))
            .collect::<Vec<_>>();
        Ok(all)
    }
}

#[derive(Clone)]
pub struct Keyvalue;

impl Keyvalue {
    pub fn put(owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        STORE.insert(format!("{owner}-{partition}-{key}"), data.to_vec());
        Ok(())
    }

    pub fn get(owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = STORE.get(&format!("{owner}-{partition}-{key}")) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    pub fn delete(owner: &str, partition: &str, key: &str) -> Result<()> {
        STORE.remove(&format!("{owner}-{partition}-{key}"));
        Ok(())
    }
}
