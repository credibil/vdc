//! # In-Memory Blockstore

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow};

type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;
static STORE: LazyLock<Store> = LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone, Debug)]
pub struct Mockstore;

impl Mockstore {
    pub fn open() -> Self {
        Self {}
    }

    pub async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.lock().map_err(|_| anyhow!("issue locking"))?.insert(key, data.to_vec());
        Ok(())
    }

    pub async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let store = STORE.lock().map_err(|_| anyhow!("issue locking"))?;
        let Some(bytes) = store.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    pub async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.lock().map_err(|_| anyhow!("issue locking"))?.remove(&key);
        Ok(())
    }

    pub async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let store = STORE.lock().expect("should unlock");
        let items = store
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{owner}-{partition}")))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        Ok(items)
    }
}
