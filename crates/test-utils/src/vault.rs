//! Vault

use std::sync::LazyLock;

use anyhow::Result;
use credibil_ecc::Vault;
use dashmap::DashMap;

static VAULT: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct KeyVault;

impl Vault for KeyVault {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        VAULT.insert(key, data.to_vec());
        Ok(())
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = VAULT.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        VAULT.remove(&key);
        Ok(())
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let all = VAULT
            .iter()
            .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
            .map(|r| (r.key().to_string(), r.value().clone()))
            .collect::<Vec<_>>();
        Ok(all)
    }
}
