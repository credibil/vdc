//! Vault

use anyhow::Result;
use credibil_ecc::Vault;

use crate::resources::store::Datastore;

#[derive(Clone, Debug)]
pub struct KeyVault;

impl Vault for KeyVault {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        Datastore::put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Datastore::get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        Datastore::delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Datastore::get_all(owner, partition).await
    }
}
