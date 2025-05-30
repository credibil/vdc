use anyhow::Result;
use cid::Cid;
use credibil_core::datastore::Datastore;
use credibil_identity::did::Document;
use credibil_identity::se::{Algorithm, Signer};
use credibil_identity::{Identity, IdentityResolver, Key, SignerExt};
use credibil_vdc::Queryable;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::datastore::Store;
use crate::identity::DidIdentity;



#[derive(Clone)]
pub struct Wallet {
    id: String,
    identity: DidIdentity,
    datastore: Store,
}

const RAW_CODEC: u64 = 0x55;
struct Block(Vec<u8>);

impl Block {
    pub fn new<T: Serialize>(data: &T) -> Result<Self> {
        let mut buf = Vec::new();
        ciborium::into_writer(&data, &mut buf)?;
        Ok(Self(buf))
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    pub fn try_into<T: DeserializeOwned>(self) -> Result<T> {
        ciborium::from_reader(self.0.as_slice()).map_err(|e| e.into())
    }

    pub fn cid(&self) -> Result<Cid> {
        let hash = Code::Sha2_256.digest(&self.0);
        Ok(Cid::new_v1(RAW_CODEC, hash))
    }

    pub fn data(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Wallet {
    pub async fn new(wallet_id: impl Into<String>) -> Self {
        let wallet_id: String = wallet_id.into();
        let datastore = Store::open();

        Self {
            identity: DidIdentity::new(&wallet_id).await,
            id: wallet_id,
            datastore,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    // Add a credential to the store.
    pub async fn add(&mut self, queryable: Queryable) -> Result<()> {
        let block = Block::new(&queryable)?;
        self.datastore.put(&self.id, "CREDENTIAL", &block.cid()?.to_string(), block.data()).await
    }

    pub async fn fetch(&self) -> Result<Vec<Queryable>> {
        let all_vcs = self.datastore.get_all(&self.id, "CREDENTIAL").await?;
        all_vcs.iter().map(|(_, v)| Block::from_slice(v).try_into()).collect()
    }

    pub async fn did(&self) -> Result<Document> {
        self.identity.document(&self.identity.owner).await
    }
}

impl IdentityResolver for Wallet {
    async fn resolve(&self, url: &str) -> Result<Identity> {
        self.identity.resolve(url).await
    }
}

impl Signer for Wallet {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.identity.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.identity.algorithm().await
    }
}

impl SignerExt for Wallet {
    async fn verification_method(&self) -> Result<Key> {
        self.identity.verification_method().await
    }
}

impl Datastore for Wallet {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        self.datastore.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.datastore.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        self.datastore.delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        self.datastore.get_all(owner, partition).await
    }
}
