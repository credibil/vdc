use anyhow::Result;
use cid::Cid;
use credibil_core::datastore::Datastore;
use credibil_ecc::{Algorithm, PublicKey, Signer};
use credibil_proof::{Resolver, Signature, VerifyBy};
use credibil_vdc::Queryable;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::identity::Identity;
use crate::store::Store;

#[derive(Clone)]
pub struct Wallet<'a> {
    wallet_id: &'a str,
    identity: Identity<'a>,
}

impl<'a> Wallet<'a> {
    pub async fn new(wallet_id: &'a str) -> Result<Self> {
        Ok(Self {
            wallet_id,
            identity: Identity::new(wallet_id).await?,
        })
    }

    pub fn id(&self) -> &str {
        self.wallet_id
    }

    // Add a credential to the store.
    pub async fn add(&self, queryable: Queryable) -> Result<()> {
        let block = Block::new(&queryable)?;
        Store.put(self.wallet_id, "credential", &block.cid()?.to_string(), block.data()).await
    }

    pub async fn fetch(&self) -> Result<Vec<Queryable>> {
        let all_vcs = Store.get_all(self.wallet_id, "credential").await?;
        all_vcs.iter().map(|(_, v)| Block::from_slice(v).try_into()).collect()
    }
}

impl Resolver for Wallet<'_> {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        self.identity.resolve(url).await
    }
}

impl Signer for Wallet<'_> {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.identity.signer().try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.identity.signer().verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.identity.signer().algorithm().await
    }
}

impl Signature for Wallet<'_> {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.identity.verification_method().await
    }
}

impl Datastore for Wallet<'_> {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        Store.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Store.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        Store.delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Store.get_all(owner, partition).await
    }
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
