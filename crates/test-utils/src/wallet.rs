use anyhow::Result;
use cid::Cid;
use credibil_core::datastore::Datastore;
use credibil_ecc::Curve::Ed25519;
use credibil_ecc::{Algorithm, Entry, Keyring, PublicKey, Signer};
use credibil_proof::{Resolver, Signature, VerifyBy};
use credibil_vdc::Queryable;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::datastore::Store;
use crate::identity::Identity;
use crate::vault::KeyVault as Vault;

#[derive(Clone)]
pub struct Wallet {
    wallet_id: String,
    signer: Entry,
    identity: Identity,
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

        let signer = Keyring::generate(&Vault, &wallet_id, "signing", Ed25519)
            .await
            .expect("should generate");
        let identity = Identity::new(&wallet_id, &signer).await;

        Self {
            wallet_id,
            signer,
            identity,
        }
    }

    pub fn id(&self) -> &str {
        &self.wallet_id
    }

    // Add a credential to the store.
    pub async fn add(&self, queryable: Queryable) -> Result<()> {
        let block = Block::new(&queryable)?;
        Store.put(&self.wallet_id, "CREDENTIAL", &block.cid()?.to_string(), block.data()).await
    }

    pub async fn fetch(&self) -> Result<Vec<Queryable>> {
        let all_vcs = Store.get_all(&self.wallet_id, "CREDENTIAL").await?;
        all_vcs.iter().map(|(_, v)| Block::from_slice(v).try_into()).collect()
    }
}

impl Resolver for Wallet {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        self.identity.resolve(url).await
    }
}

impl Signer for Wallet {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.signer.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        self.signer.algorithm().await
    }
}

impl Signature for Wallet {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.identity.verification_method().await
    }
}

impl Datastore for Wallet {
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
