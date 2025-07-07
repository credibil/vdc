use anyhow::{Result, anyhow};
use credibil_ecc::{Algorithm, PublicKey, Signer};
use credibil_proof::did::Document;
use credibil_proof::{Proof, Resolver, Signature, VerifyBy};
use credibil_vdc::Queryable;

use crate::resources::{Datastore, Identity};

#[derive(Clone)]
pub struct Wallet<'a> {
    identity: Identity<'a>,
}

impl<'a> Wallet<'a> {
    pub async fn new(owner: &'a str) -> Result<Self> {
        Ok(Self {
            identity: Identity::new(owner).await?,
        })
    }

    // Add a credential to the store.
    pub async fn add(&self, queryable: Queryable) -> Result<()> {
        let data = serde_json::to_vec(&queryable)?;
        let key =
            queryable.credential.as_str().ok_or_else(|| anyhow!("credential must be a string"))?;
        Datastore.put(self.identity.owner, "credential", key, &data).await
    }

    pub async fn fetch(&self) -> Result<Vec<Queryable>> {
        let all_vcs = Datastore.get_all(self.identity.owner, "credential").await?;
        all_vcs.iter().map(|(_, v)| Ok(serde_json::from_slice(v)?)).collect()
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

impl Proof for Wallet<'_> {
    async fn put(&self, owner: &str, document: &Document) -> Result<()> {
        let data = serde_json::to_vec(document)?;
        Datastore.put(owner, "proof", &document.id, &data).await
    }

    async fn get(&self, owner: &str, key: &str) -> Result<Option<Document>> {
        let Some(data) = Datastore.get(owner, "proof", key).await? else {
            return Err(anyhow!("could not find proof"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn delete(&self, owner: &str, key: &str) -> Result<()> {
        Datastore.delete(owner, "proof", key).await
    }

    async fn get_all(&self, owner: &str) -> Result<Vec<(String, Document)>> {
        Datastore
            .get_all(owner, "proof")
            .await?
            .iter()
            .map(|(k, v)| Ok((k.to_string(), serde_json::from_slice(v)?)))
            .collect()
    }
}
