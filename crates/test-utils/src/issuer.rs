use anyhow::Result;
use credibil_core::datastore;
use credibil_ecc::{Algorithm, PublicKey, Signer};
use credibil_proof::{Resolver, Signature, VerifyBy};

use crate::resources::{Datastore, Identity};

const ISSUER_METADATA: &[u8] = include_bytes!("../data/issuer-metadata.json");
const SERVER_METADATA: &[u8] = include_bytes!("../data/server-metadata.json");
const NORMAL_USER: &[u8] = include_bytes!("../data/normal-user.json");
const PENDING_USER: &[u8] = include_bytes!("../data/pending-user.json");
const CLIENT_METADATA: &[u8] = include_bytes!("../data/client-metadata.json");
const METADATA: &str = "metadata";
const ISSUER: &str = "issuer";
const SERVER: &str = "server";
const SUBJECT: &str = "subject";

#[derive(Clone)]
pub struct Issuer<'a> {
    identity: Identity<'a>,
}

impl<'a> Issuer<'a> {
    pub async fn new(issuer: &'a str) -> Result<Self> {
        let datastore = Datastore;
        datastore.put(issuer, METADATA, ISSUER, ISSUER_METADATA).await?;
        datastore.put(issuer, METADATA, SERVER, SERVER_METADATA).await?;
        datastore.put(issuer, METADATA, "public-client", CLIENT_METADATA).await?;
        datastore.put(issuer, SUBJECT, "normal-user", NORMAL_USER).await?;
        datastore.put(issuer, SUBJECT, "pending-user", PENDING_USER).await?;

        Ok(Self {
            identity: Identity::new(issuer).await?,
        })
    }
}

impl Resolver for Issuer<'_> {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        self.identity.resolve(url).await
    }
}

impl Signer for Issuer<'_> {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.identity.signer().sign(msg).await)
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.identity.signer().verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for Issuer<'_> {
    async fn verification_method(&self) -> Result<VerifyBy> {
        self.identity.verification_method().await
    }
}

impl datastore::Datastore for Issuer<'_> {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        Datastore.put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Datastore.get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        Datastore.delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Datastore.get_all(owner, partition).await
    }
}
