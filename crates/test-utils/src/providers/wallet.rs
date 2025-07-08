use std::thread;

use anyhow::{Result, anyhow};
use credibil_binding::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_binding::ecc::Curve::Ed25519;
use credibil_binding::ecc::{Entry, Keyring, Signer};
use credibil_binding::jose::PublicKeyJwk;
use credibil_binding::{Binding, DocumentRequest, Resolver, Signature, VerifyBy};
use credibil_ecc::{Algorithm, PublicKey};
use credibil_oid4vp::Client;
use credibil_vdc::Queryable;

use crate::resources::{Datastore, KeyVault};

#[derive(Clone)]
pub struct Wallet<'a> {
    owner: &'a str,
    signer: Entry,
}

impl<'a> Wallet<'a> {
    pub async fn new(owner: &'a str) -> Result<Self> {
        // fetch (or generate) the signing key
        let signer = match Keyring::entry(&KeyVault, owner, "signing").await {
            Ok(entry) => entry,
            Err(_) => Keyring::generate(&KeyVault, owner, "signing", Ed25519).await?,
        };

        // generate a did:web document
        let verifying_key = signer.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);

        let wallet = Self { owner, signer };
        credibil_binding::create(owner, builder, &wallet).await?;

        Ok(wallet)
    }

    // Add a credential to the store.
    pub async fn add(&self, queryable: Queryable) -> Result<()> {
        let data = serde_json::to_vec(&queryable)?;
        let key =
            queryable.credential.as_str().ok_or_else(|| anyhow!("credential must be a string"))?;
        Datastore::put(self.owner, "credential", key, &data).await
    }

    pub async fn fetch(&self) -> Result<Vec<Queryable>> {
        let all_vcs = Datastore::get_all(self.owner, "credential").await?;
        all_vcs.iter().map(|(_, v)| Ok(serde_json::from_slice(v)?)).collect()
    }
}

impl Resolver for Wallet<'_> {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let document = if thread::current().name() == Some("tokio-runtime-worker") {
            // in a tokio runtime (-> running in a web server)
            reqwest::get(url.replace("https", "http")).await?.json::<Document>().await?
        } else {
            // not in a tokio runtime (-> running in a test)
            Client::new(self.clone())
                .request(DocumentRequest { url: url.to_string() })
                .owner(self.owner)
                .await
                .map(|r| r.0.clone())?
        };
        Ok(serde_json::to_vec(&document)?)
    }
}

impl Signer for Wallet<'_> {
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

impl Signature for Wallet<'_> {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let request = DocumentRequest { url: format!("{}/.well-known/did.json", self.owner) };
        let document = Client::new(self.clone())
            .request(request)
            .owner(self.owner)
            .await
            .map(|r| r.0.clone())?;
        let Some(vm) = &document.verification_method.as_ref().and_then(|v| v.first()) else {
            return Err(anyhow!("no verification method found"));
        };
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }
}

impl Binding for Wallet<'_> {
    async fn put(&self, owner: &str, document: &Document) -> Result<()> {
        let data = serde_json::to_vec(document)?;
        Datastore::put(owner, "proof", &document.id, &data).await
    }

    async fn get(&self, owner: &str, key: &str) -> Result<Option<Document>> {
        let Some(data) = Datastore::get(owner, "proof", key).await? else {
            return Err(anyhow!("could not find proof"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn delete(&self, owner: &str, key: &str) -> Result<()> {
        Datastore::delete(owner, "proof", key).await
    }

    async fn get_all(&self, owner: &str) -> Result<Vec<(String, Document)>> {
        Datastore::get_all(owner, "proof")
            .await?
            .iter()
            .map(|(k, v)| Ok((k.to_string(), serde_json::from_slice(v)?)))
            .collect()
    }
}
