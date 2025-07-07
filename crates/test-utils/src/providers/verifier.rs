use std::str::FromStr;
use std::thread;

use anyhow::{Result, anyhow};
use credibil_binding::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_binding::ecc::Curve::Ed25519;
use credibil_binding::ecc::{Entry, Keyring, Signer};
use credibil_binding::jose::PublicKeyJwk;
use credibil_binding::{Binding, DocumentRequest, Resolver, Signature, VerifyBy};
use credibil_ecc::{Algorithm, PublicKey};
use credibil_oid4vp::provider::{Metadata, StateStore, StatusToken};
use credibil_oid4vp::{Client, State, VerifierMetadata};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::resources::{Datastore, KeyVault, Keyvalue};

const VERIFIER_METADATA: &[u8] = include_bytes!("../../data/verifier-metadata.json");

#[derive(Clone)]
pub struct Verifier<'a> {
    owner: &'a str,
    signer: Entry,
}

impl<'a> Verifier<'a> {
    pub async fn new(owner: &'a str) -> Result<Self> {
        Datastore::put(owner, "metadata", "verifier", VERIFIER_METADATA).await?;

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

        let verifier = Self { owner, signer };
        credibil_binding::create(owner, builder, &verifier).await?;

        Ok(verifier)
    }
}

impl Resolver for Verifier<'_> {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let document = if thread::current().name() == Some("tokio-runtime-worker") {
            // in a tokio runtime (-> running in a web server)
            reqwest::get(url.replace("https", "http")).await?.json::<Document>().await?
        } else {
            // not in a tokio runtime (-> running in a test)
            let request = DocumentRequest { url: url.to_string() };
            Client::new(self.clone())
                .request(request)
                .owner(self.owner)
                .await
                .map(|r| r.0.clone())?
        };
        Ok(serde_json::to_vec(&document)?)
    }
}

impl Signer for Verifier<'_> {
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

impl Signature for Verifier<'_> {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let request = DocumentRequest {
            url: format!("{}/.well-known/did.json", self.owner),
        };
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

impl Metadata for Verifier<'_> {
    async fn verifier(&self, owner: &str) -> Result<VerifierMetadata> {
        let Some(verifier) = Datastore::get(owner, "metadata", "verifier").await? else {
            return Err(anyhow!("verifier not found for {owner}"));
        };
        serde_json::from_slice(&verifier)
            .map_err(|e| anyhow!("issue deserializing verifier metadata: {e}"))
    }

    async fn register(&self, _: &str, _: &VerifierMetadata) -> Result<VerifierMetadata> {
        unimplemented!("registering clients is not implemented")
    }
}

impl StateStore for Verifier<'_> {
    async fn put<T: Serialize + Sync>(
        &self, owner: &str, key: &str, state: &State<T>,
    ) -> Result<()> {
        let state = serde_json::to_vec(state)?;
        Keyvalue::put(owner, "state", key, &state)
    }

    async fn get<T: DeserializeOwned>(&self, owner: &str, key: &str) -> Result<State<T>> {
        let Some(data) = Keyvalue::get(owner, "state", key)? else {
            return Err(anyhow!("no matching item in state store"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn purge(&self, owner: &str, key: &str) -> Result<()> {
        Keyvalue::delete(owner, "state", key)
    }
}

impl StatusToken for Verifier<'_> {
    async fn fetch(&self, uri: &str) -> Result<String> {
        let http_uri = http::Uri::from_str(uri).map_err(|_| anyhow!("invalid status token URI"))?;
        let Some(scheme) = http_uri.scheme_str() else {
            return Err(anyhow!("invalid scheme"));
        };
        let Some(authority) = http_uri.authority() else {
            return Err(anyhow!("invalid  authority"));
        };

        let owner = format!("{scheme}://{authority}");
        let Some(data) = Datastore::get(&owner, "statustoken", uri).await? else {
            return Err(anyhow!("could not find status token"));
        };
        Ok(serde_json::from_slice(&data)?)
    }
}

impl Binding for Verifier<'_> {
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
