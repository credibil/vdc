use std::thread;

use anyhow::{Result, anyhow};
use credibil_binding::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_binding::ecc::Curve::Ed25519;
use credibil_binding::ecc::{Entry, Keyring};
use credibil_binding::jose::PublicKeyJwk;
use credibil_binding::{Binding, DocumentRequest, Resolver, Signature, VerifyBy};
use credibil_ecc::{Algorithm, PublicKey, Signer};
use credibil_oid4vci::provider::{Metadata, Provider, StateStore, StatusStore, Subject};
use credibil_oid4vci::{ClientMetadata, Dataset, IssuerMetadata, ServerMetadata, State};
use credibil_oid4vp::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::resources::{Datastore, KeyVault, Keyvalue};

const ISSUER_METADATA: &[u8] = include_bytes!("../../data/issuer-metadata.json");
const SERVER_METADATA: &[u8] = include_bytes!("../../data/server-metadata.json");
const ALICE: &[u8] = include_bytes!("../../data/alice-datasets.json");
const BOB: &[u8] = include_bytes!("../../data/bob-datasets.json");
const CLIENT_METADATA: &[u8] = include_bytes!("../../data/client-metadata.json");

#[derive(Clone)]
pub struct Issuer<'a> {
    owner: &'a str,
    signer: Entry,
}

impl<'a> Issuer<'a> {
    pub async fn new(owner: &'a str) -> Result<Self> {
        Datastore::put(owner, "metadata", "issuer", ISSUER_METADATA).await?;
        Datastore::put(owner, "metadata", "server", SERVER_METADATA).await?;
        Datastore::put(owner, "metadata", "public-client", CLIENT_METADATA).await?;
        Datastore::put(owner, "subject", "alice", ALICE).await?;
        Datastore::put(owner, "subject", "bob", BOB).await?;

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

        let issuer = Self { owner, signer };
        credibil_binding::create(owner, builder, &issuer).await?;

        Ok(issuer)
    }
}

impl Provider for Issuer<'_> {}

impl Resolver for Issuer<'_> {
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

impl Signer for Issuer<'_> {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signer.sign(msg).await)
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for Issuer<'_> {
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

impl Metadata for Issuer<'_> {
    async fn client(&self, owner: &str, client_id: &str) -> Result<ClientMetadata> {
        let Some(client) = Datastore::get(owner, "metadata", client_id).await? else {
            return Err(anyhow!("client not found for {owner}:{client_id}"));
        };
        serde_json::from_slice(&client)
            .map_err(|e| anyhow!("issue deserializing client metadata: {e}"))
    }

    async fn issuer(&self, owner: &str) -> Result<IssuerMetadata> {
        let Some(issuer) = Datastore::get(owner, "metadata", "issuer").await? else {
            return Err(anyhow!("issuer not found for {owner}"));
        };
        serde_json::from_slice(&issuer)
            .map_err(|e| anyhow!("issue deserializing issuer metadata: {e}"))
    }

    async fn server(&self, owner: &str) -> Result<ServerMetadata> {
        let Some(server) = Datastore::get(owner, "metadata", "server").await? else {
            return Err(anyhow!("server not found for {owner}"));
        };
        serde_json::from_slice(&server)
            .map_err(|e| anyhow!("issue deserializing server metadata: {e}"))
    }

    async fn register(&self, _: &str, _: &ClientMetadata) -> Result<ClientMetadata> {
        unimplemented!("registering clients is not implemented")
    }
}

impl Subject for Issuer<'_> {
    async fn authorize(
        &self, owner: &str, subject: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        let Some(data) = Datastore::get(owner, "subject", subject).await? else {
            return Err(anyhow!("no dataset for subject {owner}:{subject}"));
        };
        let datasets: Vec<Dataset> = serde_json::from_slice(&data)?;

        let identifiers = datasets
            .iter()
            .filter(|ds| ds.credential_configuration_id == credential_configuration_id)
            .map(|ds| ds.credential_identifier.clone())
            .collect::<Vec<_>>();
        if identifiers.is_empty() {
            return Err(anyhow!("no dataset for {subject}:{credential_configuration_id}"));
        }

        Ok(identifiers)
    }

    async fn dataset(
        &self, owner: &str, subject: &str, credential_identifier: &str,
    ) -> Result<Dataset> {
        let Some(data) = Datastore::get(owner, "subject", subject).await? else {
            return Err(anyhow!("no datasets for subject {subject}"));
        };
        let datasets: Vec<Dataset> = serde_json::from_slice(&data)?;

        let Some(dataset) =
            datasets.iter().find(|ds| ds.credential_identifier == credential_identifier)
        else {
            return Err(anyhow!("no dataset for subject {subject}:{credential_identifier}"));
        };
        Ok(dataset.clone())
    }
}

impl StateStore for Issuer<'_> {
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

impl StatusStore for Issuer<'_> {
    async fn put(&self, owner: &str, id: &str, token: &str) -> Result<()> {
        let data = serde_json::to_vec(token)?;
        Datastore::put(owner, "statustoken", id, &data).await
    }

    async fn get(&self, owner: &str, id: &str) -> Result<Option<String>> {
        let Some(data) = Datastore::get(owner, "statustoken", id).await? else {
            return Err(anyhow!("no matching item in state store"));
        };
        Ok(serde_json::from_slice(&data)?)
    }
}

impl Binding for Issuer<'_> {
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
