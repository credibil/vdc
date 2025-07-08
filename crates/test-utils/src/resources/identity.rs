use anyhow::Result;
use credibil_binding::did::{DocumentBuilder, KeyId, VerificationMethod};
use credibil_binding::ecc::Curve::Ed25519;
use credibil_binding::ecc::{Entry, Keyring, Signer};
use credibil_binding::jose::PublicKeyJwk;

use crate::resources::KeyVault;

#[derive(Clone)]
pub struct Identity<'a> {
    pub owner: &'a str,
    signer: Entry,
}

impl<'a> Identity<'a> {
    /// Create a new identity for the specified owner.
    pub async fn new(owner: &'a str) -> Result<Self> {
        // fetch (or generate) the signing key
        let signer = match Keyring::entry(&KeyVault, owner, "signing").await {
            Ok(entry) => entry,
            Err(_) => Keyring::generate(&KeyVault, owner, "signing", Ed25519).await?,
        };

        // // generate a did:web document
        // let verifying_key = signer.verifying_key().await?;
        // let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
        // let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        // let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        // credibil_binding::create(owner, builder, &Datastore).await?;

        Ok(Self { owner, signer })
    }

    #[must_use]
    pub const fn signer(&self) -> &Entry {
        &self.signer
    }

    // pub async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
    //     let document = if thread::current().name() == Some("tokio-runtime-worker") {
    //         // in a tokio runtime (-> running in a web server)
    //         reqwest::get(url.replace("https", "http")).await?.json::<Document>().await?
    //     } else {
    //         // not in a tokio runtime (-> running in a test)
    //         let request = DocumentRequest { url: url.to_string() };
    //         Client::new(Datastore).request(request).owner(self.owner).await.map(|r| r.0.clone())?
    //     };
    //     Ok(serde_json::to_vec(&document)?)
    // }
}
