
use anyhow::Result;
use credibil_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk, Signer};
use credibil_vc::mso_mdoc::MsoMdocBuilder;
use credibil_vc::sd_jwt::DcSdJwtBuilder;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use serde_json::Value;

pub async fn issue_sd_jwt(vct: &str, claims: Value) -> String {
    let claims = claims.as_object().unwrap();

    let jwk = PublicKeyJwk {
        kty: KeyType::Okp,
        crv: Curve::Ed25519,
        x: "x".to_string(),
        ..PublicKeyJwk::default()
    };

    // serialize to SD-JWT
    DcSdJwtBuilder::new()
        .vct(vct)
        .issuer("https://example.com")
        .key_binding(jwk)
        .claims(claims.clone())
        .signer(&Keyring::new())
        .build()
        .await
        .expect("should build")
}

pub async fn issue_mso_mdoc(doctype: &str, claims: Value) -> String {
    let claims = claims.as_object().unwrap();

    // serialize to SD-JWT
    MsoMdocBuilder::new()
        .doctype(doctype)
        .claims(claims.clone())
        .signer(&Keyring::new())
        .build()
        .await
        .expect("should build")
}

#[derive(Clone, Debug)]
pub struct Keyring {
    signing_key: SigningKey,
}

impl Keyring {
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    async fn verification_method(&self) -> Result<String> {
        Ok("did:example:123#key-1".to_string())
    }
}
