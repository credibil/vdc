//! # DID

use anyhow::{Result, anyhow};
use credibil_identity::IdentityResolver;
use credibil_identity::did::Resource;
use credibil_jose::PublicKeyJwk;

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn did_jwk(did_url: &str, resolver: &impl IdentityResolver) -> Result<PublicKeyJwk> {
    let deref = credibil_identity::did::dereference(did_url, resolver)
        .await
        .map_err(|e| anyhow!("issue dereferencing DID URL {did_url}: {e}"))?;
    let Resource::VerificationMethod(vm) = deref else {
        return Err(anyhow!("Identity method not found"));
    };
    vm.key.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
}
