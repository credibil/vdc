//! # Core Utilities for Credibil VC

// // generic member access API on the error trait
// // https://github.com/rust-lang/rust/issues/99301
// #![feature(error_generic_member_access)]

pub mod api;
pub mod generate;
pub mod http;
pub mod serde_cbor;
pub mod state;
pub mod urlencode;

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
        return Err(anyhow!("Verification method not found"));
    };
    vm.key.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
}
