//! # Verifiable Credentials
//!
//! This module encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

pub mod model;
pub mod proof;

// TODO: move this macro to a more appropriate location (its own crate perhaps).
// N.B. the current dependency tree is a little complex, so this is a temporary
// solution that avoids cyclic dependencies.

/// Generate a closure to resolve public key material required by `Jws::decode`.
///
/// # Example
///
/// ```rust,ignore
/// use credibil_infosec::{verify_key, KeyOps};
///
/// let resolver = KeyOps::resolver(&provider, &request.credential_issuer)?;
/// let jwt = jws::decode(proof_jwt, verify_key!(resolver)).await?;
/// ...
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! verify_key {
    ($resolver:expr) => {{
        // create local reference before moving into closure
        let resolver = $resolver;
        move |kid: String| {
            let local_resolver = resolver.clone();
            async move {
                let resp = credibil_did::dereference(&kid, None, local_resolver)
                    .await
                    .map_err(|e| anyhow::anyhow!("issue dereferencing DID: {e}"))?;
                let Some(credibil_did::Resource::VerificationMethod(vm)) = resp.content_stream
                else {
                    return Err(anyhow::anyhow!("Verification method not found"));
                };
                vm.method_type.jwk().map_err(|e| anyhow::anyhow!("JWK not found: {e}"))
            }
        }
    }};
}
