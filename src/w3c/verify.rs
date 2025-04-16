//! Securing Credentials
//!
//! Verifiable Credentials can be secured using two different mechanisms:
//! enveloping proofs or embedded proofs. In both cases, a proof
//! cryptographically secures a Credential (for example, using digital
//! signatures). In the enveloping case, the proof wraps around the Credential,
//! whereas embedded proofs are included in the serialization, alongside the
//! Credential itself.
//!
//! ## Envelooping Proofs
//!
//! A family of enveloping proofs is defined in the [Securing Verifiable
//! Credentials using JOSE and COSE] document, relying on technologies defined
//! by the IETF. Other types of enveloping proofs may be specified by the
//! community.
//!
//! ## Embedded Proofs
//!
//! The general structure for embedded proofs is defined in a separate
//! [Verifiable Credential Data Integrity 1.0] specification. Furthermore, some
//! instances of this general structure are specified in the form of the
//! "cryptosuites": Data Integrity [EdDSA Cryptosuites v1.0], Data Integrity
//! [ECDSA Cryptosuites v1.0], and Data Integrity [BBS Cryptosuites v1.0].
//!
//! [Securing Verifiable Credentials using JOSE and COSE]: https://w3c.github.io/vc-jose-cose
//! [Verifiable Credential Data Integrity 1.0]: https://www.w3.org/TR/vc-data-integrity
//! [EdDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-eddsa
//! [ECDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-ecdsa
//! [BBS Cryptosuites v1.0]: https://w3c.github.io/vc-di-bbs

use anyhow::bail;
use credibil_did::DidResolver;
use credibil_infosec::Signer;
use credibil_infosec::jose::{jws, jwt};

use crate::core::{Kind, OneMany, did_jwk};
use crate::w3c::{Payload, Verify, VpClaims, W3cVcClaims};

/// Create a proof from a proof provider.
///
/// # Errors
/// TODO: document errors
pub async fn create(payload: Payload, signer: &impl Signer) -> anyhow::Result<String> {
    let jwt = match payload {
        Payload::Vc { vc, issued_at } => {
            let mut claims = W3cVcClaims::from(vc);
            claims.iat = issued_at;
            jws::encode(&claims, signer).await?
        }
        Payload::Vp { vp, client_id, nonce } => {
            let mut claims = VpClaims::from(vp);
            claims.aud.clone_from(&client_id);
            claims.nonce.clone_from(&nonce);
            jws::encode(&claims, signer).await?
        }
    };

    Ok(jwt)
}

/// Verify a proof.
///
/// # Errors
/// TODO: document errors
#[allow(clippy::unused_async)]
pub async fn verify<R>(proof: Verify<'_>, resolver: R) -> anyhow::Result<Payload>
where
    R: DidResolver + Send + Sync,
{
    let resolver = async |kid: String| did_jwk(&kid, &resolver).await;
    let Verify::Vp(value) = proof;

    match value {
        Kind::String(token) => {
            let jwt: jwt::Jwt<VpClaims> = jws::decode(token, resolver).await?;
            Ok(Payload::Vp {
                vp: jwt.claims.vp,
                client_id: jwt.claims.aud,
                nonce: jwt.claims.nonce,
            })
        }
        Kind::Object(vp) => {
            // TODO: Implement embedded proof verification
            let Some(OneMany::One(proof)) = &vp.proof else {
                bail!("invalid VerifiablePresentation proof")
            };
            let challenge = proof.challenge.clone().unwrap_or_default();

            Ok(Payload::Vp {
                vp: vp.clone(),
                nonce: challenge,
                client_id: String::new(),
            })
        }
    }
}
