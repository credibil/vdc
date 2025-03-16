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

use std::fmt::Display;

use anyhow::bail;
use chrono::{DateTime, Utc};
use credibil_did::DidResolver;
use credibil_infosec::Signer;
use credibil_infosec::jose::{jws, jwt};
use serde::{Deserialize, Serialize};

use crate::core::{Kind, OneMany, did_jwk};
use crate::w3c_vc::vc::{VerifiableCredential, W3cVcClaims};
use crate::w3c_vc::vp::{VerifiablePresentation, VpClaims};

/// To be verifiable, a credential must contain at least one proof mechanism,
/// and details necessary to evaluate that proof.
///
/// A proof may be external (an enveloping proof) or internal (an embedded
/// proof).
///
/// Enveloping proofs are implemented using JOSE and COSE, while embedded proofs
/// are implemented using the `Proof` object described here.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_field_names)]
pub struct Proof {
    /// An optional identifier for the proof. MUST be a URL, such as a UUID as a
    /// URN e.g. "`urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The specific proof type. MUST map to a URL. Examples include
    /// "`DataIntegrityProof`" and "`Ed25519Signature2020`". The type determines
    /// the other fields required to secure and verify the proof.
    ///
    /// When set to "`DataIntegrityProof`", the `cryptosuite` and the
    /// `proofValue` properties MUST be set.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the cryptosuite property identifies the cryptographic
    /// suite. If subtypes are supported, it MUST be the <https://w3id.org/security#cryptosuiteString>
    /// subtype of string.
    ///
    /// For example, 'ecdsa-rdfc-2019', 'eddsa-2022'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// The reason for the proof. MUST map to a URL. The proof purpose acts as a
    /// safeguard to prevent the proof from being misused.
    pub proof_purpose: String,

    /// Used to verify the proof. MUST map to a URL. For example, a link to a
    /// public key that is used by a verifier during the verification
    /// process. e.g did:example:123456789abcdefghi#keys-1.
    pub verification_method: String,

    /// The date-time the proof was created. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// The date-time the proof expires. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// One or more security domains in which the proof is meant to be used.
    /// MUST be either a string, or a set of strings. SHOULD be used by the
    /// verifier to ensure the proof is used in the correct security domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<OneMany<String>>,

    /// Used to mitigate replay attacks. SHOULD be included if a domain is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Contains the data needed to verify the proof using the
    /// verificationMethod specified. MUST be a MULTIBASE-encoded binary
    /// value.
    pub proof_value: String,

    /// Each value identifies another data integrity proof that MUST verify
    /// before the current proof is processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<OneMany<String>>,

    /// Supplied by the proof creator. Can be used to increase privacy by
    /// decreasing linkability that results from deterministically generated
    /// signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// `Payload` is used to identify the type of proof to be created.
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Payload {
    /// A Verifiable Credential proof encoded as a JWT.
    Vc {
        /// The Credential to create a proof for.
        vc: VerifiableCredential,

        /// The issuance date and time of the Credential.
        issued_at: DateTime<Utc>,
    },

    /// A Verifiable Presentation proof encoded as a JWT.
    Vp {
        /// The Presentation to create a proof for.
        vp: VerifiablePresentation,

        /// The Verifier's OpenID `client_id` (from Presentation request).
        client_id: String,

        /// The Verifier's `nonce` (from Presentation request).
        nonce: String,
    },
}

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

/// Data type to verify.
pub enum Verify<'a> {
    /// A Verifiable Presentation proof either encoded as a JWT or with an
    /// embedded a Data Integrity Proof.
    Vp(&'a Kind<VerifiablePresentation>),
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

/// The JWS `typ` header parameter.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Type {
    /// General purpose JWT type.
    #[default]
    #[serde(rename = "jwt")]
    Jwt,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    OauthAuthzReqJwt,
}

impl From<Type> for String {
    fn from(t: Type) -> Self {
        match t {
            Type::Jwt => "jwt".to_string(),
            Type::OauthAuthzReqJwt => "oauth-authz-req+jwt".to_string(),
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = self.clone().into();
        write!(f, "{s}")
    }
}
