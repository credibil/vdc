//! # VC Data Integrity
//!
//! ## Generic Data Integrity Structure
//!
//! The operation of Data Integrity is conceptually simple. To create a
//! cryptographic proof, the following steps are performed: 1) Transformation,
//! 2) Hashing, and 3) Proof Generation.
//!
//! Transformation is a process described by a transformation algorithm that
//! takes input data and prepares it for the hashing process. In the case of
//! data serialized in JSON this transformation includes the removal of all the
//! artifacts that do not influence the semantics of the data like spaces, new
//! lines, the order of JSON names, etc. (a step often referred to as
//! canonicalization). In some cases the transformation may be more involved.
//!
//! Hashing is a process described by a hashing algorithm that calculates an
//! identifier for the transformed data using a cryptographic hash function.
//! Typically, the size of the resulting hash is smaller than the data, which
//! makes it more suitable for complex cryptographic functions like digital
//! signatures.
//!
//! Proof Generation is a process described by a proof method that calculates a
//! value that protects the integrity of the input data from modification or
//! otherwise proves a certain desired threshold of trust. A typical example is
//! the application of a cryptographic signature using asymmetric keys, yielding
//! the signature of the data.
//!
//! Verification of a proof involves repeating the same steps on the verifier's
//! side and, depending on the proof method, validating the newly calculated
//! proof value with the one associated with the data. In the case of a digital
//! signature, this test usually means comparing the calculated signature value
//! with the one which is embedded in the data.

//! ## VC Data Integrity
//!
//! The Verifiable Credential Data Integrity 1.0 [VC-DATA-INTEGRITY]
//! specification relies on the general structure and defines a set of standard
//! properties describing the details of the proof generation process. The
//! specific details (canonicalization algorithm, hash and/or proof method
//! algorithms, etc.) are defined by separate cryptosuites. The Working Group
//! has defined a number of such cryptosuites as separate specifications, see
//! 4.2.3 Cryptosuites below.
//!
//! The core property, in the general structure, is proof. This property embeds
//! a claim in the Credential, referring to a separate collection of claims
//! (referred to as a Proof Graph) detailing all the claims about the proof
//! itself:

use std::convert::Infallible;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::OneMany;

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
    //---
    // /// Proof-specific additional fields.
    // #[serde(flatten)]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub extra: Option<HashMap<String, Value>>,
}

// Unused, but required by 'option_flexvec' deserializer FromStr trait
impl FromStr for Proof {
    type Err = Infallible;

    fn from_str(_: &str) -> anyhow::Result<Self, Self::Err> {
        unimplemented!("Proof::from_str")
    }
}

// /// Encode proof
// pub fn encode() {
//     todo!()
// }
