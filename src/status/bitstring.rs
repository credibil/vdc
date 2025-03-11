//! # Bitstring Status List
//!
//! Types and helpers for implementing a status list using a bitstring. Follows
//! the specification [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/).

use std::io::Write;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::bits;
use bitvec::order::Lsb0;
use bitvec::view::BitView;
use chrono::Utc;
use credibil_infosec::Signer;
use flate2::write::GzEncoder;
use serde_json::{Map, Value};

use super::config::ListConfig;
use super::log::StatusLogEntry;
use crate::w3c_vc::model::{CredentialSubject, StatusPurpose, VcBuilder};
use crate::w3c_vc::proof::{self, Payload, W3cFormat};

// TODO: Configurable.
// TODO: This is minimum length as per spec. May need to be configurable
// for data VCs where potentially huge numbers of credentials of a type
// can be issued. Or we need to use a more sophisticated list sharding.
// (Currently assumes one list per credential type.) Business requirements
// for short-lived data credentials may not require status lists anyway and
// we could just bump up this limit to something large but practical and
// only support lists up to that length. Alternatively, we can re-use list
// entries once a credential expires.
const MAX_ENTRIES: usize = 131_072;

/// Default time-to-live in milliseconds for a status list credential.
pub const DEFAULT_TTL: u64 = 300_000;

/// Generates a compressed, encoded bitstring representing the status list for
/// the given issued credentials and the purpose implied by a list
/// configuration.
///
/// # Errors
///
/// Returns an error if there is a compression or encoding problem, or the
/// provided status position is out of range of the bitstring size.
///
/// Must be a multi-base encoded base64 url without padding. It is the
/// encoded representation of the GZIP-compressed bitstring values for
/// the associated range of verifiable credential status values. The
/// uncompressed bitstring must be at least 16KB in size. The bitstring
/// must be encoded such that the first index, with a value of zero, is
/// located at the left-most bit in the bitstring, and the last index, with
/// a value of one less than the length of the bitstring, is located at the
/// right-most bit in the bitstring.
///
/// Note: This function scans the entire status log presented to construct a
/// bitstring from scratch which will be inefficient compared to a method for
/// processing a known update to the status of an individual credential. (A new
/// credential issued or an update to the status of an existing one).
//
// TODO: Provide methods for updating the bitstring incrementally.
#[allow(clippy::module_name_repetitions)]
pub fn bitstring(config: &ListConfig, issued: &[StatusLogEntry]) -> anyhow::Result<String> {
    let bits = bits![mut 0; MAX_ENTRIES];
    for entry in issued {
        for status in &entry.status {
            if status.purpose != config.purpose {
                continue;
            }

            let position = status.list_index * config.size;
            if position >= bits.len() {
                return Err(anyhow!("status index out of range"));
            }
            match config.purpose {
                StatusPurpose::Revocation | StatusPurpose::Suspension => {
                    bits.set(position, status.value != 0);
                }
                StatusPurpose::Message => {
                    let value = status.value.view_bits::<Lsb0>();
                    for (i, bit) in value.iter().enumerate() {
                        bits.set(position + i, *bit);
                    }
                }
            }
        }
    }

    let uncompressed = bits.into_iter().map(|b| if *b { '1' } else { '0' }).collect::<String>();

    let mut gz_encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz_encoder.write_all(uncompressed.as_bytes())?;
    let compressed = gz_encoder.finish()?;

    let encoded = Base64UrlUnpadded::encode_string(&compressed);

    Ok(encoded)
}

/// Generates a bitstring status list credential for the given status type.
///
/// The credential is suitable for publishing on an endpoint for verifiers to
/// check.
///
/// Requires the bitstring to be pre-generated. This allows for the implementer
/// to use an efficient generation and/or maintenance method.
///
/// If `ttl` is not provided, a value of `DEFAULT_TTL` will be used.
///
/// Generates a credential in `jwt_vc_json` format with a `jwt` proof type.
///
/// # Errors
///
/// * verifiable credential building errors.
/// * signing errors.
pub async fn credential(
    credential_issuer: &str, config: &ListConfig, status_list_base_url: &str, bitstring: &str,
    ttl: Option<u64>, signer: &impl Signer,
) -> anyhow::Result<String> {
    let mut base_url = status_list_base_url.to_string();
    if !base_url.ends_with('/') {
        base_url.push('/');
    }
    let id = format!("{base_url}/{}", config.list);

    let mut claims = Map::new();
    claims.insert("type".to_string(), Value::String("BitstringStatusList".to_string()));
    claims.insert("purpose".to_string(), Value::String(config.purpose.to_string()));
    claims.insert("encodedList".to_string(), Value::String(bitstring.into()));

    let cache_time = ttl.unwrap_or(DEFAULT_TTL);
    claims.insert("ttl".to_string(), Value::Number(cache_time.into()));

    let issued_at = Utc::now().timestamp();

    let vc = VcBuilder::new()
        .id(id.clone())
        .add_type("BitstringStatusListCredential")
        .issuer(credential_issuer)
        .add_subject(CredentialSubject {
            id: Some(format!("{id}#list")),
            claims,
        })
        .build()?;
    let jwt = proof::create(W3cFormat::JwtVcJson, Payload::Vc { vc, issued_at }, signer).await?;

    Ok(jwt)
}
