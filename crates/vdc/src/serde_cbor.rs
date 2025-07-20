//! # CBOR
//!
//! This module provides CBOR helper functions and types.

use anyhow::{Context, Result};
// use ciborium::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Serialize a value to a CBOR byte vector.
///
/// # Errors
/// TODO: Document errors
pub fn to_vec<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Deserialize a value from a CBOR byte slice.
///
/// # Errors
/// TODO: Document errors
pub fn from_slice<T>(slice: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    ciborium::from_reader(slice).context("failed to deserialize CBOR")
}
