//! # CBOR
//!
//! This module provides CBOR helper functions and types.

use anyhow::anyhow;
use ciborium::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Serialize a value to a CBOR byte vector.
///
/// # Errors
/// TODO: Document errors
pub fn to_vec<T>(value: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Serialize a value to a ciborium `Value`.
///
/// # Errors
/// TODO: Document errors
pub fn to_value<T>(value: &T) -> anyhow::Result<Value>
where
    T: Serialize,
{
    ciborium::cbor!(value).map_err(|e| anyhow!(e))
}

/// Deserialize a value from a CBOR byte slice.
///
/// # Errors
/// TODO: Document errors
pub fn from_slice<T>(slice: &[u8]) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    ciborium::from_reader(slice).map_err(|e| anyhow!(e))
}
