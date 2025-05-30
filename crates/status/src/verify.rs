//! Token Status for Verifiers

use std::fmt::Debug;
use std::io::Read;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::order::Lsb0;
use bitvec::view::BitView;
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};

use crate::StatusList;

impl StatusList {
    /// Check if the status list contains a valid status for the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the Zlib decompression fails or if the index is
    /// out of bounds.
    pub fn is_valid(&self, idx: usize) -> Result<bool> {
        let deflated = Base64UrlUnpadded::decode_vec(&self.lst)
            .map_err(|_| anyhow!("Invalid base64url-encoded status list"))?;
        let mut decoder = ZlibDecoder::new(deflated.as_slice());
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated)?;

        let bitslice = inflated.view_bits::<Lsb0>();
        Ok(bitslice.get(idx).is_some_and(|x| *x))
    }
}

/// Used to query the Status List endpoint in order to return Status List
/// Token(s).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListRequest {
    /// The index of the Status List to retrieve. When not specified, all
    /// status lists should be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
