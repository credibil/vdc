//! Token Status for Verifiers

use std::io::Read;

use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::order::Lsb0;
use bitvec::view::BitView;
use flate2::read::ZlibDecoder;

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
            .context("invalid base64url-encoded status list")?;
        let mut decoder = ZlibDecoder::new(deflated.as_slice());
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated)?;

        let bitslice = inflated.view_bits::<Lsb0>();
        Ok(bitslice.get(idx).is_some_and(|x| *x))
    }
}
