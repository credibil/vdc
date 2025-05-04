//! Token Status for Issuers

use std::fmt::Debug;
use std::io::{Read, Write};

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use bitvec::view::BitView;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};

use crate::token_status::{BitsPerToken, StatusClaim, StatusList, StatusListEntry};

/// `StatusStore` is used to store and retrieve Status Tokens.
pub trait StatusStore: Send + Sync {
    /// Store the Status Token using the provided key.
    fn put(&self, uri: &str, token: &str) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve the specified Status Token.
    fn get(&self, uri: &str) -> impl Future<Output = Result<Option<String>>> + Send;
}

impl StatusList {
    /// Create a new Status List with one bit per referenced token and all
    /// bits set to a default of `StatusType::Valid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the Zlib compression fails.
    pub fn new() -> Result<Self> {
        let bitslice = BitSlice::<u8>::from_slice(&[u8::MIN]);
        let mut bitvec: BitVec<u8> = bitslice.to_bitvec();

        let mut encoder = ZlibEncoder::new(vec![], Compression::best());
        encoder.write_all(bitvec.as_raw_mut_slice())?;
        let deflated = encoder.finish()?;

        Ok(Self {
            bits: BitsPerToken::One,
            lst: Base64UrlUnpadded::encode_string(&deflated),
            aggregation_uri: None,
        })
    }

    /// Add an entry to the Status List, returning the claim to use in the
    /// referenced token/credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the Zlib decompression fails.
    pub fn add_entry(&mut self, uri: impl Into<String>) -> Result<StatusClaim> {
        // inflate the list
        let deflated = Base64UrlUnpadded::decode_vec(&self.lst)
            .map_err(|_| anyhow!("Invalid base64url-encoded status list"))?;
        let mut decoder = ZlibDecoder::new(deflated.as_slice());
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated)?;

        let idx = 0;

        // resize
        // inflated.resize(1, 0);
        let bitslice = inflated.view_bits_mut::<Lsb0>();
        bitslice.set(idx, true);

        // compress and update the list
        let mut encoder = ZlibEncoder::new(vec![], Compression::best());
        encoder.write_all(inflated.as_slice())?;
        let deflated = encoder.finish()?;
        self.lst = Base64UrlUnpadded::encode_string(&deflated);

        Ok(StatusClaim {
            status_list: StatusListEntry { idx, uri: uri.into() },
        })
    }

    /// Encode the Status List Token as a JWT.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization to JSON fails.
    pub fn to_jwt(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(Base64UrlUnpadded::encode_string(&bytes))
    }
}

/// Used to query the Status List endpoint in order to return Status List
/// Token(s).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListResponse(pub String);
