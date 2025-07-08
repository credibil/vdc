//! Token Status for Issuers

use std::fmt::Debug;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use bitvec::view::BitView;
use chrono::{DateTime, Utc};
use credibil_binding::Signature;
use credibil_jose::Jws;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};

use crate::{BitsPerToken, StatusClaim, StatusList, StatusListClaims, StatusListEntry};

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

        Ok(StatusClaim { status_list: StatusListEntry { idx, uri: uri.into() } })
    }
}

/// Used to query the Status List endpoint in order to return Status List
/// Token(s).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListResponse(pub String);

/// Generate a Status List token.
#[derive(Debug)]
pub struct TokenBuilder<L, U, S> {
    status_list: L,
    uri: U,
    expiry: Option<DateTime<Utc>>,
    signer: S,
}

/// Builder has no status list.
#[doc(hidden)]
pub struct NoList;
/// Builder has a status list.
#[doc(hidden)]
pub struct HasList(StatusList);

/// Builder has no Status List Token URI.
#[doc(hidden)]
pub struct NoUri;
/// Builder has a Status List Token URI.
#[doc(hidden)]
pub struct HasUri(String);

/// Builder has no signer.
#[doc(hidden)]
pub struct NoSigner;
/// Builder state has a signer.
#[doc(hidden)]
pub struct HasSigner<'a, S: Signature>(pub &'a S);

impl Default for TokenBuilder<NoList, NoUri, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBuilder<NoList, NoUri, NoSigner> {
    /// Create a new `TokenBuilder`.
    #[must_use]
    pub const fn new() -> Self {
        Self { status_list: NoList, uri: NoUri, expiry: None, signer: NoSigner }
    }
}

impl<U, S> TokenBuilder<NoList, U, S> {
    /// Set the status list.
    pub fn status_list(self, status_list: StatusList) -> TokenBuilder<HasList, U, S> {
        TokenBuilder {
            status_list: HasList(status_list),
            uri: self.uri,
            expiry: self.expiry,
            signer: self.signer,
        }
    }
}

impl<L, S> TokenBuilder<L, NoUri, S> {
    /// Set the status list URI (`sub` claim).
    pub fn uri(self, uri: impl Into<String>) -> TokenBuilder<L, HasUri, S> {
        TokenBuilder {
            status_list: self.status_list,
            uri: HasUri(uri.into()),
            expiry: self.expiry,
            signer: self.signer,
        }
    }
}

impl<L, U, S> TokenBuilder<L, U, S> {
    /// Set the expiration date for the status list.
    #[must_use]
    pub const fn expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.expiry = Some(expiry);
        self
    }
}

impl<L, U> TokenBuilder<L, U, NoSigner> {
    /// Set the token signer.
    #[must_use]
    pub fn signer<S: Signature>(self, signer: &'_ S) -> TokenBuilder<L, U, HasSigner<'_, S>> {
        TokenBuilder {
            status_list: self.status_list,
            uri: self.uri,
            expiry: self.expiry,
            signer: HasSigner(signer),
        }
    }
}

impl<S: Signature> TokenBuilder<HasList, HasUri, HasSigner<'_, S>> {
    /// Build the token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token JWS cannot be built.
    pub async fn build(self) -> Result<String> {
        let claims = StatusListClaims {
            sub: self.uri.0,
            iat: Utc::now(),
            exp: self.expiry,
            ttl: None,
            status_list: self.status_list.0,
        };

        let key_binding = self.signer.0.verification_method().await?.try_into()?;
        let jws = Jws::builder()
            .typ("statuslist+jwt")
            .payload(claims)
            .key_binding(&key_binding)
            .add_signer(self.signer.0)
            .build()
            .await
            .context("building Status List Token")?
            .to_string();

        Ok(jws)
    }
}
