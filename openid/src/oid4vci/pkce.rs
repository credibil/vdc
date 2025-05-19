//! # Generate PKCE Code Challenge & Verifier

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::common::generate::random_string;

const CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.~_";
const MIN_LEN: usize = 43;
const MAX_LEN: usize = 128;

/// Generate a random code verifier for PKCE.
#[must_use]
pub fn code_verifier() -> String {
    let len = fastrand::usize(MIN_LEN..=MAX_LEN);
    random_string(len, CHARS)
}

/// Generate a code challenge for PKCE from a code verifier.
#[must_use]
pub fn code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}
