//! # Generate
//!
//! Generate random strinsg for use in authorzation code, token, state,
//! nonce, etc.

// LATER: replace with a proper random string generator

/// Random string generation for auth code, token, state, and nonce.
use base64ct::{Base64UrlUnpadded, Encoding};

const SAFE_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";
const STATE_LEN: usize = 32;

/// Generates a base64 encoded random string for nonce
#[must_use]
pub fn nonce() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a base64 encoded random string for `issuer_state`
#[must_use]
pub fn uri_token() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a random string from a given set of characters. Uses fastrand so is
/// not cryptographically secure.
#[must_use]
pub fn random_string(len: usize, charset: &str) -> String {
    let chars: Vec<char> = charset.chars().collect();
    (0..len).map(|_| chars[fastrand::usize(..chars.len())]).collect()
}
