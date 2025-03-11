//! # Generate
//!
//! Generate random strinsg for use in authorzation code, token, state,
//! nonce, etc.

// LATER: replace with a proper random string generator

/// Random string generation for auth code, token, state, and nonce.
use base64ct::{Base64UrlUnpadded, Encoding};

const PIN_CHARS: &str = "0123456789";
const PIN_LEN: usize = 6;

const SAFE_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";
const STATE_LEN: usize = 32;

/// Generates a base64 encoded random string for authorization code.
#[must_use]
pub fn auth_code() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

// /// Generates a base64 encoded random string for `issuer_state`
// #[must_use]
// pub fn issuer_state() -> String {
//     let rnd = random_string(STATE_LEN, SAFE_CHARS);
//     Base64UrlUnpadded::encode_string(rnd.as_bytes())
// }

/// Generates a base64 encoded random string for nonce
#[must_use]
pub fn nonce() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a base64 encoded random string for deferred issuance
/// `transaction_id`.
#[must_use]
pub fn notification_id() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a base64 encoded random string for `issuer_state`
#[must_use]
pub fn uri_token() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a base64 encoded random string for token
#[must_use]
pub fn token() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a base64 encoded random string for deferred issuance
/// `transaction_id`.
#[must_use]
pub fn transaction_id() -> String {
    let rnd = random_string(STATE_LEN, SAFE_CHARS);
    Base64UrlUnpadded::encode_string(rnd.as_bytes())
}

/// Generates a use PIN code.
#[must_use]
pub fn tx_code() -> String {
    random_string(PIN_LEN, PIN_CHARS)
}

/// Generates a random string from a given set of characters. Uses fastrand so is
/// not cryptographically secure.
#[must_use]
pub fn random_string(len: usize, charset: &str) -> String {
    let chars: Vec<char> = charset.chars().collect();
    (0..len).map(|_| chars[fastrand::usize(..chars.len())]).collect()
}

// ///
// /// Generate a new random, base64-encoded 128-bit CSRF token.
// pub fn new_random() -> Self {
//     CsrfToken::new_random_len(16)
// }
// ///
// /// Generate a new random, base64-encoded CSRF token of the specified length.
// ///
// /// # Arguments
// ///
// /// * `num_bytes` - Number of random bytes to generate, prior to
// base64-encoding. pub fn new_random_len(num_bytes: u32) -> Self {
//     let random_bytes: Vec<u8> = (0..num_bytes).map(|_|
// thread_rng().gen::<u8>()).collect();
//     CsrfToken::new(base64::encode_config(&random_bytes,
// base64::URL_SAFE_NO_PAD)) }
