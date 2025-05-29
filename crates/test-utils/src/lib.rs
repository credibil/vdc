//! # Mock Provider

pub mod issuer;
pub mod verifier;
pub mod wallet;

mod datastore;
mod identity;

pub use issuer::Issuer;
pub use verifier::Verifier;
pub use wallet::Wallet;
