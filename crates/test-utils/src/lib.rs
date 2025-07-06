//! # Mock Provider

#![feature(random)]

pub mod issuer;
pub mod verifier;
pub mod wallet;

mod resources;

pub use issuer::Issuer;
pub use verifier::Verifier;
pub use wallet::Wallet;
