#[path = "../kms/mod.rs"]
mod kms;

// use credibil_vc::oid4vp::types::{ClaimQuery, CredentialQuery, CredentialSetQuery};
pub use kms::Keyring;

pub fn keyring() -> Keyring {
    Keyring::new_key()
}
