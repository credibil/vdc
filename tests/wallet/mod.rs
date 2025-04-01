#[path = "../../examples/kms/mod.rs"]
mod kms;

// pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

pub use kms::Keyring;

pub fn keyring() -> Keyring {
    Keyring::new_key()
}
