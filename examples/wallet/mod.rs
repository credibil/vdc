#![allow(unused)]

#[path = "../kms/mod.rs"]
mod kms;

use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use credibil_infosec::cose::cbor;
use credibil_vc::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use credibil_vc::oid4vci::types::{Credential, FormatProfile};
use credibil_vc::oid4vp::IssuedFormat;
use credibil_vc::oid4vp::types::{Claim, Queryable};
use credibil_vc::sd_jwt::SdJwtClaims;
use serde_json::Value;

pub use self::kms::Keyring;

pub fn keyring() -> Keyring {
    Keyring::new_key()
}

pub struct Store {
    store: Vec<Queryable>,
}

impl Store {
    pub fn new() -> Self {
        Self { store: vec![] }
    }

    // Add a credential to the store.
    pub fn add(&mut self, issued: IssuedFormat) {
        let queryable = Queryable::try_from(issued).expect("should decode");
        self.store.push(queryable);
    }

    pub fn fetch(&self) -> &[Queryable] {
        &self.store
    }
}
