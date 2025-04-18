#![allow(unused)]

use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use credibil_infosec::cose::cbor;
use credibil_vc::format::FormatProfile;
use credibil_vc::format::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use credibil_vc::format::sd_jwt::SdJwtClaims;
use credibil_vc::oid4vci::types::Credential;
use credibil_vc::oid4vp::types::{Claim, Queryable};
use serde_json::Value;

use crate::blockstore::Mockstore;
use crate::keystore::Keyring;

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
    pub fn add(&mut self, queryable: Queryable) {
        //let queryable = Queryable::try_from(issued).expect("should decode");
        self.store.push(queryable);
    }

    pub fn fetch(&self) -> &[Queryable] {
        &self.store
    }
}
