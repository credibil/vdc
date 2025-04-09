#![allow(unused)]

#[path = "../kms/mod.rs"]
mod kms;

use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use credibil_infosec::cose::cbor;
use credibil_vc::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use credibil_vc::oid4vci::types::FormatProfile;
use credibil_vc::oid4vp::types::{Claim, Credential};
use credibil_vc::sd_jwt::SdJwtClaims;
use serde_json::Value;

pub use self::kms::Keyring;

pub fn keyring() -> Keyring {
    Keyring::new_key()
}

pub struct Store {
    store: Vec<Credential>,
}

impl Store {
    pub fn new() -> Self {
        Self { store: vec![] }
    }

    // Add a credential to the store.
    pub fn add(&mut self, vc: impl Into<Value>) {
        let vc = vc.into();
        let enc_str = vc.as_str().expect("should be a string");

        // decode VC
        let credential = if enc_str.starts_with("ey") {
            let jws = Jws::from_str(enc_str).expect("should be a JWS");
            match jws.signatures[0].protected.typ.as_str() {
                "dc+sd-jwt" => from_sd_jwt(enc_str),
                _ => todo!("unsupported JWT type"),
            }
        } else {
            from_mso_mdoc(enc_str)
        };

        self.store.push(credential);
    }

    pub fn fetch(&self) -> &[Credential] {
        &self.store
    }
}

fn from_sd_jwt(jwt_str: &str) -> Credential {
    let mut split = jwt_str.split('~');
    let jws = Jws::from_str(split.next().unwrap()).expect("should be a JWS");

    // extract claims from disclosures
    let mut claims = vec![];
    while let Some(disclosure) = split.next() {
        let bytes = Base64UrlUnpadded::decode_vec(&disclosure).expect("should decode");
        let value: Value = serde_json::from_slice(&bytes).expect("should be a JSON");
        let disclosure = value.as_array().expect("should be an array");

        let nested = unpack_json(vec![disclosure[1].as_str().unwrap().to_string()], &disclosure[2]);
        claims.extend(nested);
    }

    let sd_jwt: SdJwtClaims = jws.payload().expect("should be a payload");

    Credential {
        profile: FormatProfile::DcSdJwt { vct: sd_jwt.vct },
        claims,
        issued: Value::String(jwt_str.to_string()),
    }
}

fn unpack_json(path: Vec<String>, value: &serde_json::Value) -> Vec<Claim> {
    match value {
        serde_json::Value::Object(obj) => {
            let mut claims = vec![];

            for (key, value) in obj.iter() {
                let mut new_path = path.clone();
                new_path.push(key.to_string());
                claims.extend(unpack_json(new_path, value));
            }

            claims
        }
        _ => vec![Claim {
            path,
            value: value.clone(),
        }],
    }
}

fn from_mso_mdoc(mdoc_str: &str) -> Credential {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(&mdoc_str).expect("should decode");
    let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes).expect("should deserialize");

    let mut claims = vec![];
    for (name_space, tags) in &mdoc.name_spaces {
        let mut path = vec![name_space.clone()];
        for tag in tags {
            path.push(tag.element_identifier.clone());
            let nested = unpack_cbor(path.clone(), &tag.element_value);
            claims.extend(nested);
        }
    }

    let mso_bytes = mdoc.issuer_auth.0.payload.expect("should have payload");
    let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes).expect("should deserialize");

    Credential {
        profile: FormatProfile::MsoMdoc {
            doctype: mso.doc_type,
        },
        claims,
        issued: Value::String(mdoc_str.to_string()),
    }
}

fn unpack_cbor(path: Vec<String>, value: &ciborium::Value) -> Vec<Claim> {
    match value {
        ciborium::Value::Map(map) => {
            let mut claims = vec![];

            for (key, value) in map {
                let mut new_path = path.clone();
                new_path.push(key.as_text().unwrap().to_string());
                claims.extend(unpack_cbor(new_path, value));
            }

            claims
        }
        ciborium::Value::Text(txt) => {
            vec![Claim {
                path,
                value: serde_json::Value::String(txt.to_string()),
            }]
        }
        _ => todo!(),
    }
}
