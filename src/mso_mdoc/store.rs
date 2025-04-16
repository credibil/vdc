//! # Store

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::cose::cbor;

use crate::core::Kind;
use crate::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use crate::oid4vci::types::FormatProfile;
use crate::oid4vp::types::{Claim, Queryable};

/// Convert a `mso_mdoc` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub fn to_queryable(issued: &str) -> Result<Queryable> {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(issued)?;
    let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes)?;

    let mut claims = vec![];
    for (name_space, tags) in &mdoc.name_spaces {
        let mut path = vec![name_space.clone()];
        for tag in tags {
            path.push(tag.element_identifier.clone());
            let nested = unpack_claims(path.clone(), &tag.element_value);
            claims.extend(nested);
        }
    }

    let Some(mso_bytes) = mdoc.issuer_auth.0.payload else {
        return Err(anyhow!("missing MSO payload"));
    };
    let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes)?;

    Ok(Queryable {
        meta: FormatProfile::MsoMdoc {
            doctype: mso.doc_type,
        },
        claims,
        credential: Kind::String(issued.to_string()),
    })
}

fn unpack_claims(path: Vec<String>, value: &ciborium::Value) -> Vec<Claim> {
    match value {
        ciborium::Value::Map(map) => {
            let mut claims = vec![];

            for (key, value) in map {
                let mut new_path = path.clone();
                new_path.push(key.as_text().unwrap().to_string());
                claims.extend(unpack_claims(new_path, value));
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
