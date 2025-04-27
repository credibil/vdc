//! # Store

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};

use crate::core::Kind;
use crate::format::FormatProfile;
use crate::format::mso_mdoc::{DataItem, IssuerSigned, MobileSecurityObject, serde_cbor};
use crate::oid4vp::types::{Claim, Queryable};

/// Convert a `mso_mdoc` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails.
pub fn to_queryable(issued: &str) -> Result<Queryable> {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(issued)?;
    let mdoc: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes)?;

    let mut claims = vec![];
    for (name_space, tags) in &mdoc.name_spaces {
        let mut path = vec![name_space.clone()];
        for tag in tags {
            path.push(tag.element_identifier.clone());
            let nested = unpack_claims(path.clone(), &tag.element_value);
            claims.extend(nested);
        }
    }

    // FIXME: verify MSO
    let Some(mso_bytes) = mdoc.issuer_auth.0.payload else {
        return Err(anyhow!("missing MSO payload"));
    };
    let mso: DataItem<MobileSecurityObject> = serde_cbor::from_slice(&mso_bytes)?;

    Ok(Queryable {
        meta: FormatProfile::MsoMdoc {
            doctype: mso.0.doc_type,
        },
        claims,
        credential: Kind::String(issued.to_string()),
    })
}

fn unpack_claims(path: Vec<String>, value: &ciborium::Value) -> Vec<Claim> {
    match value {
        ciborium::Value::Map(map) => map.iter().fold(vec![], |mut acc, (key, value)| {
            let mut new_path = path.clone();
            new_path.push(key.as_text().unwrap_or_default().to_string());
            acc.extend(unpack_claims(new_path, value));
            acc
        }),
        ciborium::Value::Text(txt) => {
            vec![Claim {
                path,
                value: serde_json::Value::String(txt.to_string()),
            }]
        }
        _ => todo!(),
    }
}
