//! # Store

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_identity::IdentityResolver;

use crate::core::Kind;
use crate::format::FormatProfile;
use crate::format::mso_mdoc::{DataItem, IssuerSigned, MobileSecurityObject, serde_cbor, verify};
use crate::oid4vp::types::{Claim, Queryable};

/// Convert a `mso_mdoc` encoded credential to a `Queryable` object.
///
/// # Errors
///
/// Returns an error if the decoding fails or if the `mdoc` signature
/// verification fails.
pub async fn to_queryable(issued: &str, resolver: &impl IdentityResolver) -> Result<Queryable> {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(issued)?;
    let issuer_signed: IssuerSigned = serde_cbor::from_slice(&mdoc_bytes)?;

    // verify mso
    verify::verify_signature(&issuer_signed.issuer_auth, resolver).await?;

    // doctype
    let Some(mso_bytes) = issuer_signed.issuer_auth.0.payload else {
        return Err(anyhow!("missing MSO payload"));
    };
    let mso: DataItem<MobileSecurityObject> = serde_cbor::from_slice(&mso_bytes)?;

    // claims
    let mut claims = vec![];
    for (name_space, issued_items) in &issuer_signed.name_spaces {
        for item in issued_items {
            let path = vec![name_space.clone(), item.element_identifier.clone()];
            claims.extend(unpack_claims(path.clone(), &item.element_value));
        }
    }

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
