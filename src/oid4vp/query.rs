//! # Query

mod dcql;
mod dif_exch;

use std::str::FromStr;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use credibil_infosec::cose::cbor;
use serde_json::{Map, Value, json};

use crate::Kind;
use crate::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use crate::oid4vci::types::{Credential, CredentialDefinition, FormatProfile};
use crate::sd_jwt::SdJwtClaims;
use crate::w3c_vc::vc::{VerifiableCredential, W3cVcClaims};

/// Implemented by wallets in order to support DCQL queries.
#[derive(Debug)]
pub struct Queryable {
    /// The credential's format profile.
    pub profile: FormatProfile,

    /// The credential's claims.
    pub claims: Vec<Claim>,

    /// The original issued credential.
    pub issued: Kind<VerifiableCredential>,
}

/// A generic credential claim to use with DCQL queries.
#[derive(Clone, Debug)]
pub struct Claim {
    /// The path to the claim within the credential.
    pub path: Vec<String>,

    /// The claim's values.
    pub value: Value,
}

impl TryFrom<Credential> for Queryable {
    type Error = anyhow::Error;

    fn try_from(credential: Credential) -> Result<Self> {
        match &credential.credential {
            Kind::String(encoded) => {
                if encoded.starts_with("ey") {
                    from_json(encoded)
                } else {
                    from_cbor(encoded)
                }
            }
            Kind::Object(_) => Err(anyhow!("credential is not a string")),
        }
    }
}

impl TryFrom<&Value> for Queryable {
    type Error = anyhow::Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::String(encoded) => {
                if encoded.starts_with("ey") {
                    from_json(encoded)
                } else {
                    from_cbor(encoded)
                }
            }
            _ => return Err(anyhow!("unexpected VC format: {value}")),
        }
    }
}

impl TryFrom<&Queryable> for Value {
    type Error = anyhow::Error;

    fn try_from(queryable: &Queryable) -> Result<Self> {
        let mut value = match &queryable.profile {
            FormatProfile::JwtVcJson {
                credential_definition,
            } => {
                json!({
                    "@context": credential_definition.context,
                    "type": credential_definition.type_,
                })
            }
            FormatProfile::DcSdJwt { vct } => json!({"vct": vct}),
            FormatProfile::MsoMdoc { doctype } => json!({"doctype": doctype}),
            _ => {
                return Err(anyhow!("unsupported profile"));
            }
        };

        let mut default = Map::new();

        for claim in &queryable.claims {
            let mut claims_map = value.as_object_mut().unwrap_or(&mut default);

            for (i, key) in claim.path.iter().enumerate() {
                if i == claim.path.len() - 1 {
                    claims_map.insert(key.to_string(), claim.value.clone());
                } else {
                    if !claims_map.contains_key(key) {
                        claims_map.insert(key.to_string(), json!({}));
                    }
                    claims_map = claims_map.get_mut(key).unwrap().as_object_mut().unwrap();
                }
            }
        }

        Ok(value)
    }
}

fn from_json(json_enc: &str) -> Result<Queryable> {
    let mut split = json_enc.split('~');
    let Some(jwt_enc) = split.next() else {
        return Err(anyhow!("missing encoded part"));
    };
    let jws = Jws::from_str(jwt_enc)?;

    match jws.signatures[0].protected.typ.as_str() {
        "dc+sd-jwt" => from_sd_jwt(json_enc),
        "jwt" => from_vc_json(json_enc),
        _ => todo!("unsupported JWT type"),
    }
}

fn from_sd_jwt(json_enc: &str) -> Result<Queryable> {
    let mut split = json_enc.split('~');

    let Some(jwt_enc) = split.next() else {
        return Err(anyhow!("missing encoded part"));
    };
    let jws = Jws::from_str(jwt_enc)?;

    // extract claims from disclosures
    let mut claims = vec![];
    for encoded in split {
        let bytes = Base64UrlUnpadded::decode_vec(encoded)?;
        let value: Value = serde_json::from_slice(&bytes)?;

        let Some(disclosure) = value.as_array() else {
            return Err(anyhow!("disclosure is not an array"));
        };
        let Some(root) = disclosure[1].as_str() else {
            return Err(anyhow!("first element in a disclosure should be a string"));
        };

        let nested = unpack_json(vec![root.to_string()], &disclosure[2]);
        claims.extend(nested);
    }

    let sd_jwt: SdJwtClaims = jws.payload().expect("should be a payload");

    Ok(Queryable {
        profile: FormatProfile::DcSdJwt { vct: sd_jwt.vct },
        claims,
        issued: Kind::String(jwt_enc.to_string()),
    })
}

fn from_vc_json(json_enc: &str) -> Result<Queryable> {
    let jws = Jws::from_str(json_enc)?;
    let jwt_claims: W3cVcClaims = jws.payload().expect("should be a payload");

    let vc = jwt_claims.vc;
    let mut claims = vec![];

    for subj in &vc.credential_subject.to_vec() {
        let value = Value::Object(subj.claims.clone());
        let nested = unpack_json(vec!["credentialSubject".to_string()], &value);
        claims.extend(nested);
    }

    Ok(Queryable {
        profile: FormatProfile::JwtVcJson {
            credential_definition: CredentialDefinition {
                context: None,
                type_: vc.type_.to_vec(),
            },
        },
        claims,
        issued: Kind::String(json_enc.to_string()),
    })
}

fn from_cbor(mdoc_str: &str) -> Result<Queryable> {
    let mdoc_bytes = Base64UrlUnpadded::decode_vec(mdoc_str)?;
    let mdoc: IssuerSigned = cbor::from_slice(&mdoc_bytes)?;

    let mut claims = vec![];
    for (name_space, tags) in &mdoc.name_spaces {
        let mut path = vec![name_space.clone()];
        for tag in tags {
            path.push(tag.element_identifier.clone());
            let nested = unpack_cbor(path.clone(), &tag.element_value);
            claims.extend(nested);
        }
    }

    let Some(mso_bytes) = mdoc.issuer_auth.0.payload else {
        return Err(anyhow!("missing MSO payload"));
    };
    let mso: MobileSecurityObject = cbor::from_slice(&mso_bytes)?;

    Ok(Queryable {
        profile: FormatProfile::MsoMdoc {
            doctype: mso.doc_type,
        },
        claims,
        issued: Kind::String(mdoc_str.to_string()),
    })
}

fn unpack_json(path: Vec<String>, value: &Value) -> Vec<Claim> {
    match value {
        Value::Object(claims_map) => {
            let mut claims = vec![];

            for (key, value) in claims_map {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vci::types::{CredentialDefinition, FormatProfile};
    use crate::oid4vp::query::{Claim, Queryable};

    #[test]
    fn to_json() {
        let queryable = &Queryable {
            profile: FormatProfile::JwtVcJson {
                credential_definition: CredentialDefinition {
                    context: None,
                    type_: vec![
                        "VerifiableCredential".to_string(),
                        "EmployeeIDCredential".to_string(),
                    ],
                },
            },
            claims: vec![
                Claim {
                    path: vec!["credentialSubject".to_string(), "employeeId".to_string()],
                    value: Value::String("1234567890".to_string()),
                },
                Claim {
                    path: vec!["credentialSubject".to_string(), "family_name".to_string()],
                    value: Value::String("Doe".to_string()),
                },
            ],
            issued: Kind::String("jwt_str".to_string()),
        };

        let json: Value = queryable.try_into().expect("should convert");
        println!("json: {json}");
    }
}
