//! # Digital Credentials Query Language (DCQL)

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::Jws;
use credibil_infosec::cose::cbor;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Kind;
use crate::mso_mdoc::{IssuerSigned, MobileSecurityObject};
use crate::oid4vci::types::{Credential, CredentialDefinition, FormatProfile};
use crate::sd_jwt::SdJwtClaims;
use crate::w3c_vc::vc::{VerifiableCredential, W3cVcClaims};

/// DCQL query for requesting Verifiable Presentations.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlQuery {
    /// Identifies requested credentials.
    pub credentials: Vec<CredentialQuery>,

    /// Additional constraints on requested credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// A request for the presentation of a single credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identifies the credential in the response and, if provided, the
    /// constraints in `credential_sets`.
    pub id: String,

    /// The format of the requested credential
    pub format: CredentialFormat,

    /// Indicates whether multiple credentials can be returned for this
    /// query. Defaults to false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Additional properties requested that apply to the metadata of the
    /// credential. Properties are specific to Credential Format Profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetadataQuery>,

    /// Issuer certification authorities or trust frameworks that the Verifier
    /// will accept. Every credential returned by the Wallet SHOULD match at
    /// least one of the conditions present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

    /// Indicates whether the Verifier requires a Cryptographic Holder Binding
    /// proof. The default value is true, i.e., a Verifiable Presentation with
    /// Cryptographic Holder Binding is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,

    /// An array of objects that specifies claims in the requested credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,

    /// Combinations of claims to use when requesting credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// Contains a request for one or more credentials that satisfy a particular
/// use case for the Verifier.
///
/// A Credential Set Query is used when multiple Credential Queries need to be
/// combined to satisfy the Verifier's requirements.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialSetQuery {
    /// A list of Credential Query sets, one of which must identify a set of
    /// Credentials that satisfies the query.
    ///
    /// Each value in the array contains a set of Credential Query identifiers
    /// (`CredentialQuery.id`) pointing to a Credential Query objects in the
    /// `credentials` array.
    pub options: Vec<Vec<String>>,

    /// Specifies whether this Credential Set Query entry is required.
    /// Defaults to true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Claims entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimQuery {
    /// Identifies the claim within the claims array.
    ///
    /// Required when `claim_sets` is present in the Credential Query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// An array of claims path pointers specifying the path to a claim within
    /// the credential.
    pub path: Vec<String>,

    /// The expected values of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,

    /// Equivalent to `IntentToRetain` variable defined in ISO.18013-5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

/// Credential metadata query parameters. Properties are specific to Credential
/// Format Profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MetadataQuery {
    /// ISO-MDL format credential metadata.
    MsoMdoc {
        /// Allowed value for the `doctype` of the requested credential.
        doctype_value: String,
    },

    /// SD-JWT format credential metadata.
    SdJwt {
        /// Allowed `vct` values when querying for SD-JWT Credentials.
        vct_values: Vec<String>,
    },

    /// W3C VC format credential metadata.
    W3cVc {
        /// The fully expanded types after the @context has been applied to the
        /// VC `type` parameter.
        ///
        /// Each top-level array specifies one alternative to match the type
        /// values of the Verifiable Credential against. Each inner array
        /// specifies a set of fully expanded types that MUST be present
        /// in the type property of the Verifiable Credential, regardless
        ///  of order or the presence of additional types.
        ///
        /// For example, the following query
        ///
        /// ```json
        /// "type_values":[
        ///   [
        ///       "https://www.w3.org/2018/credentials#VerifiableCredential",
        ///       "https://example.org/examples#AlumniCredential",
        ///       "https://example.org/examples#BachelorDegree"
        ///   ],
        ///   [
        ///       "https://www.w3.org/2018/credentials#VerifiableCredential",
        ///       "https://example.org/examples#UniversityDegreeCredential"
        ///   ]
        /// ]
        /// ```
        ///
        /// would match a credential with the following type property:
        /// ```json
        /// {
        ///   "@context": [
        ///     "https://www.w3.org/2018/credentials/v1",
        ///     "https://www.w3.org/2018/credentials/examples/v1"
        ///   ],
        ///   "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        ///   ...
        /// }
        /// ```
        type_values: Vec<Vec<String>>,
    },
}

/// The format of the requested credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum CredentialFormat {
    /// A W3C Verifiable Credential.
    #[serde(rename = "jwt_vc_json")]
    #[default]
    JwtVcJson,

    /// A W3C Verifiable Credential not using JSON-LD.
    #[serde(rename = "ldp-vc")]
    LdpVc,

    /// A W3C Verifiable Credential using JSON-LD.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,

    /// An ISO mDL (ISO.18013-5) mobile driving licence format credential.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,

    /// An IETF SD-JWT format credential.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

impl Display for CredentialFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwtVcJson => write!(f, "jwt_vc_json"),
            Self::LdpVc => write!(f, "ldp-vc"),
            Self::JwtVcJsonLd => write!(f, "jwt_vc_json-ld"),
            Self::MsoMdoc => write!(f, "mso_mdoc"),
            Self::DcSdJwt => write!(f, "dc+sd-jwt"),
        }
    }
}

/// Represents information that helps to identify an Issuer certification
/// authority or trust framework.
///
/// A credential is a match to a Trusted Authorities Query if it matches with
/// one of the values in one of the provided types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedAuthoritiesQuery {
    /// An array of objects that specifies claims in the requested credential.
    #[serde(rename = "type")]
    pub type_: Option<Vec<AuthorityType>>,

    /// Combinations of claims to use when requesting credentials. Each set
    /// consists of one or more `claims` identifiers (i.e. `ClaimsQuery.id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Vec<String>>>,
}

/// The type of information about the Issuer trust framework.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum AuthorityType {
    /// The `KeyIdentifier` of the X.509 `AuthorityKeyIdentifier` as a base64url
    /// encoded string.
    ///
    /// The raw byte representation of this element MUST match with the
    /// `AuthorityKeyIdentifier` element of an X.509 certificate in the
    /// certificate chain present in the credential (e.g., in the header of an
    /// `mdoc` or `SD-JWT`).
    #[serde(rename = "aki")]
    #[default]
    Aki,

    /// The identifier of an ETSI TS Trusted List.
    ///
    /// The trust chain of a matching credential MUST contain at least one
    /// X.509 Certificate that matches one of the entries of the Trusted List
    /// or its cascading Trusted Lists.
    #[serde(rename = "etsi_tl")]
    EtsiTl,

    /// An OpenID.Federation Entity Identifier.
    ///
    /// A valid trust path, including the given Entity Identifier, must be
    /// constructible from a matching credential.
    #[serde(rename = "openid_federation")]
    OpenidFederation,
}

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

// impl TryFrom<&Value> for Queryable {
//     type Error = anyhow::Error;

//     fn try_from(value: &Value) -> Result<Self> {
//         match value {
//             Value::String(encoded) => {
//                 if encoded.starts_with("ey") {
//                     from_json(encoded)
//                 } else {
//                     from_cbor(encoded)
//                 }
//             }
//             _ => Err(anyhow!("unexpected VC format: {value}")),
//         }
//     }
// }

// impl TryFrom<&Queryable> for Value {
//     type Error = anyhow::Error;

//     fn try_from(queryable: &Queryable) -> Result<Self> {
//         let mut value = match &queryable.profile {
//             FormatProfile::JwtVcJson {
//                 credential_definition,
//             } => {
//                 json!({
//                     "@context": credential_definition.context,
//                     "type": credential_definition.type_,
//                 })
//             }
//             FormatProfile::DcSdJwt { vct } => json!({"vct": vct}),
//             FormatProfile::MsoMdoc { doctype } => json!({"doctype": doctype}),
//             _ => {
//                 return Err(anyhow!("unsupported profile"));
//             }
//         };

//         let mut default = Map::new();

//         for claim in &queryable.claims {
//             let mut claims_map = value.as_object_mut().unwrap_or(&mut default);

//             for (i, key) in claim.path.iter().enumerate() {
//                 if i == claim.path.len() - 1 {
//                     claims_map.insert(key.to_string(), claim.value.clone());
//                 } else {
//                     if !claims_map.contains_key(key) {
//                         claims_map.insert(key.to_string(), json!({}));
//                     }
//                     claims_map = claims_map.get_mut(key).unwrap().as_object_mut().unwrap();
//                 }
//             }
//         }

//         Ok(value)
//     }
// }

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
    // use super::*;
    // use crate::oid4vci::types::{CredentialDefinition, FormatProfile};
    // use crate::oid4vp::query::{Claim, Queryable};

    // #[test]
    // fn to_json() {
    //     let queryable = &Queryable {
    //         profile: FormatProfile::JwtVcJson {
    //             credential_definition: CredentialDefinition {
    //                 context: None,
    //                 type_: vec![
    //                     "VerifiableCredential".to_string(),
    //                     "EmployeeIDCredential".to_string(),
    //                 ],
    //             },
    //         },
    //         claims: vec![
    //             Claim {
    //                 path: vec!["credentialSubject".to_string(), "employeeId".to_string()],
    //                 value: Value::String("1234567890".to_string()),
    //             },
    //             Claim {
    //                 path: vec!["credentialSubject".to_string(), "family_name".to_string()],
    //                 value: Value::String("Doe".to_string()),
    //             },
    //         ],
    //         issued: Kind::String("jwt_str".to_string()),
    //     };

    //     let json: Value = queryable.try_into().expect("should convert");
    //     println!("json: {json}");
    // }
}
