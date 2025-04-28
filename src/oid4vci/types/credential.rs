use std::fmt::Debug;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::Kind;
use crate::format::w3c::VerifiableCredential;

/// The user information returned by the Subject trait.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Dataset {
    /// The credential configuration ID of the credential this dataset is for.
    pub credential_configuration_id: String,

    /// The credential subject populated for the user.
    pub claims: Map<String, Value>,

    /// Specifies whether user information required for the credential subject
    /// is pending.
    pub pending: bool,
}

/// `CredentialRequest` is used by the Client to make a Credential Request to
/// the Credential Endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialRequest {
    /// Identifies the credential requested for issuance using either a
    /// `credential_identifier` or a supported format.
    ///
    /// If `credential_identifiers` were returned in the Token
    /// Response, they MUST be used here. Otherwise, they MUST NOT be used.
    #[serde(flatten)]
    pub credential: RequestBy,

    /// Wallet's proof of possession of cryptographic key material the issued
    /// Credential will be bound to.
    /// REQUIRED if the `proof_types_supported` parameter is non-empty and
    /// present in the `credential_configurations_supported` parameter of
    /// the Issuer metadata for the requested Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub proof: Option<Proof>,

    /// If present, specifies how the Credential Response should be encrypted.
    /// If not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

/// Means used to identifiy Credential type and format when requesting a
/// Credential.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum RequestBy {
    /// Credential is requested by `credential_identifier`.
    /// REQUIRED when an Authorization Details of type `openid_credential` was
    /// returned from the Token Response.
    #[serde(rename = "credential_identifier")]
    Identifier(String),

    /// Credential is requested by `credential_configuration_id`. This
    /// identifies the entry in the `credential_configurations_supported`
    /// Issuer metadata.
    #[serde(rename = "credential_configuration_id")]
    ConfigurationId(String),
}

impl Default for RequestBy {
    fn default() -> Self {
        Self::Identifier(String::new())
    }
}

/// Wallet's proof of possession of the key material the issued Credential is to
/// be bound to.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Proof {
    /// A single proof of possession of the cryptographic key material to which
    /// the issued Credential instance will be bound to.
    #[serde(rename = "proof")]
    Single(SingleProof),

    /// One or more proof of possessions of the cryptographic key material to
    /// which the issued Credential instances will be bound to.
    #[serde(rename = "proofs")]
    Multiple(MultipleProofs),
}

impl Default for Proof {
    fn default() -> Self {
        Self::Single(SingleProof::default())
    }
}

/// A single proof of possession of the cryptographic key material provided by
/// the Wallet to which the issued Credential instance will be bound.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "proof_type")]
pub enum SingleProof {
    /// The JWT containing the Wallet's proof of possession of key material.
    #[serde(rename = "jwt")]
    Jwt {
        /// The JWT containing the Wallet's proof of possession of key material.
        jwt: String,
    },

    /// A JWT containg a key attestation without using a proof of possession
    /// of the key material that is being attested.
    #[serde(rename = "attestation")]
    Attestation {
        /// The JWT containing the Wallet's proof of possession of key material.
        attestation: String,
    },
    //
    // /// A W3C Verifiable Presentation object signed using the Data Integrity Proof.
    // #[serde(rename = "ldp_vp")]
    // LdpVp {
    //     /// The JWT containing the Wallet's proof of possession of key material.
    //     ldp_vp: String,
    // },
}

impl Default for SingleProof {
    fn default() -> Self {
        Self::Jwt { jwt: String::new() }
    }
}

/// A a single proof of possession of the cryptographic key material provided by
/// the Wallet to which the issued Credential instance will be bound.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum MultipleProofs {
    /// JWTs containing the Wallet's proof of possession of key material.
    #[serde(rename = "jwt")]
    Jwt(Vec<String>),

    /// JWTs containg a key attestation without using a proof of possession
    /// of the key material that is being attested.
    #[serde(rename = "attestation")]
    Attestation(Vec<String>),
}

impl Default for MultipleProofs {
    fn default() -> Self {
        Self::Jwt(vec![String::new()])
    }
}

/// Claims containing a Wallet's proof of possession of key material that can be
/// used for binding an issued Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofClaims {
    /// The `client_id` of the Client making the Credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iss")]
    pub client_id: Option<String>,

    /// The Credential Issuer Identifier.
    #[serde(rename = "aud")]
    pub credential_issuer: String,

    /// The time at which the proof was issued.
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// A server-provided `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl ProofClaims {
    /// Create a new `ProofClaims` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            iat: Utc::now(),
            ..Self::default()
        }
    }

    /// Set the `client_id` of the Client making the Credential request.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the Credential Issuer Identifier.
    #[must_use]
    pub fn credential_issuer(mut self, credential_issuer: impl Into<String>) -> Self {
        self.credential_issuer = credential_issuer.into();
        self
    }

    /// Set the server-provided `c_nonce`.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

/// Claims containing a Wallet's proof of possession of key material that can be
/// used for binding an issued Credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AttestationClaims {
    /// The time at which the proof was issued, as a `NumericDate` (seconds
    /// since 01-01-1970).
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The time at which the key attestation and the key(s) it is attesting
    /// expire, as a `NumericDate` (seconds since 01-01-1970).
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,

    /// Attested keys from the same key storage component.
    pub attested_keys: Vec<PublicKeyJwk>,

    /// Values that assert the attack potential resistance of the key storage
    /// component and the keys attested to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<Vec<AttackPotentialResistance>>,

    /// Values that assert the attack potential resistance of the user
    /// authentication methods allowed to access the private keys of the
    /// keys attested to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<Vec<AttackPotentialResistance>>,

    /// A server-provided `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Defines the supported revocation check mechanisms. For example,
    /// [ietf-oauth-status-list](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Options for asserting the attack potential resistance of `key_storage` and
/// `user_authentication` parameters.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttackPotentialResistance {
    /// Used when key storage or user authentication is resistant to attack
    /// with attack potential "High", equivalent to VAN.5 according to ISO
    /// 18045.
    Iso18045High,

    /// Used when key storage or user authentication is resistant to attack
    /// with attack potential "Moderate", equivalent to VAN.4 according to
    /// ISO 18045.
    Iso18045Moderate,

    /// Used when key storage or user authentication is resistant to attack
    /// with attack potential "Enhanced-Basic", equivalent to VAN.3 according
    /// to ISO 18045.
    Iso18045EnhancedBasic,

    /// Used when key storage or user authentication is resistant to attack
    /// with attack potential "Basic", equivalent to VAN.2 according to ISO
    /// 18045.
    #[default]
    Iso18045EBasic,
}

/// Contains information about whether the Credential Issuer supports encryption
/// of the Credential Response on top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    /// The public key used for encrypting the Credential Response.
    pub jwk: PublicKeyJwk,

    /// JWE [RFC7516] alg algorithm [RFC7518] for encrypting Credential
    /// Response.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg: String,

    /// JWE [RFC7516] enc algorithm [RFC7518] for encoding Credential Response.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc: String,
}

/// The Credential Response can be Synchronous or Deferred.
///
/// The Credential Issuer MAY be able to immediately issue a requested
/// Credential. In other cases, the Credential Issuer MAY NOT be able to
/// immediately issue a requested Credential and will instead return a
/// `transaction_id` to be used later to retrieve a Credential when it is ready.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CredentialResponse {
    /// Contains an array of issued Credentials. The values in the array MAY be
    /// a string or an object, depending on the Credential Format Profile.
    Credentials {
        /// An array of one or more issued Credentials
        credentials: Vec<Credential>,

        /// Used to identify one or more of the Credentials returned in the
        /// response. The `notification_id` is included in the Notification
        /// Request.
        #[serde(skip_serializing_if = "Option::is_none")]
        notification_id: Option<String>,
    },

    /// String identifying a Deferred Issuance transaction. This parameter is
    /// contained in the response if the Credential Issuer cannot
    /// immediately issue the Credential. The value is subsequently used to
    /// obtain the respective Credential with the Deferred Credential
    /// Endpoint.
    TransactionId {
        /// The Deferred Issuance transaction identifier.
        transaction_id: String,
    },
}

impl Default for CredentialResponse {
    fn default() -> Self {
        Self::Credentials {
            credentials: vec![Credential {
                credential: Kind::default(),
            }],
            notification_id: None,
        }
    }
}

/// The issued credential
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Credential {
    /// Contains one issued Credential. It MAY be a string or an object,
    /// depending on the Credential Format Profile.
    pub credential: Kind<VerifiableCredential>,
}

/// An HTTP POST request, which accepts an `acceptance_token` as the only
/// parameter. The `acceptance_token` parameter MUST be sent as Access Token in
/// the HTTP header.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeferredCredentialRequest {
    /// Identifies a Deferred Issuance transaction from an earlier Credential
    /// Request.
    pub transaction_id: String,
}

/// The Deferred Credential Response uses the same format and credential
/// parameters defined for a Credential Response.
pub type DeferredCredentialResponse = CredentialResponse;

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::oid4vci::types::CredentialConfiguration;

    #[test]
    fn credential_identifier() {
        let json = serde_json::json!({
            "credential_identifier": "EngineeringDegree2023",
            "proof": {
                "proof_type": "jwt",
                "jwt": "SomeJWT"
            }
        });

        let deserialized: CredentialRequest =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        assert_snapshot!("credential_identifier", &deserialized);

        let request = CredentialRequest {
            credential: RequestBy::Identifier("EngineeringDegree2023".to_string()),
            proof: Some(Proof::Single(SingleProof::Jwt {
                jwt: "SomeJWT".to_string(),
            })),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }

    #[test]
    fn multiple_proofs() {
        let json = serde_json::json!({
            "credential_identifier": "EngineeringDegree2023",
            "proofs": {
                "jwt": [
                    "SomeJWT1",
                    "SomeJWT2"
                ]
            }
        });

        let deserialized: CredentialRequest =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        assert_snapshot!("multiple_proofs", &deserialized);

        let request = CredentialRequest {
            credential: RequestBy::Identifier("EngineeringDegree2023".to_string()),
            proof: Some(Proof::Multiple(MultipleProofs::Jwt(vec![
                "SomeJWT1".to_string(),
                "SomeJWT2".to_string(),
            ]))),
            ..CredentialRequest::default()
        };

        let serialized = serde_json::to_value(&request).expect("should serialize to string");
        assert_eq!(json, serialized);
    }

    #[test]
    fn claim_label_display() {
        let json = serde_json::json!({
            "format": "jwt_vc_json",
            "scope": "EmployeeIDCredential",
            "cryptographic_binding_methods_supported": [
                "did:key",
                "did:web"
            ],
            "credential_signing_alg_values_supported": [
                "ES256K",
                "EdDSA"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256K",
                        "EdDSA"
                    ]
                }
            },
            "display": [
                {
                    "name": "Employee ID",
                    "description": "Credibil employee ID credential",
                    "locale": "en-NZ",
                    "logo": {
                        "uri": "https://credibil.io/assets/employee.png",
                        "alt_text": "Employee ID Logo"
                    },
                    "text_color": "#ffffff",
                    "background_color": "#323ed2",
                    "background_image": {
                        "uri": "https://credibil.io/assets/employee-background.png",
                        "alt_text": "Employee ID Background"
                    }
                }
            ],
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            },
            "claims": [
                {
                    "path": [
                        "credentialSubject",
                        "email"
                    ],
                    "mandatory": true,
                    "display": [
                        {
                            "name": "Email",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "family_name"
                    ],
                    "mandatory": true,
                    "display": [
                        {
                            "name": "Family name",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "given_name"
                    ],
                    "mandatory": true,
                    "display": [
                        {
                            "name": "Given name",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "address"
                    ],
                    "display": [
                        {
                            "name": "Residence",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "address",
                        "street_address"
                    ],
                    "display": [
                        {
                            "name": "Street Address",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "address",
                        "locality"
                    ],
                    "display": [
                        {
                            "name": "Locality",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "address",
                        "region"
                    ],
                    "display": [
                        {
                            "name": "Region",
                            "locale": "en-NZ"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "address",
                        "country"
                    ],
                    "display": [
                        {
                            "name": "Country",
                            "locale": "en-NZ"
                        }
                    ]
                }
            ]
        });

        let config: CredentialConfiguration =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        let claims = config.claims_display(Some("en-NZ"));
        assert_snapshot!("claim_label_display_en-NZ", &claims, {
            "." => insta::sorted_redaction(),
        });
        let default = config.claims_display(None);
        assert_snapshot!("claim_label_display_default", &default, {
            "." => insta::sorted_redaction(),
        });
    }
}
