//! Tests for the Verifier API

#[path = "../examples/kms/mod.rs"]
mod kms;
#[path = "../examples/wallet/mod.rs"]
mod wallet;

use std::sync::LazyLock;

use credibil_infosec::{Curve, KeyType, PublicKeyJwk};
use credibil_vc::mso_mdoc::MsoMdocBuilder;
use credibil_vc::oid4vp::types::DcqlQuery;
use credibil_vc::sd_jwt::SdJwtVcBuilder;
use credibil_vc::{mso_mdoc, sd_jwt};
use futures::executor::block_on;
use serde_json::{Map, Value, json};

use self::kms::Keyring;

// Create a mock wallet populated with test credentials.
static WALLET_DB: LazyLock<wallet::Store> =
    LazyLock::new(|| block_on(async { load_wallet().await }));

// Should request a Credential with the claims `vehicle_holder` and `first_name`.
#[test]
fn multiple_claims() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [{
            "id": "my_credential",
            "format": "mso_mdoc",
            "meta": {
                "doctype_value": "org.iso.7367.1.mVRC"
            },
            "claims": [
                {"path": ["org.iso.7367.1", "vehicle_holder"]},
                {"path": ["org.iso.18013.5.1", "given_name"]}
            ]
        }]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 1);

    // 1. build presentation

    // 2. send vp_token to verifier
}

// Should return multiple Credentials.
#[test]
fn multiple_credentials() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                ]
            },
            {
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                },
                "claims": [
                    {"path": ["org.iso.7367.1", "vehicle_holder"]},
                    {"path": ["org.iso.18013.5.1", "first_name"]}
                ]
            }
        ]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 2);

    // 1. build presentation
    for selected in results {
        println!("selected credential: {:?}", selected);
    }

    // 2. send vp_token to verifier
}

// Should return one of a `pid`, OR the `other_pid`, OR both
// `pid_reduced_cred_1` and `pid_reduced_cred_2` credentials.
//
// Should also optionally return the `nice_to_have` credential.
#[test]
fn complex_query() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                ]
            },
            {
                "id": "other_pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://othercredentials.example/pid"]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                ]
            },
            {
                "id": "pid_reduced_cred_1",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                },
                "claims": [
                    {"path": ["family_name"]},
                    {"path": ["given_name"]}
                ]
            },
            {
                "id": "pid_reduced_cred_2",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://cred.example/residence_credential"]
                },
                "claims": [
                    {"path": ["postal_code"]},
                    {"path": ["locality"]},
                    {"path": ["region"]}
                ]
            },
            {
                "id": "nice_to_have",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://company.example/company_rewards"]
                },
                "claims": [
                    {"path": ["rewards_number"]}
                ]
            }
        ],
        "credential_sets": [
            {
                "purpose": "Identification",
                "options": [
                    [ "pid" ],
                    [ "other_pid" ],
                    [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                ]
            },
            {
                "purpose": "Show your rewards card",
                "required": false,
                "options": [
                    [ "nice_to_have" ]
                ]
            }
        ]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 2);
}

// Should return an ID and address from any credential.
#[test]
fn any_credential() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [
            {
                "id": "mdl-id",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                },
                "claims": [
                    {
                        "id": "given_name",
                        "path": ["org.iso.18013.5.1", "given_name"]
                    },
                    {
                        "id": "family_name",
                        "path": ["org.iso.18013.5.1", "family_name"]
                    },
                    {
                        "id": "portrait",
                        "path": ["org.iso.18013.5.1", "portrait"]
                    }
                ]
            },
            {
                "id": "mdl-address",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                },
                "claims": [
                    {
                    "id": "resident_address",
                    "path": ["org.iso.18013.5.1", "resident_address"]
                    },
                    {
                    "id": "resident_country",
                    "path": ["org.iso.18013.5.1", "resident_country"]
                    }
                ]
            },
            {
                "id": "photo_card-id",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.23220.photoid.1"
                },
                "claims": [
                    {
                        "id": "given_name",
                        "path": ["org.iso.18013.5.1", "given_name"]
                    },
                    {
                        "id": "family_name",
                        "path": ["org.iso.18013.5.1", "family_name"]
                    },
                    {
                        "id": "portrait",
                        "path": ["org.iso.18013.5.1", "portrait"]
                    }
                ]
            },
            {
                "id": "photo_card-address",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.23220.photoid.1"
                },
                "claims": [
                    {
                    "id": "resident_address",
                    "path": ["org.iso.18013.5.1", "resident_address"]
                    },
                    {
                    "id": "resident_country",
                    "path": ["org.iso.18013.5.1", "resident_country"]
                    }
                ]
            }
        ],
        "credential_sets": [
            {
                "purpose": "Identification",
                "options": [
                    [ "mdl-id" ],
                    [ "photo_card-id" ]
                ]
            },
            {
                "purpose": "Proof of address",
                "required": false,
                "options": [
                    [ "mdl-address"],
                    ["photo_card-address" ]
                ]
            }
        ]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 2);
}

// Should return the mandatory claims `last_name` and `date_of_birth`, and
// either the claim `postal_code`, or, if that is not available, both of
// the claims `locality` and `region`.
#[test]
fn alt_claims() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": [ "https://credentials.example.com/identity_credential" ]
                },
                "claims": [
                    {"id": "a", "path": ["last_name"]},
                    {"id": "b", "path": ["postal_code"]},
                    {"id": "c", "path": ["locality"]},
                    {"id": "d", "path": ["region"]},
                    {"id": "e", "path": ["date_of_birth"]}
                ],
                "claim_sets": [
                    ["a", "c", "d", "e"],
                    ["a", "b", "e"]
                ]
            }
        ]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 1);
}

// Should return a credential for a request using specific values for the
// `last_name` and `postal_code` claims.
#[test]
fn specific_values() {
    let all_vcs = WALLET_DB.fetch();

    let query_json = json!({
        "credentials": [
            {
                "id": "my_credential",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": [ "https://credentials.example.com/identity_credential" ]
                },
                "claims": [
                    {
                        "path": ["last_name"],
                        "values": ["Doe"]
                    },
                    {"path": ["first_name"]},
                    {"path": ["address", "street_address"]},
                    {
                        "path": ["postal_code"],
                        "values": ["90210", "90211"]
                    }
                ]
            }
        ]
    });

    let query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 1);
}

// Initialise a mock "wallet" with test credentials.
async fn load_wallet() -> wallet::Store {
    let mut store = wallet::Store::new();

    // load credentials
    let vct = "https://credentials.example.com/identity_credential";
    let claims = json!({
        "given_name": "Alice",
        "family_name": "Holder",
        "address": {
            "street_address": "123 Elm St",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "90210",
            "country": "USA"
        },
        "birthdate": "2000-01-01"
    });
    let jwt = sd_jwt(vct, claims.as_object().unwrap().clone()).await;
    let q = sd_jwt::to_queryable(&jwt).expect("should be SD-JWT");
    store.add(q);

    let vct = "https://othercredentials.example/pid";
    let claims = json!({
        "given_name": "John",
        "family_name": "Doe",
        "address": {
            "street_address": "34 Drake St",
            "locality": "Auckland",
            "region": "Auckland",
            "postal_code": "1010",
            "country": "New Zealand"
        },
        "birthdate": "2000-01-01"
    });
    let jwt = sd_jwt(vct, claims.as_object().unwrap().clone()).await;
    let q = sd_jwt::to_queryable(&jwt).expect("should be SD-JWT");
    store.add(q);

    let vct = "https://cred.example/residence_credential";
    let claims = json!({
        "address": {
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "90210",
        },
    });
    let jwt = sd_jwt(vct, claims.as_object().unwrap().clone()).await;
    let q = sd_jwt::to_queryable(&jwt).expect("should be SD-JWT");
    store.add(q);

    let vct = "https://company.example/company_rewards";
    let claims = json!({
        "rewards_number": "1234567890",
    });
    let jwt = sd_jwt(vct, claims.as_object().unwrap().clone()).await;
    let q = sd_jwt::to_queryable(&jwt).expect("should be SD-JWT");
    store.add(q);

    let doctype = "org.iso.18013.5.1.mDL";
    let claims = json!({
        "org.iso.18013.5.1": {
            "given_name": "Normal",
            "family_name": "Person",
            "portrait": "https://example.com/portrait.jpg",
        },
    });
    let mdoc = mso_mdoc(doctype, claims.as_object().unwrap().clone()).await;
    let q = mso_mdoc::to_queryable(&mdoc).expect("should be mdoc");
    store.add(q);

    let doctype = "org.iso.7367.1.mVRC";
    let claims = json!({
        "org.iso.7367.1": {
            "vehicle_holder": "Alice Holder",
        },
        "org.iso.18013.5.1": {
            "given_name": "Normal",
            "family_name": "Person",
            "portrait": "https://example.com/portrait.jpg",
        },
    });
    let mdoc = mso_mdoc(doctype, claims.as_object().unwrap().clone()).await;
    let q = mso_mdoc::to_queryable(&mdoc).expect("should be mdoc");
    store.add(q);

    store
}

async fn sd_jwt(vct: &str, claims: Map<String, Value>) -> String {
    SdJwtVcBuilder::new()
        .vct(vct)
        .claims(claims)
        .issuer("https://example.com")
        .key_binding(PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: "x".to_string(),
            ..PublicKeyJwk::default()
        })
        .signer(&Keyring::new())
        .build()
        .await
        .expect("should build")
}

async fn mso_mdoc(doctype: &str, claims: Map<String, Value>) -> String {
    MsoMdocBuilder::new()
        .doctype(doctype)
        .claims(claims)
        .signer(&Keyring::new())
        .build()
        .await
        .expect("should build")
}
