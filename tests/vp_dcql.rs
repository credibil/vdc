//! Tests for the Verifier API

#[path = "../examples/issuer/mod.rs"]
mod issuer;
#[path = "../examples/issuer/provider/mod.rs"]
mod provider;
#[path = "../examples/wallet/mod.rs"]
mod wallet;

use credibil_vc::oid4vp::types::DcqlQuery;
use serde_json::json;

// Should request a Credential with the claims `vehicle_holder` and `first_name`.
#[tokio::test]
async fn multiple_claims() {
    // The issuer issues a credential with the claims `vehicle_holder` and `first_name`.
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 1);
}

// Request multiple Credentials all of which should be returned.
#[tokio::test]
async fn multiple_credentials() {
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 2);
}

// Make a complex query where the Wallet is requested to deliver:
//  - The `pid` credential
//  - OR the `other_pid` credential,
//  - OR both `pid_reduced_cred_1` and `pid_reduced_cred_2`.
//
// Additionally, the `nice_to_have` credential may optionally be delivered.
#[tokio::test]
async fn complex_query() {
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 2);
}

// Request an ID and address from any credential.
#[tokio::test]
async fn any_credential() {
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 2);
}

// Requests the mandatory claims `last_name` and `date_of_birth`, and
// either the claim `postal_code`, or, if that is not available, both of
// the claims `locality` and `region`.
#[tokio::test]
async fn alt_claims() {
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 1);
}

// Requests a credential using specific values for the `last_name` and `postal_code` claims.
#[tokio::test]
async fn specific_values() {
    let wallet = mock_wallet().await;
    let all_vcs = wallet.fetch();

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
    let res = query.execute(all_vcs).expect("should execute");
    assert_eq!(res.len(), 1);
}

// Initialise the wallet with test credentials.
async fn mock_wallet() -> wallet::Store {
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
    let vc = issuer::issue_sd_jwt(vct, claims).await;
    store.add(vc.clone());

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
    let vc = issuer::issue_sd_jwt(vct, claims).await;
    store.add(vc.clone());

    let vct = "https://cred.example/residence_credential";
    let claims = json!({
        "address": {
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "90210",
        },
    });
    let vc = issuer::issue_sd_jwt(vct, claims).await;
    store.add(vc.clone());

    let vct = "https://company.example/company_rewards";
    let claims = json!({
        "rewards_number": "1234567890",
    });
    let vc = issuer::issue_sd_jwt(vct, claims).await;
    store.add(vc.clone());

    let doctype = "org.iso.18013.5.1.mDL";
    let claims = json!({
        "org.iso.18013.5.1": {
            "given_name": "Normal",
            "family_name": "Person",
            "portrait": "https://example.com/portrait.jpg",
        },
    });
    let vc = issuer::issue_mso_mdoc(doctype, claims).await;
    store.add(vc.clone());

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
    let vc = issuer::issue_mso_mdoc(doctype, claims).await;
    store.add(vc.clone());

    store
}
