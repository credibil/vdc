//! Tests for the Verifier API

use credibil_oid4vp::datastore::Datastore;
use credibil_oid4vp::identity::{Key, SignerExt};
use credibil_oid4vp::jose::PublicKeyJwk;
use credibil_oid4vp::status::{StatusClaim, StatusList, TokenBuilder};
use credibil_oid4vp::vdc::{
    DcqlQuery, MdocBuilder, SdJwtVcBuilder, W3cVcBuilder, mso_mdoc, sd_jwt, w3c_vc,
};
use credibil_oid4vp::{
    AuthorizationResponse, DeviceFlow, GenerateRequest, GenerateResponse, ResponseMode, did_jwk,
    vp_token,
};
use serde_json::{Value, json};
use test_utils::issuer::Issuer;
use test_utils::verifier::Verifier;
use test_utils::wallet::Wallet;
use tokio::sync::OnceCell;

const ISSUER_ID: &str = "http://localhost:8080";
const VERIFIER_ID: &str = "http://localhost:8081";

static VERIFIER: OnceCell<Verifier> = OnceCell::const_new();
static ISSUER: OnceCell<Issuer> = OnceCell::const_new();
static WALLET: OnceCell<Wallet> = OnceCell::const_new();
async fn verifier() -> &'static Verifier {
    VERIFIER.get_or_init(|| async { Verifier::new(VERIFIER_ID).await }).await
}
async fn issuer() -> &'static Issuer {
    ISSUER.get_or_init(|| async { Issuer::new(ISSUER_ID).await }).await
}
async fn wallet() -> &'static Wallet {
    WALLET.get_or_init(|| async { populate("https://dcql.io/wallet").await }).await
}

// Should request a Credential with the claims `vehicle_holder` and `first_name`.
#[tokio::test]
async fn multiple_claims() {
    let verifier = verifier().await;

    // --------------------------------------------------
    // Verifier creates an Authorization Request to request presentation of
    // credentials and sends to Wallet
    // --------------------------------------------------
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
    let dcql_query = serde_json::from_value::<DcqlQuery>(query_json).expect("should deserialize");

    let request = GenerateRequest {
        dcql_query,
        client_id: VERIFIER_ID.to_string(),
        device_flow: DeviceFlow::SameDevice,
        response_mode: ResponseMode::DirectPost {
            response_uri: "http://localhost:3000/cb".to_string(),
        },
    };
    let response = credibil_oid4vp::handle(VERIFIER_ID, request, verifier)
        .await
        .expect("should create request");

    // extract request object and send to Wallet
    let GenerateResponse::Object(request_object) = response.body else {
        panic!("should be object");
    };

    // --------------------------------------------------
    // Wallet processes the Authorization Request and returns an Authorization
    // Response with the requested presentations in the VP token.
    // --------------------------------------------------
    let wallet = wallet().await;
    let stored_vcs = wallet.fetch();
    let results = request_object.dcql_query.execute(stored_vcs).expect("should execute");
    // assert_eq!(results.len(), 2);

    let vp_token =
        vp_token::generate(&request_object, &results, wallet).await.expect("should get token");
    let request = AuthorizationResponse {
        vp_token,
        state: request_object.state,
    };

    // --------------------------------------------------
    // Verifier processes the Wallets's Authorization Response.
    // --------------------------------------------------
    let response = credibil_oid4vp::handle(VERIFIER_ID, request, verifier)
        .await
        .expect("should create request");

    // --------------------------------------------------
    // Wallet follows Verifier's redirect.
    // --------------------------------------------------
    assert_eq!(response.status, 200);
    assert_eq!(response.body.redirect_uri.unwrap(), "http://localhost:3000/cb");
}

// Should return multiple Credentials.
#[tokio::test]
async fn multiple_credentials() {
    let verifier = verifier().await;

    // --------------------------------------------------
    // Verifier creates an Authorization Request to request presentation of
    // credentials and sends to Wallet
    // --------------------------------------------------
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
                    {"path": ["address"]}
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
                    {"path": ["org.iso.18013.5.1", "given_name"]}
                ]
            },
            {
                "id": "w3c",
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["VerifiableCredential", "EmployeeIDCredential"]]
                },
                "claims": [
                    {"path": ["credentialSubject", "family_name"]},
                    {"path": ["credentialSubject", "given_name"]}
                ]
            }
        ]
    });
    let dcql_query = serde_json::from_value(query_json).expect("should deserialize");

    let request = GenerateRequest {
        dcql_query,
        client_id: VERIFIER_ID.to_string(),
        device_flow: DeviceFlow::SameDevice,
        response_mode: ResponseMode::DirectPost {
            response_uri: "http://localhost:3000/cb".to_string(),
        },
    };
    let response = credibil_oid4vp::handle(VERIFIER_ID, request, verifier)
        .await
        .expect("should create request");

    // extract request object and send to Wallet
    let GenerateResponse::Object(request_object) = response.body else {
        panic!("should be object");
    };

    // --------------------------------------------------
    // Wallet processes the Authorization Request and returns an Authorization
    // Response to the Verifier.
    // --------------------------------------------------
    let wallet = wallet().await;
    let stored_vcs = wallet.fetch();
    let results = request_object.dcql_query.execute(stored_vcs).expect("should execute");
    assert_eq!(results.len(), 3);

    // return a single `vp_token` for the query
    // each credential query will result in a separate presentation
    let vp_token =
        vp_token::generate(&request_object, &results, wallet).await.expect("should get token");
    assert_eq!(vp_token.len(), 3);

    let request = AuthorizationResponse {
        vp_token,
        state: request_object.state,
    };
    let response = credibil_oid4vp::handle(VERIFIER_ID, request, verifier)
        .await
        .expect("should create request");

    // --------------------------------------------------
    // Wallet follows Verifier's redirect.
    // --------------------------------------------------
    assert_eq!(response.status, 200);
    assert_eq!(response.body.redirect_uri.unwrap(), "http://localhost:3000/cb");
}

// Should return one of a `pid`, OR the `other_pid`, OR both
// `pid_reduced_cred_1` and `pid_reduced_cred_2` credentials.
//
// Should also optionally return the `nice_to_have` credential.
#[tokio::test]
async fn complex_query() {
    // let verifier = verifier().await;
    let wallet = wallet().await;
    let all_vcs = wallet.fetch();

    // --------------------------------------------------
    // Verifier creates an Authorization Request to request presentation of
    // credentials and sends to Wallet
    // --------------------------------------------------
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
#[tokio::test]
async fn any_credential() {
    // let verifier = verifier().await;
    let wallet = wallet().await;
    let all_vcs = wallet.fetch();

    // --------------------------------------------------
    // Verifier creates an Authorization Request to request presentation of
    // credentials and sends to Wallet
    // --------------------------------------------------
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
#[tokio::test]
async fn alt_claims() {
    let wallet = wallet().await;
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
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 1);
}

// Should return a credential for a request using specific values for the
// `last_name` and `postal_code` claims.
#[tokio::test]
async fn specific_values() {
    let wallet = wallet().await;
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
    let results = query.execute(all_vcs).expect("should execute");
    assert_eq!(results.len(), 1);
}

// Initialise a mock "wallet" with test credentials.
async fn populate(owner: &str) -> Wallet {
    let mut wallet = Wallet::new(owner).await;
    let issuer = issuer().await;

    let Key::KeyId(did_url) = wallet.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let holder_jwk = did_jwk(&did_url, &wallet).await.expect("should get key");

    // create a status list token
    let mut status_list = StatusList::new().expect("should create status list");
    let status_claim = status_list.add_entry("http://credibil.io/statuslists/1").unwrap();
    let token = TokenBuilder::new()
        .status_list(status_list.clone())
        .uri("https://example.com/statuslists/1")
        .signer(issuer)
        .build()
        .await
        .expect("should build status list token");
    let data = serde_json::to_vec(&token).expect("should serialize");
    Datastore::put(issuer, "owner", "STATUSTOKEN", "http://credibil.io/statuslists/1", data)
        .await
        .unwrap();

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
    let jwt = sd_jwt(vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, issuer).await.expect("should be SD-JWT");
    wallet.add(q);

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
    let jwt = sd_jwt(vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, issuer).await.expect("should be SD-JWT");
    wallet.add(q);

    let vct = "https://cred.example/residence_credential";
    let claims = json!({
        "address": {
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "90210",
        },
    });
    let jwt = sd_jwt(vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, issuer).await.expect("should be SD-JWT");
    wallet.add(q);

    let vct = "https://company.example/company_rewards";
    let claims = json!({
        "rewards_number": "1234567890",
    });
    let jwt = sd_jwt(vct, claims, &holder_jwk, &status_claim).await;
    let q = sd_jwt::to_queryable(&jwt, issuer).await.expect("should be SD-JWT");
    wallet.add(q);

    let doctype = "org.iso.18013.5.1.mDL";
    let claims = json!({
        "org.iso.18013.5.1": {
            "given_name": "Normal",
            "family_name": "Person",
            "portrait": "https://example.com/portrait.jpg",
        },
    });
    let mdoc = mso_mdoc(doctype, claims, &holder_jwk).await;
    let q = mso_mdoc::to_queryable(&mdoc, &wallet).await.expect("should be mdoc");
    wallet.add(q);

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
    let mdoc = mso_mdoc(doctype, claims, &holder_jwk).await;
    let q = mso_mdoc::to_queryable(&mdoc, &wallet).await.expect("should be mdoc");
    wallet.add(q);

    let r#type = vec!["VerifiableCredential".to_string(), "EmployeeIDCredential".to_string()];
    let claims = json!({
        "credentialSubject": {
            "given_name": "Jane",
            "family_name": "Doe",
        },
    });
    let did = did_url.split_once('#').unwrap().0;
    let jwt = w3c_vc(r#type, claims, did).await;
    let q = w3c_vc::to_queryable(jwt, &wallet).await.expect("should be mdoc");
    wallet.add(q);

    wallet
}

async fn sd_jwt(
    vct: &str, claims: Value, holder_jwk: &PublicKeyJwk, status_claim: &StatusClaim,
) -> String {
    SdJwtVcBuilder::new()
        .vct(vct)
        .claims(claims.as_object().unwrap().clone())
        .issuer(ISSUER_ID)
        .key_binding(holder_jwk.clone())
        .status(status_claim.clone())
        .signer(issuer().await)
        .build()
        .await
        .expect("should build")
}

async fn mso_mdoc(doctype: &str, claims: Value, holder_jwk: &PublicKeyJwk) -> String {
    MdocBuilder::new()
        .doctype(doctype)
        .device_key(holder_jwk.clone())
        .claims(claims.as_object().unwrap().clone())
        .signer(issuer().await)
        .build()
        .await
        .expect("should build")
}

async fn w3c_vc(r#type: Vec<String>, claims: Value, did: &str) -> String {
    W3cVcBuilder::new()
        .r#type(r#type)
        .claims(claims.as_object().unwrap().clone())
        .issuer(ISSUER_ID)
        .holder(did)
        .signer(issuer().await)
        .build()
        .await
        .expect("should build")
}
