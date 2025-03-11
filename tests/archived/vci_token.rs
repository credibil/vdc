//! Tests for the token endpoint.

mod utils;

use chrono::Utc;
use credibil_vc::core::pkce;
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::{Authorization, Expire, Offer, Stage, State};
use credibil_vc::oid4vci::types::{
    AuthorizationCredential, AuthorizationDetail, AuthorizationDetailType, AuthorizedDetail,
    TokenRequest, TokenResponse,
};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};


#[tokio::test]
async fn authorized() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let verifier = "ABCDEF12345";

    // set up Authorization state
    let state = State {
        stage: Stage::Authorized(Authorization {
            code_challenge: pkce::code_challenge(verifier),
            code_challenge_method: "S256".to_string(),
            details: vec![AuthorizedDetail {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential: AuthorizationCredential::ConfigurationId {
                        credential_configuration_id: "EmployeeID_JWT".to_string(),
                    },
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".to_string()],
            }],
            client_id: CLIENT_ID.into(),
            ..Authorization::default()
        }),
        subject_id: Some(NORMAL_USER.into()),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };

    let code = "ABCDEF";

    StateStore::put(&provider, code, &state, state.expires_at).await.expect("state exists");

    // create TokenRequest to 'send' to the app
    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
    });
    let request: TokenRequest = serde_json::from_value(value).expect("request is valid");
    let token_resp: TokenResponse =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");

    assert_snapshot!("token:authorized:response", &token_resp, {
        ".access_token" => "[access_token]",
        ".c_nonce" => "[c_nonce]"
    });

    // authorization state should be removed
    assert!(StateStore::get::<State>(&provider, code).await.is_err());

    // should be able to retrieve state using access token
    let state =
        StateStore::get::<State>(&provider, &token_resp.access_token).await.expect("state exists");

    assert_snapshot!("token:authorized:state", state, {
        ".expires_at" => "[expires_at]",
        ".stage.access_token" => "[access_token]",
        ".stage.c_nonce" => "[c_nonce]",
        ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]",
    });
}

#[tokio::test]
async fn authorization_details() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let verifier = "ABCDEF12345";

    // set up Authorization state
    let state = State {
        stage: Stage::Authorized(Authorization {
            client_id: CLIENT_ID.into(),
            redirect_uri: Some("https://example.com".to_string()),
            code_challenge: pkce::code_challenge(verifier),
            code_challenge_method: "S256".to_string(),
            details: vec![AuthorizedDetail {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential: AuthorizationCredential::ConfigurationId {
                        credential_configuration_id: "EmployeeID_JWT".to_string(),
                    },
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".to_string()],
            }],
            ..Authorization::default()
        }),
        subject_id: Some(NORMAL_USER.into()),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };

    let code = "ABCDEF";

    StateStore::put(&provider, code, &state, state.expires_at).await.expect("state exists");

    // create TokenRequest to 'send' to the app
    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com",
        "authorization_details": [{
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            }
        }],
    });
    let request: TokenRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");

    assert_snapshot!("token:authorization_details:response", &response, {
        ".access_token" => "[access_token]",
        ".c_nonce" => "[c_nonce]"
    });

    // auth_code state should be removed
    assert!(StateStore::get::<State>(&provider, code).await.is_err());

    // should be able to retrieve state using access token
    let state =
        StateStore::get::<State>(&provider, &response.access_token).await.expect("state exists");

    assert_snapshot!("token:authorization_details:state", state, {
        ".expires_at" => "[expires_at]",
        ".stage.access_token" => "[access_token]",
        ".stage.c_nonce" => "[c_nonce]",
        ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]",
    });
}
