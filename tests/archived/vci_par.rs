//! Tests for Pushed Authorization Request endpoint

mod utils;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::State;
use credibil_vc::oid4vci::types::{AuthorizationRequest, PushedAuthorizationRequest};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn request() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "EmployeeID_JWT",
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });
    let request = serde_json::from_value(value).expect("request is valid");

    let AuthorizationRequest::Object(req_obj) = request else {
        panic!("Invalid Authorization Request");
    };

    let request = PushedAuthorizationRequest {
        request: req_obj,
        client_assertion: None,
    };
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");
    assert_snapshot!("par:request:response", response, {
        ".request_uri" => "[request_uri]",
    });

    // check saved state
    let state =
        StateStore::get::<State>(&provider, &response.request_uri).await.expect("state exists");
    assert_snapshot!(format!("par:request:state"), state, {
        ".expires_at" => "[expires_at]",
        ".stage.expires_at" => "[expires_at]"
    });
}
