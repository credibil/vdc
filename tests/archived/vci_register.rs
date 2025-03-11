//! Tests for the `register` endpoint.

mod utils;

use chrono::Utc;
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::{Expire, Stage, State, Token};
use credibil_vc::oid4vci::types::RegistrationRequest;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER};

#[tokio::test]
async fn registration_ok() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let access_token = "ABCDEF";

    // set up state
    let mut state = State {
        expires_at: Utc::now() + Expire::Authorized.duration(),
        ..State::default()
    };

    state.stage = Stage::Validated(Token {
        access_token: access_token.to_string(),
        ..Token::default()
    });

    StateStore::put(&provider, access_token, &state, state.expires_at).await.expect("state saved");

    let body = json!({
        "client_id": CLIENT_ID,
        "redirect_uris": [
            "http://localhost:3000/callback"
        ],
        "grant_types": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ],
        "response_types": [
            "code"
        ],
        "scope": "openid credential",
        "credential_offer_endpoint": "openid-credential-offer://"
    });

    let mut request =
        serde_json::from_value::<RegistrationRequest>(body).expect("request should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();
    request.access_token = access_token.to_string();

    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is ok");
    assert_snapshot!("register:registration_ok:response", response, {
        ".client_id" => "[client_id]",
    });
}
