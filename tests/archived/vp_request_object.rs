//! Tests for the request object endpoint.

mod utils;

use chrono::Utc;
use credibil_infosec::jose::jws;
use credibil_vc::core::Kind;
use credibil_vc::dif_exch::PresentationDefinition;
use credibil_vc::oid4vp::endpoint;
use credibil_vc::oid4vp::provider::StateStore;
use credibil_vc::oid4vp::state::{Expire, State};
use credibil_vc::oid4vp::types::{
    ClientIdScheme, RequestObject, RequestObjectRequest, RequestObjectType, ResponseType, Verifier,
};
use credibil_vc::verify_key;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_verifier::VERIFIER_ID;

#[tokio::test]
async fn request_jwt() {
    utils::init_tracer();
    let provider = test_verifier::ProviderImpl::new();

    let state_key = "ABCDEF123456";
    let nonce = "1234567890";

    let req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        client_id: format!("{VERIFIER_ID}/post"),
        state: Some(state_key.to_string()),
        nonce: nonce.to_string(),
        response_mode: Some("direct_post".to_string()),
        response_uri: Some(format!("{VERIFIER_ID}/post")),
        presentation_definition: Kind::Object(PresentationDefinition::default()),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        client_metadata: Verifier::default(),

        // TODO: populate missing RequestObject attributes
        redirect_uri: None,
        scope: None,
    };

    let state = State {
        expires_at: Utc::now() + Expire::Request.duration(),
        request_object: req_obj,
    };
    StateStore::put(&provider, &state_key, &state, state.expires_at).await.expect("state exists");

    let request = RequestObjectRequest {
        client_id: VERIFIER_ID.to_string(),
        id: state_key.to_string(),
    };
    let response = endpoint::handle("http://localhost:8080", request, &provider).await.expect("ok");

    let RequestObjectType::Jwt(jwt_enc) = &response.request_object else {
        panic!("no JWT found in response");
    };

    let jwt: jws::Jwt<RequestObject> =
        jws::decode(&jwt_enc, verify_key!(&provider)).await.expect("jwt is valid");
    assert_snapshot!("response", jwt);

    // request state should not exist
    assert!(StateStore::get::<State>(&provider, state_key).await.is_ok());
}
