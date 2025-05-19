//! Tests for the verifier metadata endpoint.

mod utils;

// use providers::wallet_provider::holder_provider::CLIENT_ID;
use credibil_openid::oid4vp::endpoint;
use credibil_openid::oid4vp::types::IssuerRequest;
use insta::assert_yaml_snapshot as assert_snapshot;

#[tokio::test]
async fn metadata_ok() {
    utils::init_tracer();
    let provider = test_verifier::ProviderImpl::new();

    let request = IssuerRequest {
        client_id: "http://localhost:8080".to_string(),
    };
    let response = endpoint::handle("http://localhost:8080", request, &provider).await.expect("ok");
    assert_snapshot!("response", response, {
        ".vp_format_supported" => insta::sorted_redaction()
    });
}
