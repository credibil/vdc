//! Tests for the verifier metadata endpoint.

mod utils;

// use providers::wallet_provider::holder_provider::CLIENT_ID;
use credibil_vc::oid4vp::endpoint;
use credibil_vc::oid4vp::types::MetadataRequest;
use insta::assert_yaml_snapshot as assert_snapshot;

#[tokio::test]
async fn metadata_ok() {
    utils::init_tracer();
    let provider = test_verifier::ProviderImpl::new();

    let request = MetadataRequest {
        client_id: "http://localhost:8080".to_string(),
    };
    let response = endpoint::handle("http://localhost:8080", request, &provider).await.expect("ok");
    assert_snapshot!("response", response, {
        ".vp_formats" => insta::sorted_redaction()
    });
}
