//! Tests for the metadata endpoint.

mod utils;

use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::types::MetadataRequest;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_issuer::CREDENTIAL_ISSUER;

#[tokio::test]
async fn metadata_ok() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let request = MetadataRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        languages: None,
    };
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is ok");
    assert_snapshot!("metadata:metadata_ok:response", response, {
        ".scopes_supported" => insta::sorted_redaction(),
        ".credential_configurations_supported" => insta::sorted_redaction(),
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
        ".**[\"org.iso.18013.5.1.mDL\"].claims" => insta::sorted_redaction(),
        ".**[\"org.iso.18013.5.1.mDL\"].claims[\"org.iso.18013.5.1\"]" => insta::sorted_redaction()
    });
}
