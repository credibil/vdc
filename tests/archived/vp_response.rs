//! Tests for the `response` endpoint

mod utils;

use std::sync::LazyLock;

use chrono::Utc;
use credibil_vc::core::Kind;
use credibil_vc::dif_exch::PresentationDefinition;
use credibil_vc::oid4vp::endpoint;
use credibil_vc::oid4vp::provider::StateStore;
use credibil_vc::oid4vp::state::{Expire, State};
use credibil_vc::oid4vp::types::{
    ClientIdScheme, RequestObject, ResponseRequest, ResponseType, Verifier,
};
use serde_json::{Value, json};

const CLIENT_ID: &str = "http://credibil.io";

#[tokio::test]
async fn send_response() {
    utils::init_tracer();
    let provider = test_verifier::ProviderImpl::new();

    let pres_def = serde_json::from_value::<PresentationDefinition>(DEFINITION.to_owned())
        .expect("definition to deserialize");
    let state_key = "1234ABCD".to_string();
    let nonce = "ABCDEFG".to_string();

    let req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        client_id: CLIENT_ID.to_string(),
        redirect_uri: None,
        scope: None,
        state: Some(state_key.clone()),
        nonce: nonce.clone(),
        response_mode: Some("direct_post.jwt".to_string()),
        response_uri: Some(format!("{CLIENT_ID}/direct_post.jwt")),
        presentation_definition: Kind::Object(pres_def.clone()),
        client_id_scheme: Some(ClientIdScheme::Did),
        client_metadata: Verifier::default(),
    };

    // set up state
    let state = State {
        expires_at: Utc::now() + Expire::Request.duration(),
        request_object: req_obj,
    };
    StateStore::put(&provider, &state_key, &state, state.expires_at).await.expect("state exists");

    // replace placeholders with actual values
    let mut vp_token = VP_TOKEN.to_owned();
    let mut submission = SUBMISSION.to_owned();

    // replace placeholders with actual values
    *vp_token.get_mut(0).unwrap().get_mut("proof").unwrap().get_mut("challenge").unwrap() =
        json!(nonce);
    *submission.get_mut("definition_id").unwrap() = json!(pres_def.id);

    let body = json!({
        "vp_token":  vp_token,
        "presentation_submission": submission,
        "state": state_key,
    });

    let request = serde_json::from_value::<ResponseRequest>(body).expect("should deserialize");
    let response = endpoint::handle("http://localhost:8080", request, &provider).await.expect("ok");

    let redirect = response.redirect_uri.as_ref().expect("has redirect_uri");
    assert_eq!(redirect, "http://localhost:3000/cb");
}

static DEFINITION: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "id": "2d1691c1-2daa-4416-9d10-bc6790e72fad",
        "input_descriptors": [
            {
                "id": "EmployeeIDCredential",
                "constraints":  {
                    "fields": [ {
                        "path": ["$.type"],
                        "filter": {
                            "type": "string",
                            "const": "EmployeeIDCredential"
                        }
                    }],
                }
            }
        ],
        "format": {
            "jwt_vc":  {
                "alg": ["EdDSA"],
            }
        }
    })
});

static VP_TOKEN: LazyLock<Value> = LazyLock::new(|| {
    json!([{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "proof": {
            "challenge": "<replace me!>",
        },
        "type": [
            "VerifiablePresentation",
            "EmployeeIDPresentation"
        ],
        "verifiableCredential": [
            "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCIsImtpZCI6ImRpZDp3ZWI6ZGVtby5jcmVkaWJpbC5pbyNrZXktMCJ9.eyJzdWIiOiJkaWQ6a2V5Ono2TWtqOEpyMXJnM1lqVldXaGc3YWhFWUppYnFoakJnWnQxcERDYlQ0THY3RDRIWCIsIm5iZiI6MTcyMTcwMjg5MSwiaXNzIjoiaHR0cDovL3ZlcmNyZS5pbyIsImlhdCI6MTcyMTcwMjg5MSwianRpIjoiaHR0cDovL3ZlcmNyZS5pby9jcmVkZW50aWFscy9FbXBsb3llZUlEQ3JlZGVudGlhbCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cDovL3ZlcmNyZS5pby9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly92ZXJjcmUuaW8vY3JlZGVudGlhbHMvRW1wbG95ZWVJRENyZWRlbnRpYWwiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRW1wbG95ZWVJRENyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cDovL3ZlcmNyZS5pbyIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDctMjNUMDI6NDg6MTEuMjgyOTg5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rajhKcjFyZzNZalZXV2hnN2FoRVlKaWJxaGpCZ1p0MXBEQ2JUNEx2N0Q0SFgiLCJmYW1pbHlOYW1lIjoiUGVyc29uIiwiZ2l2ZW5OYW1lIjoiTm9ybWFsIn19fQ.HQHedefAHp1PM3lKugM7nQ-ogzV1Qs4eO0QvMP5vfSVb0wT1GJ425-j_zUSSPkhAslSC4aeNosnS_3dRet7wAQ"
        ]
    }])
});
static SUBMISSION: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "id": "fcc96706-b20f-4aa7-b34d-c1f0b630c8cb",
        "definition_id": "<replace me!>",
        "descriptor_map": [
            {
                "id": "EmployeeIDCredential",
                "format": "jwt_vc_json",
                "path": "$",
                "path_nested": {
                    "format": "jwt_vc_json",
                    "path": "$.verifiableCredential[0]"
                }
            },
            {
                "id": "CitizenshipCredential",
                "format": "jwt_vc_json",
                "path": "$",
                "path_nested": {
                    "format": "jwt_vc_json",
                    "path": "$.verifiableCredential[0]"
                }
            }
        ]
    })
});
