//! Tests for the `credential` endpoint.

mod utils;

use assert_let_bind::assert_let;
use chrono::Utc;
use credibil_infosec::jose::jws::JwsBuilder;
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::{Expire, Stage, State, Token};
use credibil_vc::oid4vci::types::{
    AuthorizationCredential, AuthorizationDetail, AuthorizedDetail, Credential, CredentialRequest,
    ProofClaims, ResponseType,
};
use credibil_vc::w3c_vc::proof::{self, Payload, Type, Verify};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn identifier() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let access_token = "ABCDEF";
    let c_nonce = "1234ABCD";

    // set up state
    let state = State {
        stage: Stage::Validated(Token {
            access_token: access_token.into(),
            details: vec![AuthorizedDetail {
                authorization_detail: AuthorizationDetail {
                    credential: AuthorizationCredential::ConfigurationId {
                        credential_configuration_id: "EmployeeID_JWT".to_string(),
                    },
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".to_string()],
            }],
        }),
        subject_id: Some(NORMAL_USER.into()),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };

    StateStore::put(&provider, access_token, &state, state.expires_at).await.expect("state exists");

    let claims = ProofClaims {
        iss: Some(CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.into(),
        iat: Utc::now().timestamp(),
        nonce: Some(c_nonce.into()),
    };
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(claims)
        .add_signer(&test_holder::ProviderImpl)
        .build()
        .await
        .expect("jws should build");
    let jwt = jws.encode().expect("should encode");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": access_token,
        "credential_identifier": "PHLEmployeeID",
        "proof":{
            "proof_type": "jwt",
            "jwt": jwt
        }
    });
    let request: CredentialRequest = serde_json::from_value(value).expect("request is valid");

    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");
    assert_snapshot!("credential:identifier:response", &response, {
        ".credential" => "[credential]",
        ".c_nonce" => "[c_nonce]",
        ".notification_id" => "[notification_id]",
    });

    // verify credential
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected a single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    let Payload::Vc { vc, .. } =
        proof::verify(Verify::Vc(&credential), provider.clone()).await.expect("should decode")
    else {
        panic!("should be VC");
    };

    assert_snapshot!("credential:identifier:vc", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction(),
        ".credentialSubject.address" => insta::sorted_redaction()
    });

    // token state should remain unchanged
    assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
    assert_snapshot!("credential:identifier:state", state, {
        ".expires_at" => "[expires_at]",
        ".stage.c_nonce"=>"[c_nonce]",
        ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
    });
}

#[tokio::test]
#[ignore]
async fn format() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let access_token = "ABCDEF";
    let c_nonce = "1234ABCD";

    // set up state
    let state = State {
        stage: Stage::Validated(Token {
            access_token: access_token.into(),
            details: vec![AuthorizedDetail {
                authorization_detail: AuthorizationDetail {
                    credential: AuthorizationCredential::ConfigurationId {
                        credential_configuration_id: "EmployeeID_JWT".to_string(),
                    },
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".to_string()],
            }],
        }),
        subject_id: Some(NORMAL_USER.into()),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };

    StateStore::put(&provider, access_token, &state, state.expires_at).await.expect("state saved");

    // create CredentialRequest to 'send' to the app
    let claims = ProofClaims {
        iss: Some(CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.into(),
        iat: Utc::now().timestamp(),
        nonce: Some(c_nonce.into()),
    };
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(claims)
        .add_signer(&test_holder::ProviderImpl)
        .build()
        .await
        .expect("jws should build");
    let jwt = jws.encode().expect("should encode");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": access_token,
        "format": "jwt_vc_json",
        "credential_definition": {
            "type": [
                "VerifiableCredential",
                "EmployeeIDCredential"
            ]
        },
        "proof":{
            "proof_type": "jwt",
            "jwt": jwt
        }
    });
    let request: CredentialRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");

    assert_snapshot!("credential:format:response", &response, {
        ".credential" => "[credential]",
        ".c_nonce" => "[c_nonce]",
    });

    // verify credential
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected a single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    let Payload::Vc { vc, .. } =
        credibil_vc::w3c_vc::proof::verify(Verify::Vc(&credential), provider.clone())
            .await
            .expect("should decode")
    else {
        panic!("should be VC");
    };

    assert_snapshot!("vc", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction()
    });

    // token state should remain unchanged
    assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
    assert_snapshot!("credential:format:state", state, {
        ".expires_at" => "[expires_at]",
        ".stage.c_nonce"=>"[c_nonce]",
        ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
    });
}

#[tokio::test]
#[ignore]
async fn iso_mdl() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let access_token = "ABCDEF";
    let c_nonce = "1234ABCD";

    // set up state
    let state = State {
        stage: Stage::Validated(Token {
            access_token: access_token.into(),
            details: vec![AuthorizedDetail {
                authorization_detail: AuthorizationDetail {
                    credential: AuthorizationCredential::ConfigurationId {
                        credential_configuration_id: "org.iso.18013.5.1.mDL".to_string(),
                    },
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["DriverLicence".to_string()],
            }],
        }),
        subject_id: Some(NORMAL_USER.into()),
        expires_at: Utc::now() + Expire::Authorized.duration(),
    };

    StateStore::put(&provider, access_token, &state, state.expires_at).await.expect("state exists");

    let claims = ProofClaims {
        iss: Some(CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.into(),
        iat: Utc::now().timestamp(),
        nonce: Some(c_nonce.into()),
    };
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(claims)
        .add_signer(&test_holder::ProviderImpl)
        .build()
        .await
        .expect("jws should build");
    let jwt = jws.encode().expect("should encode");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": access_token,
        "credential_identifier": "DriverLicence",
        "proof":{
            "proof_type": "jwt",
            "jwt": jwt
        }
    });

    let request: CredentialRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("response is valid");
    assert_snapshot!("credential:iso_mdl:response", &response, {
        ".credential" => "[credential]",
        ".c_nonce" => "[c_nonce]",
        ".notification_id" => "[notification_id]",
    });

    // verify credential
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected a single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    let Payload::Vc { vc, .. } =
        proof::verify(Verify::Vc(&credential), provider.clone()).await.expect("should decode")
    else {
        panic!("should be VC");
    };

    assert_snapshot!("credential:iso_mdl:vc", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction(),
        ".credentialSubject.address" => insta::sorted_redaction()
    });

    // token state should remain unchanged
    assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
    assert_snapshot!("credential:iso_mdl:state", state, {
        ".expires_at" => "[expires_at]",
        ".stage.c_nonce"=>"[c_nonce]",
        ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
    });
}
