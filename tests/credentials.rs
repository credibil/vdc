//! Credential Format Tests

//! Pre-Authorized Code Flow Tests

mod utils;

use std::sync::LazyLock;

use credibil_infosec::jose::JwsBuilder;
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::proof::{self, Payload, Type, Verify};
use credibil_vc::oid4vci::types::{
    CreateOfferRequest, Credential, CredentialRequest, NonceRequest, ProofClaims, ResponseType,
    TokenGrantType, TokenRequest,
};
use http::header::{AUTHORIZATION, HeaderMap};
use insta::assert_yaml_snapshot as assert_snapshot;
use utils::issuer::{CREDENTIAL_ISSUER as ALICE_ISSUER, NORMAL_USER, ProviderImpl};
use utils::wallet::{self, Keyring};

static BOB_KEYRING: LazyLock<Keyring> = LazyLock::new(wallet::keyring);

// Should allow the Wallet to provide 2 JWT proofs when requesting a credential.
#[tokio::test]
async fn two_proofs() {
    let provider = ProviderImpl::new();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(NORMAL_USER)
        .with_credential("EmployeeID_JWT")
        .build();
    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let pre_auth_grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .build();
    let token =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares 2 proofs for the credential request
    // --------------------------------------------------
    let nonce =
        endpoint::handle(ALICE_ISSUER, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let jws_1 = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(ProofClaims::new().credential_issuer(ALICE_ISSUER).nonce(&nonce.c_nonce))
        .add_signer(&*BOB_KEYRING)
        .build()
        .await
        .expect("builds JWS");

    let jws_2 = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(ProofClaims::new().credential_issuer(ALICE_ISSUER).nonce(nonce.c_nonce))
        .add_signer(&wallet::keyring())
        .build()
        .await
        .expect("builds JWS");

    // --------------------------------------------------
    // Bob requests a credential with both proofs
    // --------------------------------------------------
    let details = &token.authorization_details.expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jws_1.encode().expect("should encode JWS"))
        .with_proof(jws_2.encode().expect("should encode JWS"))
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, token.access_token.parse().unwrap());
    let request = endpoint::Request {
        body: request,
        headers: Some(headers),
        headers2:None
    };

    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credentials
    // --------------------------------------------------
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected single credential");
    };

    assert_eq!(credentials.len(), 2);

    for (i, credential) in credentials.iter().enumerate() {
        let Credential { credential } = credential;

        // verify the credential proof
        let Ok(Payload::Vc { vc, .. }) =
            proof::verify(Verify::Vc(credential), provider.clone()).await
        else {
            panic!("should be valid VC");
        };

        assert_snapshot!(format!("vc_{i}"), vc, {
            ".validFrom" => "[validFrom]",
            ".credentialSubject" => insta::sorted_redaction(),
            ".credentialSubject.id" => "[id]"
        });
    }
}
