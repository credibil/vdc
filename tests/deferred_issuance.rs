//! Deferred Issuance Tests

mod utils;

use std::sync::LazyLock;

use credibil_infosec::jose::JwsBuilder;
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::proof::{self, Payload, Type, Verify};
use credibil_vc::oid4vci::types::{
    CreateOfferRequest, Credential, CredentialHeaders, CredentialRequest,
    DeferredCredentialRequest, DeferredHeaders, NonceRequest, ProofClaims, ResponseType,
    TokenGrantType, TokenRequest,
};
use insta::assert_yaml_snapshot as assert_snapshot;
use utils::issuer::{CREDENTIAL_ISSUER as ALICE_ISSUER, PENDING_USER, ProviderImpl};
use utils::wallet::{self, Keyring};

static BOB_KEYRING: LazyLock<Keyring> = LazyLock::new(wallet::keyring);

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by value.
#[tokio::test]
async fn deferred() {
    let provider = ProviderImpl::new();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(PENDING_USER)
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
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce =
        endpoint::handle(ALICE_ISSUER, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(ProofClaims::new().credential_issuer(ALICE_ISSUER).nonce(nonce.c_nonce))
        .add_signer(&*BOB_KEYRING)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests a credential and receives a deferred response
    // --------------------------------------------------
    let details = &token.authorization_details.expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();

    let request = endpoint::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };

    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return credential");

    // --------------------------------------------------
    // Bob waits for a brief period and then retrieves the credential
    // --------------------------------------------------
    let ResponseType::TransactionId { transaction_id } = &response.response else {
        panic!("expected transaction_id");
    };

    let request = endpoint::Request {
        body: DeferredCredentialRequest {
            transaction_id: transaction_id.clone(),
        },
        headers: DeferredHeaders {
            authorization: token.access_token.clone(),
        },
    };
    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected single credential");
    };

    let Credential { credential } = credentials.first().expect("should have credential");

    // verify the credential proof
    let Ok(Payload::Vc { vc, .. }) = proof::verify(Verify::Vc(credential), provider.clone()).await
    else {
        panic!("should be valid VC");
    };

    assert_snapshot!("issued", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction(),
        ".credentialSubject.id" => "[id]"
    });
}
