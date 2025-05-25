//! Deferred Issuance Tests

use std::collections::HashMap;

use credibil_oid4vci::blockstore::BlockStore;
use credibil_oid4vci::identity::{Key, SignerExt};
use credibil_oid4vci::jose::{JwsBuilder, Jwt, decode_jws};
use credibil_oid4vci::proof::W3cVcClaims;
use credibil_oid4vci::types::{
    CreateOfferRequest, Credential, CredentialRequest, CredentialResponse, Dataset,
    DeferredCredentialRequest, NonceRequest, ProofClaims, TokenGrantType, TokenRequest,
};
use credibil_oid4vci::{CredentialHeaders, DeferredHeaders, JwtType, OneMany, did_jwk};
use serde_json::json;
use test_utils::issuer::{CAROL_ID, ISSUER_ID, Issuer, data};
use test_utils::wallet::Wallet;
use tokio::sync::OnceCell;

static CAROL: OnceCell<Wallet> = OnceCell::const_new();
async fn carol() -> &'static Wallet {
    CAROL.get_or_init(|| async { Wallet::new("https://deferred.io/carol").await }).await
}

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by value.
#[tokio::test]
async fn deferred() {
    let provider = Issuer::new("https://deferred.io/deferred").await;
    let carol = carol().await;

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", CAROL_ID, data::PENDING_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(CAROL_ID)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response =
        credibil_oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
        credibil_oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce = credibil_oid4vci::handle(ISSUER_ID, NonceRequest, &provider)
        .await
        .expect("should return nonce");

    // proof of possession of key material
    let key = carol
        .verification_method()
        .await
        .expect("should have did")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&key)
        .add_signer(carol)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests a credential and receives a deferred response
    // --------------------------------------------------
    let details = token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();

    let request = credibil_oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };

    let response = credibil_oid4vci::handle(ISSUER_ID, request, &provider)
        .await
        .expect("should return credential");

    // --------------------------------------------------
    // Alice approves issuance of the credential
    // HACK: update subject's pending state
    // --------------------------------------------------
    let credential_identifier = &details[0].credential_identifiers[0];
    let mut subject: HashMap<String, Dataset> = serde_json::from_slice(data::PENDING_USER).unwrap();
    let mut credential: Dataset = subject.get(credential_identifier).unwrap().clone();
    credential.pending = false;

    subject.insert(credential_identifier.to_string(), credential);
    let data = serde_json::to_vec(&subject).unwrap();

    BlockStore::delete(&provider, "owner", "SUBJECT", CAROL_ID).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", CAROL_ID, &data).await.unwrap();

    // --------------------------------------------------
    // After a brief wait Bob retrieves the credential
    // --------------------------------------------------
    let CredentialResponse::TransactionId { transaction_id } = &*response else {
        panic!("expected transaction_id");
    };

    let request = credibil_oid4vci::Request {
        body: DeferredCredentialRequest {
            transaction_id: transaction_id.clone(),
        },
        headers: DeferredHeaders {
            authorization: token.access_token.clone(),
        },
    };
    let response = credibil_oid4vci::handle(ISSUER_ID, request, &provider)
        .await
        .expect("should return credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };

    let Credential { credential } = credentials.first().expect("should have credential");

    // verify the credential proof
    let token = credential.as_str().expect("should be a string");
    let resolver = async |kid: String| did_jwk(&kid, &provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    // verify the credential
    let Key::KeyId(carol_kid) = carol.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let carol_did = carol_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER_ID);
    assert_eq!(jwt.claims.sub, carol_did);

    let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
        panic!("should be a single credential subject");
    };
    assert_eq!(subject.id, Some(carol_did.to_string()));
    assert_eq!(subject.claims.get("family_name"), Some(&json!("Person")));
}
