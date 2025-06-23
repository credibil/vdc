//! Pre-Authorized Code Flow Tests

use std::collections::HashMap;

use credibil_oid4vci::identity::{Signature, VerifyBy};
use credibil_oid4vci::jose::{JwsBuilder, Jwt, decode_jws};
use credibil_oid4vci::proof::W3cVcClaims;
use credibil_oid4vci::types::{
    AuthorizationDetail, CreateOfferRequest, Credential, CredentialOfferRequest, CredentialRequest,
    CredentialResponse, NonceRequest, NotificationEvent, NotificationRequest, ProofClaims,
    TokenGrantType, TokenRequest,
};
use credibil_oid4vci::{Client, CredentialHeaders, JwtType, NotificationHeaders, OneMany};
use credibil_proof::resolve_jwk;
use serde_json::json;
use test_utils::issuer::Issuer;
use test_utils::wallet::Wallet;
use tokio::sync::OnceCell;

const ISSUER: &str = "http://localhost:8080";
const BOB_SUBJECT: &str = "normal_user";

static CLIENT: OnceCell<Client<Issuer>> = OnceCell::const_new();
async fn client() -> &'static Client<Issuer> {
    CLIENT.get_or_init(|| async { Client::new(ISSUER, Issuer::new(ISSUER).await) }).await
}
static BOB: OnceCell<Wallet> = OnceCell::const_new();
async fn bob() -> &'static Wallet {
    BOB.get_or_init(|| async { Wallet::new("https://pre_auth.io/bob").await }).await
}

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by value.
#[tokio::test]
async fn offer_val() {
    let client = client().await; // Client::new(ISSUER, Issuer::new(ISSUER).await);
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response = client.request(request).execute().await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .build();
    let token = client.request(request).execute().await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce = client.request(NonceRequest).execute().await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests a credential
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();

    let headers = CredentialHeaders {
        authorization: token.access_token.clone(),
    };
    let response =
        client.request(request).headers(headers).execute().await.expect("should get credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    let token = credential.as_str().expect("should be a string");
    let resolver = async |kid: String| resolve_jwk(&kid, &client.provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    let VerifyBy::KeyId(bob_kid) = bob.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER);
    assert_eq!(jwt.claims.sub, bob_did.to_string());

    let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
        panic!("should be a single credential subject");
    };
    assert_eq!(subject.id, Some(bob_did.to_string()));
    assert_eq!(subject.claims.get("family_name"), Some(&json!("Person")));
}

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by reference.
#[tokio::test]
async fn offer_ref() {
    let client = client().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("EmployeeID_W3C_VC")
        .by_ref(true)
        .build();
    let create_offer = client.request(request).execute().await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer URI and fetches the offer
    // --------------------------------------------------
    let uri = create_offer.offer_type.as_uri().expect("should have offer");
    let path = format!("{ISSUER}/credential_offer/");
    let Some(id) = uri.strip_prefix(&path) else {
        panic!("should have prefix");
    };
    let request = CredentialOfferRequest { id: id.to_string() };
    let response = client.request(request).execute().await.expect("should fetch offer");

    // validate offer
    let offer = response.0.clone();
    assert_eq!(offer.credential_configuration_ids, vec!["EmployeeID_W3C_VC".to_string()]);

    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");
    assert_eq!(grant.pre_authorized_code.len(), 43);
}

// Should return two credential datasets for a single credential
// configuration id.
#[tokio::test]
async fn two_datasets() {
    let client = client().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("Developer_W3C_VC")
        .build();
    let response = client.request(request).execute().await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .build();
    let token = client.request(request).execute().await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares 2 credential requests
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let expected = HashMap::from([
        ("OpenSourceDeveloper", vec!["A. Mazing", "Hacker"]),
        ("PHLDeveloper", vec!["A. Developer", "Lead"]),
    ]);

    for identifier in &details[0].credential_identifiers {
        let nonce = client.request(NonceRequest).execute().await.expect("should return nonce");

        // proof of possession of key material
        let bob_key = bob
            .verification_method()
            .await
            .expect("should have key")
            .try_into()
            .expect("should map key to key binding");

        let jws = JwsBuilder::new()
            .typ(JwtType::ProofJwt)
            .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
            .key_ref(&bob_key)
            .add_signer(bob)
            .build()
            .await
            .expect("builds JWS");
        let jwt = jws.encode().expect("encodes JWS");

        // --------------------------------------------------
        // Bob requests a credential
        // --------------------------------------------------
        let request =
            CredentialRequest::builder().credential_identifier(identifier).with_proof(jwt).build();
        let headers = CredentialHeaders {
            authorization: token.access_token.clone(),
        };
        let response =
            client.request(request).headers(headers).execute().await.expect("should execute");

        // --------------------------------------------------
        // Bob extracts and verifies the received credential
        // --------------------------------------------------
        let CredentialResponse::Credentials { credentials, .. } = &*response else {
            panic!("expected single credential");
        };
        let Credential { credential } = credentials.first().expect("should have credential");

        // verify the credential proof
        let token = credential.as_str().expect("should be a string");
        let resolver = async |kid: String| resolve_jwk(&kid, &client.provider).await;
        let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

        // validate the credential subject
        let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
            panic!("should have single subject");
        };
        assert_eq!(subject.claims["name"], expected[identifier.as_str()][0]);
        assert_eq!(subject.claims["role"], expected[identifier.as_str()][1]);
    }
}

// Should return a single credential when two are offered and only one is
// requested in the token request.
#[tokio::test]
async fn reduce_credentials() {
    let client = client().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob with 2 credentials
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("Developer_W3C_VC")
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response = client.request(request).execute().await.expect("should create offer");

    let offer = response.offer_type.as_object().expect("should have offer");
    assert_eq!(offer.credential_configuration_ids.len(), 2);

    // --------------------------------------------------
    // Bob receives the offer and requests a token for 1 of the offered
    // credentials
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .with_authorization_detail(
            AuthorizationDetail::builder().configuration_id("EmployeeID_W3C_VC").build(),
        )
        .build();
    let token = client.request(request).execute().await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a credential request
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    assert_eq!(details[0].credential_identifiers.len(), 1);

    let identifier = &details[0].credential_identifiers[0];
    let nonce = client.request(NonceRequest).execute().await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests the credential
    // --------------------------------------------------
    let request =
        CredentialRequest::builder().credential_identifier(identifier).with_proof(jwt).build();
    let headers = CredentialHeaders {
        authorization: token.access_token.clone(),
    };
    let response =
        client.request(request).headers(headers).execute().await.expect("should get credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    // verify the credential proof
    let token = credential.as_str().expect("should be a string");
    let resolver = async |kid: String| resolve_jwk(&kid, &client.provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    // validate the credential subject
    let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
        panic!("should have single subject");
    };
    assert_eq!(subject.claims["given_name"], "Normal");
    assert_eq!(subject.claims["family_name"], "Person");
}

// Should return fewer claims when requested in token request.
#[tokio::test]
async fn reduce_claims() {
    let client = client().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response = client.request(request).execute().await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .with_authorization_detail(
            AuthorizationDetail::builder()
                .configuration_id("EmployeeID_W3C_VC")
                .with_claim(&vec!["credentialSubject", "given_name"])
                .with_claim(&vec!["credentialSubject", "family_name"])
                .build(),
        )
        .build();
    let token = client.request(request).execute().await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce = client.request(NonceRequest).execute().await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests a credential
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();
    let headers = CredentialHeaders {
        authorization: token.access_token.clone(),
    };

    let response =
        client.request(request).headers(headers).execute().await.expect("should get credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    // verify the credential proof
    let token = credential.as_str().expect("should be a string");
    let resolver = async |kid: String| resolve_jwk(&kid, &client.provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    let VerifyBy::KeyId(bob_kid) = bob.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER);
    assert_eq!(jwt.claims.sub, bob_did.to_string());

    let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
        panic!("should be a single credential subject");
    };
    assert_eq!(subject.id, Some(bob_did.to_string()));
    assert_eq!(subject.claims.get("family_name"), Some(&json!("Person")));
    assert_eq!(subject.claims.get("email"), None);
}

// Should handle an acceptance notication from the wallet.
#[tokio::test]
async fn notify_accepted() {
    let client = client().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_SUBJECT)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response = client.request(request).execute().await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequest::builder()
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .build();
    let token = client.request(request).execute().await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce = client.request(NonceRequest).execute().await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests a credential
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jwt)
        .build();
    let headers = CredentialHeaders {
        authorization: token.access_token.clone(),
    };

    let response =
        client.request(request).headers(headers).execute().await.expect("should get credential");

    // --------------------------------------------------
    // Bob send a notication advising the credential was accepted
    // --------------------------------------------------
    let CredentialResponse::Credentials { notification_id, .. } = &*response else {
        panic!("should have notification id");
    };

    let request = NotificationRequest::builder()
        .notification_id(notification_id.as_ref().unwrap())
        .event(NotificationEvent::CredentialAccepted)
        .event_description("Credential accepted")
        .build();
    let headers = NotificationHeaders {
        authorization: token.access_token.clone(),
    };
    client.request(request).headers(headers).execute().await.expect("response is ok");
}
