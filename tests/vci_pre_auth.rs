//! Pre-Authorized Code Flow Tests

use std::collections::HashMap;
use std::sync::LazyLock;

use credibil_identity::{Key, SignerExt};
use credibil_jose::{JwsBuilder, Jwt, decode_jws};
use credibil_vc::core::did_jwk;
use credibil_vc::oid4vci::types::{
    AuthorizationDetail, CreateOfferRequest, Credential, CredentialHeaders, CredentialOfferRequest,
    CredentialRequest, CredentialResponse, NonceRequest, NotificationEvent, NotificationHeaders,
    NotificationRequest, ProofClaims, TokenGrantType, TokenRequest, W3cVcClaims,
};
use credibil_vc::oid4vci::{self, JwtType};
use credibil_vc::{BlockStore, OneMany};
use provider::issuer::{BOB_ID, ISSUER_ID, Issuer, data};
use provider::wallet::Wallet;
use serde_json::json;

static BOB: LazyLock<Wallet> = LazyLock::new(Wallet::new);

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by value.
#[tokio::test]
async fn offer_val() {
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
    let token = oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce =
        oid4vci::handle(ISSUER_ID, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = BOB
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(&*BOB)
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

    let request = oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return credential");

    // --------------------------------------------------
    // Bob extracts and verifies the received credential
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    let token = credential.as_str().expect("should be a string");
    let resolver = async |kid: String| did_jwk(&kid, &provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    let Key::KeyId(bob_kid) = BOB.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER_ID);
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
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("EmployeeID_W3C_VC")
        .by_ref(true)
        .build();
    let create_offer =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer URI and fetches the offer
    // --------------------------------------------------
    let uri = create_offer.offer_type.as_uri().expect("should have offer");
    let path = format!("{ISSUER_ID}/credential_offer/");
    let Some(id) = uri.strip_prefix(&path) else {
        panic!("should have prefix");
    };
    let request = CredentialOfferRequest { id: id.to_string() };
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should fetch offer");

    // validate offer
    let offer = response.credential_offer.clone();
    assert_eq!(offer.credential_configuration_ids, vec!["EmployeeID_W3C_VC".to_string()]);

    let grants = offer.grants.expect("should have grant");
    let grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");
    assert_eq!(grant.pre_authorized_code.len(), 43);
}

// Should return two credential datasets for a single credential
// configuration id.
#[tokio::test]
async fn two_datasets() {
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("Developer_W3C_VC")
        .build();
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
    let token = oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares 2 credential requests
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let expected = HashMap::from([
        ("OpenSourceDeveloper", vec!["A. Mazing", "Hacker"]),
        ("PHLDeveloper", vec!["A. Developer", "Lead"]),
    ]);

    for identifier in &details[0].credential_identifiers {
        let nonce =
            oid4vci::handle(ISSUER_ID, NonceRequest, &provider).await.expect("should return nonce");

        // proof of possession of key material
        let bob_key = BOB
            .verification_method()
            .await
            .expect("should have key")
            .try_into()
            .expect("should map key to key binding");

        let jws = JwsBuilder::new()
            .typ(JwtType::ProofJwt)
            .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
            .key_ref(&bob_key)
            .add_signer(&*BOB)
            .build()
            .await
            .expect("builds JWS");
        let jwt = jws.encode().expect("encodes JWS");

        // --------------------------------------------------
        // Bob requests a credential
        // --------------------------------------------------
        let request =
            CredentialRequest::builder().credential_identifier(identifier).with_proof(jwt).build();

        let request = oid4vci::Request {
            body: request,
            headers: CredentialHeaders {
                authorization: token.access_token.clone(),
            },
        };

        let response =
            oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return credential");

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
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob with 2 credentials
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("Developer_W3C_VC")
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
        // .client_id(BOB_CLIENT)
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .with_authorization_detail(
            AuthorizationDetail::builder().configuration_id("EmployeeID_W3C_VC").build(),
        )
        .build();
    let token = oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a credential request
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    assert_eq!(details[0].credential_identifiers.len(), 1);

    let identifier = &details[0].credential_identifiers[0];

    let nonce =
        oid4vci::handle(ISSUER_ID, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = BOB
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(&*BOB)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // --------------------------------------------------
    // Bob requests the credential
    // --------------------------------------------------
    let request =
        CredentialRequest::builder().credential_identifier(identifier).with_proof(jwt).build();

    let request = oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };

    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return credential");

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
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
    let token = oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce =
        oid4vci::handle(ISSUER_ID, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = BOB
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(&*BOB)
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

    let request = oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };

    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return credential");

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

    let Key::KeyId(bob_kid) = BOB.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER_ID);
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
    let provider = Issuer::new();

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject_id(BOB_ID)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should create offer");

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
    let token = oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce =
        oid4vci::handle(ISSUER_ID, NonceRequest, &provider).await.expect("should return nonce");

    // proof of possession of key material
    let bob_key = BOB
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(&*BOB)
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

    let request = oid4vci::Request {
        body: request,
        headers: CredentialHeaders {
            authorization: token.access_token.clone(),
        },
    };

    let response =
        oid4vci::handle(ISSUER_ID, request, &provider).await.expect("should return credential");

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

    let request = oid4vci::Request {
        body: request,
        headers: NotificationHeaders {
            authorization: token.access_token.clone(),
        },
    };

    oid4vci::handle(ISSUER_ID, request, &provider).await.expect("response is ok");
}
