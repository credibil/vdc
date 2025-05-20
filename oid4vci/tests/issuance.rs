//! Credential Format Profile Tests

//! Pre-Authorized Code Flow Tests

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_core::blockstore::BlockStore;
use credibil_core::{OneMany, did_jwk};
use credibil_identity::{Key, SignerExt};
use credibil_jose::{JwsBuilder, Jwt, decode_jws};
use credibil_oid4vci::issuer::{
    CreateOfferRequest, Credential, CredentialHeaders, CredentialRequest, CredentialResponse,
    NonceRequest, ProofClaims, TokenGrantType, TokenRequest, W3cVcClaims,
};
use credibil_oid4vci::{self, JwtType};
use credibil_vdc::sd_jwt::SdJwtClaims;
use serde_json::json;
use sha2::{Digest, Sha256};
use test_utils::issuer::{BOB_ID, ISSUER_ID, Issuer, data};
use test_utils::wallet::Wallet;
use tokio::sync::OnceCell;

static BOB: OnceCell<Wallet> = OnceCell::const_new();
async fn bob() -> &'static Wallet {
    BOB.get_or_init(|| async { Wallet::new("vci_issuance_bob").await }).await
}

// Should allow the Wallet to provide 2 JWT proofs when requesting a credential.
#[tokio::test]
async fn two_proofs() {
    let provider = Issuer::new("vci_issuance_two_proofs").await;
    let bob = bob().await;

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
    // Bob receives the token and prepares 2 proofs for the credential request
    // --------------------------------------------------
    let nonce = credibil_oid4vci::handle(ISSUER_ID, NonceRequest, &provider)
        .await
        .expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws_1 = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");

    let dan = Wallet::new("vci_issuance_two_proofs_dan").await;
    let dan_key = dan
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws_2 = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&dan_key)
        .add_signer(&dan)
        .build()
        .await
        .expect("builds JWS");

    // --------------------------------------------------
    // Bob requests a credential with both proofs
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jws_1.encode().expect("should encode JWS"))
        .with_proof(jws_2.encode().expect("should encode JWS"))
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
    // Bob extracts and verifies the received credentials
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };

    assert_eq!(credentials.len(), 2);

    let Key::KeyId(bob_kid) = bob.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    let Key::KeyId(dan_kid) = dan.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let dan_did = dan_kid.split('#').next().expect("should have did");

    let resolver = async |kid: String| did_jwk(&kid, &provider).await;
    let dids = vec![bob_did.to_string(), dan_did.to_string()];

    for (i, credential) in credentials.iter().enumerate() {
        let Credential { credential } = credential;

        // verify the credential proof
        let token = credential.as_str().expect("should be a string");
        let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

        assert_eq!(jwt.claims.iss, ISSUER_ID);
        assert_eq!(jwt.claims.sub, dids[i]);

        let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
            panic!("should be a single credential subject");
        };
        assert_eq!(subject.id, Some(dids[i].clone()));
        assert_eq!(subject.claims.get("family_name"), Some(&json!("Person")));
    }
}

// Should issue a SD-JWT credential.
#[tokio::test]
async fn sd_jwt() {
    let provider = Issuer::new("vci_issuance_sd_jwt").await;
    let bob = bob().await;

    BlockStore::put(&provider, "owner", "ISSUER", ISSUER_ID, data::ISSUER).await.unwrap();
    BlockStore::put(&provider, "owner", "SERVER", ISSUER_ID, data::SERVER).await.unwrap();
    BlockStore::put(&provider, "owner", "SUBJECT", BOB_ID, data::NORMAL_USER).await.unwrap();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request =
        CreateOfferRequest::builder().subject_id(BOB_ID).with_credential("Identity_SD_JWT").build();
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
    // Bob receives the token and prepares 2 proofs for the credential request
    // --------------------------------------------------
    let nonce = credibil_oid4vci::handle(ISSUER_ID, NonceRequest, &provider)
        .await
        .expect("should return nonce");

    // proof of possession of key material
    let bob_key = bob
        .verification_method()
        .await
        .expect("should have key")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER_ID).nonce(&nonce.c_nonce))
        .key_ref(&bob_key)
        .add_signer(bob)
        .build()
        .await
        .expect("builds JWS");

    // --------------------------------------------------
    // Bob requests a credential with both proofs
    // --------------------------------------------------
    let details = &token.authorization_details.as_ref().expect("should have authorization details");
    let request = CredentialRequest::builder()
        .credential_identifier(&details[0].credential_identifiers[0])
        .with_proof(jws.encode().expect("should encode JWS"))
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
    // Bob extracts and verifies the received credentials
    // --------------------------------------------------
    let CredentialResponse::Credentials { credentials, .. } = &*response else {
        panic!("expected single credential");
    };

    assert_eq!(credentials.len(), 1);
    let Credential { credential } = &credentials[0];

    // verify the credential proof
    let sd_jwt = credential.as_str().expect("should be a string");
    let parts = sd_jwt.split_once('~').expect("should split");

    let token = parts.0;
    let resolver = async |kid: String| did_jwk(&kid, &provider).await;
    let jwt: Jwt<SdJwtClaims> = decode_jws(token, resolver).await.expect("should decode");

    // verify the credential
    let Key::KeyId(bob_kid) = bob.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let bob_did = bob_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.header.typ, "dc+sd-jwt");
    assert_eq!(jwt.claims.iss, ISSUER_ID);
    assert_eq!(jwt.claims.vct, "Identity_SD_JWT");
    assert_eq!(jwt.claims.sub, Some(bob_did.to_string()));

    // verify disclosures
    let disclosures = parts.1.split('~').collect::<Vec<&str>>();
    for d in &disclosures {
        let sd_hash = Base64UrlUnpadded::encode_string(Sha256::digest(d).as_slice());
        assert!(jwt.claims.sd.contains(&sd_hash), "disclosure not found");
    }
}
