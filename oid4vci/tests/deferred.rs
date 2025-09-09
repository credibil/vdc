//! Deferred Issuance Tests

use credibil_binding::resolve_jwk;
use credibil_oid4vci::api::Client;
use credibil_oid4vci::identity::{Signature, VerifyBy};
use credibil_oid4vci::jose::{JwsBuilder, Jwt, decode_jws};
use credibil_oid4vci::proof::W3cVcClaims;
use credibil_oid4vci::types::{
    CreateOfferRequest, Credential, CredentialRequest, CredentialResponse, Dataset,
    DeferredCredentialRequest, NonceRequest, ProofClaims, TokenGrantType, TokenRequest,
};
use credibil_oid4vci::{CredentialHeaders, DeferredHeaders, JwtType, OneMany};
use serde_json::json;
use test_utils::{Datastore, Issuer, Wallet};
use tokio::sync::OnceCell;

static CLIENT: OnceCell<Client<Issuer>> = OnceCell::const_new();
static BOB: OnceCell<Wallet> = OnceCell::const_new();

async fn client() -> &'static Client<Issuer<'static>> {
    CLIENT
        .get_or_init(|| async {
            Client::new(Issuer::new(ISSUER).await.expect("should create issuer"))
        })
        .await
}
async fn bob() -> &'static Wallet<'static> {
    BOB.get_or_init(|| async {
        Wallet::new("https://deferred.io/bob").await.expect("should create wallet")
    })
    .await
}
const BOB_SUBJECT: &str = "bob";
const ISSUER: &str = "http://localhost:8080";

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the Wallet is made by value.
#[tokio::test]
async fn deferred() {
    let client = client().await; // Client::new(Issuer::new(ISSUER).await);
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequest::builder()
        .subject(BOB_SUBJECT)
        .with_credential("EmployeeID_W3C_VC")
        .build();
    let response = client.request(request).owner(ISSUER).await.expect("should create offer");

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
    let token = client.request(request).owner(ISSUER).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and prepares a proof for a credential request
    // --------------------------------------------------
    let nonce = client.request(NonceRequest).owner(ISSUER).await.expect("should return nonce");

    // proof of possession of key material
    let key = bob
        .verification_method()
        .await
        .expect("should have did")
        .try_into()
        .expect("should map key to key binding");

    let jws = JwsBuilder::new()
        .typ(JwtType::ProofJwt)
        .payload(ProofClaims::new().credential_issuer(ISSUER).nonce(&nonce.c_nonce))
        .key_binding(&key)
        .add_signer(bob)
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

    let response = client
        .request(request)
        .owner(ISSUER)
        .headers(CredentialHeaders { authorization: token.access_token.clone() })
        .await
        .expect("should return credential");

    // --------------------------------------------------
    // Alice approves issuance of the credential
    // HACK: update subject's pending state
    // --------------------------------------------------
    let credential_identifier = &details[0].credential_identifiers[0];

    let data = Datastore::get(ISSUER, "subject", BOB_SUBJECT).await.unwrap().unwrap();
    let mut subject: Vec<Dataset> = serde_json::from_slice(&data).unwrap();

    let dataset = subject
        .iter_mut()
        .find(|ds| &ds.credential_identifier == credential_identifier)
        .expect("should find dataset");
    dataset.pending = false;

    let data = serde_json::to_vec(&subject).unwrap();
    Datastore::put(ISSUER, "subject", BOB_SUBJECT, &data).await.unwrap();

    // --------------------------------------------------
    // After a brief wait Bob retrieves the credential
    // --------------------------------------------------
    let CredentialResponse::TransactionId { transaction_id } = &*response else {
        panic!("expected transaction_id");
    };

    let request = DeferredCredentialRequest { transaction_id: transaction_id.clone() };
    let headers = DeferredHeaders { authorization: token.access_token.clone() };
    let response = client
        .request(request)
        .owner(ISSUER)
        .headers(headers)
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
    let resolver = async |kid: String| resolve_jwk(&kid, &client.provider).await;
    let jwt: Jwt<W3cVcClaims> = decode_jws(token, resolver).await.expect("should decode");

    // verify the credential
    let VerifyBy::KeyId(carol_kid) = bob.verification_method().await.unwrap() else {
        panic!("should have did");
    };
    let carol_did = carol_kid.split('#').next().expect("should have did");

    assert_eq!(jwt.claims.iss, ISSUER);
    assert_eq!(jwt.claims.sub, carol_did);

    let OneMany::One(subject) = jwt.claims.vc.credential_subject else {
        panic!("should be a single credential subject");
    };
    assert_eq!(subject.id, Some(carol_did.to_string()));
    assert_eq!(subject.claims.get("family_name"), Some(&json!("User")));
}
