#![allow(dead_code)]
#![allow(missing_docs)]

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use credibil_infosec::jose::JwsBuilder;
use credibil_vc::oid4vci::proof::{self, Payload, Type, Verify};
use credibil_vc::oid4vci::types::{
    AuthorizationRequest, AuthorizationResponse, Credential, CredentialOfferRequest,
    CredentialRequest, DeferredCredentialRequest, DeferredCredentialResponse, Format, OfferType,
    ProofClaims, ResponseType, TokenGrantType, TokenRequest, TokenResponse,
};
use credibil_vc::oid4vci::{Error, Result, endpoint};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, ProviderImpl};

pub const CODE_VERIFIER: &str = "ABCDEF12345";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";

#[derive(Default)]
pub struct Wallet {
    pub provider: ProviderImpl,
    pub format: Format,
    pub tx_code: Option<String>,
}

impl Wallet {
    pub async fn self_initiated(&self) -> Result<()> {
        let auth = self.authorize(None).await?;

        let grant_type = TokenGrantType::AuthorizationCode {
            code: auth.code,
            code_verifier: Some(CODE_VERIFIER.to_string()),
            redirect_uri: Some(REDIRECT_URI.into()),
        };

        let token = self.token(grant_type).await?;
        self.credential(token).await
    }

    pub async fn issuer_initiated(&self, offer_type: OfferType) -> Result<()> {
        let offer = match offer_type {
            OfferType::Object(offer) => offer,
            OfferType::Uri(uri) => {
                let path = format!("{CREDENTIAL_ISSUER}/credential_offer/");
                let Some(id) = uri.strip_prefix(&path) else {
                    panic!("should have prefix");
                };
                let request = CredentialOfferRequest {
                    credential_issuer: CREDENTIAL_ISSUER.into(),
                    id: id.to_string(),
                };

                let offer_resp =
                    endpoint::handle(CREDENTIAL_ISSUER, request, &self.provider).await?;
                offer_resp.credential_offer
            }
        };

        let grants = offer.grants.unwrap_or_default();

        let grant_type = if let Some(grant) = grants.pre_authorized_code {
            TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: grant.pre_authorized_code,
                tx_code: self.tx_code.clone(),
            }
        } else {
            let issuer_state =
                if let Some(grant) = grants.authorization_code { grant.issuer_state } else { None };
            let auth = self.authorize(issuer_state).await?;

            TokenGrantType::AuthorizationCode {
                code: auth.code,
                redirect_uri: Some(auth.redirect_uri),
                code_verifier: Some(CODE_VERIFIER.to_string()),
            }
        };

        let token = self.token(grant_type).await?;
        self.credential(token).await
    }

    // Simulate Issuer request to '/create_offer' endpoint to get credential offer
    // to use to make credential offer to Wallet.
    pub async fn authorize(&self, state: Option<String>) -> Result<AuthorizationResponse> {
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": state.unwrap_or("1234".to_string()),
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ],
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "email": {}
                    }
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        });
        // let request = serde_json::from_value(value).expect("request is valid");
        // oid4vci::authorize(self.provider.clone(), request).await

        let request: AuthorizationRequest =
            serde_json::from_value(value).expect("should deserialize");

        endpoint::handle(CREDENTIAL_ISSUER, request, &self.provider).await
    }

    async fn token(&self, grant_type: TokenGrantType) -> Result<TokenResponse> {
        let token_req = TokenRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            client_id: Some(CLIENT_ID.into()),
            grant_type,
            ..TokenRequest::default()
        };
        endpoint::handle(CREDENTIAL_ISSUER, token_req, &self.provider).await
    }

    async fn credential(&self, token_resp: TokenResponse) -> Result<()> {
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some("token_resp.c_nonce".to_string()),
        };
        let jws = JwsBuilder::new()
            .jwt_type(Type::Openid4VciProofJwt)
            .payload(claims)
            .add_signer(&test_holder::ProviderImpl)
            .build()
            .await
            .map_err(|e| server!("{e}"))?;
        let jwt = jws.encode().map_err(|e| server!("{e}"))?;

        // FIXME: two paths: credential_identifier or format/type
        let Some(auth_dets) = &token_resp.authorization_details else {
            panic!("authorization_details should be set");
        };

        // FIXME: loop through all credential identifiers
        let credential_identifier = &auth_dets[0].credential_identifiers[0];
        let access_token = &token_resp.access_token;

        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
            "credential_identifier": credential_identifier,
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request: CredentialRequest = serde_json::from_value(value).expect("request is valid");
        let mut response = endpoint::handle(CREDENTIAL_ISSUER, request, &self.provider).await?;

        // fetch credential if response is deferred
        if let ResponseType::TransactionId { transaction_id } = &response.response {
            let deferred_resp = self.deferred(token_resp.clone(), transaction_id.clone()).await?;
            response = deferred_resp.credential_response;
        }

        let ResponseType::Credentials { credentials, .. } = &response.response else {
            panic!("expected single credential");
        };
        let Credential { credential } = credentials.first().expect("should have credential");

        // TODO: verify signature

        // verify the credential is as expected
        let Ok(Payload::Vc { vc, .. }) =
            proof::verify(Verify::Vc(credential), self.provider.clone()).await
        else {
            panic!("should be VC");
        };

        assert_snapshot!("credential", vc, {
            ".validFrom" => "[validFrom]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // TODO: verify format is the one specified in request

        Ok(())
    }

    async fn deferred(
        &self, tkn_resp: TokenResponse, transaction_id: String,
    ) -> Result<DeferredCredentialResponse> {
        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: tkn_resp.access_token,
            transaction_id,
        };
        endpoint::handle(CREDENTIAL_ISSUER, request, &self.provider).await
    }
}
