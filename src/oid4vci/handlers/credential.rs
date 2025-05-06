//! # Batch Credential Endpoint
//!
//! The Batch Credential Endpoint issues multiple Credentials in one Batch
//! Credential Response as approved by the End-User upon presentation of a valid
//! Access Token representing this approval.
//!
//! A Wallet can request issuance of multiple Credentials of certain types and
//! formats in one Batch Credential Request. This includes Credentials of the
//! same type and multiple formats, different types and one format, or both.

use std::collections::HashSet;
use std::fmt::Debug;

use anyhow::Context as _;
use chrono::Utc;
use credibil_jose::{Jwt, KeyBinding, decode_jws};

use crate::core::state::State;
use crate::core::{did_jwk, generate};
use crate::oid4vci::JwtType;
use crate::oid4vci::error::server;
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::issuer::{
    AuthorizedDetail, Credential, CredentialConfiguration, CredentialHeaders, CredentialRequest,
    CredentialResponse, Dataset, Issuer, MultipleProofs, Proof, ProofClaims, RequestBy,
    SingleProof,
};
use crate::oid4vci::provider::{Metadata, Provider, StateStore, Subject};
use crate::oid4vci::state::{Deferred, Expire, Token};
use crate::status::{StatusList, StatusStore, TokenBuilder};
use crate::vdc::FormatProfile;
use crate::vdc::mso_mdoc::MdocBuilder;
use crate::vdc::sd_jwt::SdJwtVcBuilder;
use crate::vdc::w3c_vc::W3cVcBuilder;

/// Credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
pub async fn credential(
    issuer: &str, provider: &impl Provider, request: Request<CredentialRequest, CredentialHeaders>,
) -> Result<CredentialResponse> {
    let Ok(state) = StateStore::get::<Token>(provider, &request.headers.authorization).await else {
        return Err(Error::AccessDenied("invalid access token".to_string()));
    };

    // create a request context for data accessed more than once
    let mut ctx = Context {
        state,
        issuer: Metadata::issuer(provider, issuer).await.context("fetching metadata")?,
        configuration: CredentialConfiguration::default(),
        proof_kids: vec![],
    };

    let request = request.body;
    let authorized = request.authorized_detail(&ctx)?;

    // check whether issuance should be deferred
    let dataset = ctx.dataset(provider, &request, &authorized).await?;
    if dataset.pending {
        return ctx.defer(provider, request).await;
    }

    // credential configuration
    let Some(config_id) = authorized.credential_configuration_id() else {
        return Err(Error::InvalidCredentialRequest("no credential_configuration_id".to_string()));
    };
    let Some(config) = ctx.issuer.credential_configurations_supported.get(config_id) else {
        return Err(server!("credential configuration unable to be found"));
    };

    ctx.configuration = config.clone();
    request.verify(provider, &mut ctx).await?;
    ctx.issue(provider, dataset).await
}

impl<P: Provider> Handler<P> for Request<CredentialRequest, CredentialHeaders> {
    type Error = Error;
    type Provider = P;
    type Response = CredentialResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        credential(issuer, provider, self).await
    }
}

impl Body for CredentialRequest {}

#[derive(Debug)]
struct Context {
    state: State<Token>,
    issuer: Issuer,
    configuration: CredentialConfiguration,
    proof_kids: Vec<String>,
}

impl CredentialRequest {
    // TODO: check this list for compliance
    // To validate a key proof, ensure that:
    //   - the header parameter does not contain a private key
    //   - the creation time of the JWT, as determined by either the issuance time,
    //     or a server managed timestamp via the nonce claim, is within an
    //     acceptable window (see Section 11.5).

    // Verify the credential request
    async fn verify(&self, provider: &impl Provider, ctx: &mut Context) -> Result<()> {
        tracing::debug!("credential::verify");

        if ctx.state.is_expired() {
            return Err(Error::InvalidCredentialRequest("token state expired".to_string()));
        }

        // FIXME: refactor into separate function.
        if let Some(supported_types) = &ctx.configuration.proof_types_supported {
            let Some(proof) = &self.proof else {
                return Err(Error::InvalidProof("proof not set".to_string()));
            };

            // TODO: cater for non-JWT proofs - use w3c-vc::decode method
            let _ = supported_types.get("jwt").ok_or_else(|| {
                Error::InvalidCredentialRequest("proof type not supported".to_string())
            })?;

            // extract proof JWT(s) from request
            let proof_jwts = match proof {
                Proof::Single(proof_type) => match proof_type {
                    SingleProof::Jwt { jwt } => &vec![jwt.clone()],
                    SingleProof::Attestation { .. } => todo!(),
                },
                Proof::Multiple(proofs_type) => match proofs_type {
                    MultipleProofs::Jwt(proof_jwts) => proof_jwts,
                    MultipleProofs::Attestation(_) => todo!(),
                },
            };

            // the same c_nonce should be used for all proofs
            let mut nonces = HashSet::new();
            let resolver = async |kid: String| did_jwk(&kid, provider).await;

            for proof in proof_jwts {
                // TODO: ProofClaims cannot use `client_id` if the access token was
                // obtained in a pre-auth flow with anonymous access to the token
                // endpoint
                // TODO: check proof is signed with supported algorithm (from proof_type)

                let jwt: Jwt<ProofClaims> = match decode_jws(proof, resolver).await {
                    Ok(jwt) => jwt,
                    Err(e) => {
                        return Err(Error::InvalidProof(format!("issue decoding JWT: {e}")));
                    }
                };

                // proof type
                if jwt.header.typ != JwtType::ProofJwt.to_string() {
                    return Err(Error::InvalidProof("invalid proof type".to_string()));
                }
                if jwt.claims.credential_issuer != ctx.issuer.credential_issuer {
                    return Err(Error::InvalidProof("invalid proof issuer".to_string()));
                }

                // c_nonce issued by token endpoint
                let c_nonce = jwt.claims.nonce.as_ref().ok_or_else(|| {
                    Error::InvalidProof("proof JWT nonce claim is missing".to_string())
                })?;
                nonces.insert(c_nonce.clone());

                // extract Key ID for use when building credential
                let KeyBinding::Kid(kid) = &jwt.header.key else {
                    return Err(Error::InvalidProof("Proof JWT 'kid' is missing".to_string()));
                };
                ctx.proof_kids.push(kid.to_string());
            }

            // should only be a single c_nonce, but just in case...
            for c_nonce in nonces {
                StateStore::get::<String>(provider, &c_nonce).await.context("proof nonce claim")?;
                StateStore::purge(provider, &c_nonce).await.context("deleting proof nonce")?;
            }
        }

        Ok(())
    }

    // Get `Authorized` for `credential_identifier` and
    // `credential_configuration_id`.
    fn authorized_detail(&self, ctx: &Context) -> Result<AuthorizedDetail> {
        let token = &ctx.state.body;

        match &self.credential {
            RequestBy::Identifier(id) => {
                for ad in &token.authorized_details {
                    if ad.credential_identifiers.contains(id) {
                        return Ok(ad.clone());
                    }
                }
            }
            RequestBy::ConfigurationId(id) => {
                for ad in &token.authorized_details {
                    if Some(id.as_str()) == ad.credential_configuration_id() {
                        return Ok(ad.clone());
                    }
                }
            }
        }

        Err(Error::InvalidCredentialRequest("unauthorized credential requested".to_string()))
    }
}

impl Context {
    // Issue the requested credential.
    async fn issue(
        &self, provider: &impl Provider, dataset: Dataset,
    ) -> Result<CredentialResponse> {
        let mut credentials = vec![];

        let mut status_list = StatusList::new().context("creating status list")?;

        // create a credential for each proof
        for kid in &self.proof_kids {
            let status_claim = status_list
                .add_entry("http://credibil.io/statuslists/1")
                .context("creating status claim")?;

            let credential = match &self.configuration.profile {
                FormatProfile::JwtVcJson {
                    credential_definition,
                } => {
                    // FIXME: do we need to resolve DID document?
                    let Some(did) = kid.split('#').next() else {
                        return Err(Error::InvalidProof("Proof JWT DID is invalid".to_string()));
                    };
                    let jwt = W3cVcBuilder::new()
                        .r#type(credential_definition.r#type.clone())
                        .issuer(&self.issuer.credential_issuer)
                        .holder(did)
                        .status(status_claim)
                        .claims(dataset.claims.clone())
                        .signer(provider)
                        .build()
                        .await
                        .context("creating `jwt_vc_json` credential")?;

                    Credential {
                        credential: jwt.into(),
                    }
                }
                FormatProfile::MsoMdoc { doctype } => {
                    let jwk = did_jwk(kid, provider)
                        .await
                        .context("retrieving JWK for `dc+sd-jwt` credential")?;

                    let mdl = MdocBuilder::new()
                        .doctype(doctype)
                        .device_key(jwk)
                        .claims(dataset.claims.clone())
                        .signer(provider)
                        .build()
                        .await
                        .context("creating `mso_mdoc` credential")?;

                    Credential {
                        credential: mdl.into(),
                    }
                }
                FormatProfile::DcSdJwt { vct } => {
                    // TODO: cache the result of jwk when verifying proof (`verify` method)
                    let jwk =
                        did_jwk(kid, provider).await.context("getting JWK for `dc+sd-jwt`")?;
                    let Some(did) = kid.split('#').next() else {
                        return Err(Error::InvalidProof("Proof JWT DID is invalid".to_string()));
                    };

                    let sd_jwt = SdJwtVcBuilder::new()
                        .vct(vct)
                        .issuer(self.issuer.credential_issuer.clone())
                        .claims(dataset.claims.clone())
                        .key_binding(jwk)
                        .holder(did)
                        .status(status_claim)
                        .signer(provider)
                        .build()
                        .await
                        .context("creating `dc+sd-jwt` credential")?;

                    Credential {
                        credential: sd_jwt.into(),
                    }
                }
                FormatProfile::JwtVcJsonLd { .. } => todo!(),
                FormatProfile::LdpVc { .. } => todo!(),
            };

            credentials.push(credential);
        }

        let token = TokenBuilder::new()
            .status_list(status_list.clone())
            .uri("https://example.com/statuslists/1")
            .signer(provider)
            .build()
            .await
            .context("building status list token")?;
        StatusStore::put(provider, "https://example.com/statuslists/1", &token)
            .await
            .context("saving status list")?;

        // update token state with new `c_nonce`
        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let token = &state.body;
        StateStore::put(provider, &token.access_token, &state).await.context("saving state")?;

        // TODO: create issuance state for notification endpoint
        let notification_id = generate::notification_id();
        StateStore::put(provider, &notification_id, &state).await.context("saving state")?;

        Ok(CredentialResponse::Credentials {
            credentials,
            notification_id: Some(notification_id),
        })
    }

    // Defer issuance of the requested credential.
    async fn defer(
        &self, provider: &impl Provider, request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        let txn_id = generate::transaction_id();

        let state = State {
            body: Deferred {
                transaction_id: txn_id.clone(),
                credential_request: request,
            },
            expires_at: Utc::now() + Expire::Access.duration(),
        };
        StateStore::put(provider, &txn_id, &state).await.context("saving state")?;

        Ok(CredentialResponse::TransactionId {
            transaction_id: txn_id,
        })
    }

    // Get credential dataset for the request
    async fn dataset(
        &self, provider: &impl Provider, request: &CredentialRequest, authorized: &AuthorizedDetail,
    ) -> Result<Dataset> {
        let RequestBy::Identifier(identifier) = &request.credential else {
            return Err(Error::InvalidCredentialRequest(
                "requesting credentials by `credential_configuration_id` is unsupported"
                    .to_string(),
            ));
        };

        // get claims dataset for `credential_identifier`
        let subject_id = &self.state.body.subject_id;
        let mut dataset = Subject::dataset(provider, subject_id, identifier)
            .await
            .context("populating claims")?;

        // only include previously requested/authorized claims
        if let Some(claims) = &authorized.authorization_detail.claims {
            dataset.claims.retain(|k, _| claims.iter().any(|c| c.path.contains(k)));
        }

        Ok(dataset)
    }
}
