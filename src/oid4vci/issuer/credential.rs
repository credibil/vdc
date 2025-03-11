//! # Batch Credential Endpoint
//!
//! The Batch Credential Endpoint issues multiple Credentials in one Batch
//! Credential Response as approved by the End-User upon presentation of a valid
//! Access Token representing this approval.
//!
//! A Wallet can request issuance of multiple Credentials of certain types and
//! formats in one Batch Credential Request. This includes Credentials of the
//! same type and multiple formats, different types and one format, or both.

use std::fmt::Debug;

use chrono::{DateTime, Utc};
use credibil_infosec::Signer;
use credibil_infosec::jose::jws::{self, Key};
use tracing::instrument;

use crate::core::{Kind, generate};
use crate::oid4vci::endpoint::{Body, Handler, Request};
use crate::oid4vci::provider::{Metadata, Provider, StateStore, Subject};
use crate::oid4vci::state::{Deferrance, Expire, Stage, State};
use crate::oid4vci::types::{
    AuthorizedDetail, Credential, CredentialConfiguration, CredentialDefinition, CredentialDisplay,
    CredentialHeaders, CredentialRequest, CredentialResponse, Dataset, Format, Issuer,
    MultipleProofs, Proof, ProofClaims, RequestBy, ResponseType, SingleProof,
};
use crate::oid4vci::{Error, Result};
use crate::status::issuer::Status;
use crate::w3c_vc::model::types::{LangString, LangValue};
use crate::w3c_vc::model::{CredentialSubject, VerifiableCredential};
use crate::w3c_vc::proof::{self, Payload, Type, W3cFormat};
use crate::{server, verify_key};

/// Credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub(crate) async fn credential(
    issuer: &str, provider: &impl Provider, request: Request<CredentialRequest, CredentialHeaders>,
) -> Result<CredentialResponse> {
    tracing::debug!("credential");

    let Ok(state) = StateStore::get::<State>(provider, &request.headers.authorization).await else {
        return Err(Error::AccessDenied("invalid access token".to_string()));
    };
    let iss =
        Metadata::issuer(provider, issuer).await.map_err(|e| server!("metadata issue: {e}"))?;

    // create a request context with data accessed more than once
    let mut ctx = Context {
        state,
        issuer: iss,
        ..Context::default()
    };

    let request = request.body;

    // authorized credential
    ctx.authorized = request.authorized_detail(&ctx)?;

    // credential configuration
    let Some(config_id) = ctx.authorized.credential_configuration_id() else {
        return Err(Error::InvalidCredentialRequest("no credential_configuration_id".to_string()));
    };
    let Some(config) = ctx.issuer.credential_configurations_supported.get(config_id) else {
        return Err(server!("credential configuration unable to be found"));
    };
    ctx.configuration = config.clone();

    request.verify(provider, &mut ctx).await?;

    let dataset = ctx.dataset(provider, &request).await?;

    // defer issuance as claims are pending (approval)
    if dataset.pending {
        return ctx.defer(provider, request).await;
    }

    // delete nonces
    for nonce in &ctx.nonces {
        StateStore::purge(provider, nonce)
            .await
            .map_err(|e| server!("issue deleting nonce: {e}"))?;
    }

    // issue VC
    ctx.issue(provider, dataset).await
}

impl Handler for Request<CredentialRequest, CredentialHeaders> {
    type Response = CredentialResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        credential(issuer, provider, self)
    }
}

impl Body for CredentialRequest {}

#[derive(Debug, Default)]
struct Context {
    state: State,
    issuer: Issuer,
    authorized: AuthorizedDetail,
    configuration: CredentialConfiguration,
    holder_dids: Vec<String>,
    nonces: Vec<String>,
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

            for proof_jwt in proof_jwts {
                // TODO: ProofClaims cannot use `client_id` if the access token was
                // obtained in a pre-auth flow with anonymous access to the token
                // endpoint

                // TODO: check proof is signed with supported algorithm (from proof_type)
                
                let jwt: jws::Jwt<ProofClaims> =
                    match jws::decode(proof_jwt, verify_key!(provider)).await {
                        Ok(jwt) => jwt,
                        Err(e) => {
                            return Err(Error::InvalidProof(format!("issue decoding JWT: {e}")));
                        }
                    };

                // proof type
                if jwt.header.typ != Type::Openid4VciProofJwt.to_string() {
                    return Err(Error::InvalidProof("invalid proof type".to_string()));
                }

                // previously issued c_nonce
                let c_nonce = jwt.claims.nonce.as_ref().ok_or_else(|| {
                    Error::InvalidProof("proof JWT nonce claim is missing".to_string())
                })?;
                StateStore::get::<String>(provider, c_nonce)
                    .await
                    .map_err(|e| server!("proof nonce claim is invalid: {e}"))?;

                // save nonce for deletion when not defering issuance
                ctx.nonces.push(c_nonce.clone());

                // Key ID
                let Key::KeyId(kid) = &jwt.header.key else {
                    return Err(Error::InvalidProof("Proof JWT 'kid' is missing".to_string()));
                };

                // FIXME: save extracted DID for later use when issuing credential
                let Some(did) = kid.split('#').next() else {
                    return Err(Error::InvalidProof("Proof JWT DID is invalid".to_string()));
                };

                // TODO: support multiple DID bindings
                ctx.holder_dids.push(did.to_string());
            }
        }

        Ok(())
    }

    // Get `Authorized` for `credential_identifier` and
    // `credential_configuration_id`.
    fn authorized_detail(&self, ctx: &Context) -> Result<AuthorizedDetail> {
        let Stage::Validated(token) = &ctx.state.stage else {
            return Err(Error::AccessDenied("invalid access token state".to_string()));
        };

        match &self.credential {
            RequestBy::Identifier(ident) => {
                for ad in &token.details {
                    if ad.credential_identifiers.contains(ident) {
                        return Ok(ad.clone());
                    }
                }
            }
            RequestBy::ConfigurationId(id) => {
                for ad in &token.details {
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
        // generate the issuance time stamp
        let issuance_date = Utc::now();

        // determine credential format
        let response = match &self.configuration.format {
            Format::JwtVcJson(w3c) => {
                let mut vcs = vec![];

                for did in &self.holder_dids {
                    let subject = CredentialSubject {
                        id: Some(did.clone()),
                        claims: dataset.claims.clone(),
                    };

                    let vc = self.w3c_vc(provider, &w3c.credential_definition, subject).await?;
                    vcs.push(vc);
                }
                self.jwt_vc_json(vcs, provider.clone(), issuance_date).await?
            }
            Format::IsoMdl(_) => self.mso_mdoc(dataset, provider.clone()).await?,

            // TODO: remaining credential formats
            Format::JwtVcJsonLd(_) => todo!(),
            Format::LdpVc(_) => todo!(),
            Format::VcSdJwt(_) => todo!(),
        };

        // update token state with new `c_nonce`
        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let Stage::Validated(token_state) = state.stage else {
            return Err(Error::AccessDenied("invalid access token state".to_string()));
        };
        state.stage = Stage::Validated(token_state.clone());

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| server!("issue saving state: {e}"))?;

        // TODO: create issuance state for notification endpoint
        // state.stage = Stage::Issued(credential_configuration_id, credential_identifier);
        let notification_id = generate::notification_id();

        StateStore::put(provider, &notification_id, &state, state.expires_at)
            .await
            .map_err(|e| server!("issue saving state: {e}"))?;

        Ok(CredentialResponse {
            response,
            notification_id: Some(notification_id),
        })
    }

    // Generate a W3C Verifiable Credential.
    async fn w3c_vc(
        &self, provider: &impl Provider, credential_definition: &CredentialDefinition,
        subject: CredentialSubject,
    ) -> Result<VerifiableCredential> {
        // credential type
        let Some(credential_type) = credential_definition.type_.get(1) else {
            return Err(server!("Credential type not set"));
        };

        // credential's status lookup information
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".to_string()));
        };
        let status = Status::status(provider, subject_id, "credential_identifier")
            .await
            .map_err(|e| server!("issue populating credential status: {e}"))?;

        let credential_issuer = &self.issuer.credential_issuer;
        let (name, description) =
            self.configuration.display.as_ref().map_or((None, None), create_names);

        VerifiableCredential::builder()
            .add_context(Kind::String(format!("{credential_issuer}/credentials/v1")))
            // TODO: generate credential id
            .id(format!("{credential_issuer}/credentials/{credential_type}"))
            .add_type(credential_type)
            .add_name(name)
            .add_description(description)
            .issuer(credential_issuer)
            .add_subject(subject)
            .status(status)
            .build()
            .map_err(|e| server!("issue building VC: {e}"))
    }

    // Generate a `jwt_vc_json` format credential .
    async fn jwt_vc_json(
        &self, vcs: Vec<VerifiableCredential>, signer: impl Signer, issuance_date: DateTime<Utc>,
    ) -> Result<ResponseType> {
        // sign and return JWT(s)
        let mut credentials = vec![];

        for vc in vcs {
            let jwt = proof::create(
                W3cFormat::JwtVcJson,
                Payload::Vc {
                    vc: vc.clone(),
                    issued_at: issuance_date.timestamp(),
                },
                &signer,
            )
            .await
            .map_err(|e| server!("issue generating `jwt_vc_json` credential: {e}"))?;

            credentials.push(Credential {
                credential: Kind::String(jwt),
            });
        }

        Ok(ResponseType::Credentials {
            credentials,
            notification_id: None,
        })
    }

    // Generate a `mso_mdoc` format credential.
    async fn mso_mdoc(&self, dataset: Dataset, signer: impl Signer) -> Result<ResponseType> {
        let mdl = crate::iso_mdl::to_credential(dataset.claims, signer)
            .await
            .map_err(|e| server!("issue generating `mso_mdoc` credential: {e}"))?;

        Ok(ResponseType::Credentials {
            credentials: vec![Credential {
                credential: Kind::String(mdl),
            }],
            notification_id: None,
        })
    }

    // Defer issuance of the requested credential.
    async fn defer(
        &self, provider: &impl Provider, request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        let txn_id = generate::transaction_id();

        let state = State {
            subject_id: None,
            stage: Stage::Deferred(Deferrance {
                transaction_id: txn_id.clone(),
                credential_request: request,
            }),
            expires_at: Utc::now() + Expire::Access.duration(),
        };
        StateStore::put(provider, &txn_id, &state, state.expires_at)
            .await
            .map_err(|e| server!("issue saving state: {e}"))?;

        Ok(CredentialResponse {
            response: ResponseType::TransactionId {
                transaction_id: txn_id,
            },
            notification_id: None,
        })
    }

    // Get credential dataset for the request
    async fn dataset(
        &self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<Dataset> {
        let RequestBy::Identifier(identifier) = &request.credential else {
            return Err(Error::InvalidCredentialRequest(
                "requesting credentials by `credential_configuration_id` is unsupported"
                    .to_string(),
            ));
        };

        // get claims dataset for `credential_identifier`
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".to_string()));
        };
        let mut dataset = Subject::dataset(provider, subject_id, identifier)
            .await
            .map_err(|e| server!("issue populating claims: {e}"))?;

        // only include previously requested/authorized claims
        if let Some(claims) = &self.authorized.authorization_detail.claims {
            dataset.claims.retain(|k, _| claims.iter().any(|c| c.path.contains(k)));
        }

        Ok(dataset)
    }
}

// Extract language object name and description from a `CredentialDisplay`
// vector.
fn create_names(display: &Vec<CredentialDisplay>) -> (Option<LangString>, Option<LangString>) {
    let mut name: Option<LangString> = None;
    let mut description: Option<LangString> = None;
    for d in display {
        let n = LangValue {
            value: d.name.clone(),
            language: d.locale.clone(),
            ..LangValue::default()
        };
        if let Some(nm) = &mut name {
            nm.add(n);
        } else {
            name = Some(LangString::new_object(n));
        }
        if d.description.is_some() {
            let d = LangValue {
                value: d.description.clone().unwrap(),
                language: d.locale.clone(),
                ..LangValue::default()
            };
            if let Some(desc) = &mut description {
                desc.add(d);
            } else {
                description = Some(LangString::new_object(d));
            }
        }
    }
    (name, description)
}
