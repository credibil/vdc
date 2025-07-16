//! # Authorization Endpoint
//!
//! The Authorization Endpoint is used by Wallets to request access to the
//! Credential Endpoint, that is, to request issuance of a Credential. The
//! endpoint is used in the same manner as defined in [RFC6749].
//!
//! Wallets can request authorization for issuance of a Credential using
//! `authorization_details` (as defined in [RFC9396]) or `scope` parameters (or
//! both).

use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::Context as _;
use chrono::Utc;
use credibil_core::api::{Body, Handler, Request, Response};
use credibil_core::state::State;

use crate::error::{invalid, server};
use crate::generate;
use crate::handlers::{Error, Result};
use crate::oauth::GrantType;
use crate::provider::{Metadata, Provider, StateStore, Subject};
use crate::state::{Authorized, Expire, Offered};
use crate::types::{
    AuthorizationDefinition, AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest,
    AuthorizationResponse, AuthorizedDetail, IssuerMetadata, RequestObject,
};

/// Authorization request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn authorize(
    issuer: &str, provider: &impl Provider, request: AuthorizationRequest,
) -> Result<AuthorizationResponse> {
    // request object or URI (Pushed Authorization Request)
    let mut is_par = false;
    let request = match request {
        AuthorizationRequest::Object(request) => request,
        AuthorizationRequest::Uri(uri) => {
            is_par = true;
            let state = StateStore::get::<RequestObject>(provider, issuer, &uri.request_uri)
                .await
                .context("issue retrieving state")?;

            if state.expires_at < Utc::now() {
                return Err(invalid!("`request_uri` has expired"));
            }
            state.body.clone()
        }
    };

    // get issuer metadata
    let Ok(issuer_meta) = Metadata::issuer(provider, issuer).await else {
        return Err(invalid!("invalid `credential_issuer`"));
    };

    let mut ctx = Context { issuer: issuer_meta, is_par, ..Context::default() };
    ctx.verify(issuer, provider, &request).await?;

    // authorization_detail
    let mut details = vec![];

    for (config_id, mut auth_det) in ctx.auth_dets.clone() {
        let identifiers = Subject::authorize(provider, issuer, &request.subject_id, &config_id)
            .await
            .map_err(|e| Error::AccessDenied(format!("issue authorizing subject: {e}")))?;

        auth_det.credential = AuthorizationDefinition::ConfigurationId {
            credential_configuration_id: config_id.clone(),
        };

        details.push(AuthorizedDetail {
            authorization_detail: auth_det.clone(),
            credential_identifiers: identifiers.clone(),
        });
    }

    // return an error if holder is not authorized for any requested credentials
    if details.is_empty() {
        return Err(Error::AccessDenied(
            "holder is not authorized for requested credentials".to_string(),
        ));
    }

    // save authorization state
    let state = State {
        expires_at: Utc::now() + Expire::Authorized.duration(),
        body: Authorized {
            subject_id: request.subject_id,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            details,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri.clone(),
        },
    };

    let code = generate::auth_code();
    StateStore::put(provider, issuer, &code, &state).await.context("issue saving authorization state")?;

    // remove offer state
    if let Some(issuer_state) = &request.issuer_state {
        StateStore::purge(provider, issuer, issuer_state).await.context("issue purging offer state")?;
    }

    Ok(AuthorizationResponse {
        code,
        state: request.state,
        redirect_uri: request.redirect_uri.unwrap_or_default(),
    })
}

impl<P: Provider> Handler<AuthorizationResponse, P> for Request<AuthorizationRequest> {
    type Error = Error;

    async fn handle(self, issuer: &str, provider: &P) -> Result<Response<AuthorizationResponse>> {
        Ok(authorize(issuer, provider, self.body).await?.into())
    }
}

impl Body for AuthorizationRequest {}

#[derive(Debug, Default)]
pub struct Context {
    pub issuer: IssuerMetadata,
    pub auth_dets: HashMap<String, AuthorizationDetail>,
    pub is_par: bool,
}

impl Context {
    pub async fn verify(
        &mut self, issuer: &str, provider: &impl Provider, request: &RequestObject,
    ) -> Result<()> {
        // client and server metadata
        let Ok(client) = Metadata::client(provider, issuer, &request.client_id).await else {
            return Err(Error::InvalidClient(format!(
                "{} is not a valid client_id",
                request.client_id
            )));
        };
        // TODO: support authorization issuers
        let Ok(server) = Metadata::server(provider, &self.issuer.credential_issuer).await else {
            return Err(invalid!("invalid `credential_issuer`"));
        };

        // If the server requires pushed authorization requests, the request
        // must be a PAR.
        if server.oauth.require_pushed_authorization_requests.is_some_and(|par| par && !self.is_par)
        {
            return Err(invalid!("pushed authorization request is required"));
        }

        // Requested `response_type` must be supported by the authorization server.
        if !server.oauth.response_types_supported.contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported by server".to_string(),
            ));
        }

        // Client and server must support the same scopes.
        if let Some(client_scope) = &client.oauth.scope {
            if let Some(server_scopes) = &server.oauth.scopes_supported {
                let scopes: Vec<&str> = client_scope.split_whitespace().collect();
                if !scopes.iter().all(|s| server_scopes.contains(&(*s).to_string())) {
                    return Err(invalid!("client scope not supported"));
                }
            } else {
                return Err(invalid!("server supported scopes not set"));
            }
        } else {
            return Err(invalid!("client scope not set"));
        }

        // 'authorization_code' grant_type allowed (client and server)?
        let client_grant_types = client.oauth.grant_types.unwrap_or_default();
        if !client_grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(Error::UnauthorizedClient(
                "authorization_code grant not supported for client".to_string(),
            ));
        }
        let server_grant_types = server.oauth.grant_types_supported.unwrap_or_default();
        if !server_grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(invalid!("authorization_code grant not supported by server"));
        }

        // is holder identified (authenticated)?
        if request.subject_id.is_empty() {
            return Err(invalid!("missing holder subject"));
        }

        // does offer `subject_id`  match request `subject_id`?
        if let Some(issuer_state) = &request.issuer_state {
            let state = StateStore::get::<Offered>(provider, issuer, issuer_state)
                .await
                .context("issue retrieving state")?;

            if state.is_expired() {
                return Err(invalid!("issuer state expired"));
            }

            if state.body.subject_id.as_ref() != Some(&request.subject_id) {
                return Err(invalid!("request `subject_id` does not match offer"));
            }
        }

        // has a credential been requested?
        if request.authorization_details.is_none() && request.scope.is_none() {
            return Err(invalid!("no credentials requested"));
        }

        // verify authorization_details
        if let Some(authorization_details) = &request.authorization_details {
            self.verify_authorization_details(authorization_details.clone())?;
        }
        // verify scope
        if let Some(scope) = &request.scope {
            self.verify_scope(scope)?;
        }

        // redirect_uri
        let Some(redirect_uri) = &request.redirect_uri else {
            return Err(invalid!("no `redirect_uri` specified"));
        };
        let Some(redirect_uris) = client.oauth.redirect_uris else {
            return Err(server!("`redirect_uri`s not set for client"));
        };
        if !redirect_uris.contains(redirect_uri) {
            return Err(invalid!("`redirect_uri` is not registered"));
        }

        // response_type
        if !client.oauth.response_types.unwrap_or_default().contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported for client".to_string(),
            ));
        }
        if !server.oauth.response_types_supported.contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported by server".to_string(),
            ));
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server.oauth.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&request.code_challenge_method) {
            return Err(invalid!("unsupported `code_challenge_method`"));
        }
        if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
            return Err(invalid!("code_challenge must be between 43 and 128 characters"));
        }

        Ok(())
    }

    // Verify Credentials requested in `authorization_details` are supported.
    // N.B. has side effect of saving valid `authorization_detail` objects into
    // context for later use.
    fn verify_authorization_details(
        &mut self, authorization_details: Vec<AuthorizationDetail>,
    ) -> Result<()> {
        // check each credential requested is supported by the issuer
        for mut detail in authorization_details {
            if detail.r#type != AuthorizationDetailType::OpenIdCredential {
                return Err(Error::InvalidAuthorizationDetails(
                    "invalid authorization_details type".to_string(),
                ));
            }

            // verify requested claims
            let config_id = match &detail.credential {
                AuthorizationDefinition::ConfigurationId { credential_configuration_id } => {
                    credential_configuration_id
                }
                AuthorizationDefinition::FormatProfile(fmt) => {
                    let config_id = self
                        .issuer
                        .credential_configuration_id(fmt)
                        .context("issue getting `credential_configuration_id`")?;
                    detail.credential = AuthorizationDefinition::ConfigurationId {
                        credential_configuration_id: config_id.clone(),
                    };
                    config_id
                }
            };

            // check claims are supported and include all mandatory claims
            if let Some(requested) = &detail.claims {
                let Some(config) = self.issuer.credential_configurations_supported.get(config_id)
                else {
                    return Err(Error::InvalidAuthorizationDetails(
                        "invalid credential_configuration_id".to_string(),
                    ));
                };
                config.verify_claims(requested).map_err(|e| invalid!("{e}"))?;
            }

            self.auth_dets.insert(config_id.clone(), detail.clone());
        }

        Ok(())
    }

    // Verify Credentials requested in `scope` are supported.
    // N.B. has side effect of saving valid scope items into context for later use.
    fn verify_scope(&mut self, scope: &str) -> Result<()> {
        if let Some(scope_item) = scope.split_whitespace().next() {
            // find supported configuration with the requested scope
            let mut found = false;
            for (config_id, cred_cfg) in &self.issuer.credential_configurations_supported {
                // `authorization_details` credential request takes precedence `scope` request
                if self.auth_dets.contains_key(config_id) {
                    continue;
                }

                // save scope item + credential_configuration_id
                if cred_cfg.scope == Some(scope_item.to_string()) {
                    let detail = AuthorizationDetail {
                        r#type: AuthorizationDetailType::OpenIdCredential,
                        credential: AuthorizationDefinition::ConfigurationId {
                            credential_configuration_id: config_id.clone(),
                        },
                        claims: None,
                        locations: None,
                    };

                    self.auth_dets.insert(config_id.clone(), detail);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(Error::InvalidScope("invalid scope".to_string()));
            }
        }

        Ok(())
    }
}
