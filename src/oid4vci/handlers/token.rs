//! # Token Endpoint
//!
//! The Token Endpoint issues an Access Token and, optionally, a Refresh Token
//! in exchange for the Authorization Code that client obtained in a successful
//! Authorization Response. It is used in the same manner as defined in
//! [RFC6749](https://tools.ietf.org/html/rfc6749#section-5.1) and follows the
//! recommendations given in [I-D.ietf-oauth-security-topics].
//!
//! The authorization server MUST include the HTTP "Cache-Control" response
//! header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-store" in any response containing tokens,
//! credentials, or other sensitive information, as well as the "Pragma"
//! response header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-cache".

// TODO: verify `client_assertion` JWT, when set

use std::fmt::Debug;

use anyhow::Context as _;
use chrono::Utc;
use serde::de::DeserializeOwned;

use crate::generate;
use crate::oauth::GrantType;
use crate::oid4vci::error::{invalid, server};
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::issuer::{
    AuthorizationCredential, AuthorizationDetail, AuthorizedDetail, Issuer, TokenGrantType,
    TokenRequest, TokenResponse, TokenType,
};
use crate::oid4vci::pkce;
use crate::oid4vci::provider::{Metadata, Provider, StateStore};
use crate::oid4vci::state::{Authorized, Expire, Offered, Token};
use crate::state::State;

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn token(
    issuer: &str, provider: &impl Provider, request: TokenRequest,
) -> Result<TokenResponse> {
    let mut ctx = Context {
        issuer,
        offered: None,
        authorized: None,
    };

    // get previously authorized credentials from state
    let (subject_id, authorized_details) = match &request.grant_type {
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => {
            let state = get_state::<Offered>(pre_authorized_code, provider).await?;
            ctx.offered = Some(state.body.clone());
            let Some(subject_id) = state.body.subject_id else {
                return Err(server!("no authorized subject"));
            };
            let Some(authorization_details) = state.body.details else {
                return Err(server!("no authorized items"));
            };
            (subject_id, authorization_details)
        }
        TokenGrantType::AuthorizationCode { code, .. } => {
            let state = get_state::<Authorized>(code, provider).await?;
            ctx.authorized = Some(state.body.clone());
            (state.body.subject_id, state.body.details)
        }
    };

    request.verify(provider, &ctx).await?;

    // get the subset of requested credentials from those previously authorized
    let retained_details = request.retain(provider, &ctx, &authorized_details).await?;

    // update state
    let state = State {
        body: Token {
            subject_id,
            access_token: generate::token(),
            authorized_details: retained_details,
        },
        expires_at: Utc::now() + Expire::Access.duration(),
    };
    StateStore::put(provider, &state.body.access_token, &state).await.context("saving state")?;

    // return response
    Ok(TokenResponse {
        access_token: state.body.access_token,
        token_type: TokenType::Bearer,
        expires_in: Expire::Access.duration().num_seconds(),
        authorization_details: Some(state.body.authorized_details),
    })
}

impl<P: Provider> Handler<P> for Request<TokenRequest> {
    type Error = Error;
    type Provider = P;
    type Response = TokenResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        token(issuer, provider, self.body).await
    }
}

impl Body for TokenRequest {}

#[derive(Debug)]
struct Context<'a> {
    issuer: &'a str,
    offered: Option<Offered>,
    authorized: Option<Authorized>,
}

async fn get_state<T: DeserializeOwned>(code: &str, provider: &impl Provider) -> Result<State<T>> {
    let Ok(state) = StateStore::get::<T>(provider, code).await else {
        return Err(Error::InvalidGrant("invalid authorization code".to_string()));
    };
    StateStore::purge(provider, code).await.context("purging state")?;
    if state.is_expired() {
        return Err(invalid!("authorization state expired"));
    }
    Ok(state)
}

impl TokenRequest {
    // Verify the token request.
    async fn verify(&self, provider: &impl Provider, ctx: &Context<'_>) -> Result<()> {
        tracing::debug!("token::verify");

        // TODO: get Issuer metadata
        // If the Token Request contains authorization_details and Issuer
        // metadata contains an authorization_servers parameter, the
        // authorization_details object MUST contain the Issuer's identifier
        // in locations.

        let Ok(server) = Metadata::server(provider, ctx.issuer).await else {
            return Err(invalid!("unknown authorization server"));
        };
        let Some(grant_types_supported) = &server.oauth.grant_types_supported else {
            return Err(server!("authorization server grant types not set"));
        };

        // grant_type
        match &self.grant_type {
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Some(offer) = &ctx.offered else {
                    return Err(server!("pre-authorized state not set"));
                };
                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::PreAuthorizedCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".to_string()));
                }

                // anonymous access allowed?
                if (self.client_id.as_ref().is_none()
                    || self.client_id.as_ref().is_some_and(String::is_empty))
                    && !server.pre_authorized_grant_anonymous_access_supported
                {
                    return Err(Error::InvalidClient(
                        "anonymous access is not supported".to_string(),
                    ));
                }

                // tx_code (PIN)
                if tx_code != &offer.tx_code {
                    return Err(Error::InvalidGrant("invalid `tx_code` provided".to_string()));
                }
            }
            TokenGrantType::AuthorizationCode {
                redirect_uri,
                code_verifier,
                ..
            } => {
                let Some(authorization) = &ctx.authorized else {
                    return Err(server!("authorization state not set"));
                };

                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::AuthorizationCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".to_string()));
                }

                // client_id is the same as the one used to obtain the authorization code
                if self.client_id.is_none() {
                    return Err(invalid!("`client_id` is missing"));
                }
                if self.client_id.as_ref() != Some(&authorization.client_id) {
                    return Err(Error::InvalidClient(
                        "`client_id` differs from authorized one".to_string(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &authorization.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "`redirect_uri` differs from authorized one".to_string(),
                    ));
                }

                // verifier matches challenge received in authorization request
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("`code_verifier` is missing".to_string()));
                };
                if pkce::code_challenge(verifier) != authorization.code_challenge {
                    return Err(Error::AccessDenied("`code_verifier` is invalid".to_string()));
                }
            }
        }

        if let Some(client_id) = &self.client_id {
            // client metadata
            let Ok(client) = Metadata::client(provider, client_id).await else {
                return Err(Error::InvalidClient("invalid `client_id`".to_string()));
            };
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
        }

        Ok(())
    }

    // TODO: add `client_assertion` JWT verification

    // Filter previously authorized credentials by those selfed.
    async fn retain(
        &self, provider: &impl Provider, ctx: &Context<'_>, authorized: &[AuthorizedDetail],
    ) -> Result<Vec<AuthorizedDetail>> {
        // no `authorization_details` in request, return all previously authorized
        let Some(requested) = self.authorization_details.as_ref() else {
            return Ok(authorized.to_vec());
        };

        let Ok(issuer) = Metadata::issuer(provider, ctx.issuer).await else {
            return Err(invalid!("unknown authorization server"));
        };

        // filter by requested authorization_details
        let mut retained = vec![];

        for detail in requested {
            // check requested `authorization_detail` has been previously authorized
            let mut found = false;
            for ad in authorized {
                if ad.authorization_detail.credential == detail.credential {
                    verify_claims(&issuer, detail)?;

                    let mut ad = ad.clone();
                    if detail.claims.is_some() {
                        ad.authorization_detail.claims.clone_from(&detail.claims);
                    }
                    retained.push(ad.clone());

                    found = true;
                    break;
                }
            }

            if !found {
                // we're here if requested `authorization_detail` has not been authorized
                return Err(Error::AccessDenied(
                    "requested credential has not been authorized".to_string(),
                ));
            }
        }

        Ok(retained)
    }
}

// Verify requested claims exist as supported claims and all mandatory claims
// have been requested.
fn verify_claims(issuer: &Issuer, detail: &AuthorizationDetail) -> Result<()> {
    let Some(claims) = &detail.claims else {
        return Ok(());
    };

    // get credential configuration with claim metadata
    let config_id = match &detail.credential {
        AuthorizationCredential::ConfigurationId {
            credential_configuration_id,
        } => credential_configuration_id,
        AuthorizationCredential::FormatProfile(fmt) => {
            issuer.credential_configuration_id(fmt).context("issuer issue")?
        }
    };
    let config = issuer.credential_configuration(config_id).map_err(|e| {
        Error::InvalidAuthorizationDetails(format!("unknown credential configuration: {e}"))
    })?;

    // check claims are supported and include all mandatory claims
    config.verify_claims(claims).map_err(|e| Error::InvalidAuthorizationDetails(e.to_string()))?;

    Ok(())
}
