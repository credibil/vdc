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

use tracing::instrument;

use crate::core::{generate, pkce};
use crate::oauth::GrantType;
use crate::oid4vci::endpoint::{Body, NoHeaders, Handler, Request};
use crate::oid4vci::provider::{Metadata, Provider, StateStore};
use crate::oid4vci::state::{Expire, Stage, State, Token};
use crate::oid4vci::types::{
    AuthorizationCredential, AuthorizationDetail, AuthorizedDetail, Issuer, TokenGrantType,
    TokenRequest, TokenResponse, TokenType,
};
use crate::oid4vci::{Error, Result};
use crate::{invalid, server};

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn token(
    issuer: &str, provider: &impl Provider, request: TokenRequest,
) -> Result<TokenResponse> {
    tracing::debug!("token");

    // restore state
    let auth_code = match &request.grant_type {
        TokenGrantType::AuthorizationCode { code, .. } => code,
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => pre_authorized_code,
    };

    // RFC 6749 requires a particular error here
    let Ok(state) = StateStore::get::<State>(provider, auth_code).await else {
        return Err(Error::InvalidGrant("authorization code is invalid".to_string()));
    };
    // authorization code is one-time use
    StateStore::purge(provider, auth_code)
        .await
        .map_err(|e| server!("issue purging authorizaiton state: {e}"))?;

    let ctx = Context {
        issuer,
        state: state.clone(),
    };

    request.verify(provider, &ctx).await?;

    // get previously authorized credentials from state
    let authorized_details = match &request.grant_type {
        TokenGrantType::PreAuthorizedCode { .. } => {
            let Stage::Offered(offer) = &state.stage else {
                return Err(server!("pre-authorized state not set"));
            };
            let Some(authorization_details) = &offer.details else {
                return Err(server!("no authorized items"));
            };
            authorization_details
        }
        TokenGrantType::AuthorizationCode { .. } => {
            let Stage::Authorized(authorization) = &state.stage else {
                return Err(server!("authorization state not set"));
            };
            &authorization.details
        }
    };

    // find the subset of requested credentials from those previously authorized
    let authorized_details = request.retain(provider, &ctx, authorized_details).await?;
    let access_token = generate::token();

    // update state
    let mut state = state;
    state.stage = Stage::Validated(Token {
        access_token: access_token.clone(),
        details: authorized_details.clone(),
    });
    StateStore::put(provider, &access_token, &state, state.expires_at)
        .await
        .map_err(|e| server!("issue saving state: {e}"))?;

    // return response
    Ok(TokenResponse {
        access_token,
        token_type: TokenType::Bearer,
        expires_in: Expire::Access.duration().num_seconds(),
        authorization_details: Some(authorized_details),
    })
}

impl Handler for Request<TokenRequest, NoHeaders> {
    type Response = TokenResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        token(issuer, provider, self.body)
    }
}

impl Body for TokenRequest {}

#[derive(Debug)]
struct Context<'a> {
    issuer: &'a str,
    state: State,
}

impl TokenRequest {
    // Verify the token request.
    async fn verify(&self, provider: &impl Provider, ctx: &Context<'_>) -> Result<()> {
        tracing::debug!("token::verify");

        if ctx.state.is_expired() {
            return Err(invalid!("authorization state expired"));
        }

        // TODO: support optional authorization issuers
        let Ok(server) = Metadata::server(provider, ctx.issuer, None).await else {
            return Err(invalid!("unknown authorization server"));
        };
        let Some(grant_types_supported) = &server.oauth.grant_types_supported else {
            return Err(server!("authorization server grant types not set"));
        };

        // grant_type
        match &self.grant_type {
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Stage::Offered(auth_state) = &ctx.state.stage else {
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
                if tx_code != &auth_state.tx_code {
                    return Err(Error::InvalidGrant("invalid `tx_code` provided".to_string()));
                }
            }
            TokenGrantType::AuthorizationCode {
                redirect_uri,
                code_verifier,
                ..
            } => {
                let Stage::Authorized(auth_state) = &ctx.state.stage else {
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
                if self.client_id.as_ref() != Some(&auth_state.client_id) {
                    return Err(Error::InvalidClient(
                        "`client_id` differs from authorized one".to_string(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &auth_state.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "`redirect_uri` differs from authorized one".to_string(),
                    ));
                }

                // verifier matches challenge received in authorization request
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("`code_verifier` is missing".to_string()));
                };
                if pkce::code_challenge(verifier) != auth_state.code_challenge {
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
        AuthorizationCredential::Format(fmt) => {
            issuer.credential_configuration_id(fmt).map_err(|e| server!("issuer issue: {e}"))?
        }
    };
    let config = issuer.credential_configuration(config_id).map_err(|e| {
        Error::InvalidAuthorizationDetails(format!("unknown credential configuration: {e}"))
    })?;

    // check claims are supported and include all mandatory claims
    config.verify_claims(claims).map_err(|e| Error::InvalidAuthorizationDetails(e.to_string()))?;

    Ok(())
}
