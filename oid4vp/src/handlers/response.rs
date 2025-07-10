//! # Response Endpoint
//!
//! This endpoint is where the Wallet **redirects** to when returning an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).
//! Authorization Response when both Wallet and Verifier interact on the same
//! device. That is, during a 'same-device flow'.
//!
//! The Wallet only returns a VP Token if the corresponding Authorization
//! Request contained a `presentation_definition` parameter, a
//! `presentation_definition_uri` parameter, or a `scope` parameter representing
//! a Presentation Definition.
//!
//! The VP Token can be returned in the Authorization Response or the Token
//! Response depending on the Response Type used.
//!
//! If the Authorization Request's Response Type value is "`vp_token`", the VP
//! Token is returned in the Authorization Response. When the Response Type
//! value is "`vp_token id_token`" and the scope parameter contains "openid",
//! the VP Token is returned in the Authorization Response alongside a
//! Self-Issued ID Token as defined in [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).
//!
//! If the Response Type value is "code" (Authorization Code Grant Type), the VP
//! Token is provided in the Token Response.

use anyhow::Context;
use credibil_core::Kind;
use credibil_core::api::{Body, Handler, Request, Response};
use credibil_vdc::dcql::{FormatQuery, Queryable};
use credibil_vdc::{mso_mdoc, sd_jwt, w3c_vc};

use crate::error::invalid;
use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::types::{AuthorizationResponse, RedirectResponse, RequestObject};

/// Endpoint for the Wallet to respond Verifier's Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn response(
    verifier: &str, provider: &impl Provider, request: AuthorizationResponse,
) -> Result<RedirectResponse> {
    // FIXME: handle case where Wallet returns error instead of presentation
    verify(verifier, provider, &request).await?;

    // retrive state and clear
    let Some(state_key) = &request.state else {
        return Err(invalid!("client state not found"));
    };
    StateStore::purge(provider, verifier, state_key).await.context("purging state")?;

    Ok(RedirectResponse {
        // FIXME: add response to state using `response_code` so Wallet can fetch full response
        // FIXME: align redirct_uri to spec
        // redirect_uri: Some(format!("http://localhost:3000/cb#response_code={}", "1234")),
        redirect_uri: Some("http://localhost:3000/cb".to_string()),
        response_code: None,
    })
}

impl<P: Provider> Handler<RedirectResponse, P> for Request<AuthorizationResponse> {
    type Error = Error;

    async fn handle(self, verifier: &str, provider: &P) -> Result<Response<RedirectResponse>> {
        Ok(response(verifier, provider, self.body).await?.into())
    }
}

impl Body for AuthorizationResponse {}

// Verfiy the `vp_token` and presentation against the `dcql_query`.
async fn verify(
    verifier: &str, provider: &impl Provider, request: &AuthorizationResponse,
) -> Result<()> {
    // get state by client state key
    let Some(state_key) = &request.state else {
        return Err(invalid!("client state not found"));
    };
    let Ok(state) = StateStore::get::<RequestObject>(provider, verifier, state_key).await else {
        return Err(invalid!("state not found"));
    };

    let request_object = &state.body;
    let dcql_query = &request_object.dcql_query;

    // verify presentation matches query:
    //  FIXME: verify request has been fulfilled for each credential requested:
    //  FIXME: check VC format matches a requested format
    //  FIXME: verify query constraints have been met
    //  FIXME: verify VC is valid (hasn't expired, been revoked, etc)

    let mut found = vec![];

    // process each presentation
    for (query_id, presentations) in &request.vp_token {
        let Some(query) = dcql_query.credentials.iter().find(|q| q.id == *query_id) else {
            return Err(invalid!("query not found: {query_id}"));
        };

        let nonce = &request_object.nonce;
        let client_id = &request_object.client_id.to_string();

        for vp in presentations {
            let claims = match query.format {
                FormatQuery::DcSdJwt { .. } => sd_jwt::verify_vp(vp, nonce, client_id, provider)
                    .await
                    .map_err(|e| invalid!("failed to verify presentation: {e}"))?,
                FormatQuery::MsoMdoc { .. } => mso_mdoc::verify_vp(vp, provider)
                    .await
                    .map_err(|e| invalid!("failed to verify presentation: {e}"))?,
                FormatQuery::JwtVcJson { .. } => w3c_vc::verify_vp(vp, nonce, client_id, provider)
                    .await
                    .map_err(|e| invalid!("failed to verify presentation: {e}"))?,
                _ => {
                    return Err(invalid!("unsupported format: {:?}", query.format));
                }
            };

            found.push(Queryable {
                meta: query.format.clone().into(),
                claims,
                credential: Kind::String(String::new()),
            });
        }
    }

    // re-query presentations to confirm the query constraints have been met
    let result =
        dcql_query.execute(&found).map_err(|e| invalid!("failed to execute query: {e}"))?;

    if request.vp_token.len() != result.len() {
        return Err(invalid!("presentation does not match query: {}", result.len()));
    }

    // FIXME: look up credential status using status.id
    // if let Some(_status) = &vc.credential_status {
    //     // FIXME: look up credential status using status.id
    // }

    // FIXME: perform Verifier policy checks
    // Checks based on the set of trust requirements such as trust frameworks
    // it belongs to (i.e., revocation checks), if applicable.

    Ok(())
}
