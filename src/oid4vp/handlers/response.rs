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

use serde_json::Value;
use serde_json_path::JsonPath;
use tracing::instrument;

use crate::core::Kind;
use crate::oid4vp::endpoint::{Body, Handler, Request};
use crate::oid4vp::provider::{Provider, StateStore};
use crate::oid4vp::state::State;
use crate::oid4vp::types::{ResponseRequest, ResponseResponse};
use crate::oid4vp::{Error, Result};
use crate::w3c_vc;
use crate::w3c_vc::model::VerifiableCredential;
use crate::w3c_vc::proof::{Payload, Verify};

/// Endpoint for the Wallet to respond Verifier's Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn response(
    credential_issuer: &str, provider: &impl Provider, request: ResponseRequest,
) -> Result<ResponseResponse> {
    tracing::debug!("response");

    // TODO: handle case where Wallet returns error instead of submission
    verify(provider.clone(), &request).await?;

    // clear state
    let Some(state_key) = &request.state else {
        return Err(Error::InvalidRequest("client state not found".to_string()));
    };
    StateStore::purge(provider, state_key)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    Ok(ResponseResponse {
        // TODO: add response to state using `response_code` so Wallet can fetch full response
        // TODO: align redirct_uri to spec
        // redirect_uri: Some(format!("http://localhost:3000/cb#response_code={}", "1234")),
        redirect_uri: Some("http://localhost:3000/cb".to_string()),
        response_code: None,
    })
}

impl Handler for Request<ResponseRequest> {
    type Response = ResponseResponse;

    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        response(credential_issuer, provider, self.body)
    }
}

impl Body for ResponseRequest {}

// TODO: validate  Verifiable Presentation by format
// Check integrity, authenticity, and holder binding of each Presentation
// in the VP Token according to the rules for the Presentation's format.

// Verfiy the vp_token and presentation subm
#[allow(clippy::too_many_lines)]
async fn verify(provider: impl Provider, request: &ResponseRequest) -> Result<()> {
    tracing::debug!("response::verify");

    // get state by client state key
    let Some(state_key) = &request.state else {
        return Err(Error::InvalidRequest("client state not found".to_string()));
    };
    let Ok(state) = StateStore::get::<State>(&provider, state_key).await else {
        return Err(Error::InvalidRequest("state not found".to_string()));
    };
    let saved_req = &state.request_object;

    let Some(vp_token) = request.vp_token.clone() else {
        return Err(Error::InvalidRequest("vp_token not founnd".to_string()));
    };

    let mut vps = vec![];

    // check nonce matches
    for vp_val in &vp_token {
        let (vp, nonce) = match w3c_vc::proof::verify(Verify::Vp(vp_val), provider.clone()).await {
            Ok(Payload::Vp { vp, nonce, .. }) => (vp, nonce),
            Ok(_) => return Err(Error::InvalidRequest("proof payload is invalid".to_string())),
            Err(e) => return Err(Error::ServerError(format!("issue verifying VP proof: {e}"))),
        };

        // else {
        //     return Err(Error::InvalidRequest("invalid vp_token".to_string()));
        // };
        if nonce != saved_req.nonce {
            return Err(Error::InvalidRequest("nonce does not match".to_string()));
        }
        vps.push(vp);
    }

    let Some(subm) = &request.presentation_submission else {
        return Err(Error::InvalidRequest("no presentation_submission".to_string()));
    };
    let def = match &saved_req.presentation_definition {
        Kind::Object(def) => def,
        Kind::String(_) => {
            return Err(Error::InvalidRequest(
                "presentation_definition_uri is unsupported".to_string(),
            ));
        }
    };

    // verify presentation subm matches definition
    // N.B. technically, this is redundant as it is done when looking up state
    if subm.definition_id != def.id {
        return Err(Error::InvalidRequest("definition_ids do not match".to_string()));
    }

    let input_descs = &def.input_descriptors;
    let desc_map = &subm.descriptor_map;

    // convert VP Token to JSON Value for JSONPath querying
    // N.B. because of Mapping path syntax, we need to convert single entry
    // Vec to an req_obj

    let vp_val: Value = match vps.len() {
        1 => serde_json::to_value(vps[0].clone())
            .map_err(|e| Error::ServerError(format!("issue converting VP to Value: {e}")))?,
        _ => serde_json::to_value(vps)
            .map_err(|e| Error::ServerError(format!("issue aggregating vp values: {e}")))?,
    };

    // Verify request has been fulfilled for each credential requested:
    //  - use the Input Descriptor Mapping Object(s) in the Submission to identify
    //    the matching VC in the VP Token, and verify the VC.
    for input in input_descs {
        // find Input Descriptor Mapping Object
        let Some(mapping) = desc_map.iter().find(|idmo| idmo.id == input.id) else {
            return Err(Error::InvalidRequest(format!(
                "input descriptor mapping req_obj not found for {}",
                input.id
            )));
        };

        // check VC format matches a requested format
        if let Some(fmt) = input.format.as_ref() {
            if !fmt.contains_key(&mapping.path_nested.format) {
                return Err(Error::InvalidRequest(format!(
                    "invalid format {}",
                    mapping.path_nested.format
                )));
            }
        }

        // search VP Token for VC specified by mapping path
        let jpath = JsonPath::parse(&mapping.path_nested.path)
            .map_err(|e| Error::ServerError(format!("issue parsing JSON Path: {e}")))?;
        let Ok(vc_node) = jpath.query(&vp_val).exactly_one() else {
            return Err(Error::InvalidRequest(format!(
                "no match for path_nested {}",
                mapping.path_nested.path
            )));
        };

        let vc_kind: Kind<VerifiableCredential> = match vc_node {
            Value::String(token) => Kind::String(token.to_string()),
            Value::Object(_) => {
                let vc: VerifiableCredential = serde_json::from_value(vc_node.clone())
                    .map_err(|e| Error::ServerError(format!("issue deserializing vc: {e}")))?;
                Kind::Object(vc)
            }
            _ => return Err(Error::InvalidRequest(format!("unexpected VC format: {vc_node}"))),
        };

        let Payload::Vc { vc, .. } = w3c_vc::proof::verify(Verify::Vc(&vc_kind), provider.clone())
            .await
            .map_err(|e| Error::InvalidRequest(format!("invalid VC proof: {e}")))?
        else {
            return Err(Error::InvalidRequest("proof payload is invalid".to_string()));
        };

        // verify input constraints have been met
        if !input
            .constraints
            .satisfied(&vc)
            .map_err(|e| Error::ServerError(format!("issue matching constraints: {e}")))?
        {
            return Err(Error::InvalidRequest("input constraints not satisfied".to_string()));
        }

        // check VC is valid (hasn't expired, been revoked, etc)
        if vc.valid_until.is_some_and(|exp| exp < chrono::Utc::now()) {
            return Err(Error::InvalidRequest("credential has expired".to_string()));
        }

        // TODO: look up credential status using status.id
        // if let Some(_status) = &vc.credential_status {
        //     // TODO: look up credential status using status.id
        // }
    }

    // TODO: perform Verifier policy checks
    // Checks based on the set of trust requirements such as trust frameworks
    // it belongs to (i.e., revocation checks), if applicable.

    Ok(())
}
