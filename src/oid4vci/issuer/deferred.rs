//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the
//! Credential Endpoint or Batch Credential Endpoint in cases where the
//! Credential Issuer was not able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is
//! valid for the issuance of the Credential previously requested at the
//! Credential Endpoint or the Batch Credential Endpoint.

use tracing::instrument;

use crate::oid4vci::endpoint::{Body, Handler, Request};
use crate::oid4vci::issuer::credential::credential;
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::{Stage, State};
use crate::oid4vci::types::{
    CredentialHeaders, DeferredCredentialRequest, DeferredCredentialResponse, DeferredHeaders,
    ResponseType,
};
use crate::oid4vci::{Error, Result};
use crate::{invalid, server};

/// Deferred credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn deferred(
    issuer: &str, provider: &impl Provider,
    request: Request<DeferredCredentialRequest, DeferredHeaders>,
) -> Result<DeferredCredentialResponse> {
    tracing::debug!("deferred");

    let transaction_id = &request.body.transaction_id;

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<State>(provider, &transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".to_string()));
    };
    if state.is_expired() {
        return Err(invalid!("state expired"));
    }
    let Stage::Deferred(deferred_state) = state.stage else {
        return Err(server!("Deferred state not found."));
    };

    // make credential request
    let req = Request {
        body: deferred_state.credential_request,
        headers: CredentialHeaders {
            authorization: request.headers.authorization,
        },
    };
    let response = credential(issuer, provider, req).await?;

    // is issuance still pending?
    if let ResponseType::TransactionId { .. } = response.response {
        // TODO: make retry interval configurable
        return Err(Error::IssuancePending(5));
    }

    // remove deferred state item
    StateStore::purge(provider, &transaction_id)
        .await
        .map_err(|e| server!("issue purging state: {e}"))?;

    Ok(response)
}

impl Handler for Request<DeferredCredentialRequest, DeferredHeaders> {
    type Response = DeferredCredentialResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        deferred(issuer, provider, self)
    }
}

impl Body for DeferredCredentialRequest {}
