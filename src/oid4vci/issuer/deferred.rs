//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the
//! Credential Endpoint or Batch Credential Endpoint in cases where the
//! Credential Issuer was not able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is
//! valid for the issuance of the Credential previously requested at the
//! Credential Endpoint or the Batch Credential Endpoint.

use anyhow::Context as _;

use crate::invalid;
use crate::oid4vci::endpoint::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::issuer::credential::credential;
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Deferrance;
use crate::oid4vci::types::{
    CredentialHeaders, CredentialResponse, DeferredCredentialRequest, DeferredCredentialResponse,
    DeferredHeaders,
};

/// Deferred credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn deferred(
    issuer: &str, provider: &impl Provider,
    request: Request<DeferredCredentialRequest, DeferredHeaders>,
) -> Result<DeferredCredentialResponse> {
    let transaction_id = &request.body.transaction_id;

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<Deferrance>(provider, transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".to_string()));
    };
    if state.is_expired() {
        return Err(invalid!("state expired"));
    }

    // make credential request
    let req = Request {
        body: state.body.credential_request,
        headers: CredentialHeaders {
            authorization: request.headers.authorization,
        },
    };
    let response = credential(issuer, provider, req).await?;

    // is issuance still pending?
    if let CredentialResponse::TransactionId { .. } = response {
        // TODO: make retry interval configurable
        return Err(Error::IssuancePending(5));
    }

    // remove deferred state item
    StateStore::purge(provider, transaction_id).await.context("purging state")?;

    Ok(response)
}

impl<P: Provider> Handler<P> for Request<DeferredCredentialRequest, DeferredHeaders> {
    type Error = Error;
    type Provider = P;
    type Response = DeferredCredentialResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        deferred(issuer, provider, self).await
    }
}

impl Body for DeferredCredentialRequest {}
