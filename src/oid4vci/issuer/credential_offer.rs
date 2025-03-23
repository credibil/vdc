//! # Credential Offer Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created
//! Credential Offer.
//!
//! The Credential Offer is created by the Issuer when calling the `Create
//! Offer` endpoint to create an Credential Offer. Instead of sending the Offer
//! to the Wallet, the Issuer sends a response containing a
//! `credential_offer_uri` which can be used to retrieve the saved Credential
//! Offer.
//!
//! Per the [JWT VC Issuance Profile], the Credential Offer MUST be returned as
//! an encoded JWT.
//!
//! [JWT VC Issuance Profile]: (https://identity.foundation/jwt-vc-issuance-profile)

use crate::oid4vci::Result;
use crate::oid4vci::endpoint::{Body, Handler, NoHeaders, Request, Response};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::{Stage, State};
use crate::oid4vci::types::{CredentialOfferRequest, CredentialOfferResponse};
use crate::{invalid, server};

/// Endpoint for the Wallet to request the Issuer's Credential Offer when
/// engaged in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn credential_offer(
    _issuer: &str, provider: &impl Provider, request: CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    // retrieve and then purge Credential Offer from state
    let state = StateStore::get::<State>(provider, &request.id)
        .await
        .map_err(|e| server!("issue fetching state: {e}"))?;
    StateStore::purge(provider, &request.id)
        .await
        .map_err(|e| server!("issue purging state: {e}"))?;

    if state.is_expired() {
        return Err(invalid!("state expired"));
    }

    let Stage::Pending(credential_offer) = state.stage else {
        return Err(invalid!("no credential offer found"));
    };

    Ok(CredentialOfferResponse { credential_offer })
}

impl Handler for Request<CredentialOfferRequest, NoHeaders> {
    type Response = CredentialOfferResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<impl Into<Response<Self::Response>>>> + Send {
        credential_offer(issuer, provider, self.body)
    }
}

impl Body for CredentialOfferRequest {}
