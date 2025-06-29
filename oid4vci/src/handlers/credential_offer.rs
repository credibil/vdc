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

use anyhow::Context as _;
use credibil_core::api::{Body, Handler, Request, Response};

use crate::error::invalid;
use crate::handlers::{Error, Result};
use crate::provider::{Provider, StateStore};
use crate::types::{CredentialOffer, CredentialOfferRequest, CredentialOfferResponse};

/// Endpoint for the Wallet to request the Issuer's Credential Offer when
/// engaged in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn credential_offer(
    issuer: &str, provider: &impl Provider, request: CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    let state = StateStore::get::<CredentialOffer>(provider, issuer, &request.id)
        .await
        .context("credential offer not found in state")?;
    StateStore::purge(provider, issuer, &request.id).await.context("purging state")?;

    if state.is_expired() {
        return Err(invalid!("state expired"));
    }

    Ok(CredentialOfferResponse(state.body))
}

impl<P: Provider> Handler<CredentialOfferResponse, P> for Request<CredentialOfferRequest> {
    type Error = Error;

    async fn handle(self, issuer: &str, provider: &P) -> Result<Response<CredentialOfferResponse>> {
        Ok(credential_offer(issuer, provider, self.body).await?.into())
    }
}

impl Body for CredentialOfferRequest {}
