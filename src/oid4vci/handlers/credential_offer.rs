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

use crate::oid4vci::error::invalid;
use crate::oid4vci::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::issuer::{CredentialOffer, CredentialOfferRequest, CredentialOfferResponse};

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
    let state = StateStore::get::<CredentialOffer>(provider, &request.id)
        .await
        .context("credential offer not found in state")?;
    StateStore::purge(provider, &request.id).await.context("purging state")?;

    if state.is_expired() {
        return Err(invalid!("state expired"));
    }

    Ok(CredentialOfferResponse {
        credential_offer: state.body,
    })
}

impl<P: Provider> Handler<P> for Request<CredentialOfferRequest> {
    type Error = Error;
    type Provider = P;
    type Response = CredentialOfferResponse;

    async fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        credential_offer(issuer, provider, self.body).await
    }
}

impl Body for CredentialOfferRequest {}
