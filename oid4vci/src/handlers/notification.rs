// TODO: implement Notification endpoint

//! # Notification Endpoint
//!
//! This endpoint is used by the Wallet to notify the Credential Issuer of
//! certain events for issued Credentials. These events enable the Credential
//! Issuer to take subsequent actions after issuance.
//!
//! The Credential Issuer needs to return one or
//! more `notification_id` parameters in the Credential Response or the Batch
//! Credential Response for the Wallet to be able to use this Endpoint. Support
//! for this endpoint is OPTIONAL. The Issuer cannot assume that a notification
//! will be sent for every issued credential since the use of this Endpoint is
//! not mandatory for the Wallet.
//!
//! The notification from the Wallet is idempotent. When the Credential Issuer
//! receives multiple identical calls from the Wallet for the same
//! `notification_id`, it returns success. Due to the network errors, there are
//! no guarantees that a Credential Issuer will receive a notification within a
//! certain time period or at all.

use credibil_api::{Body, Handler, Headers, Request, Response};

use crate::handlers::{Error, NotificationHeaders, Result};
use crate::provider::{Provider, StateStore};
use crate::state::Token;
use crate::types::{NotificationRequest, NotificationResponse};

/// Notification request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn notification(
    issuer: &str, provider: &impl Provider,
    request: Request<NotificationRequest, NotificationHeaders>,
) -> Result<NotificationResponse> {
    // verify access token
    let _ = StateStore::get::<Token>(provider, issuer, &request.headers.authorization)
        .await
        .map_err(|_e| Error::AccessDenied("invalid access token".to_string()))?;

    let request = request.body;
    let Ok(_state) = StateStore::get::<Token>(provider, issuer, &request.notification_id).await
    else {
        return Err(Error::AccessDenied("invalid notification id".to_string()));
    };

    tracing::info!("notification: {:#?}, {:#?}", request.event, request.event_description,);

    Ok(NotificationResponse)
}

impl<P: Provider> Handler<NotificationResponse, P>
    for Request<NotificationRequest, NotificationHeaders>
{
    type Error = Error;

    async fn handle(self, owner: &str, provider: &P) -> Result<Response<NotificationResponse>> {
        Ok(notification(owner, provider, self).await?.into())
    }
}

impl Body for NotificationRequest {}

impl Headers for NotificationHeaders {}
