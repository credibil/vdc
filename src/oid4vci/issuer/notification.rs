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

use http::header::AUTHORIZATION;
use tracing::instrument;

use crate::invalid;
use crate::oid4vci::endpoint::{Body, Handler, Headers, Request};
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::State;
use crate::oid4vci::types::{NotificationHeaders, NotificationRequest, NotificationResponse};
use crate::oid4vci::{Error, Result};

/// Notification request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn notification(
    issuer: &str, provider: &impl Provider,
    request: Request<NotificationRequest, NotificationHeaders>,
) -> Result<NotificationResponse> {
    tracing::debug!("notification");

    println!("{:?}", request);

    let Some(headers) = request.headers else {
        return Err(invalid!("headers not set"));
    };
    let access_token = headers[AUTHORIZATION].to_str().map_err(|_| invalid!("no access token"))?;

    // verify access token
    let _ = StateStore::get::<State>(provider, access_token)
        .await
        .map_err(|_| Error::AccessDenied("invalid access token".to_string()))?;

    let request = request.body;
    let Ok(_state) = StateStore::get::<State>(provider, &request.notification_id).await else {
        return Err(Error::AccessDenied("invalid notification id".to_string()));
    };

    tracing::info!("notification: {:#?}, {:#?}", request.event, request.event_description,);

    Ok(NotificationResponse)
}

impl Handler for Request<NotificationRequest, NotificationHeaders> {
    type Response = NotificationResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        notification(issuer, provider, self)
    }
}

impl Body for NotificationRequest {}

impl Headers for NotificationHeaders {}
