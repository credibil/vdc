//! # Create Request Endpoint
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use to request Verifiable Presentations from an
//! End-User's Wallet.
//!
//! While based on the [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! specification, the endpoint only implements a subset of the specification
//! requirements as recommended in the [JWT VC Presentation Profile](https://identity.foundation/jwt-vc-presentation-profile).
//! Aside from reducing complexity, the profile enables greater presentation
//! interoperability between Wallets and Verifiers.
//!
//! The Verifier requests an Authorization Request be prepared by articulating
//! the Credential(s) desired using a Credential Definition and, optionally,
//! specifying the device flow that will be used.
//!
//! # Example
//!
//! ```json
//! {
//!     "purpose": "To verify employment",
//!     "input_descriptors": [{
//!         "id": "employment",
//!         "constraints": {
//!             "fields": [{
//!                 "path":["$.type"],
//!                 "filter": {
//!                     "type": "string",
//!                     "const": "EmployeeIDCredential"
//!                 }
//!             }]
//!         }
//!     }],
//!     "device_flow": "CrossDevice"
//! }
//! ```
//!
//! The prepared Authorization Request Object may be sent by value or by
//! reference as defined in JWT-Secured Authorization Request (JAR) [RFC9101](https://www.rfc-editor.org/rfc/rfc9101).
//! If sent by value, the Request Object is sent directly to the Wallet as a URL
//! fragment in the Authorization Request. If by reference, the Authorization
//! Request will contain a `request_uri` pointing to the prepared Request
//! Object.

use std::collections::HashMap;

use chrono::Utc;
use credibil_infosec::Algorithm;
use tracing::instrument;
use uuid::Uuid;

use crate::core::{Kind, generate};
use crate::dif_exch::{ClaimFormat, PresentationDefinition};
use crate::oid4vp::endpoint::{Body, Handler, Request};
use crate::oid4vp::provider::{Metadata, Provider, StateStore};
use crate::oid4vp::state::{Expire, State};
use crate::oid4vp::types::{
    ClientIdScheme, CreateRequestRequest, CreateRequestResponse, DeviceFlow, RequestObject,
    ResponseType,
};
use crate::oid4vp::{Error, Result};

// TODO: request supported Client Identifier schemes from the Wallet
// TODO: add support for other Client Identifier schemes

// StaticConfigurationValues
// {
//   "authorization_endpoint": "openid4vp:",
//   "response_types_supported": [
//     "vp_token"
//   ],
//   "vp_formats_supported": {
//     "jwt_vp_json": {
//       "alg_values_supported": ["ES256"]
//     },
//     "jwt_vc_json": {
//       "alg_values_supported": ["ES256"]
//     }
//   },
//   "request_object_signing_alg_values_supported": [
//     "ES256"
//   ]
// }

/// Initiate an Authorization Request flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn create_request(
    provider: &impl Provider, request: CreateRequestRequest,
) -> Result<CreateRequestResponse> {
    tracing::debug!("create_request");

    verify(&request).await?;

    // TODO: build dynamically...
    let fmt = ClaimFormat {
        alg: Some(vec![Algorithm::EdDSA.to_string()]),
        proof_type: None,
    };

    let pres_def = PresentationDefinition {
        id: Uuid::new_v4().to_string(),
        purpose: Some(request.purpose.clone()),
        input_descriptors: request.input_descriptors.clone(),
        format: Some(HashMap::from([("jwt_vc".to_string(), fmt)])),
        name: None,
    };
    let uri_token = generate::uri_token();

    // get client metadata
    let Ok(verifier_meta) = Metadata::verifier(provider, &request.client_id).await else {
        return Err(Error::InvalidRequest("invalid client_id".to_string()));
    };

    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(uri_token.clone()),
        nonce: generate::nonce(),
        presentation_definition: Kind::Object(pres_def),
        client_metadata: verifier_meta,
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        ..Default::default()
    };

    let mut response = CreateRequestResponse::default();

    // Response Mode "direct_post" is RECOMMENDED for cross-device flows.
    // TODO: replace hard-coded endpoints with Provider-set values
    if request.device_flow == DeviceFlow::CrossDevice {
        req_obj.response_mode = Some("direct_post".to_string());
        req_obj.client_id = format!("{}/post", request.client_id);
        req_obj.response_uri = Some(format!("{}/post", request.client_id));
        response.request_uri = Some(format!("{}/request/{uri_token}", request.client_id));
    } else {
        req_obj.client_id = format!("{}/callback", request.client_id);
        response.request_object = Some(req_obj.clone());
    }

    // save request object in state
    let state = State {
        expires_at: Utc::now() + Expire::Request.duration(),
        request_object: req_obj,
    };

    StateStore::put(provider, &uri_token, &state, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(response)
}

impl Handler for Request<CreateRequestRequest> {
    type Response = CreateRequestResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        create_request(provider, self.body)
    }
}

impl Body for CreateRequestRequest {}

#[allow(clippy::unused_async)]
async fn verify(request: &CreateRequestRequest) -> Result<()> {
    tracing::debug!("create_request::verify");

    if request.input_descriptors.is_empty() {
        return Err(Error::InvalidRequest("no credentials specified".to_string()));
    }
    Ok(())
}
