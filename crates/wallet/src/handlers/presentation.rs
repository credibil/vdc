use std::str::FromStr;

use anyhow::{Context, Result, anyhow, ensure};
use credibil_binding::ecc::Algorithm;
use credibil_binding::resolve_jwk;
use credibil_oid4vp::jose::Jwt;
use credibil_oid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientId, RequestObject, RequestUriMethod,
    RequestUriRequest, RequestUriResponse, ResponseMode, SubmissionResponse, VpFormat,
    WalletMetadata, jose, vp_token,
};
use futures::executor::block_on;
use wasi_http_ext::{Client, Request, Response};

use crate::provider::Wallet;

// Authorize a presentation to a verifier.
pub fn authorize(request: &Request) -> Result<Response> {
    let Some(captures) = request.captures() else {
        return Err(anyhow!("captures are missing"));
    };
    let Some(subject) = captures.get("subject") else {
        return Err(anyhow!("`subject` capture is missing"));
    };
    let host = request.host();
    let uri = request.uri();

    let owner = format!("{host}/{subject}");
    let provider = block_on(async { Wallet::new(&owner).await }).context("creating provider")?;

    // extract the credential offer URI from the query string
    let Some(query) = uri.query() else {
        return Err(anyhow!("missing query string"));
    };

    // --------------------------------------------------
    // Fetch Authorization Request Object
    // --------------------------------------------------
    let auth_req = AuthorizationRequest::from_str(query).context("deserializing request")?;
    let req_uri = match &auth_req {
        AuthorizationRequest::Uri(req_uri) => req_uri,
        AuthorizationRequest::Object(_) => return Err(anyhow!("expected request URI")),
    };
    ensure!(
        req_uri.request_uri_method == Some(RequestUriMethod::Post),
        "`request_uri_method` must be 'post'"
    );

    let object_req = RequestUriRequest {
        id: req_uri.request_uri.clone(),
        wallet_metadata: Some(WalletMetadata {
            vp_formats_supported: Some(vec![VpFormat::DcSdJwt {
                sd_jwt_alg_values: Some(vec![Algorithm::EdDSA]),
                kb_jwt_alg_values: Some(vec![Algorithm::EdDSA]),
            }]),
            ..Default::default()
        }),
        // FIXME: generate nonce
        wallet_nonce: Some("qPmxiNFCR3QTm19POc8u".to_string()),
    };
    let http_resp = Client::new()
        .get(&req_uri.request_uri)
        .form(object_req)
        .send()
        .context("fetching authorization request")?;

    // --------------------------------------------------
    // Verify the Authorization Request
    // --------------------------------------------------
    let request_uri: RequestUriResponse =
        http_resp.json().context("parsing authorization request")?;
    let RequestUriResponse::Jwt(jwt) = request_uri else {
        return Err(anyhow!("expected JWT in response"));
    };
    let resolver = async |kid: String| resolve_jwk(&kid, &provider).await;
    let decoded: Jwt<RequestObject> =
        block_on(async { jose::decode_jws(&jwt, resolver).await }).context("decoding JWT")?;
    let request_object = decoded.claims;

    // --------------------------------------------------
    // Process the Authorization Request
    // --------------------------------------------------
    let credentials = provider.fetch().context("fetching credentials")?;
    let results =
        request_object.dcql_query.execute(&credentials).context("executing DCQL query")?;
    ensure!(!results.is_empty(), "no matching credentials found");

    // --------------------------------------------------
    // Generate a VP token
    // --------------------------------------------------
    let vp_token =
        block_on(async { vp_token::generate(&request_object, &results, &provider).await })
            .context("generating VP token")?;
    let auth_resp = AuthorizationResponse { vp_token, state: request_object.state };

    // --------------------------------------------------
    // Return an Authorization Response to verifier
    // --------------------------------------------------
    let response_uri = match &request_object.response_mode {
        ResponseMode::DirectPostJwt { response_uri }
        | ResponseMode::DirectPost { response_uri } => response_uri,
        ResponseMode::Fragment { .. } => {
            return Err(anyhow!("`response_mode` must be 'direct_post'"));
        }
    };
    ensure!(req_uri.client_id == ClientId::RedirectUri(response_uri.clone()), "invalid client id");

    let response = Client::new()
        .post(response_uri)
        .form(auth_resp)
        .send()
        .context("issuing authorization response")?;

    // --------------------------------------------------
    // Redirect the user agent to the endpoint indicated
    // --------------------------------------------------
    // FIXME: handle the redirect response
    let subm_resp =
        response.json::<SubmissionResponse>().context("deserializing submission response")?;
    Ok(subm_resp.vp_data_id.into_bytes().into())
}
