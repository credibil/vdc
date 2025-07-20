//! Examples
//!
//! Example Issuer, Wallet, and Verifier

use anyhow::{Context, Result, anyhow};
use credibil_oid4vci::{CreateOfferResponse, OfferType};
use credibil_oid4vp::{AuthorizationRequest, CreateResponse};
use examples::{issuer, verifier, wallet};
use http::StatusCode;
use serde_json::json;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const ISSUER: &str = "http://localhost:8080";
const VERIFIER: &str = "http://localhost:8081";
const WALLET: &str = "http://localhost:8082";

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    issuer::serve(ISSUER).await?;
    verifier::serve(VERIFIER).await?;
    wallet::serve(WALLET).await?;

    // issue credentials
    let offer = create_offer().await?;
    make_offer(&offer).await?;

    // verify credentials
    let response = create_request().await?;
    request_authorization(&response.0).await?;

    Ok(())
}

async fn create_offer() -> Result<CreateOfferResponse> {
    let request = json!({
        "subject": "alice",
        "credential_configuration_ids": ["Identity_SD_JWT"],
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "pre-authorize": true,
        "tx_code_required": true
    });
    let http_resp =
        reqwest::Client::new().post(format!("{ISSUER}/create_offer")).json(&request).send().await?;
    if http_resp.status() != StatusCode::CREATED {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }
    http_resp.json::<CreateOfferResponse>().await.context("issue deserializing")
}

async fn make_offer(response: &CreateOfferResponse) -> Result<()> {
    let OfferType::Uri(uri) = &response.offer_type else {
        return Err(anyhow!("expected offer URI"));
    };
    let Some(tx_code) = &response.tx_code else {
        return Err(anyhow!("expected transaction code"));
    };
    let url = format!("{WALLET}/credential_offer?credential_offer_uri={uri}&tx_code={tx_code}");

    let http_resp = reqwest::Client::new().get(url).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    Ok(())
}

async fn create_request() -> Result<CreateResponse> {
    let request = json!({
        "client_id": VERIFIER,
        "response_mode": "direct_post.jwt",
        "response_uri": format!("{VERIFIER}/post"),
        "device_flow": "CrossDevice",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["Identity_SD_JWT"]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address"]}
                ]
            }]
        }
    });

    let client = reqwest::Client::new();
    let http_resp = client.post(format!("{VERIFIER}/create_request")).json(&request).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }
    http_resp.json::<CreateResponse>().await.context("issue deserializing")
}

async fn request_authorization(auth_req: &AuthorizationRequest) -> Result<()> {
    let client = reqwest::Client::new();

    let qs = auth_req.url_encode()?;
    let http_resp = client.get(format!("{WALLET}/authorize?{qs}")).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    Ok(())
}
