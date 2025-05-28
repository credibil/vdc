//! Examples
//!
//! Example Issuer, Wallet, and Verifier

use anyhow::{Result, anyhow};
use credibil_oid4vci::blockstore::BlockStore;
use credibil_oid4vci::{CreateOfferResponse, OfferType};
use credibil_oid4vp::GenerateResponse;
use examples::{issuer, verifier, wallet};
use http::StatusCode;
use serde_json::json;
use test_utils::issuer::Issuer;
use test_utils::issuer::data::{
    CLIENT, ISSUER as ISSUER_METADATA, NORMAL_USER, SERVER as SERVER_METADATA,
};
use test_utils::verifier::Verifier;
use test_utils::verifier::data::VERIFIER as VERIFIER_METADATA;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const ISSUER: &str = "localhost:8080";
const VERIFIER: &str = "localhost:8081";
const WALLET: &str = "localhost:8082";

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber).expect("should set subscriber");

    let issuer_id = format!("http://{ISSUER}");
    let verifier_id = format!("http://{VERIFIER}");
    let wallet_id = format!("http://{WALLET}");

    // initialize issuer
    let issuer = Issuer::new(&issuer_id).await;
    BlockStore::put(&issuer, "owner", "ISSUER", &issuer_id, ISSUER_METADATA).await?;
    BlockStore::put(&issuer, "owner", "SERVER", &issuer_id, SERVER_METADATA).await?;
    BlockStore::put(&issuer, "owner", "SUBJECT", "normal_user", NORMAL_USER).await?;
    BlockStore::put(&issuer, "owner", "CLIENT", &format!("http://{WALLET}"), CLIENT).await?;
    issuer::serve(ISSUER, issuer).await?;

    // initialize verifier
    let verifier = Verifier::new(&verifier_id).await;
    BlockStore::put(&verifier, "owner", "VERIFIER", &verifier_id, VERIFIER_METADATA).await?;
    verifier::serve(VERIFIER, verifier).await?;

    // initialize wallet
    let wallet = test_utils::wallet::Wallet::new(&wallet_id).await;
    wallet::serve(WALLET, wallet).await?;

    // issue credentials
    let offer = create_offer().await?;
    make_offer(&offer).await?;

    // verify credentials
    let request = create_request().await?;
    request_authorization(&request).await?;

    Ok(())
}

async fn create_offer() -> Result<CreateOfferResponse> {
    let client = reqwest::Client::new();

    let value = json!({
        "subject_id": "normal_user",
        "credential_configuration_ids": ["Identity_SD_JWT"],
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "pre-authorize": true,
        "tx_code_required": true
    });

    let http_resp =
        client.post(format!("http://{ISSUER}/create_offer")).json(&value).send().await?;
    if http_resp.status() != StatusCode::CREATED {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    http_resp
        .json::<CreateOfferResponse>()
        .await
        .map_err(|e| anyhow!("issue deserializing offer: {e}"))
}

async fn make_offer(response: &CreateOfferResponse) -> Result<()> {
    let client = reqwest::Client::new();

    let OfferType::Uri(uri) = &response.offer_type else {
        return Err(anyhow!("expected offer URI"));
    };
    let Some(tx_code) = &response.tx_code else {
        return Err(anyhow!("expected transaction code"));
    };

    let url =
        format!("http://{WALLET}/credential_offer?credential_offer_uri={uri}&tx_code={tx_code}");

    let http_resp = client.get(url).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    Ok(())
}

async fn create_request() -> Result<GenerateResponse> {
    let client = reqwest::Client::new();

    let value = json!({
        "client_id": "http://localhost:8081",
        "response_mode": "direct_post.jwt",
        "response_uri": "http://localhost:8081/post",
        "device_flow": "CrossDevice",
        "dcql_query": {
            "credentials": [
                {
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
                }
            ]
        }
    });

    let http_resp =
        client.post(format!("http://{VERIFIER}/create_request")).json(&value).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    http_resp
        .json::<GenerateResponse>()
        .await
        .map_err(|e| anyhow!("issue deserializing offer: {e}"))
}

async fn request_authorization(response: &GenerateResponse) -> Result<()> {
    let client = reqwest::Client::new();

    let client_id = format!("redirect_uri:http://{VERIFIER}/post");
    let GenerateResponse::Uri(uri) = response else {
        return Err(anyhow!("expected request URI"));
    };

    let url = format!(
        "http://{WALLET}/authorize?client_id={client_id}&request_uri={uri}&request_uri_method=post"
    );
    let http_resp = client.get(url).send().await?;
    if http_resp.status() != StatusCode::OK {
        let body = http_resp.text().await?;
        return Err(anyhow!("{body}"));
    }

    Ok(())
}
