#![allow(missing_docs)]

//! Issuer-initiated Tests

mod utils;
mod wallet;

use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::types::{CreateOfferRequest, FormatProfile, ProfileW3c, SendType};
use rstest::rstest;
use serde_json::json;
use test_issuer::{BOB_ID, CAROL_ID, CREDENTIAL_ISSUER, ProviderImpl};
use utils::{Issuance, provider};

/// Immediate and deferred issuance variants
#[rstest]
#[case(Issuance::Immediate)]
#[case(Issuance::Deferred)]
async fn issuance(provider: ProviderImpl, #[case] issue: Issuance) {
    utils::init_tracer();

    let subject_id = match issue {
        Issuance::Immediate => BOB_ID,
        Issuance::Deferred => CAROL_ID,
    };

    let value = json! ({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_W3C_VC"],
        "subject_id": subject_id,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider,
        tx_code: response.tx_code,
        format: FormatProfile::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

/// Credential format variants
#[rstest]
#[case(FormatProfile::JwtVcJson(ProfileW3c::default()))]
async fn format(provider: ProviderImpl, #[case] credential_format: FormatProfile) {
    utils::init_tracer();
    snapshot!("issuer:{credential_format}");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_W3C_VC"],
        "subject_id": BOB_ID,
         "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: credential_format,
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

// Authorization Code flow
#[rstest]
async fn authorization(provider: ProviderImpl) {
    utils::init_tracer();
    snapshot!("issuer:authorization");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_W3C_VC"],
        "subject_id": BOB_ID,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: FormatProfile::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

// Send Credential Offer ByRef and ByVal
#[rstest]
#[case(SendType::ByRef)]
#[case(SendType::ByVal)]
async fn offer_type(provider: ProviderImpl, #[case] send_type: SendType) {
    utils::init_tracer();
    snapshot!("issuer:authorization:{send_type:?}");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_W3C_VC"],
        "subject_id": BOB_ID,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": send_type,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: FormatProfile::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}
