//! Wallet-initiated Tests

mod utils;
mod wallet;

use credibil_vc::oid4vci::types::{Format, ProfileW3c};
use rstest::rstest;
use test_issuer::ProviderImpl;
use utils::{Issuance, provider};

#[rstest]
#[case(Issuance::Immediate)]
#[case(Issuance::Deferred)]
async fn issuance(provider: ProviderImpl, #[case] issue: Issuance) {
    utils::init_tracer();
    snapshot!("wallet:{issue}");

    let wallet = wallet::Wallet {
        provider,
        format: Format::JwtVcJson(ProfileW3c::default()),
        ..Default::default()
    };

    wallet.self_initiated().await.expect("should get credential");
}
