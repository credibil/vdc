//! Examples
//!
//! Example Issuer, Wallet, and Verifier

use anyhow::Result;
// use examples::{issuer, verifier, wallet};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber).expect("should set subscriber");

    // issuer::serve("localhost:8080").await?;
    // verifier::serve("localhost:8081").await?;
    // wallet::serve("localhost:8082").await?;

    // block until `ctrl-c`
    Ok(tokio::signal::ctrl_c().await?)
}

// TODO:
// - pre-load wallet with some credentials
// - load issuer metadata, clients, etc.
// - replace references to hard-coded IDs with dynamic ones
