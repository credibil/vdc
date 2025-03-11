#![allow(missing_docs)]
#![allow(dead_code)]

mod auth;
pub mod issuer;
pub mod wallet;

use std::fmt::Display;
use std::sync::Once;

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// initalise tracing once for all tests
static INIT: Once = Once::new();

/// Configure Insta snapshot name.
///
/// # Example
///
/// ```rust,ignore
/// snapshot!("issuer:immediate");
///
/// ...
///
/// assert_snapshot!("credential", vc, {
///    ".validFrom" => "[validFrom]",
///    ".credentialSubject" => insta::sorted_redaction()
/// });
/// ```
///
/// will result in a snapshot named `credential@issuer:immediate.snap`.
#[macro_export]
macro_rules! snapshot{
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_suffix(format!($($expr,)*));
        settings.set_prepend_module_to_snapshot(false);
        let _guard = settings.bind_to_scope();
    }
}

/// Initialise tracing for tests.
///
/// # Panics
///
/// Panics if the tracing subscriber cannot be set.
pub fn init_tracer() {
    INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
        tracing::subscriber::set_global_default(subscriber).expect("subscriber set");
    });
}

/// Issuance variants
pub enum Issuance {
    /// Immediate issuance
    Immediate,
    /// Deferred issuance
    Deferred,
}

impl Display for Issuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Issuance::Immediate => write!(f, "immediate"),
            Issuance::Deferred => write!(f, "deferred"),
        }
    }
}
