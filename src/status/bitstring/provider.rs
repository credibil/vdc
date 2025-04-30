//! Status Provider

/// Result is used for all external errors.
pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;
