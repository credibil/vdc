//! # Handlers
//!
//! `Handlers` provide the entry point for the `OpenId4VP` API. Requests are
//! routed to the appropriate handler for processing, returning a response
//! that can be serialized to JSON or directly to HTTP (using the
//! [`crate::core::http::IntoHttp`] trait).

mod create_request;
mod metadata;
mod request_uri;
mod response;

pub use crate::error::Error;

/// Result type for `OpenID` for Verifiable Presentations.
pub type Result<T> = anyhow::Result<T, Error>;
