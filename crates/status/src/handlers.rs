//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

mod statuslist;

pub use credibil_core::api::{Body, Client, Handler, Headers, Request, RequestBuilder, Response};

use crate::error::Error;

/// Result type for Token Status endpoints.
pub type Result<T> = anyhow::Result<T, Error>;
