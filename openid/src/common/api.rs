//! # API
//!
//! The api module provides the entry point to the public API. Requests are routed
//! to the appropriate handler for processing, returning a response that can
//! be serialized to a JSON object or directly to HTTP.

use std::fmt::Debug;

pub use credibil_core::api::*;

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Handler<P> {
    /// The provider type used to access the implementer's capability provider.
    type Provider;
    /// The inner reply type specific to the implementing message.
    type Response;
    /// The error type returned by the handler.
    type Error;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, issuer: &str, provider: &Self::Provider,
    ) -> impl Future<Output = Result<impl Into<Response<Self::Response>>, Self::Error>> + Send;
}

/// Implement empty headers for use by handlers that do not require headers.
#[derive(Clone, Debug)]
pub struct NoHeaders;
impl Headers for NoHeaders {}
