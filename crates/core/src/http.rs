//! # HTTP
//!
//! HTTP helper methods.

use bytes::Bytes;
use http::{Response, StatusCode, header};
use serde::Serialize;

use crate::api;

/// Trait for converting a `Result` into an HTTP response.
pub trait IntoHttp {
    /// The body type of the HTTP response.
    type Body: http_body::Body<Data = Bytes> + Send + 'static;

    /// Convert into an HTTP response.
    fn into_http(self) -> Response<Self::Body>;
}

impl<T, E> IntoHttp for Result<api::Response<T>, E>
where
    T: Serialize,
    E: Serialize,
{
    type Body = http_body_util::Full<Bytes>;

    /// Create a new reply with the given status code and body.
    fn into_http(self) -> http::Response<Self::Body> {
        let result = match self {
            Ok(r) => {
                let body = serde_json::to_vec(&r.body).unwrap_or_default();
                Response::builder()
                    .status(r.status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Self::Body::from(body))
            }
            Err(e) => {
                let body = serde_json::to_vec(&e).unwrap_or_default();
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Self::Body::from(body))
            }
        };
        result.unwrap_or_default()
    }
}
