//! # Axum Response

use axum::body::Bytes;
use http::{Response, StatusCode};
use http_body::Body;
use serde::Serialize;

use crate::oid4vci::{Result, endpoint};

/// Trait for converting a `Result` into an HTTP response.
pub trait IntoHttp {
    /// The body type of the HTTP response.
    type Body: Body<Data = Bytes> + Send + 'static;

    /// Convert into an HTTP response.
    fn into_http(self) -> Response<Self::Body>;
}

impl<T: Serialize> IntoHttp for Result<endpoint::Response<T>> {
    type Body = axum::body::Body;

    fn into_http(self) -> Response<Self::Body> {
        // TODO: handle errors and return StatusCode::SERVER_ERROR
        let result = match self {
            Ok(r) => {
                let body = serde_json::to_vec(&r.body).unwrap_or_default();
                Response::builder()
                    .status(r.status)
                    .header("Content-Type", "application/json")
                    .body(Self::Body::from(body))
            }
            Err(e) => {
                let body = serde_json::to_vec(&e).unwrap_or_default();
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Self::Body::from(body))
            }
        };
        result.unwrap_or_default()
    }
}
