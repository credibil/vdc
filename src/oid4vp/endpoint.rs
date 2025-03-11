//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use crate::oid4vp::Result;
use crate::oid4vp::provider::Provider;

/// Handle incoming messages.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the imcoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
pub async fn handle<T, U>(
    owner: &str, request: impl Into<Request<T>>, provider: &impl Provider,
) -> Result<U>
where
    T: Body,
    Request<T>: Handler<Response = U>,
{
    let request: Request<T> = request.into();
    request.validate(owner, provider).await?;
    request.handle(owner, provider).await
}

/// A request to process.
#[derive(Clone, Debug)]
pub struct Request<T: Body> {
    /// The request to process.
    pub body: T,

    /// Optional headers associated with this request.
    pub headers: Option<String>,
}

impl<T: Body> From<T> for Request<T> {
    fn from(body: T) -> Self {
        Self { body, headers: None }
    }
}

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Handler: Clone + Debug + Send + Sync {
    /// The inner reply type specific to the implementing message.
    type Response;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send;

    /// Perform initial validation of the message.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    fn validate(
        &self, _credential_issuer: &str, _provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant_gate.active(credential_issuer)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }
            // `credential_issuer` required
            // if credential_issuer.is_empty() {
            //     return Err(invalid!("no `credential_issuer` specified"));
            // }

            // // validate the message schema during development
            // #[cfg(debug_assertions)]
            // schema::validate(self)?;

            // // authenticate the requestor
            // if let Some(authzn) = self.authorization() {
            //     if let Err(e) = authzn.verify(provider.clone()).await {
            //         return Err(unauthorized!("failed to authenticate: {e}"));
            //     }
            // }

            Ok(())
        }
    }
}

pub(crate) use seal::Body;
pub(crate) mod seal {
    use std::fmt::Debug;

    /// The `Body` trait is used to restrict the types able to be a Request
    /// body. It is implemented by all `xxxRequest` types.
    pub trait Body: Clone + Debug + Send + Sync {}
}
