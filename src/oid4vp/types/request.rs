use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::io::Cursor;

use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use credibil_infosec::PublicKeyJwk;
pub use credibil_infosec::Signer;
use qrcode::QrCode;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::core::urlencode;
use crate::dif_exch::{InputDescriptor, PresentationDefinition};
use crate::oid4vp::types::{Format, VpFormat};

/// The Request Object Request is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CreateRequestRequest {
    /// The reason the Verifier is requesting the Verifiable Presentation.
    pub purpose: String,

    /// Input Descriptors describing the information required from the
    /// Holder.
    pub input_descriptors: Vec<InputDescriptor>,

    /// The Verifier can specify whether Authorization Requests and Responses
    /// are to be passed between endpoints on the same device or across devices
    pub device_flow: DeviceFlow,

    /// The Client ID
    pub client_id_scheme: String,
}

/// Used to specify whether Authorization Requests and Responses are to be
/// passed between endpoints on the same device or across devices
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum DeviceFlow {
    /// With the cross-device flow the Verifier renders the Authorization
    /// Request as a QR Code which the User scans with the Wallet. In
    /// response, the Verifiable Presentations are sent to a URL controlled
    /// by the Verifier using HTTPS POST.
    ///
    /// To initiate this flow, the Verifier specifies a Response Type of
    /// "`vp_token`" and a Response Mode of "`direct_post`" in the Request
    /// Object.
    ///
    /// In order to keep the size of the QR Code small and be able to sign and
    /// optionally encrypt the Request Object, the Authorization Request only
    /// contains a Request URI which the wallet uses to retrieve the actual
    /// Authorization Request data.
    ///
    /// It is RECOMMENDED that Response Mode "`direct_post`" and `request_uri`
    /// are used for cross-device flows, as Authorization Request size might
    /// be large and may not fit in a QR code.
    #[default]
    CrossDevice,

    /// The same-device flow uses HTTP redirects to pass Authorization Request
    /// and Response between Verifier and Wallet. Verifiable Presentations
    /// are returned to the Verifier in the fragment part of the redirect
    /// URI, when the Response Mode is "`fragment`".
    SameDevice,
}

/// The response to the originator of the Request Object Request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CreateRequestResponse {
    /// The generated Authorization Request Object, ready to send to the Wallet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// A URI pointing to a location where the Authorization Request Object can
    /// be retrieved by the Wallet.
    #[serde(rename = "request_uri")]
    Uri(String),
}

impl Default for CreateRequestResponse {
    fn default() -> Self {
        Self::Uri(String::new())
    }
}

impl CreateRequestResponse {
    /// Convenience method to convert the `CreateRequestResponse` to a QR code.
    ///
    /// If the `request_object` is set, the method will generate a QR code for
    /// that in favour of the `request_uri`.
    ///
    /// TODO: Revisit the logic to determine default type if this struct is made
    /// an enum.
    ///
    /// # Errors
    /// Returns an error if the neither the `request_object` nor `request_uri` is
    /// set or the respective field cannot be represented as a base64-encoded PNG
    /// image of a QR code.
    pub fn to_qrcode(&self, endpoint: Option<&str>) -> anyhow::Result<String> {
        match self {
            Self::Object(req_obj) => {
                let Some(endpoint) = endpoint else {
                    return Err(anyhow!("no endpoint provided for object-type response"));
                };
                req_obj.to_qrcode(endpoint)
            }
            Self::Uri(uri) => {
                let qr_code =
                    QrCode::new(uri).map_err(|e| anyhow!("Failed to create QR code: {e}"))?;
                let img_buf = qr_code.render::<image::Luma<u8>>().build();
                let mut buffer: Vec<u8> = Vec::new();
                let mut writer = Cursor::new(&mut buffer);
                img_buf
                    .write_to(&mut writer, image::ImageFormat::Png)
                    .map_err(|e| anyhow!("Failed to create QR code: {e}"))?;
                Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
            }
        }
    }
}

/// The Authorization Request follows the definition given in [RFC6749].
///
/// The Verifier may send an Authorization Request as Request Object by value or
/// by reference as defined in JWT-Secured Authorization Request (JAR)
/// [RFC9101].
///
/// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
/// [RFC9101]:https://www.rfc-editor.org/rfc/rfc9101
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestObject {
    /// The type of response expected from the Wallet (as Authorization Server).
    ///
    /// If Response Type is:
    ///  - "`vp_token`": a VP Token is returned in an Authorization Response.
    ///  - "`vp_token id_token`" AND the `scope` parameter contains "`openid`":
    ///    a VP Token and a Self-Issued ID Token are returned in an
    ///    Authorization Response.
    ///  - "`code`": a VP Token is returned in a Token Response.
    ///
    /// The default Response Mode is "fragment": response parameters are encoded
    /// in the fragment added to the `redirect_uri` when redirecting back to the
    /// Verifier.
    pub response_type: ResponseType,

    /// The Verifier's `client_id`.
    pub client_id: String,

    /// The URI to redirect to the Verifier's redirection endpoint as
    /// established during client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// The nonce is used to securely bind the requested Verifiable
    /// Presentation(s) provided by the Wallet to the particular
    /// transaction. Returned in the VP's Proof.challenge parameter.
    pub nonce: String,

    /// The Wallet MAY allow Verifiers to request presentation of Verifiable
    /// Credentials by utilizing a pre-defined scope value. Defined in
    /// [RFC6749].
    ///
    /// [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// While the `response_type` parameter informs the Authorization Server
    /// (Wallet) of the desired authorization flow, the `response_mode`
    /// parameter informs it of the mechanism to use when returning an
    /// Authorization Response.
    ///
    /// A Response Mode of "`direct_post`" allows the Wallet to send the
    /// Authorization Response to an endpoint controlled by the Verifier as
    /// an HTTPS POST request.
    ///
    /// If not set, the default value is "`fragment`".
    ///
    /// Response parameters are returned using the
    /// "application/x-www-form-urlencoded" content type. The flow can end
    /// with an HTTPS POST request from the Wallet to the Verifier, or it
    /// can end with a redirect that follows the HTTPS POST request,
    /// if the Verifier responds with a redirect URI to the Wallet.
    ///
    /// Response Mode "`direct_post.jwt`" causes the Wallet to send the
    /// Authorization Response as an HTTPS POST request (as for
    /// "`direct_post`") except the Wallet sets a `response` parameter to a
    /// JWT containing the Authorization Response. See [JARM] for more
    /// detail.
    ///
    /// [JARM]: (https://openid.net/specs/oauth-v2-jarm-final.html)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// OPTIONAL. MUST be set when the Response Mode "`direct_post`" is used.
    ///
    /// The URI to which the Wallet MUST send the Authorization Response using
    /// an HTTPS POST request as defined by the Response Mode
    /// "`direct_post`".
    ///
    /// When `response_uri` is set, `redirect_uri` MUST NOT be set. If set when
    /// Response Mode is "`direct_post`", the Wallet MUST return an
    /// "`invalid_request`" error.
    ///
    /// Note: If the Client Identifier scheme `redirect_uri` is used in
    /// conjunction with the Response Mode "`direct_post`", and the
    /// `response_uri` parameter is present, the `client_id` value MUST be
    /// equal to the `response_uri` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,

    /// State is used to maintain state between the Authorization Request and
    /// subsequent callback from the Wallet ('Authorization Server').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// The type of request used to request Verifiable Presentations.
    #[serde(flatten)]
    pub request_type: RequestType,

    /// Client Metadata contains Verifier metadata values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<VerifierMetadata>,

    /// The HTTP method to be used when the `request_uri` parameter is included
    /// in the same request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<UriMethod>,

    /// An array of base64url encoded JSON objects, each containing a parameter
    /// set with details about the transaction that the Verifier is requesting
    /// the End-User to authorize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,
}

impl RequestObject {
    /// Generate qrcode for Request Object.
    /// Use the `endpoint` parameter to specify the Wallet's endpoint using deep
    /// link or direct call format.
    ///
    /// For example,
    ///
    /// ```http
    ///   openid-vc://?request_uri=
    ///   or GET https://holder.wallet.io/authorize?
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> Result<String> {
        let qs =
            self.to_querystring().map_err(|e| anyhow!("Failed to generate querystring: {e}"))?;

        // generate qr code
        let qr_code = QrCode::new(format!("{endpoint}{qs}"))
            .map_err(|e| anyhow!("Failed to create QR code: {e}"))?;

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        img_buf
            .write_to(&mut writer, image::ImageFormat::Png)
            .map_err(|e| anyhow!("Failed to create QR code: {e}"))?;

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }

    /// Generate a query string for the Request Object.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub fn to_querystring(&self) -> Result<String> {
        urlencode::to_string(self).map_err(|e| anyhow!("issue creating query string: {e}"))
    }
}

/// The type of Presentation Definition returned by the `RequestObject`:
/// either an object or a URI.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum RequestType {
    /// A JSON-encoded DCQL query.
    #[serde(rename = "dcql_query")]
    DcqlQuery(String),

    /// A Presentation Definition object embedded in the `RequestObject`.
    #[serde(rename = "presentation_definition")]
    Definition(PresentationDefinition),

    /// A URI pointing to where a Presentation Definition object can be
    /// retrieved. This parameter MUST be set when neither
    /// `presentation_definition` nor a Presentation Definition scope value
    /// are set.
    #[serde(rename = "presentation_definition_uri")]
    DefinitionUri(String),
}

impl Default for RequestType {
    fn default() -> Self {
        Self::DcqlQuery(String::new())
    }
}

/// The type of response expected from the Wallet (as Authorization Server).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ResponseType {
    /// A VP Token is returned in an Authorization Response
    #[default]
    #[serde(rename = "vp_token")]
    VpToken,

    /// A VP Token and a Self-Issued ID Token are returned in an Authorization
    /// Response (if `scope` is set to "openid").
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,

    /// A VP Token is returned in a Token Response
    #[serde(rename = "code")]
    Code,
}

/// OAuth 2 client metadata used for registering clients of the issuance and
/// wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifierMetadata {
    /// Public keys, such as those used by the Wallet as an input to a key
    /// agreement that may be used for encryption of the Authorization Response
    /// or where the Wallet will require the public key of the Verifier to
    /// generate the Verifiable Presentation. This allows the Verifier to pass
    /// ephemeral keys specific to this Authorization Request. Public keys
    /// included in this parameter MUST NOT be used to verify the signature of
    /// signed Authorization Requests.
    pub jwks: Option<String>,

    /// An object defining the formats and proof types of Verifiable
    /// Presentations and Verifiable Credentials that a Verifier supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<HashMap<Format, VpFormat>>,

    // FIXME: use credibil_infosec::SigningAlgorithm
    /// <https://openid.net/specs/oauth-v2-jarm-final.html>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,

    // FIXME: use credibil_infosec::EncryptionAlgorithm
    /// <https://openid.net/specs/oauth-v2-jarm-final.html>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<String>,

    // FIXME: use credibil_infosec::EncryptionEncoding
    /// <https://openid.net/specs/oauth-v2-jarm-final.html>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc: Option<String>,
}

/// JSON Web Key Set (JWKS) containing the public keys of the Verifier.
pub struct Jwks {
    /// Keys in the set.
    pub keys: Vec<PublicKeyJwk>,
}

/// HTTP method options available for use when the `request_uri` parameter is
/// included in the same request.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UriMethod {
    /// GET method.
    #[default]
    GET,

    /// POST method.
    POST,
}

/// Details about the transaction that the Verifier is requesting the End-User
/// to authorize.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct TransactionData {
    /// The name of the parameter set.
    #[serde(rename = "type")]
    pub type_: String,

    /// Credential IDs requested that can be used to authorize the transaction.
    /// In [DIF.PresentationExchange], the string matches the id field in the
    /// Input Descriptor. In the Digital Credentials Query Language, the string
    /// matches the id field in the Credential Query.
    pub credential_ids: Vec<String>,

    /// Hash algorithm identifiers, one of which MUST be used to calculate
    /// hashes in `transaction_data_hashes` in the response.
    ///
    /// Defaults to "sha-256" when not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<Vec<String>>,
}

/// The Request Object Request is used (indirectly) by the Wallet to retrieve a
/// previously generated Authorization Request Object.
///
/// The Wallet is sent a `request_uri` containing a unique URL pointing to the
/// Request Object. The URI has the form `client_id/request/state_key`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestObjectRequest {
    /// The unique identifier of the the previously generated Request Object.
    pub id: String,
}

/// The Request Object Response returns a previously generated Authorization
/// Request Object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestObjectResponse {
    /// The Authorization Request Object generated by the `request` endpoint
    /// either as an object or serialised to a JWT.
    pub request_object: RequestObjectType,
}

/// The type of Authorization Request Object returned in the `RequestObject`:
/// either an object or a JWT.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RequestObjectType {
    /// The repsonse contains an Authorization Request Object objet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// The response contains an Authorization Request Object encoded as a JWT.
    #[serde(rename = "jwt")]
    Jwt(String),
}

impl Default for RequestObjectType {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

/// Serialize to 'unwrapped' JWT if Request Object is JWT (`jwt parameter is
/// set`).
impl Serialize for RequestObjectResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.request_object {
            RequestObjectType::Object(_) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("request_object", &self.request_object)?;
                map.end()
            }
            RequestObjectType::Jwt(jwt) => jwt.serialize(serializer),
        }
    }
}

/// Deserialize from JSON or 'unwrapped' JWT if Request Object is JWT.
impl<'de> Deserialize<'de> for RequestObjectResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VisitorImpl;

        impl<'de> Visitor<'de> for VisitorImpl {
            type Value = RequestObjectResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a RequestObjectResponse or JWT")
            }

            fn visit_str<E>(self, value: &str) -> Result<RequestObjectResponse, E>
            where
                E: de::Error,
            {
                Ok(RequestObjectResponse {
                    request_object: RequestObjectType::Jwt(value.to_string()),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<RequestObjectResponse, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut resp = RequestObjectResponse::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "request_object" => {
                            resp.request_object = RequestObjectType::Object(map.next_value()?);
                        }
                        "jwt" => resp.request_object = RequestObjectType::Jwt(map.next_value()?),
                        _ => {
                            return Err(de::Error::unknown_field(&key, &["request_object", "jwt"]));
                        }
                    }
                }

                Ok(resp)
            }
        }

        deserializer.deserialize_any(VisitorImpl)
    }
}
