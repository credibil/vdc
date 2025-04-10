use std::collections::HashMap;
// use std::fmt;
use std::fmt::Debug;
use std::io::Cursor;

use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use credibil_infosec::PublicKeyJwk;
pub use credibil_infosec::Signer;
use credibil_infosec::jose::jwa::Algorithm;
use credibil_infosec::jose::jwe::{ContentAlgorithm, KeyAlgorithm};
use qrcode::QrCode;
// use serde::de::{self, Deserializer, Visitor};
// use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::core::urlencode;
use crate::dif_exch::PresentationDefinition;
use crate::oid4vp::DcqlQuery;
use crate::oid4vp::types::{Format, VpFormat};

/// The Request Object Request is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GenerateRequest {
    /// The DCQL query to use to request the Verifiable Presentation.
    pub query: DcqlQuery,

    /// The Client ID
    pub client_id: String,

    /// The Verifier can specify whether Authorization Requests and Responses
    /// are to be passed between endpoints on the same device or across devices
    pub device_flow: DeviceFlow,
}

/// Used to specify whether Authorization Requests and Responses are to be
/// passed between endpoints on the same device or across devices
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum DeviceFlow {
    /// With the cross-device flow the Verifier renders the Authorization
    /// Request as a QR Code which the User scans with the Wallet. In
    /// response, the Verifiable Presentations are sent to a URL controlled
    /// by the Verifier using HTTPS POST.
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
pub enum GenerateResponse {
    /// The generated Authorization Request Object, ready to send to the Wallet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// A URI pointing to a location where the Authorization Request Object can
    /// be retrieved by the Wallet.
    #[serde(rename = "request_uri")]
    Uri(String),
}

impl Default for GenerateResponse {
    fn default() -> Self {
        Self::Uri(String::new())
    }
}

impl GenerateResponse {
    /// Convenience method to convert the `GenerateResponse` to a QR code.
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
    pub response_type: ResponseType,

    /// The Verifier's `client_id`.
    pub client_id: ClientIdentifier,

    /// The nonce is used to securely bind the requested Verifiable
    /// Presentation(s) provided by the Wallet to the particular
    /// transaction. Returned in the VP's Proof.challenge parameter.
    pub nonce: String,

    /// The Wallet MAY allow Verifiers to request presentation of Verifiable
    /// Credentials by utilizing a pre-defined scope value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Inform the Wallet of the mechanism to use when returning an
    /// Authorization Response. Defaults to "`fragment`".
    #[serde(flatten)]
    pub response_mode: ResponseMode,

    /// The query used to request Verifiable Presentations.
    #[serde(flatten)]
    pub query: Query,

    /// Client Metadata contains Verifier metadata values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<VerifierMetadata>,

    /// The HTTP method to be used by the Wallet when sending a request to the
    /// `request_uri` endpoint.
    ///
    /// The endpoint is called by the Wallet when it wants to provide the
    /// Verifier details about its technical capabilities so it can generate a
    /// an accceptable request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<RequestUriMethod>,

    /// An array of base64url-encoded JSON objects, each containing details
    /// about the transaction that the Verifier is requesting the End-User to
    /// authorize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,

    /// State is used to maintain state between the Authorization Request and
    /// subsequent callback from the Wallet ('Authorization Server').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
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

/// Client Identifier schemes indicate how the Wallet should interpret the
/// `client_id` in the process of Client identification, authentication, and
/// authorization.
///
/// If a : character is not present in the Client Identifier, the Wallet MUST treat the Client Identifier as referencing a pre-registered client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientIdentifier {
    /// The Verifier's redirect URI (or response URI when Response Mode is
    /// `direct_post`).
    ///
    /// For example, `https://client.example.org/cb`.
    RedirectUri(String),

    /// An Entity Identifier as defined in OpenID Federation.
    ///
    /// For example, `https://federation-verifier.example.com`.
    Https(String),

    /// A DID URI as defined in DID Core specification.
    ///
    /// For example, `did:example:123456789abcdefghi`.
    Did(String),

    /// The `sub` claim in the Verifier attestation JWT when the Verifier
    /// authenticates using a JWT.
    ///
    /// For example, `verifier.example`.
    VerifierAttestation(String),

    /// A DNS name matching a dNSName Subject Alternative Name (SAN) entry in
    /// the leaf certificate passed with the request.
    ///
    /// For example, `client.example.org`.
    X509SanDns(String),

    /// The audience for a Credential Presentation. Only used with
    /// presentations over the Digital Credentials API.
    ///
    /// For example, `https://verifier.example.com/`
    Origin(String),

    /// A hash of the leaf certificate passed with the request.
    ///
    /// For example, `Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk`.
    X509Hash(String),

    /// A pre-registered client ID.
    ///
    /// For example, `example-client`.
    Preregistered(String),
}

impl Default for ClientIdentifier {
    fn default() -> Self {
        Self::Preregistered(String::new())
    }
}

impl Serialize for ClientIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            Self::RedirectUri(uri) => &format!("redirect_uri:{uri}"),
            Self::Https(uri) => uri,
            Self::Did(did) => did,
            Self::VerifierAttestation(sub) => &format!("verifier_attestation:{sub}"),
            Self::X509SanDns(fqdn) => &format!("x509_san_dns:{fqdn}"),
            Self::Origin(uri) => &format!("origin:{uri}"),
            Self::X509Hash(hash) => &format!("x509_hash:{hash}"),
            Self::Preregistered(id) => id,
        };
        Ok(value.serialize(serializer)?)
    }
}

impl<'a> Deserialize<'a> for ClientIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let value = String::deserialize(deserializer)?;
        if value.starts_with("redirect_uri:") {
            Ok(Self::RedirectUri(value[13..].to_string()))
        } else if value.starts_with("https:") {
            Ok(Self::Https(value))
        } else if value.starts_with("did:") {
            Ok(Self::Did(value))
        } else if value.starts_with("verifier_attestation:") {
            Ok(Self::VerifierAttestation(value[20..].to_string()))
        } else if value.starts_with("x509_san_dns:") {
            Ok(Self::X509SanDns(value[13..].to_string()))
        } else if value.starts_with("origin:") {
            Ok(Self::Origin(value[7..].to_string()))
        } else if value.starts_with("x509_hash:") {
            Ok(Self::X509Hash(value[10..].to_string()))
        } else {
            Ok(Self::Preregistered(value))
        }
    }
}

/// The type of Presentation Definition returned by the `RequestObject`:
/// either an object or a URI.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Query {
    /// A JSON-encoded DCQL query.
    #[serde(rename = "dcql_query")]
    Dcql(DcqlQuery),

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

impl Default for Query {
    fn default() -> Self {
        Self::Dcql(DcqlQuery::default())
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
    /// Response (provided `scope` is set to "openid").
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,

    /// A VP Token is returned in a Token Response
    #[serde(rename = "code")]
    Code,
}

/// Inform the Wallet of the mechanism to use when returning an Authorization
/// Response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "response_mode")]
pub enum ResponseMode {
    /// The Wallet sends the Authorization Response to an endpoint controlled by
    /// the Verifier as an HTTPS POST request.
    #[serde(rename = "direct_post")]
    DirectPost {
        /// The URI to which the Wallet sends the Authorization Response.
        response_uri: String,
    },

    /// The Wallet sends the Authorization Response as an HTTPS POST request
    /// except the Wallet sets a `response` parameter to a JWT containing the
    /// Authorization Response.
    ///
    /// See [JARM](https://openid.net/specs/oauth-v2-jarm-final.html) for more
    /// detail.
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt {
        /// The URI to which the Wallet sends the Authorization Response.
        response_uri: String,
    },

    /// The Wallet sends the Authorization Response as a URI fragment to the
    ///  Verifier's redirection endpoint (as established during client
    /// registration).
    #[serde(rename = "fragment")]
    Fragment {
        /// The Verifier's redirection endpoint.
        redirect_uri: String,
    },
}

impl Default for ResponseMode {
    fn default() -> Self {
        Self::Fragment {
            redirect_uri: String::new(),
        }
    }
}

/// Verifier metadata when sent directly in the `RequestObject`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifierMetadata {
    /// Public keys, such as those used by the Wallet for encryption of the
    /// Authorization Response or where the Wallet will require the public key
    /// of the Verifier to generate the Verifiable Presentation.
    ///
    /// This allows the Verifier to pass ephemeral keys specific to this
    /// Authorization Request.
    pub jwks: Option<String>,

    /// An object defining the formats and proof types of Verifiable
    /// Presentations and Verifiable Credentials that a Verifier supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<HashMap<Format, VpFormat>>,

    /// The JWS `alg` algorithm for signing authorization responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<Algorithm>,

    /// The JWE `alg` algorithm for encrypting authorization responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<KeyAlgorithm>,

    /// The JWE `enc` algorithm for encrypting authorization responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc: Option<ContentAlgorithm>,
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
pub enum RequestUriMethod {
    /// Requires the Wallet to send the request to retrieve the Request Object
    /// using the HTTP GET method.
    #[default]
    Get,

    /// Requires the Wallet to send the request to retrieve the Request Object
    /// using the HTTP POST method.
    Post,
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
/// Request Object. Will be either an object or a JWT.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RequestObjectResponse {
    /// The repsonse contains an Authorization Request Object objet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// The response contains an Authorization Request Object encoded as a JWT.
    #[serde(rename = "jwt")]
    Jwt(String),
}

impl Default for RequestObjectResponse {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "development only"]
    fn serialize_request_object() {
        let request_object = RequestObject {
            response_type: ResponseType::VpToken,
            client_id: ClientIdentifier::Preregistered("client_id".to_string()),
            nonce: "nonce".to_string(),
            scope: Some("scope".to_string()),
            response_mode: ResponseMode::Fragment {
                redirect_uri: "redirect_uri".to_string(),
            },
            state: Some("state".to_string()),
            query: Query::Definition(PresentationDefinition::default()),
            client_metadata: Some(VerifierMetadata::default()),
            request_uri_method: Some(RequestUriMethod::Get),
            transaction_data: Some(vec![TransactionData::default()]),
        };

        let serialized = serde_json::to_string_pretty(&request_object).unwrap();
        println!("{serialized}");

        // let deserialized: RequestObject = serde_json::from_str(&serialized).unwrap();

        // assert_eq!(request_object, deserialized);
    }
}
