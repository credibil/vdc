use std::fmt::{Debug, Display, Formatter};
use std::io::Cursor;
use std::str::FromStr;

use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
pub use credibil_binding::Signature;
use credibil_core::{Kind, html};
use credibil_ecc::EncAlgorithm;
use credibil_jose::{JwsBuilder, PublicKeyJwk};
use credibil_vdc::dcql::DcqlQuery;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::JwtType;
use crate::types::metadata::{VpFormat, WalletMetadata};

/// The Request Object Request is created by the Verifier to generate an
/// Authorization Request Object.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CreateRequest {
    /// The DCQL query to use to request the Verifiable Presentation.
    pub dcql_query: DcqlQuery,

    /// The Client ID
    pub client_id: String,

    /// The Verifier can specify whether Authorization Requests and Responses
    /// are to be passed between endpoints on the same device or across devices
    pub device_flow: DeviceFlow,

    /// Inform the Wallet of the mechanism to use when returning an
    /// Authorization Response.
    #[serde(flatten)]
    pub response_mode: ResponseMode,
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
#[serde(transparent)]
pub struct CreateResponse(pub AuthorizationRequest);

/// Authorization Request for Verifier to send to Wallet.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorizationRequest {
    /// A URI pointing to a location where the Authorization Request Object can
    /// be retrieved by the Wallet.
    Uri(RequestUri),

    /// The generated Authorization Request Object, ready to send to the Wallet.
    Object(RequestObject),
}

impl AuthorizationRequest {
    /// URL-encode the Authorization Request.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the request cannot be
    /// serialized.
    pub fn url_encode(&self) -> Result<String> {
        html::url_encode(self)
    }

    /// Convert a url-encoded string into an `AuthorizationRequest`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the string cannot be decoded
    /// to an `AuthorizationRequest`.
    pub fn url_decode(s: &str) -> Result<Self> {
        html::url_decode(s)
    }

    /// Generate qrcode for the Request Object.
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
        let qs = self.url_encode()?;

        // generate qr code
        let qr_code =
            QrCode::new(format!("{endpoint}{qs}")).context("issue failed to create QR code")?;

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        img_buf
            .write_to(&mut writer, image::ImageFormat::Png)
            .context("issue failed to create QR code")?;

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self::Uri(RequestUri::default())
    }
}

impl FromStr for AuthorizationRequest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('=') && s.contains('&') {
            Ok(html::url_decode(s)?)
        } else {
            Ok(Self::Object(serde_json::from_str(s)?))
        }
    }
}

/// `RequestUri` is used by the Verifier to send an Authorization Request by
/// reference to the Wallet.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RequestUri {
    /// The Verifier's `client_id`.
    pub client_id: ClientId,

    /// The unique identifier of the Request Object.
    pub request_uri: String,

    /// The HTTP method to be used by the Wallet when sending a request to the
    /// `request_uri` endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<RequestUriMethod>,
}

/// `RequestObject` is used by the Verifier to send an Authorization Request by
/// value to the Wallet.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestObject {
    /// The type of response expected from the Wallet (as Authorization Server).
    pub response_type: ResponseType,

    /// The Verifier's `client_id`.
    pub client_id: ClientId,

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
    pub dcql_query: DcqlQuery,

    /// Client Metadata contains Verifier metadata values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,

    /// An array of base64url-encoded JSON objects, each containing details
    /// about the transaction that the Verifier is requesting the End-User to
    /// authorize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,

    /// Information about the Verifier relevant to the Credential Request.
    ///
    /// `VerifierInfo` is intended to support authorization decisions, inform
    /// Wallet policy enforcement, or enrich the End-User consent dialog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<Vec<VerifierInfo>>,

    /// The Wallet provided nonce used to mitigate replay attacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,

    /// State is used to maintain state between the Authorization Request and
    /// subsequent callback from the Wallet ('Authorization Server').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl RequestObject {
    /// URL-encode the Authorization Request, base64 encoding the Request
    /// Object.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub async fn url_encode_jwt(&self, signer: &impl Signature) -> Result<String> {
        let payload: AuthorizationClaims = self.clone().into();

        let key_binding = signer.verification_method().await?.try_into()?;
        let jws = JwsBuilder::new()
            .typ(JwtType::OauthAuthzReqJwt)
            .payload(payload)
            .key_binding(&key_binding)
            .add_signer(signer)
            .build()
            .await
            .context("issue building jwt")?;

        let encoded = jws.encode().context("issue encoding jws")?;

        let mut client_id = Map::new();
        client_id.insert("client_id".to_string(), Value::String(self.client_id.to_string()));
        let client_param = html::url_encode(&client_id).context("issue encoding `client_id`")?;

        Ok(format!("{client_param}&request={encoded}"))
    }
}

/// Client Identifier schemes indicate how the Wallet should interpret the
/// `client_id` in the process of Client identification, authentication, and
/// authorization.
///
/// When no `:` character is present, the Wallet MUST treat the Client
/// Identifier as referencing a pre-registered client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientId {
    /// The Verifier's redirect URI (or response URI when Response Mode is
    /// `direct_post`).
    ///
    /// For example, `https://client.example.org/cb`.
    RedirectUri(String),

    /// An Entity Identifier as defined in OpenID Federation.
    ///
    /// For example, `https://federation-verifier.example.com`.
    OpenIdFederation(String),

    /// A DID URI as defined in DID Core specification.
    ///
    /// For example, `did:example:123456789abcdefghi`.
    DecentralizedIdentifier(String),

    /// The `sub` claim in the Verifier attestation JWT when the Verifier
    /// authenticates using a JWT.
    ///
    /// For example, `verifier.example`.
    VerifierInfo(String),

    /// A DNS name matching a dNSName Subject Alternative Name (SAN) entry in
    /// the leaf certificate passed with the request.
    ///
    /// For example, `client.example.org`.
    X509SanDns(String),

    /// A hash of the leaf certificate passed with the request.
    ///
    /// For example, `Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk`.
    X509Hash(String),

    /// The audience for a Credential Presentation. Only used with
    /// presentations over the Digital Credentials API.
    ///
    /// For example, `https://verifier.example.com/`
    Origin(String),

    /// A pre-registered client ID.
    ///
    /// For example, `example-client`.
    Preregistered(String),
}

impl Default for ClientId {
    fn default() -> Self {
        Self::Preregistered(String::new())
    }
}

impl Display for ClientId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedirectUri(uri) => write!(f, "redirect_uri:{uri}"),
            Self::OpenIdFederation(uri) => write!(f, "openid_federation:{uri}"),
            Self::DecentralizedIdentifier(did) => write!(f, "decentralized_identifier:{did}"),
            Self::VerifierInfo(sub) => write!(f, "verifier_attestation:{sub}"),
            Self::X509SanDns(fqdn) => write!(f, "x509_san_dns:{fqdn}"),
            Self::Origin(uri) => write!(f, "origin:{uri}"),
            Self::X509Hash(hash) => write!(f, "x509_hash:{hash}"),
            Self::Preregistered(id) => write!(f, "{id}"),
        }
    }
}

impl From<String> for ClientId {
    fn from(value: String) -> Self {
        #[allow(clippy::option_if_let_else)]
        if let Some(uri) = value.strip_prefix("redirect_uri:") {
            Self::RedirectUri(uri.to_string())
        } else if let Some(uri) = value.strip_prefix("openid_federation:") {
            Self::OpenIdFederation(uri.to_string())
        } else if let Some(did) = value.strip_prefix("decentralized_identifier:") {
            Self::DecentralizedIdentifier(did.to_string())
        } else if let Some(sub) = value.strip_prefix("verifier_attestation:") {
            Self::VerifierInfo(sub.to_string())
        } else if let Some(fqdn) = value.strip_prefix("x509_san_dns:") {
            Self::X509SanDns(fqdn.to_string())
        } else if let Some(uri) = value.strip_prefix("origin:") {
            Self::Origin(uri.to_string())
        } else if let Some(hash) = value.strip_prefix("x509_hash:") {
            Self::X509Hash(hash.to_string())
        } else {
            Self::Preregistered(value)
        }
    }
}

impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

impl Serialize for ClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.to_string();
        value.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for ClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from(value))
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
        Self::Fragment { redirect_uri: String::new() }
    }
}

/// Verifier metadata when sent directly in the `RequestObject`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientMetadata {
    /// Public keys, such as those used by the Wallet for encryption of the
    /// Authorization Response or where the Wallet will require the public key
    /// of the Verifier to generate the Verifiable Presentation.
    ///
    /// This allows the Verifier to pass ephemeral keys specific to this
    /// Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Jwks>,

    /// A list of supported `enc` algorithms that can be used for encrypting
    /// responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_response_enc_values_supported: Option<Vec<EncAlgorithm>>,

    /// An object defining the formats and proof types of Verifiable
    /// Presentations and Verifiable Credentials that a Verifier supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats_supported: Option<Vec<VpFormat>>,
}

/// JSON Web Key Set (JWKS) containing the public keys of the Verifier.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
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
    pub r#type: String,

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

/// Details about the transaction that the Verifier is requesting the End-User
/// to authorize.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct VerifierInfo {
    /// The format of the attestation and how it is encoded.
    pub format: String,

    /// An object or string containing an attestation (e.g. a JWT). The payload
    /// is defined on a per format level. The Wallet MUST validate the
    /// attestation signature and ensure binding.
    pub data: Kind<Value>,

    /// References credentials requested for which the attestation is relevant.
    /// Each entry matches the `id` field in a DCQL Credential Query.
    /// If omitted, the attestation is relevant to all requested credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ids: Option<Vec<String>>,
}

/// The Request Object Request is used (indirectly) by the Wallet to retrieve a
/// previously generated Authorization Request Object.
///
/// The Wallet is sent a `request_uri` containing a unique URL pointing to the
/// Request Object. The URI has the form `client_id/request/state_key`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestUriRequest {
    /// The unique identifier of the the previously generated Request Object.
    pub id: String,

    /// Wallet metadata parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_metadata: Option<WalletMetadata>,

    /// Provided by the wallet to mitigate replay attacks of the Authorization
    /// Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,
}

impl RequestUriRequest {
    /// Create an `application/x-www-form-urlencoded` representation of the
    /// `RequestUriRequest` suitable for use in an HTML form post.
    ///
    /// # Errors
    ///
    /// Will return an error if any of the object-type fields cannot be
    /// serialized to JSON and URL-encoded. (`authorization_details` and
    /// `client_assertion`).
    pub fn form_encode(&self) -> Result<Vec<(String, String)>> {
        html::form_encode(self)
    }

    /// Create a `RequestUriRequest` from a `x-www-form-urlencoded` form.
    ///
    /// # Errors
    ///
    /// Will return an error if any of the object-type fields, assumed to be
    /// URL-encoded JSON, cannot be decoded.
    pub fn form_decode(form: &[(String, String)]) -> Result<Self> {
        html::form_decode(form)
    }
}

/// The Request Object Response returns a previously generated Authorization
/// Request Object. Will be either an object or a JWT.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RequestUriResponse {
    /// The repsonse contains an Authorization Request Object objet.
    #[serde(rename = "request_object")]
    Object(RequestObject),

    /// The response contains an Authorization Request Object encoded as a JWT.
    #[serde(rename = "jwt")]
    Jwt(String),
}

impl Default for RequestUriResponse {
    fn default() -> Self {
        Self::Object(RequestObject::default())
    }
}

/// The Request Object Claims are the claims contained in the JWT
/// representation of the Request Object.
///
/// The claims are used to serialize/deserialize the Request Object to/from a
/// JWT.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthorizationClaims {
    /// The Verifier's `client_id`.
    pub iss: String,

    /// Equal to the issuer claim when Dynamic Discovery is performed OR
    /// `"https://self-issued.me/v2"`, when Static Discovery metadata is used.
    pub aud: String,

    /// Remaining [`RequestObject`] attributes.
    #[serde(flatten)]
    pub request_object: RequestObject,
}

impl From<RequestObject> for AuthorizationClaims {
    fn from(request_object: RequestObject) -> Self {
        Self {
            iss: request_object.client_id.to_string(),
            aud: "https://self-issued.me/v2".to_string(),
            request_object,
        }
    }
}

#[cfg(test)]
mod tests {
    use credibil_jose::Jwt;
    use test_utils::Verifier;

    use super::*;

    #[test]
    #[ignore = "development only"]
    fn request_object() {
        let request_object = RequestObject {
            response_type: ResponseType::VpToken,
            client_id: ClientId::Preregistered("client_id".to_string()),
            nonce: "n-0S6_WzA2Mj".to_string(),
            dcql_query: DcqlQuery::default(),
            scope: None,
            response_mode: ResponseMode::Fragment {
                redirect_uri: "https://client.example.org/cb".to_string(),
            },
            state: Some("af0ifjsldkj".to_string()),
            client_metadata: Some(ClientMetadata::default()),
            transaction_data: Some(vec![TransactionData::default()]),
            verifier_info: Some(vec![VerifierInfo::default()]),
            wallet_nonce: None,
        };

        let serialized = serde_json::to_string_pretty(&request_object).unwrap();
        let deserialized: RequestObject = serde_json::from_str(&serialized).unwrap();
        assert_eq!(request_object, deserialized);
    }

    #[tokio::test]
    #[ignore = "development only"]
    async fn querystring() {
        let request_object = RequestObject {
            response_type: ResponseType::VpToken,
            client_id: ClientId::RedirectUri("https://client.example.com".to_string()),
            nonce: "n-0S6_WzA2Mj".to_string(),
            dcql_query: DcqlQuery::default(),
            scope: None,
            response_mode: ResponseMode::Fragment {
                redirect_uri: "https://client.example.org/cb".to_string(),
            },
            state: Some("af0ifjsldkj".to_string()),
            client_metadata: Some(ClientMetadata::default()),
            transaction_data: Some(vec![TransactionData::default()]),
            verifier_info: Some(vec![VerifierInfo::default()]),
            wallet_nonce: None,
        };

        let verifier = Verifier::new("http://verifier.io").await.expect("should create verifier");
        let querystring = request_object.url_encode_jwt(&verifier).await.unwrap();

        let request = querystring
            .split('&')
            .find(|s| s.starts_with("request="))
            .unwrap()
            .strip_prefix("request=")
            .unwrap();

        let jwt: Jwt<AuthorizationClaims> = request.parse().unwrap();
        assert_eq!(jwt.claims.request_object, request_object);
    }
}
