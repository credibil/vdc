use std::fmt::{Debug, Display, Formatter};
use std::io::Cursor;

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
pub use credibil_identity::SignerExt;
use credibil_jose::{JwsBuilder, PublicKeyJwk};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::Kind;
use crate::oid4vp::JwtType;
use crate::oid4vp::verifier::{DcqlQuery, VerifierMetadata};
use crate::oid4vp::wallet::Wallet;

const UNRESERVED: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'&').remove(b'=').remove(b'.').remove(b'_').remove(b'-').remove(b'~');

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

    /// Inform the Wallet of the mechanism to use when returning an
    /// Authorization Response.
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
    pub async fn to_qrcode(
        &self, endpoint: Option<&str>, signer: &impl SignerExt,
    ) -> anyhow::Result<String> {
        match self {
            Self::Object(req_obj) => {
                let Some(endpoint) = endpoint else {
                    return Err(anyhow!("no endpoint provided for object-type response"));
                };
                req_obj.to_qrcode(endpoint, signer).await
            }
            Self::Uri(uri) => {
                let qr_code = QrCode::new(uri).context("failed to create QR code")?;
                let img_buf = qr_code.render::<image::Luma<u8>>().build();
                let mut buffer: Vec<u8> = Vec::new();
                let mut writer = Cursor::new(&mut buffer);
                img_buf
                    .write_to(&mut writer, image::ImageFormat::Png)
                    .context("failed to create QR code")?;
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
    pub client_id: ClientId,

    /// The nonce is used to securely bind the requested Verifiable
    /// Presentation(s) provided by the Wallet to the particular
    /// transaction. Returned in the VP's Proof.challenge parameter.
    pub nonce: String,

    /// The Wallet MAY allow Verifiers to request presentation of Verifiable
    /// Credentials by utilizing a pre-defined scope value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    //
    /// Inform the Wallet of the mechanism to use when returning an
    /// Authorization Response. Defaults to "`fragment`".
    #[serde(flatten)]
    pub response_mode: ResponseMode,

    /// The query used to request Verifiable Presentations.
    pub dcql_query: DcqlQuery,

    /// Client Metadata contains Verifier metadata values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<VerifierMetadata>,

    /// The HTTP method to be used by the Wallet when sending a request to the
    /// `request_uri` endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<RequestUriMethod>,

    /// An array of base64url-encoded JSON objects, each containing details
    /// about the transaction that the Verifier is requesting the End-User to
    /// authorize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,

    /// Attestations about the Verifier relevant to the Credential Request.
    ///
    /// Attestations are intended to support authorization decisions, inform
    /// Wallet policy enforcement, or enrich the End-User consent dialog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_attestations: Option<Vec<VerifierAttestation>>,

    /// The Wallet provided nonce used to mitigate replay attacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,

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
    pub async fn to_qrcode(&self, endpoint: &str, signer: &impl SignerExt) -> Result<String> {
        let qs = self.to_querystring(signer).await?;

        // generate qr code
        let qr_code = QrCode::new(format!("{endpoint}{qs}")).context("failed to create QR code")?;

        // write image to buffer
        let img_buf = qr_code.render::<image::Luma<u8>>().build();
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        img_buf
            .write_to(&mut writer, image::ImageFormat::Png)
            .context("failed to create QR code")?;

        // base64 encode image
        Ok(format!("data:image/png;base64,{}", Base64::encode_string(buffer.as_slice())))
    }

    /// Generate an Authorization Request query string with URL-encoded
    /// parameters.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    #[deprecated(since = "0.1.0", note = "please use `url_value` instead")]
    pub fn url_params(&self) -> Result<String> {
        serde_urlencoded::to_string(self).context("creating query string")
    }

    /// Generate an  Authorization Request query string with a base64 encoded
    /// Request Object.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if the Request Object cannot be
    /// serialized.
    pub async fn to_querystring(&self, signer: &impl SignerExt) -> Result<String> {
        let payload: RequestObjectClaims = self.clone().into();

        let key_ref = signer.verification_method().await?.try_into()?;
        let jws = JwsBuilder::new()
            .typ(JwtType::OauthAuthzReqJwt)
            .payload(payload)
            .key_ref(&key_ref)
            .add_signer(signer)
            .build()
            .await
            .context("building jwt")?;

        let encoded = jws.encode().context("encoding jws")?;
        let client_id = utf8_percent_encode(&self.client_id.to_string(), UNRESERVED).to_string();

        Ok(format!("{client_id}&request={encoded}"))
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

impl Default for ClientId {
    fn default() -> Self {
        Self::Preregistered(String::new())
    }
}

impl Display for ClientId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedirectUri(uri) => write!(f, "redirect_uri:{uri}"),
            Self::Https(uri) => write!(f, "openid_federation:{uri}"),
            Self::Did(did) => write!(f, "decentralized_identifier:{did}"),
            Self::VerifierAttestation(sub) => write!(f, "verifier_attestation:{sub}"),
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
            Self::Https(uri.to_string())
        } else if let Some(did) = value.strip_prefix("decentralized_identifier:") {
            Self::Did(did.to_string())
        } else if let Some(sub) = value.strip_prefix("verifier_attestation:") {
            Self::VerifierAttestation(sub.to_string())
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
        Self::Fragment {
            redirect_uri: String::new(),
        }
    }
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

/// Details about the transaction that the Verifier is requesting the End-User
/// to authorize.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct VerifierAttestation {
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
    pub wallet_metadata: Option<Wallet>,

    /// Provided by the wallet to mitigate replay attacks of the Authorization
    /// Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,
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
pub struct RequestObjectClaims {
    /// The Verifier's `client_id`.
    pub iss: String,

    /// Equal to the issuer claim when Dynamic Discovery is performed OR
    /// `"https://self-issued.me/v2"`, when Static Discovery metadata is used.
    pub aud: String,

    /// Remaining [`RequestObject`] attributes.
    #[serde(flatten)]
    pub request_object: RequestObject,
}

impl From<RequestObject> for RequestObjectClaims {
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
    use provider::verifier::Verifier;

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
            client_metadata: Some(VerifierMetadata::default()),
            request_uri_method: Some(RequestUriMethod::Get),
            transaction_data: Some(vec![TransactionData::default()]),
            verifier_attestations: Some(vec![VerifierAttestation::default()]),
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
            client_metadata: Some(VerifierMetadata::default()),
            request_uri_method: Some(RequestUriMethod::Get),
            transaction_data: Some(vec![TransactionData::default()]),
            verifier_attestations: Some(vec![VerifierAttestation::default()]),
            wallet_nonce: None,
        };

        let querystring = request_object.to_querystring(&Verifier::new()).await.unwrap();

        let request = querystring
            .split('&')
            .find(|s| s.starts_with("request="))
            .unwrap()
            .strip_prefix("request=")
            .unwrap();

        let jwt: Jwt<RequestObjectClaims> = request.parse().unwrap();
        assert_eq!(jwt.claims.request_object, request_object);
    }
}
