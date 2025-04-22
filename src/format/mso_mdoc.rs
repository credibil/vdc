//! # ISO mDL-based Credential Format
//!
//! This module provides the implementation of ISO mDL credentials.
//!
//! The Mobile Security Object (MSO) Mobile Device Object (MDOC) is a data
//! structure that contains the data elements that are signed by the issuer
//! and the mobile device. The issuer signs the data elements to authenticate
//! the issuer data, and the mobile device signs the data elements to
//! authenticate the mobile device data. The MSO MDOC is returned in the
//! `DeviceResponse` structure.

mod issue;
mod present;
mod store;

use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use chrono::{Duration, SecondsFormat, Utc};
use ciborium::{Value, cbor};
use coset::{AsCborValue, CoseMac0, CoseSign1};
use credibil_infosec::cose::{CoseKey, Tag24};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

pub use self::issue::MsoMdocBuilder;
pub use self::present::DeviceResponseBuilder;
pub use self::store::to_queryable;

// ----------------------------------------------------------------------------
/// # 8.2 Device engagement (pg 24)
// ----------------------------------------------------------------------------

/// Information to perform device engagement.
///
/// ```cddl
/// DeviceEngagement = {
///     0: tstr, ; Version
///     1: Security,
///     ? 2: DeviceRetrievalMethods, ; Is absent if NFC is used for device engagement
///     ? 3: ServerRetrievalMethods,
///     ? 4: ProtocolInfo,
///     * int => any
/// }
/// ```
/// Represents a device engagement.
#[derive(Clone, Debug)]
pub struct DeviceEngagement {
    /// Version.
    pub version: String,

    /// Security information containing the device public key and cipher suite.
    pub security: Security,

    /// Usedwhen performing device engagement using the QR code. Absent when
    /// using NFC.
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,

    /// The optional server retrieval methods for the device engagement.
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,

    /// The optional protocol information for the device engagement.
    pub protocol_info: Option<ProtocolInfo>,
}

impl Serialize for DeviceEngagement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::<i64, Value>::new();
        map.insert(0, self.version.clone().into());
        map.insert(1, cbor!(self.security).map_err(|e| ser::Error::custom(e))?);
        if let Some(ref methods) = self.device_retrieval_methods {
            map.insert(2, cbor!(methods).map_err(|e| ser::Error::custom(e))?);
        }
        if let Some(ref methods) = self.server_retrieval_methods {
            map.insert(3, cbor!(methods).map_err(|e| ser::Error::custom(e))?);
        }
        if let Some(ref info) = self.protocol_info {
            map.insert(4, info.clone());
        }
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceEngagement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<i64, Value>::deserialize(deserializer)?;

        // required fields
        let Some(version) = map.get(&0) else {
            return Err(de::Error::custom("missing version"));
        };
        let Some(security) = map.get(&1) else {
            return Err(de::Error::custom("missing security"));
        };

        let mut de = Self {
            version: version.deserialized().map_err(de::Error::custom)?,
            security: security.deserialized().map_err(de::Error::custom)?,
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        // optional fields
        if let Some(methods) = map.get(&2) {
            de.device_retrieval_methods = methods.deserialized().map_err(de::Error::custom)?;
        };
        if let Some(methods) = map.get(&3) {
            de.server_retrieval_methods = methods.deserialized().map_err(de::Error::custom)?;
        };
        if let Some(protocol_info) = map.get(&4) {
            de.protocol_info = protocol_info.deserialized().map_err(de::Error::custom)?;
        };

        Ok(de)
    }
}

/// Device security information in the form of a cipher suite identifier and
/// public key.
///
/// ```cddl
/// Security = [
///     int, ; Cipher suite identifier
///     EDeviceKeyBytes
/// ]
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Security(pub CipherSuite, pub EDeviceKeyBytes);

/// Supported device retrieval security mechanisms cipher suites.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(into = "i64", try_from = "i64")]
pub enum CipherSuite {
    /// Cipher suite 1
    Suite1 = 1,
}

impl From<CipherSuite> for i64 {
    fn from(value: CipherSuite) -> Self {
        value as i64
    }
}

impl TryFrom<i64> for CipherSuite {
    type Error = anyhow::Error;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CipherSuite::Suite1),
            _ => Err(anyhow::anyhow!("unsupported cipher suite")),
        }
    }
}

/// A list of the device retrieval methods supported by the mdoc.
///
/// ```cddl
/// DeviceRetrievalMethods = [
///     + DeviceRetrievalMethod
/// ]
/// ```
pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;

/// Device retrieval method.
///
/// ```cddl
/// DeviceRetrievalMethod = [
///     uint, ; Type
///     uint, ; Version
///     RetrievalOptions ; Specific option(s) to the type of retrieval method
/// ]
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceRetrievalMethod(
    // The type of transfer method.
    pub u64,
    // The version of the transfer method.
    pub u64,
    /// Additional options for each connection.
    pub Vec<RetrievalOption>,
);

/// Supported device retrieval options.
///
/// See 8.2.2.3 Device engagement using QR code, pg 28.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RetrievalOption {
    /// WiFi options.
    WifiOptions,

    /// Bluetooth low energy options.
    BleOptions,

    /// NFC options.
    NfcOptions,
}

/// ```cddl
/// WifiOptions = {
///     ? 0: tstr,  ; Pass-phrase Info Pass-phrase
///     ? 1: uint,  ; Channel Info Operating Class
///     ? 2: uint,  ; Channel Info Channel Number
///     ? 3: bstr   ; Band Info Supported Bands
/// }
/// ```
#[derive(Clone, Debug)]
pub struct WifiOptions {
    /// Pass-phrase information.
    pub passphrase: Option<String>,

    /// Operating class.
    pub operating_class: Option<u64>,

    /// Channel info channel number.
    pub channel_number: Option<u64>,

    /// Band Info supported bands.
    pub supported_bands: Option<Vec<u8>>,
}

/// BleOptions = {
///     0 : bool,       ; Indicates support for mdoc peripheral server mode
///     1 : bool,       ; Indicates support for mdoc central client mode
///     ? 10 : bstr,    ; UUID for mdoc peripheral server mode
///     ? 11 : bstr     ; UUID for mdoc client central mode
///     ? 20 : bstr     ; mdoc BLE Device Address for mdoc peripheral server mode
/// }

/// NfcOptions = {
///     0 : uint,   ; Maximum length of command data field
///     1 : uint    ; Maximum length of response data field
// }

/// Supported server retrieval methods.
///
/// See 8.2.1.2 Server retrieval information, pg 25.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    /// Server retrieval using web API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_api: Option<RetrievalInformation>,

    /// Server retrieval using OIDC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<RetrievalInformation>,
}

/// Server retrival using OIDC or web API.
///
/// ```cddl
/// Oidc = [
///     uint, ; Version
///     tstr, ; Issuer URL
///     tstr ; Server retrieval token
/// ]
/// ```
///
/// See 8.2.1.2 Server retrieval information, pg 26.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetrievalInformation(
    // The version of the transfer methods.
    pub u64,
    // The issuer URL.
    pub String,
    /// The server retrieval token as provided by the mdoc reader.
    pub String,
);

/// ProtocolInfo
pub type ProtocolInfo = Value;

// ----------------------------------------------------------------------------
/// # 8.3.1 Data model
// ----------------------------------------------------------------------------
/// Document type
///
/// See 8.3.1 Data model, pg 29.
pub type DocType = String;

/// Element namespace
///
/// See 8.3.1 Data model, pg 29.
pub type NameSpace = String;

/// Data element identifier
///
/// See 8.3.1 Data model, pg 29.
pub type DataElementIdentifier = String;

/// Data element identifier
///
/// See 8.3.1 Data model, pg 29.
pub type DataElementValue = Value;

// ----------------------------------------------------------------------------
/// # 8.3.2.1.2.2 Device retrieval mdoc response (pg 30)
// ----------------------------------------------------------------------------

/// Device retrieval mdoc response.
///
/// The MSO is used to provide Issuer data authentication for the associated
/// `mdoc`. It contains a signed digest (e.g. SHA-256) of the `mdoc`, including
/// the digests in the MSO.
///
/// See 8.3.2.1.2.2 Device retrieval mdoc response, pg 30.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    /// Version of the DeviceResponse structure.
    pub version: String,

    /// Returned documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<Document>>,

    /// Error codes for unreturned documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<BTreeMap<DocType, ErrorCode>>,

    /// Status code.
    pub status: u64,
}

/// Document to return in the device response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// Returned data elements for each namespace (`IssuerNameSpaces` element)
    pub doc_type: DocType,

    /// Returned data elements signed by the issuer.
    pub issuer_signed: IssuerSigned,

    /// Returned data elements signed by the mdoc device.
    pub device_signed: DeviceSigned,

    /// Error codes for each namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

/// Data elements (claims) returned by the Issuer. Each data element is
/// hashed and signed by the Issuer in the MSO.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    /// Returned data elements for each namespace (`IssuerNameSpaces` element)
    pub name_spaces: IssuerNameSpaces,

    /// The mobile security object (MSO) for issuer data authentication.
    /// `COSE_Sign1` with a payload of `MobileSecurityObjectBytes`
    pub issuer_auth: IssuerAuth,
}

impl IssuerSigned {
    /// Create a new `IssuerSigned` with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name_spaces: BTreeMap::new(),
            issuer_auth: IssuerAuth::default(),
        }
    }
}

impl Default for IssuerSigned {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned data elements for each namespace
pub type IssuerNameSpaces = BTreeMap<NameSpace, Vec<IssuerSignedItemBytes>>;

/// CBOR serialized, tagged `IssuerSignedItem`.
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Issuer-signed data element
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerSignedItem {
    /// Id of the digest as added to the MSO `value_digests` parameter.
    pub digest_id: DigestId,

    /// Random hexadecimal value for issuer data authentication.
    /// (min. 16 bytes).
    pub random: Vec<u8>,

    /// Data element identifier. For example, "`family_name`"
    pub element_identifier: DataElementIdentifier,

    /// Data element value. For example, "`Smith`"
    pub element_value: DataElementValue,
}

impl IssuerSignedItem {
    fn to_bytes(self) -> IssuerSignedItemBytes {
        Tag24(self)
    }
}

/// Used by the mdoc device to sign the data elements in the `Document`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    /// Returned data elements
    pub name_spaces: DeviceNameSpacesBytes,

    /// Contains the device authentication for mdoc authentication
    pub device_auth: DeviceAuth,
}

/// CBOR serialized, tagged `DeviceNameSpaces`.
pub type DeviceNameSpacesBytes = Tag24<DeviceNameSpaces>;

/// Returned data elements for each namespace.
pub type DeviceNameSpaces = BTreeMap<NameSpace, Vec<DeviceSignedItems>>;

/// Returned data elements (identifier and value) for each namespace.
pub type DeviceSignedItems = BTreeMap<String, ciborium::Value>;

/// Device authentication used to authenticate the mdoc response.
///
/// N.B. a single mdoc authentication key cannot be used to produce both
/// signature and MAC.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuth {
    /// EdDSA signature
    device_signature: DeviceSignature,

    /// ECDH-agreed MAC
    device_mac: DeviceMac,
}

/// Error codes for each namespace.
pub type Errors = BTreeMap<NameSpace, Vec<ErrorItems>>;

/// Error code per data element
pub type ErrorItems = BTreeMap<DataElementIdentifier, ErrorCode>;

/// Error code.
pub type ErrorCode = i64;

// ----------------------------------------------------------------------------
/// # 9.1.2.4 Signing method and structure for MSO (pg 50)
// ----------------------------------------------------------------------------

/// `IssuerAuth` is comprised of an MSO encapsulated and signed by an untagged
/// `COSE_Sign1` type (RFC 8152).
///
/// The `COSE_Sign1` payload is `MobileSecurityObjectBytes` with the
/// `Sig_structure.external_aad` set to a zero-length bytestring.
#[derive(Clone, Debug, Default)]
pub struct IssuerAuth(pub CoseSign1);

// Use custom serialization/deserialization because `CoseSign1` does not
// implement `Serialize` and `Deserialize` traits.
impl Serialize for IssuerAuth {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.clone().to_cbor_value().map_err(ser::Error::custom)?.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for IssuerAuth {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        CoseSign1::from_cbor_value(value).map_err(de::Error::custom).map(Self)
    }
}

/// CBOR serialized, tagged `MobileSecurityObject`.
pub type MobileSecurityObjectBytes = Tag24<MobileSecurityObject>;

/// An mdoc digital signature is generated over the mobile security object
/// (MSO).
///
/// The MSO is used to provide Issuer data authentication for the associated
/// `mdoc`. It contains a signed digest (e.g. SHA-256) of the `mdoc`, including
/// the digests in the MSO.
///
/// See 9.1.2.4 Signing method and structure for MSO, pg 50.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    /// Version of the `MobileSecurityObject`. Must be 1.0.
    version: String,

    /// Message digest algorithm used.
    pub digest_algorithm: DigestAlgorithm,

    /// An ordered set of value digests for each data element in each name
    /// space.
    pub value_digests: BTreeMap<NameSpace, BTreeMap<DigestId, Digest>>,

    /// Device key information
    pub device_key_info: DeviceKeyInfo,

    /// The document type of the document being signed.
    pub doc_type: String,

    /// Validity information for the MSO
    pub validity_info: ValidityInfo,
}

impl MobileSecurityObject {
    /// Create a new `MobileSecurityObject` with default values.
    #[must_use]
    pub fn new() -> Self {
        // TODO: get valid_xxx dates from issuer
        let until = Utc::now() + Duration::days(365);

        Self {
            version: "1.0".to_string(),
            digest_algorithm: DigestAlgorithm::Sha256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo::default(),
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                valid_from: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                valid_until: until.to_rfc3339_opts(SecondsFormat::Secs, true),
                expected_update: None,
            },
        }
    }

    fn to_bytes(self) -> MobileSecurityObjectBytes {
        Tag24(self)
    }
}

impl Default for MobileSecurityObject {
    fn default() -> Self {
        Self::new()
    }
}

/// `DigestID` is an unsigned integer (0 < 2^31) used to match the hashes in
/// the MSO to the data elements in the mdoc response.
///
/// The Digest ID must be unique within a namespace with no correlation between
/// ID’s for the same namespace/element in different MSO’s. The value must be
/// smaller than 2^31.
pub type DigestId = i32;

/// The SHA digest of a data element.
pub type Digest = Vec<u8>;

/// Digest algorithm used by the MSO.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256
    #[serde(rename = "SHA-256")]
    Sha256,
    //
    // /// SHA-384
    // #[serde(rename = "SHA-384")]
    // Sha384,

    // /// SHA-512
    // #[serde(rename = "SHA-512")]
    // Sha512,
}

/// Used to hold the mdoc authentication public key and information related to
/// this key. Encoded as an untagged `COSE_Key` element as specified in
/// [RFC 9052] and [RFC 9053].
///
/// See 9.1.2.4 Signing method and structure for MSO, pg 50
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// Device key
    pub device_key: CoseKey,

    /// Key authorizations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,

    /// Key info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<BTreeMap<i64, Value>>,
}

/// Name spaces authorized for the MSO
pub type AuthorizedNameSpaces = Vec<NameSpace>;

/// Data elements authorized for the MSO
pub type AuthorizedDataElements = BTreeMap<NameSpace, DataElementsArray>;

/// Array of data element identifiers
pub type DataElementsArray = Vec<DataElementIdentifier>;

/// Key authorizations
///
/// See 9.1.2.4 Signing method and structure for MSO, pg 50
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    /// Key authorization namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<AuthorizedNameSpaces>,

    /// Map of data elements by name space.
    /// e.g. <namespace: [data elements]>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<AuthorizedDataElements>,
}

/// Contains information related to the validity of the MSO and its signature.
///
/// See 9.1.2.4 Signing method and structure for MSO, pg 50.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    /// Time the MSO was signed
    pub signed: String,

    /// The timestamp before which the MSO is not yet valid. Should be equal
    /// or later than the `signed` element
    pub valid_from: String,

    /// The timestamp after which the MSO is no longer valid.
    ///
    /// The value must be later than the `valid_from` element.
    pub valid_until: String,

    /// The time at which the issuing authority expects to re-sign the MSO
    /// (and potentially update data elements).
    pub expected_update: Option<String>,
}

/// Generates unique `DigestId` values.
pub struct DigestIdGenerator {
    used: HashSet<DigestId>,
}

impl DigestIdGenerator {
    /// Create a new `DigestIdGenerator`.
    #[must_use]
    pub fn new() -> Self {
        Self { used: HashSet::new() }
    }

    /// Generate a unique `DigestId`.
    pub fn generate(&mut self) -> DigestId {
        let mut digest_id;
        loop {
            digest_id = i32::abs(rand::rng().random());
            if self.used.insert(digest_id) {
                return digest_id;
            }
        }
    }
}

impl Default for DigestIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
/// # 9.1.3.4 mdoc authentication (pg 54)
// ----------------------------------------------------------------------------

/// Device authentication used to authenticate the mdoc response.
///
/// ```cddl
/// DeviceAuthentication = [
///     "DeviceAuthentication",
///     SessionTranscript,
///     DocType,
///     DeviceNameSpacesBytes,
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthentication(
    #[serde(skip_deserializing, default = "DeviceAuthentication::identifier")] &'static str,
    pub SessionTranscript,
    pub DocType,
    pub DeviceNameSpacesBytes,
);

impl DeviceAuthentication {
    const fn identifier() -> &'static str {
        "DeviceAuthentication"
    }
}

/// CBOR serialized, tagged `DeviceAuthentication`.
pub type DeviceAuthenticationBytes = Tag24<DeviceAuthentication>;

// let signature = signer.sign(&device_authentication_bytes).await;
//
// let cose_sign_1 = CoseSign1Builder::new()
//     .protected(protected)
//     .unprotected(unprotected)
//     .payload(null) // <- !! use a null value for the payload
//     .signature(signature)
//     .build();

/// Used by `DeviceAuth` to authenticate the mdoc using an ECDSA/EdDSA
/// signature.
///
/// See 9.1.3.6 mdoc ECDSA / EdDSA Authentication, pg 54
#[derive(Clone, Debug, Default)]
pub struct DeviceSignature(pub CoseSign1);

impl Serialize for DeviceSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.clone().to_cbor_value().map_err(ser::Error::custom)?.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for DeviceSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        CoseSign1::from_cbor_value(value).map_err(de::Error::custom).map(Self)
    }
}

/// Used by `DeviceAuth` to authenticate the mdoc using an ECKA-DH derived MAC.
///
/// See 9.1.3.5 mdoc MAC Authentication, pg 54
#[derive(Clone, Debug, Default)]
pub struct DeviceMac(pub CoseMac0);

impl Serialize for DeviceMac {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.clone().to_cbor_value().map_err(ser::Error::custom)?.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for DeviceMac {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        CoseMac0::from_cbor_value(value).map_err(de::Error::custom).map(Self)
    }
}

// ----------------------------------------------------------------------------
/// # 9.1.1 Session encryption
// ----------------------------------------------------------------------------

/// Containing EDeviceKey.Pub
pub type EDeviceKey = CoseKey;

/// Containing EReaderKey.Pub
pub type EReaderKey = CoseKey;

/// CBOR serialized, tagged `EDeviceKey`.
pub type EDeviceKeyBytes = Tag24<CoseKey>;

/// CBOR serialized, tagged `EReaderKey`.
pub type EReaderKeyBytes = Tag24<CoseKey>;

// ----------------------------------------------------------------------------
/// # 9.1.5 Session transcript and cipher suite
// ----------------------------------------------------------------------------

/// CBOR serialized, tagged `SessionTranscript`.
pub type SessionTranscriptBytes = Tag24<SessionTranscript>;

/// Used in multiple security mechanisms for device retrieval.
///
/// ```cddl
/// SessionTranscript = [
///     DeviceEngagementBytes,
///     EReaderKeyBytes,
///     Handover
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript(
    /// CBOR serialized, tagged `DeviceEngagement`.
    pub DeviceEngagementBytes,
    /// CBOR serialized, tagged `EReaderKey`.
    pub EReaderKeyBytes,
    /// Handover information.
    pub OpenID4VPDCAPIHandover,
);

/// CBOR serialized, tagged `DeviceEngagement`.
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;

///
/// ```cddl
/// OpenID4VPDCAPIHandover = [
///   "OpenID4VPDCAPIHandover", ; A fixed identifier for this handover type
///   OpenID4VPDCAPIHandoverInfoHash ; A cryptographic hash of OpenID4VPDCAPIHandoverInfo
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPDCAPIHandover(
    #[serde(skip_deserializing, default = "OpenID4VPDCAPIHandover::identifier")] &'static str,
    pub OpenID4VPDCAPIHandoverInfoHash,
);

impl OpenID4VPDCAPIHandover {
    const fn identifier() -> &'static str {
        "OpenID4VPDCAPIHandover"
    }
}

/// A sha-256 hash of OpenID4VPDCAPIHandoverInfoBytes
pub type OpenID4VPDCAPIHandoverInfoHash = Vec<u8>;

/// CBOR serialized, tagged `OpenID4VPDCAPIHandoverInfo`.
pub type OpenID4VPDCAPIHandoverInfoBytes = Tag24<OpenID4VPDCAPIHandoverInfo>;

/// Array containing handover parameters
/// ```cddl
/// OpenID4VPDCAPIHandoverInfo = [
///   origin,
///   nonce,
///   jwk_thumbprint
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPDCAPIHandoverInfo(pub Origin, pub Nonce, pub JwkThumbprint);

/// Represents the Origin of the request as described in Appendix A.2. It MUST
/// NOT be prefixed with `origin:`.
pub type Origin = String;

/// The `nonce` parameter from the Authorization Request Object.
pub type Nonce = String;

/// JWK SHA-256 Thumbprint as defined in [RFC7638], encoded as a CBOR Byte
/// String, of the Verifier's public key used to encrypt the response.
///
/// If the Response Mode is `dc_api`, the third element MUST be null.
///
/// For unsigned requests, including the JWK Thumbprint in the
/// `SessionTranscript` allows the Verifier to detect whether the response was
/// re-encrypted by a third party, potentially leading to the leakage of
/// sensitive information. While this does not prevent such an attack, it makes
/// it detectable and helps preserve the confidentiality of the response.
pub type JwkThumbprint = Vec<u8>;

#[cfg(test)]
mod tests {
    use credibil_infosec::cose::serde_cbor;
    use credibil_infosec::{Curve, KeyType};

    use super::*;

    #[test]
    fn test_device_engagement() {
        let de = DeviceEngagement {
            version: "1.0".to_string(),
            security: Security(
                CipherSuite::Suite1,
                Tag24(CoseKey {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: vec![1, 2, 3],
                    y: None,
                }),
            ),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        

        let serialized = serde_cbor::to_vec(&de).unwrap();
        let deserialized: DeviceEngagement = serde_cbor::from_slice(&serialized).unwrap();

        assert_eq!(de.version, deserialized.version);
        assert_eq!(de.security.0, deserialized.security.0);
    }
}
