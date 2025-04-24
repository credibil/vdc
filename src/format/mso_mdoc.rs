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

pub mod cose;
mod issue;
mod present;
mod store;

use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::ops::Deref;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use ciborium::{Value, cbor};
use coset::{AsCborValue, CoseMac0, CoseSign1};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub use self::cose::{CoseKey, Curve, KeyType};
pub use self::issue::MsoMdocBuilder;
pub use self::present::DeviceResponseBuilder;
pub use self::store::to_queryable;
use crate::core::serde_cbor;

/// Supported device retrieval methods.
#[derive(Clone, Debug, Deserialize_repr, Serialize_repr)]
#[repr(u64)]
pub enum VersionNumber {
    /// Version 1
    One = 1,
}

/// Supported device retrieval methods.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(u64)]
pub enum VersionString {
    /// Version 1.0
    #[serde(rename = "1.0")]
    One,
}

impl Display for VersionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::One => write!(f, "1.0"),
        }
    }
}

// ----------------------------------------------------------------------------
// # 8.2 Device engagement (pg 24)
// ----------------------------------------------------------------------------

/// CBOR serialized, tagged `DeviceEngagement`.
pub type DeviceEngagementBytes = DataItem<DeviceEngagement>;

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
#[derive(Clone, Debug)]
pub struct DeviceEngagement {
    /// Version.
    pub version: VersionString,

    /// Security information containing the device public key and cipher suite.
    pub security: Security,

    /// Used when performing device engagement using the QR code. Absent when
    /// using NFC.
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,

    /// The optional server retrieval methods for the device engagement.
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,

    /// The optional protocol information for the device engagement.
    pub protocol_info: Option<ProtocolInfo>,
}

impl DeviceEngagement {
    /// Wraps the `DeviceEngagement` in a [`DataItem`] for serialization to
    /// CBOR data item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
    }
}

impl Serialize for DeviceEngagement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::<i64, Value>::new();
        map.insert(0, self.version.to_string().into());
        map.insert(1, cbor!(self.security).map_err(ser::Error::custom)?);
        if let Some(ref methods) = self.device_retrieval_methods {
            map.insert(2, cbor!(methods).map_err(ser::Error::custom)?);
        }
        if let Some(ref methods) = self.server_retrieval_methods {
            map.insert(3, cbor!(methods).map_err(ser::Error::custom)?);
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
        let version = map.get(&0).ok_or_else(|| de::Error::missing_field("version"))?;
        let security = map.get(&1).ok_or_else(|| de::Error::missing_field("security"))?;

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
        }
        if let Some(methods) = map.get(&3) {
            de.server_retrieval_methods = methods.deserialized().map_err(de::Error::custom)?;
        }
        if let Some(protocol_info) = map.get(&4) {
            de.protocol_info = protocol_info.deserialized().map_err(de::Error::custom)?;
        }

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
#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u64)]
pub enum CipherSuite {
    /// Cipher suite 1
    Suite1 = 1,
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
    /// The type of transfer method.
    pub RetrievalType,
    /// The version of the transfer method.
    pub VersionNumber,
    /// Additional options for each connection.
    pub RetrievalOptions,
);

/// Supported device retrieval methods.
#[derive(Clone, Debug, Deserialize_repr, Serialize_repr)]
#[repr(u64)]
pub enum RetrievalType {
    /// NFC
    Nfc = 1,

    /// Bluetooth low energy
    Ble = 2,

    /// Wifi
    Wifi = 3,
}

/// Supported device retrieval options.
///
/// See 8.2.2.3 Device engagement using QR code, pg 28.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RetrievalOptions {
    /// NFC options.
    NfcOptions(NfcOptions),

    /// Bluetooth low energy options.
    BleOptions(BleOptions),

    /// Wifi options.
    WifiOptions(WifiOptions),
}

/// Wifi options.
///
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

    // TODO: Use enum for operating class
    /// Channel info operating class.
    pub operating_class: Option<u64>,

    // TODO: Use enum for channel number
    /// Channel info channel number.
    pub channel_number: Option<u64>,

    /// Band Info supported bands.
    pub supported_bands: Option<Vec<u8>>,
}

impl Serialize for WifiOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::<i64, Value>::new();

        if let Some(ref passphrase) = self.passphrase {
            map.insert(0, passphrase.clone().into());
        }
        if let Some(class) = self.operating_class {
            map.insert(1, class.into());
        }
        if let Some(number) = self.channel_number {
            map.insert(2, number.into());
        }
        if let Some(ref bands) = self.supported_bands {
            map.insert(3, bands.clone().into());
        }
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WifiOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<i64, Value>::deserialize(deserializer)?;

        let mut wifi = Self {
            passphrase: None,
            operating_class: None,
            channel_number: None,
            supported_bands: None,
        };

        if let Some(passphrase) = map.get(&0) {
            wifi.passphrase = Some(passphrase.deserialized().map_err(de::Error::custom)?);
        }
        if let Some(class) = map.get(&1) {
            wifi.operating_class = Some(class.deserialized().map_err(de::Error::custom)?);
        }
        if let Some(number) = map.get(&2) {
            wifi.channel_number = Some(number.deserialized().map_err(de::Error::custom)?);
        }
        if let Some(bands) = map.get(&3) {
            wifi.supported_bands = Some(
                bands
                    .as_bytes()
                    .cloned()
                    .ok_or_else(|| de::Error::custom("`supported_bands` is not bytes"))?,
            );
        }

        Ok(wifi)
    }
}

/// Bluetooth low energy options.
///
/// ```cddl
/// BleOptions = {
///     0 : bool,       ; Indicates support for mdoc peripheral server mode
///     1 : bool,       ; Indicates support for mdoc central client mode
///     ? 10 : bstr,    ; UUID for mdoc peripheral server mode
///     ? 11 : bstr     ; UUID for mdoc client central mode
///     ? 20 : bstr     ; mdoc BLE Device Address for mdoc peripheral server mode
/// }
/// ```
#[derive(Clone, Debug)]
pub struct BleOptions {
    /// Indicates support for mdoc peripheral server mode.
    pub server_mode: bool,

    /// Indicates support for mdoc central client mode.
    pub client_mode: bool,

    /// UUID for mdoc peripheral server mode.
    pub server_mode_uuid: Option<Vec<u8>>,

    /// UUID for mdoc client central mode.
    pub client_mode_uuid: Option<Vec<u8>>,

    /// mdoc BLE Device Address for mdoc peripheral server mode.
    pub device_address: Option<Vec<u8>>,
}

impl Serialize for BleOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::<i64, Value>::new();
        map.insert(0, self.server_mode.into());
        map.insert(1, self.client_mode.into());
        if let Some(ref uuid) = self.server_mode_uuid {
            map.insert(10, uuid.clone().into());
        }
        if let Some(ref uuid) = self.client_mode_uuid {
            map.insert(11, uuid.clone().into());
        }
        if let Some(ref address) = self.device_address {
            map.insert(20, address.clone().into());
        }
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BleOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<i64, Value>::deserialize(deserializer)?;

        // required fields
        let server_mode = map.get(&0).ok_or_else(|| de::Error::missing_field("server_mode"))?;
        let client_mode = map.get(&1).ok_or_else(|| de::Error::missing_field("client_mode"))?;

        let mut ble = Self {
            server_mode: server_mode.deserialized().map_err(de::Error::custom)?,
            client_mode: client_mode.deserialized().map_err(de::Error::custom)?,
            server_mode_uuid: None,
            client_mode_uuid: None,
            device_address: None,
        };

        // optional fields
        if let Some(uuid) = map.get(&10) {
            ble.server_mode_uuid = Some(
                uuid.as_bytes().cloned().ok_or_else(|| de::Error::custom("uuid is not bytes"))?,
            );
        }
        if let Some(uuid) = map.get(&11) {
            ble.client_mode_uuid = Some(
                uuid.as_bytes().cloned().ok_or_else(|| de::Error::custom("uuid is not bytes"))?,
            );
        }
        if let Some(addr) = map.get(&20) {
            ble.device_address = Some(
                addr.as_bytes().cloned().ok_or_else(|| de::Error::custom("uuid is not bytes"))?,
            );
        }

        Ok(ble)
    }
}

/// NFC options.
///
/// ```cddl
// NfcOptions = {
//     0 : uint,   ; Maximum length of command data field
//     1 : uint    ; Maximum length of response data field
// }
/// ```
#[derive(Clone, Debug)]
pub struct NfcOptions {
    /// Maximum length of command data field.
    pub max_command_len: u64,

    /// Maximum length of response data field.
    pub max_response_len: u64,
}

impl Serialize for NfcOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::<i64, Value>::new();
        map.insert(0, self.max_command_len.into());
        map.insert(1, self.max_response_len.into());
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NfcOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<i64, Value>::deserialize(deserializer)?;
        let max_command_len =
            map.get(&0).ok_or_else(|| de::Error::missing_field("max_command_len"))?;
        let max_response_len =
            map.get(&1).ok_or_else(|| de::Error::missing_field("max_response_len"))?;

        Ok(Self {
            max_command_len: max_command_len.deserialized().map_err(de::Error::custom)?,
            max_response_len: max_response_len.deserialized().map_err(de::Error::custom)?,
        })
    }
}

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
    pub VersionNumber,
    // The issuer URL.
    pub String,
    /// The server retrieval token as provided by the mdoc reader.
    pub String,
);

/// `ProtocolInfo`
pub type ProtocolInfo = Value;

// ----------------------------------------------------------------------------
// # 8.3.1 Data model
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
// # 8.3.2.1.2.2 Device retrieval mdoc response (pg 30)
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
    /// Version of the `DeviceResponse` structure.
    pub version: VersionString,

    /// Returned documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<Document>>,

    /// Error codes for unreturned documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<BTreeMap<DocType, ErrorCode>>,

    /// Status code.
    pub status: ResponseStatus,
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
pub type IssuerSignedItemBytes = DataItem<IssuerSignedItem>;

/// Issuer-signed data element
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    /// Id of the digest as added to the MSO `value_digests` parameter.
    #[serde(rename = "digestID")]
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
    /// Wraps the `IssuerSignedItem` in a [`DataItem`] for serialization to
    /// CBOR data item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
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
pub type DeviceNameSpacesBytes = DataItem<DeviceNameSpaces>;

/// Returned data elements for each namespace.
pub type DeviceNameSpaces = BTreeMap<NameSpace, Vec<DeviceSignedItems>>;

/// Returned data elements (identifier and value) for each namespace.
pub type DeviceSignedItems = BTreeMap<String, ciborium::Value>;

/// Device authentication used to authenticate the mdoc response.
///
/// N.B. a single mdoc authentication key cannot be used to produce both
/// signature and MAC.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DeviceAuth {
    /// `EdDSA` signature
    #[serde(rename = "deviceSignature")]
    Signature(DeviceSignature),

    /// ECDH-agreed MAC
    #[serde(rename = "deviceMac")]
    Mac(DeviceMac),
}

/// Error codes for each namespace.
pub type Errors = BTreeMap<NameSpace, Vec<ErrorItems>>;

/// Error code per data element
pub type ErrorItems = BTreeMap<DataElementIdentifier, ErrorCode>;

/// Error code.
pub type ErrorCode = i64;

/// Device retrieval mdoc response status codes.
#[derive(Clone, Debug, Default, Deserialize_repr, Serialize_repr)]
#[repr(u64)]
pub enum ResponseStatus {
    /// Normal processing. Returned when no other status is returned.
    #[default]
    Ok = 0,

    /// The mdoc returns an error without any given reason.
    Error = 10,

    /// The mdoc indicates an error during CBOR decoding
    DecodingError = 11,

    /// The mdoc indicates an error during CBOR validation.
    ValidationError = 12,
}

// ----------------------------------------------------------------------------
// # 9.1.2.4 Signing method and structure for MSO (pg 50)
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
pub type MobileSecurityObjectBytes = DataItem<MobileSecurityObject>;

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
    pub version: VersionString,

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
        Self {
            version: VersionString::One,
            digest_algorithm: DigestAlgorithm::Sha256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo::default(),
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: Utc::now(),
                valid_from: Utc::now(),
                valid_until: Utc::now() + Duration::days(365),
                expected_update: None,
            },
        }
    }

    /// Wraps the `MobileSecurityObject` in a [`DataItem`] for serialization to
    /// CBOR data item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
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
    pub key_info: Option<KeyInfo>,
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

/// Positive integers are RFU, negative integers may be used for proprietary use.
pub type KeyInfo = BTreeMap<i64, Value>;

/// Contains information related to the validity of the MSO and its signature.
///
/// See 9.1.2.4 Signing method and structure for MSO, pg 50.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct ValidityInfo {
    /// Time the MSO was signed
    pub signed: DateTime<Utc>,

    /// The timestamp before which the MSO is not yet valid. Should be equal
    /// or later than the `signed` element
    #[serde(with = "chrono::serde::ts_seconds")]
    pub valid_from: DateTime<Utc>,

    /// The timestamp after which the MSO is no longer valid.
    ///
    /// The value must be later than the `valid_from` element.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub valid_until: DateTime<Utc>,

    /// The time at which the issuing authority expects to re-sign the MSO
    /// (and potentially update data elements).
    #[serde(with = "chrono::serde::ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_update: Option<DateTime<Utc>>,
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
// # 9.1.3.4 mdoc authentication (pg 54)
// ----------------------------------------------------------------------------

/// CBOR serialized, tagged `DeviceAuthentication`.
pub type DeviceAuthenticationBytes = DataItem<DeviceAuthentication>;

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
    /// The device authentication identifier.
    &'static str,
    /// Used in multiple security mechanisms for device retrieval.
    pub SessionTranscript,
    /// The document type of the document being signed.
    pub DocType,
    /// Returned data elements for each namespace
    pub DeviceNameSpacesBytes,
);

impl DeviceAuthentication {
    /// Wraps the `DeviceAuthentication` in a [`DataItem`] for serialization to
    /// CBOR data item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
    }
}

/// Used by `DeviceAuth` to authenticate the mdoc using an ECDSA/EdDSA
/// signature.
///
/// See 9.1.3.6 mdoc ECDSA/EdDSA Authentication, pg 54.
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
// # 9.1.1 Session encryption
// ----------------------------------------------------------------------------

/// Containing EDeviceKey.Pub
pub type EDeviceKey = CoseKey;

/// Containing EReaderKey.Pub
pub type EReaderKey = CoseKey;

/// CBOR serialized, tagged `EDeviceKey`.
pub type EDeviceKeyBytes = DataItem<CoseKey>;

/// CBOR serialized, tagged `EReaderKey`.
pub type EReaderKeyBytes = DataItem<CoseKey>;

// ----------------------------------------------------------------------------
// # 9.1.5 Session transcript and cipher suite
// ----------------------------------------------------------------------------

/// CBOR serialized, tagged `SessionTranscript`.
pub type SessionTranscriptBytes = DataItem<SessionTranscript>;

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

///
/// ```cddl
/// OpenID4VPDCAPIHandover = [
///   "OpenID4VPDCAPIHandover", ; A fixed identifier for this handover type
///   OpenID4VPDCAPIHandoverInfoHash ; A cryptographic hash of OpenID4VPDCAPIHandoverInfoBytes
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPDCAPIHandover(
    ///The handover type identifier.
    pub String,
    /// A sha-256 hash of `OpenID4VPDCAPIHandoverInfoBytes`.
    pub OpenID4VPDCAPIHandoverInfoHash,
);

/// A sha-256 hash of `OpenID4VPDCAPIHandoverInfoBytes`
pub type OpenID4VPDCAPIHandoverInfoHash = Vec<u8>;

/// CBOR serialized, tagged `OpenID4VPDCAPIHandoverInfo`.
pub type OpenID4VPDCAPIHandoverInfoBytes = DataItem<OpenID4VPDCAPIHandoverInfo>;

/// Array containing handover parameters
/// ```cddl
/// OpenID4VPDCAPIHandoverInfo = [
///   origin,
///   nonce,
///   jwk_thumbprint
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPDCAPIHandoverInfo(
    /// Represents the Origin of the request as described in Appendix A.2. It MUST
    /// NOT be prefixed with `origin:`.
    pub String,
    /// The `nonce` parameter from the Authorization Request Object.
    pub String,
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
    pub Vec<u8>,
);

impl OpenID4VPDCAPIHandoverInfo {
    /// Wraps the `OpenID4VPDCAPIHandoverInfo` in a [`DataItem`] for
    /// serialization to CBOR data item (tag 24).
    #[must_use]
    pub const fn into_bytes(self) -> DataItem<Self> {
        DataItem(self)
    }
}

/// Wrap types that require tagging with tag 24.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataItem<T>(pub T);

impl<T> Deref for DataItem<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Serialize for DataItem<T> {
    fn serialize<S: Serializer>(&self, s: S) -> anyhow::Result<S::Ok, S::Error> {
        let inner = serde_cbor::to_vec(&self.0)
            .map_err(|e| ser::Error::custom(format!("issue serializing DataItem: {e}")))?;
        Value::Tag(24, Box::new(inner.into())).serialize(s)
    }
}

impl<'de, T> Deserialize<'de> for DataItem<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Tag(24, value) = Value::deserialize(deserializer)? else {
            return Err(de::Error::custom("not a DataItem"));
        };
        let Value::Bytes(bytes) = value.as_ref() else {
            return Err(de::Error::custom(format!("invalid tag: {value:?}")));
        };
        let inner = serde_cbor::from_slice(bytes)
            .map_err(|e| de::Error::custom(format!("issue deserializing DataItem: {e}")))?;
        Ok(Self(inner))
    }
}

#[cfg(test)]
mod tests {
    // use hex::FromHex;
    use super::*;
    use crate::core::serde_cbor;

    #[test]
    fn device_engagement() {
        const SPEC_HEX: &str = "a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917";
        let bytes = hex::decode(SPEC_HEX).unwrap();
        let spec: DeviceEngagement = serde_cbor::from_slice(&bytes).unwrap();
        let spec_bytes = serde_cbor::to_vec(&spec).unwrap();

        let custom = DeviceEngagement {
            version: VersionString::One,
            security: Security(
                CipherSuite::Suite1,
                DataItem(CoseKey {
                    kty: KeyType::Ec,
                    crv: Curve::P256,
                    x: vec![
                        90, 136, 209, 130, 188, 229, 244, 46, 250, 89, 148, 63, 51, 53, 157, 46,
                        138, 150, 143, 242, 137, 217, 62, 95, 164, 68, 182, 36, 52, 49, 103, 254,
                    ],
                    y: Some(vec![
                        177, 110, 140, 248, 88, 221, 199, 105, 4, 7, 186, 97, 212, 195, 56, 35,
                        122, 140, 252, 243, 222, 106, 166, 114, 252, 96, 165, 87, 170, 50, 252,
                        103,
                    ]),
                }),
            ),
            device_retrieval_methods: Some(vec![DeviceRetrievalMethod(
                RetrievalType::Ble,
                VersionNumber::One,
                RetrievalOptions::BleOptions(BleOptions {
                    server_mode: false,
                    client_mode: true,
                    server_mode_uuid: None,
                    client_mode_uuid: Some(vec![
                        69, 239, 239, 116, 43, 44, 72, 55, 169, 163, 176, 225, 208, 90, 105, 23,
                    ]),
                    device_address: None,
                }),
            )]),
            server_retrieval_methods: None,
            protocol_info: None,
        };
        let custom_bytes = serde_cbor::to_vec(&custom).unwrap();

        assert_eq!(hex::encode(spec_bytes), hex::encode(custom_bytes));
        assert_eq!(spec.security.0, custom.security.0);
    }

    #[test]
    fn device_response() {
        const SPEC_HEX: &str = "a36776657273696f6e63312e3069646f63756d656e747381a367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69736f2e31383031332e352e3186d8185863a4686469676573744944006672616e646f6d58208798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d818586ca4686469676573744944036672616e646f6d5820b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d71656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d903ec6a323031392d31302d3230d818586da4686469676573744944046672616e646f6d5820c7ffa307e5de921e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf71656c656d656e744964656e7469666965726b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032342d31302d3230d818586da4686469676573744944076672616e646f6d582026052a42e5880557a806c1459af3fb7eb505d3781566329d0b604b845b5f9e6871656c656d656e744964656e7469666965726f646f63756d656e745f6e756d6265726c656c656d656e7456616c756569313233343536373839d818590471a4686469676573744944086672616e646f6d5820d094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d71656c656d656e744964656e74696669657268706f7274726169746c656c656d656e7456616c7565590412ffd8ffe000104a46494600010101009000900000ffdb004300130d0e110e0c13110f11151413171d301f1d1a1a1d3a2a2c2330453d4947443d43414c566d5d4c51685241435f82606871757b7c7b4a5c869085778f6d787b76ffdb0043011415151d191d381f1f38764f434f7676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676ffc00011080018006403012200021101031101ffc4001b00000301000301000000000000000000000005060401020307ffc400321000010303030205020309000000000000010203040005110612211331141551617122410781a1163542527391b2c1f1ffc4001501010100000000000000000000000000000001ffc4001a110101010003010000000000000000000000014111213161ffda000c03010002110311003f00a5bbde22da2329c7d692bc7d0d03f52cfb0ff75e7a7ef3e7709723a1d0dae146ddfbb3c039ce07ad2bd47a7e32dbb8dd1d52d6ef4b284f64a480067dfb51f87ffb95ff00eb9ff14d215de66af089ce44b7dbde9cb6890a2838eddf18078f7add62d411ef4db9b10a65d6b95a147381ea0d495b933275fe6bba75c114104a8ba410413e983dff004f5af5d34b4b4cde632d0bf1fd1592bdd91c6411f3934c2fa6af6b54975d106dcf4a65ae56e856001ebc03c7ce29dd9eef1ef10fc447dc9da76ad2aee93537a1ba7e4f70dd8eff0057c6dffb5e1a19854a83758e54528750946ec6704850cd037bceb08b6d7d2cc76d3317fc7b5cc04fb6707269c5c6e0c5b60ae549242123b0e493f602a075559e359970d98db89525456b51c951c8afa13ea8e98e3c596836783d5c63f5a61a99fdb7290875db4be88ab384bbbbbfc7183fdeaa633e8951db7da396dc48524fb1a8bd611a5aa2a2432f30ab420a7a6d3240c718cf031fa9ef4c9ad550205aa02951df4a1d6c8421b015b769db8c9229837ea2be8b1b0d39d0eba9c51484efdb8c0efd8d258daf3c449699f2edbd4584e7af9c64e3f96b9beb28d4ac40931e6478c8e76a24a825449501d867d2b1dcdebae99b9c752ae4ecd6dde4a179c1c1e460938f9149ef655e515c03919a289cb3dca278fb7bf177f4faa829dd8ce3f2ac9a7ecde490971fafd7dce15eed9b71c018c64fa514514b24e8e4f8c5c9b75c1e82579dc1233dfec08238f6add62d391acc1c5256a79e706d52d431c7a0145140b9fd149eb3a60dc5e88cbbc2da092411e9dc71f39a7766b447b344e847dcac9dcb5abba8d145061d43a6fcf1e65cf15d0e90231d3dd9cfe62995c6dcc5ca12a2c904a15f71dd27d451453e09d1a21450961cbb3ea8a956433b781f1ce33dfed54f0e2b50a2b71d84ed6db18028a28175f74fc6bda105c529a791c25c4f3c7a11f71586268f4a66b726e33de9ea6f1b52b181c760724e47b514520a5a28a283ffd9d81858ffa4686469676573744944096672616e646f6d58204599f81beaa2b20bd0ffcc9aa03a6f985befab3f6beaffa41e6354cdb2ab2ce471656c656d656e744964656e7469666965727264726976696e675f70726976696c656765736c656c656d656e7456616c756582a37576656869636c655f63617465676f72795f636f646561416a69737375655f64617465d903ec6a323031382d30382d30396b6578706972795f64617465d903ec6a323032342d31302d3230a37576656869636c655f63617465676f72795f636f646561426a69737375655f64617465d903ec6a323031372d30322d32336b6578706972795f64617465d903ec6a323032342d31302d32306a697373756572417574688443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87eb84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a30213112301006035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d120417301581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603551d2304183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d040302034800304502210097717ab9016740c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d43e2425caf90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d667646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a30325a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832044b890ad85aa53f129134775d733754d7cb7a413766aeff13cb2e6c6465766963655369676e6564a26a6e616d65537061636573d81841a06a64657669636541757468a1696465766963654d61638443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d6673746174757300";
        let bytes = hex::decode(SPEC_HEX).unwrap();
        let spec = serde_cbor::from_slice::<DeviceResponse>(&bytes).unwrap();
        println!("spec: {spec:?}");
    }
}
