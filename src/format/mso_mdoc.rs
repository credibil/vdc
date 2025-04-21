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

use chrono::{Duration, SecondsFormat, Utc};
use ciborium::Value;
use coset::{AsCborValue, CoseMac0, CoseSign1};
use credibil_infosec::cose::{CoseKey, Tag24, cbor};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

pub use self::issue::MsoMdocBuilder;
pub use self::present::DeviceResponseBuilder;
pub use self::store::to_queryable;

// /// Wrap types that require tagging with tag 24.
// #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
// pub struct Tag24<T>(pub T);

// impl<T> TaggedCborSerializable for Tag24<T>
// where
//     Tag24<T>: for<'a> Deserialize<'a> + Serialize,
// {
//     const TAG: u64 = 24;
// }

// impl<T> AsCborValue for Tag24<T>
// where
//     Tag24<T>: for<'a> Deserialize<'a> + Serialize,
// {
//     fn from_cbor_value(value: Value) -> coset::Result<Self> {
//         ciborium::from_reader(Cursor::new(&value.to_vec()?))
//             .map_err(|e| CoseError::DecodeFailed(Error::Semantic(None, e.to_string())))
//     }

//     fn to_cbor_value(self) -> coset::Result<Value> {
//         Value::serialized(&self)
//             .map_err(|e| CoseError::DecodeFailed(Error::Semantic(None, e.to_string())))
//     }
// }

// ----------------------------------------------------------------------------
/// # 8.2 Device engagement
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
pub type DeviceEngagement = BTreeMap<i64, Value>;

/// ```cddl
/// Security = [
///     int, ; Cipher suite identifier
///     EDeviceKeyBytes
/// ]
/// ```
pub type Security = Vec<Value>;

/// ```cddl
/// DeviceRetrievalMethods = [
///     + DeviceRetrievalMethod
/// ]
/// ```
pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;

/// ProtocolInfo
pub type ProtocolInfo = Value;

/// ```cddl
/// DeviceRetrievalMethod = [
///     uint, ; Type
///     uint, ; Version
///     RetrievalOptions ; Specific option(s) to the type of retrieval method
/// ]
/// ```
pub type DeviceRetrievalMethod = Vec<Value>;

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

    /// Serialize the `IssuerSigned` object to a CBOR byte vector.
    ///
    /// # Errors
    /// TODO: document errors
    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        cbor::to_vec(self)
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
pub type DeviceAuthentication = Vec<Value>;

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
pub type EReaderKey = CoseKey;

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
pub type SessionTranscript = Vec<Value>;

/// CBOR serialized, tagged `DeviceEngagement`.
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;

///
/// ```cddl
/// OpenID4VPDCAPIHandover = [
///   "OpenID4VPDCAPIHandover", ; A fixed identifier for this handover type
///   OpenID4VPDCAPIHandoverInfoHash ; A cryptographic hash of OpenID4VPDCAPIHandoverInfo
/// ]
/// ```
pub type OpenID4VPDCAPIHandover = Vec<Value>;

/// CBOR serialized, tagged `OpenID4VPDCAPIHandoverInfo`.
pub type OpenID4VPDCAPIHandoverInfoBytes = Tag24<OpenID4VPDCAPIHandoverInfo>;

/// Array containing handover parameters
/// ```cddl
// OpenID4VPDCAPIHandoverInfo = [
///   origin,
///   nonce,
///   jwk_thumbprint
/// ]
/// ```
pub type OpenID4VPDCAPIHandoverInfo = Vec<Value>;

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
pub type JwkThumbprint = Tag24<String>;
