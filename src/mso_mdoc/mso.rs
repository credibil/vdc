//! # Mobile Security Object (MSO)
//!
//! The MSO is used to provide Issuer data authentication for the associated
//! `mdoc`. It contains a signed digest (e.g. SHA-256) of the `mdoc`, including
//! the digests in the MSO.
//!
//! See 9.1.2.4 Signing method and structure for MSO.

use std::collections::{BTreeMap, HashSet};

use chrono::{Duration, SecondsFormat, Utc};
use ciborium::Value;
use coset::{AsCborValue, CoseSign1};
use credibil_infosec::cose::CoseKey;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

use super::mdoc::NameSpace;

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
    doc_type: String,

    /// Validity information for the MSO
    pub validity_info: ValidityInfo,
}

impl MobileSecurityObject {
    /// Create a new `MobileSecurityObject` with default values.
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
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// Device key
    pub device_key: CoseKey,

    /// Key authorizations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<Vec<KeyAuthorization>>,

    /// Key info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<BTreeMap<i64, ciborium::Value>>,
}

/// Name spaces authorized for the MSO
pub type AuthorizedNameSpaces = Vec<NameSpace>;

/// Data elements authorized for the MSO
pub type AuthorizedDataElements = BTreeMap<NameSpace, DataElementsArray>;

/// Array of data element identifiers
pub type DataElementsArray = Vec<DataElementIdentifier>;

/// Data element identifier
pub type DataElementIdentifier = String;

/// Key authorization
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorization {
    /// Key authorization namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<AuthorizedNameSpaces>,

    /// Map of data elements by name space.
    /// e.g. <namespace: [data elements]>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<AuthorizedDataElements>,
}

/// Contains information related to the validity of the MSO and its signature.
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
    pub fn new() -> Self {
        Self { used: HashSet::new() }
    }

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
