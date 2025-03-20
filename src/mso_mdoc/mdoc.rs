//! # Model

//! # MSO MDOC
//!
//! See pg 31 of spec.
//!
//! The Mobile Security Object (MSO) Mobile Device Object (MDOC) is a data
//! structure that contains the data elements that are signed by the issuer
//! and the mobile device. The issuer signs the data elements to authenticate
//! the issuer data, and the mobile device signs the data elements to
//! authenticate the mobile device data. The MSO MDOC is returned in the
//! `DeviceResponse` structure.

use std::collections::BTreeMap;

use credibil_infosec::cose::{Tag24, cbor};
use serde::{Deserialize, Serialize};

use super::mso;

pub type NameSpace = String;

/// Data elements (claims) returned by the Issuer. Each data element is
/// hashed and signed by the Issuer in the MSO.
///
/// See 8.3.2.1.2.2 Device retrieval mdoc response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    /// Returned data elements for each namespace (`IssuerNameSpaces` element)
    pub name_spaces: BTreeMap<NameSpace, Vec<IssuerSignedItemBytes>>,

    /// The mobile security object (MSO) for issuer data authentication.
    /// `COSE_Sign1` with a payload of `MobileSecurityObjectBytes`
    pub issuer_auth: mso::IssuerAuth,
}

impl IssuerSigned {
    /// Create a new `IssuerSigned` with default values.
    pub fn new() -> Self {
        Self {
            name_spaces: BTreeMap::new(),
            issuer_auth: mso::IssuerAuth::default(),
        }
    }

    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        cbor::to_vec(self)
    }
}

/// `IssuerSignedItemBytes` represents the tagged `IssuerSignedItem` after
/// CBOR serialization:  `#6.24(bstr .cbor IssuerSignedItem)`
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Issuer-signed data element
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerSignedItem {
    /// Id of the digest as added to the MSO `value_digests` parameter.
    pub digest_id: mso::DigestId,

    /// Random hexadecimal value for issuer data authentication.
    /// (min. 16 bytes).
    pub random: Vec<u8>,

    /// Data element identifier. For example, "`family_name`"
    pub element_identifier: String,

    /// Data element value. For example, "`Smith`"
    pub element_value: ciborium::Value,
}
