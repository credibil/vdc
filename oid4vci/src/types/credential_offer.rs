use std::fmt::{self, Display};
use std::io::Cursor;
use std::str::FromStr;

use anyhow::Context as _;
use base64ct::{Base64, Encoding};
use credibil_core::urlencode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

use crate::oauth::GrantType;
use crate::types::{AuthorizationCodeGrant, Grants, PreAuthorizedCodeGrant};

/// Build a Credential Offer for a Credential Issuer.
#[derive(Default, Debug)]
pub struct CreateOfferRequestBuilder<C, S, P> {
    credential_configuration_ids: C,
    subject_id: S,
    pre_authorized: P,
    grant_types: Vec<GrantType>,
    tx_code: bool,
    by_ref: bool,
}

/// No credential configuration id is set.
#[doc(hidden)]
pub struct NoIdentifiers;
/// At least one credential configuration id is set.
#[doc(hidden)]
pub struct HasIdentifiers(Vec<String>);

/// No pre-authorized grant is specified.
#[doc(hidden)]
pub struct NoPreAuthorized;
/// Pre-authorized grant is specified.
#[doc(hidden)]
pub struct PreAuthorized;

/// No subject id is set.
#[doc(hidden)]
pub struct NoSubjectId;
/// Subject id is set.
#[doc(hidden)]
pub struct SubjectId(String);

impl CreateOfferRequestBuilder<NoIdentifiers, NoSubjectId, PreAuthorized> {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subject_id: NoSubjectId,
            credential_configuration_ids: NoIdentifiers,
            pre_authorized: PreAuthorized,
            grant_types: vec![GrantType::PreAuthorizedCode],
            tx_code: true,
            by_ref: false,
        }
    }
}

impl<S, P> CreateOfferRequestBuilder<NoIdentifiers, S, P> {
    /// Specify one or more credentials to include in the offer using the
    /// `credential_configurations_id`.
    #[must_use]
    pub fn with_credential(
        self, configuration_id: impl Into<String>,
    ) -> CreateOfferRequestBuilder<HasIdentifiers, S, P> {
        CreateOfferRequestBuilder {
            subject_id: self.subject_id,
            credential_configuration_ids: HasIdentifiers(vec![configuration_id.into()]),
            pre_authorized: self.pre_authorized,
            grant_types: self.grant_types,
            tx_code: self.tx_code,
            by_ref: self.by_ref,
        }
    }
}

impl<C, P> CreateOfferRequestBuilder<C, NoSubjectId, P> {
    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when building Credential Dataset(s) for credential issuance.
    #[must_use]
    pub fn subject_id(
        self, subject_id: impl Into<String>,
    ) -> CreateOfferRequestBuilder<C, SubjectId, P> {
        CreateOfferRequestBuilder {
            subject_id: SubjectId(subject_id.into()),
            credential_configuration_ids: self.credential_configuration_ids,
            pre_authorized: self.pre_authorized,
            grant_types: self.grant_types,
            tx_code: self.tx_code,
            by_ref: self.by_ref,
        }
    }
}

impl<C, S> CreateOfferRequestBuilder<C, S, NoPreAuthorized> {
    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when building Credential Dataset(s) for credential issuance.
    #[must_use]
    pub fn with_grant(self, grant: GrantType) -> CreateOfferRequestBuilder<C, S, PreAuthorized> {
        CreateOfferRequestBuilder {
            subject_id: self.subject_id,
            credential_configuration_ids: self.credential_configuration_ids,
            pre_authorized: PreAuthorized,
            grant_types: vec![grant],
            tx_code: self.tx_code,
            by_ref: self.by_ref,
        }
    }
}

impl<C, S, P> CreateOfferRequestBuilder<C, S, P> {
    /// Specify whether a Transaction Code (PIN) will be required by the token
    /// endpoint.
    #[must_use]
    pub const fn use_tx_code(mut self, tx_code_required: bool) -> Self {
        self.tx_code = tx_code_required;
        self
    }

    /// Specify whether Credential Offer should be an object or a URI.
    #[must_use]
    pub const fn by_ref(mut self, by_ref: bool) -> Self {
        self.by_ref = by_ref;
        self
    }
}

impl<S, P> CreateOfferRequestBuilder<HasIdentifiers, S, P> {
    /// Specify one or more credentials to include in the offer using the
    /// `credential_configurations_id`.
    #[must_use]
    pub fn with_credential(mut self, configuration_id: impl Into<String>) -> Self {
        self.credential_configuration_ids.0.push(configuration_id.into());
        self
    }
}

impl CreateOfferRequestBuilder<HasIdentifiers, SubjectId, PreAuthorized> {
    /// Build the Create Offer request with a pre-authorized code grant.
    #[must_use]
    pub fn build(self) -> CreateOfferRequest {
        let send_type = if self.by_ref { SendType::ByRef } else { SendType::ByVal };

        CreateOfferRequest {
            subject_id: Some(self.subject_id.0),
            credential_configuration_ids: self.credential_configuration_ids.0,
            grant_types: Some(self.grant_types),
            tx_code_required: self.tx_code,
            send_type,
        }
    }
}

impl<P> CreateOfferRequestBuilder<HasIdentifiers, NoSubjectId, P> {
    /// Build the Create Offer request without a pre-authorized code grant.
    #[must_use]
    pub fn build(self) -> CreateOfferRequest {
        let send_type = if self.by_ref { SendType::ByRef } else { SendType::ByVal };

        let mut request = CreateOfferRequest {
            subject_id: None,
            credential_configuration_ids: self.credential_configuration_ids.0,
            grant_types: None,
            tx_code_required: self.tx_code,
            send_type,
        };

        // only use Authorization Code grant type
        if !self.grant_types.is_empty() {
            for i in 0..self.grant_types.len() {
                if self.grant_types[i] == GrantType::AuthorizationCode {
                    request.grant_types = Some(vec![self.grant_types[i].clone()]);
                    break;
                }
            }
        }

        request
    }
}

/// Request a Credential Offer for a Credential Issuer.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct CreateOfferRequest {
    /// Identifies the (previously authenticated) Holder in order that Issuer
    /// can authorize credential issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    /// A list of keys of Credentials in the
    /// `credential_configurations_supported` Credential Issuer metadata.
    ///
    /// The Wallet uses these string values to obtain the respective object
    /// containing information about the Credential being offered. For example,
    /// these string values can be used to obtain scope values to be used in
    /// the Authorization Request.
    pub credential_configuration_ids: Vec<String>,

    /// The Grant Types to include in the Offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<GrantType>>,

    /// Specifies whether a Transaction Code (PIN) is required by the `token`
    /// endpoint during the Pre-Authorized Code Flow.
    pub tx_code_required: bool,

    /// The Issuer can specify whether Credential Offer is an object or a URI.
    pub send_type: SendType,
}

impl CreateOfferRequest {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn builder() -> CreateOfferRequestBuilder<NoIdentifiers, NoSubjectId, PreAuthorized> {
        CreateOfferRequestBuilder::new()
    }
}

/// Determines how the Credential Offer is sent to the Wallet.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum SendType {
    /// The Credential Offer is sent to the Wallet by value — as an object
    /// containing the Credential Offer parameters.
    #[default]
    ByVal,

    /// The Credential Offer is sent to the Wallet by reference — as a string
    /// containing a URL pointing to a location where the offer can be
    /// retrieved.
    ByRef,
}

impl Display for SendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByVal => write!(f, "by_val"),
            Self::ByRef => write!(f, "by_ref"),
        }
    }
}

impl From<String> for SendType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "by_ref" => Self::ByRef,
            _ => Self::ByVal,
        }
    }
}

/// The response to a Credential Offer request.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateOfferResponse {
    /// A Credential Offer that can be used to initiate issuance with a Wallet.
    /// The offer can be an object or URL pointing to the Credential Offer
    /// Endpoint where A `CredentialOffer` object can be retrieved.
    #[serde(flatten)]
    pub offer_type: OfferType,

    /// A transaction code to be provided by the End-User in order to complete
    /// a credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// The type of Credential Offer returned in a `CreateOfferResponse`: either an
/// object or a URI.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum OfferType {
    /// A Credential Offer object that can be sent to a Wallet as an HTTP GET
    /// request.
    #[serde(rename = "credential_offer")]
    Object(CredentialOffer),

    /// A URI pointing to the Credential Offer Endpoint where a
    /// `CredentialOffer` object can be retrieved.
    #[serde(rename = "credential_offer_uri")]
    Uri(String),
}

impl OfferType {
    /// Convenience method for extracting a Credential Offer object from an
    /// offer type if it exists.
    #[must_use]
    pub const fn as_object(&self) -> Option<&CredentialOffer> {
        match self {
            Self::Object(offer) => Some(offer),
            Self::Uri(_) => None,
        }
    }

    /// Convenience method for extracting a Credential Offer URI from an offer
    /// type if it exists.
    #[must_use]
    pub const fn as_uri(&self) -> Option<&str> {
        match self {
            Self::Uri(uri) => Some(uri.as_str()),
            Self::Object(_) => None,
        }
    }
}

/// A Credential Offer object that can be sent to a Wallet as an HTTP GET
/// request.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer which the Wallet can use to obtain
    /// Credentials and the Issuer's Metadata.
    pub credential_issuer: String,

    /// Credentials offered to the Wallet.
    /// A list of names identifying entries in the
    /// `credential_configurations_supported` `HashMap` in the Credential
    /// Issuer metadata. The Wallet uses the identifier to obtain the
    /// respective Credential Definition containing information about the
    /// Credential being offered. For example, the identifier can be used to
    /// obtain scope value to be used in the Authorization Request.
    ///
    /// # Example
    ///
    /// ```json
    ///    "credential_configuration_ids": [
    ///       "UniversityDegree_JWT",
    ///       "org.iso.18013.5.1.mDL"
    ///    ],
    /// ```
    pub credential_configuration_ids: Vec<String>,

    /// Indicates to the Wallet the Grant Types the Credential Issuer is
    /// prepared to process for this credential offer. If not present, the
    /// Wallet MUST determine the Grant Types the Credential Issuer supports
    /// using the Issuer metadata. When multiple grants are present, it's at
    /// the Wallet's discretion which one to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

impl CredentialOffer {
    /// Generate a qrcode for the Credential Offer.
    /// Use the `endpoint` parameter to specify a wallet's endpoint using
    /// deep link or direct call format.
    ///
    /// For example,
    ///
    /// ```http
    ///   openid-credential-offer://credential_offer=
    ///   or GET https://holder.credibil.io/credential_offer?
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if error if the Credential Offer
    /// cannot be serialized.
    pub fn to_qrcode(&self, endpoint: &str) -> anyhow::Result<String> {
        let qs = self.to_querystring();

        // generate qr code
        let qr_code =
            QrCode::new(format!("{endpoint}?{qs}")).context("failed to create QR code: {e}")?;

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

    /// Generate a query string for the Credential Offer.
    ///
    /// # Errors
    ///
    /// Returns an `Error::ServerError` error if error if the Credential Offer
    /// cannot be serialized.
    #[must_use]
    pub fn to_querystring(&self) -> String {
        format!("credential_offer={self}")
    }

    /// Convenience method for extracting a pre-authorized code grant from an
    /// offer if it exists.
    #[must_use]
    pub fn pre_authorized_code(&self) -> Option<PreAuthorizedCodeGrant> {
        self.grants.as_ref().and_then(|grants| grants.pre_authorized_code.clone())
    }

    /// Convenience method for extracting an authorization code grant from an
    /// offer if it exists.
    #[must_use]
    pub fn authorization_code(&self) -> Option<AuthorizationCodeGrant> {
        self.grants.as_ref().and_then(|grants| grants.authorization_code.clone())
    }
}

impl Display for CredentialOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = urlencode::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{s}")
    }
}

impl FromStr for CredentialOffer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        urlencode::from_str(s)
    }
}

/// The Credential Offer Request is used by the Wallet to retrieve a previously
/// generated Credential Offer.
///
/// The Wallet is sent a `credential_offer_uri` containing a unique URL pointing
/// to the Offer. The URI has the form `credential_issuer/credential_offer/id`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialOfferRequest {
    /// The unique identifier for the the previously generated Credential Offer.
    pub id: String,
}

/// The Credential Offer Response is used to return a previously generated
/// Credential Offer.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct CredentialOfferResponse(pub CredentialOffer);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["UniversityDegree_JWT".to_string()],
            grants: None,
        };

        let offer_str = serde_json::to_string(&offer).expect("should serialize to string");
        let offer2: CredentialOffer =
            serde_json::from_str(&offer_str).expect("should deserialize from string");
        assert_eq!(offer, offer2);
    }

    // GET /credential_offer?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,
    //  %22credential_configuration_ids%22:%5B%22UniversityDegree_JWT%22,%22org.iso.18013.5.1.mDL%22%5D,
    //  %22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:
    //  %22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%7D%7D%7D%7D
    #[test]
    fn querystring() {
        let offer = &CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["UniversityDegree_JWT".to_string()],
            grants: None,
        };

        let qs: String = offer.to_string();
        let offer2: CredentialOffer = qs.parse().expect("should deserialize from string");

        assert_eq!(offer, &offer2);
    }

    // #[test]
    // fn querystring2() {
    //     let offer = &CredentialOffer {
    //         credential_issuer: "https://issuer.example.com".to_string(),
    //         credential_configuration_ids: vec!["UniversityDegree_JWT".to_string()],
    //         grants: None,
    //     };

    //     // let qs: String = form_urlencoded::Serializer::new(String::new())
    //     //     .append_pair("credential_offer", &offer.to_string())
    //     //     .finish();

    //     let bytes = serde_json::to_vec(&offer).expect("should serialize to string");
    //     let enc = form_urlencoded::byte_serialize(&bytes).collect::<String>();
    //     println!("enc: {:?}", enc);

    //     let dec = form_urlencoded::parse(enc.as_bytes()).into_owned().collect::<String>();

    //     let offer2: CredentialOffer = enc.parse().expect("should deserialize from string");
    //     assert_eq!(offer, &offer2);
    // }
}
