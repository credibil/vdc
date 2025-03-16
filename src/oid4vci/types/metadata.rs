use std::collections::HashMap;
use std::fmt::{self, Debug};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::core::strings::title_case;
use crate::oauth::{OAuthClient, OAuthServer};

/// Request to retrieve the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetadataRequest;

/// Response containing the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataResponse {
    /// The Credential Issuer metadata for the specified Credential Issuer.
    #[serde(flatten)]
    pub credential_issuer: Issuer,
}

/// Request to retrieve the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OAuthServerRequest {
    /// Authorization issuer identifier.
    ///
    /// This identifier can be obtained from the `authorization_servers`
    /// parameter in the Credential Issuer metadata. If that parameter is
    /// not present, the `issuer` parameter should be `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Response containing the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthServerResponse {
    /// The OAuth 2.0 Authorization Server metadata for the Issuer.
    pub authorization_server: Server,
}

/// The registration request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RegistrationRequest {
    /// Metadata provided by the client undertaking registration.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The registration response for a successful request.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationResponse {
    /// Registered Client metadata.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Issuer {
    /// The Credential Issuer's identifier.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Authorization Server's identifier (metadata `issuer` parameter). If
    /// omitted, the Credential Issuer is acting as the AS. That is, the
    /// `credential_issuer` value is also used as the Authorization Server
    /// `issuer` value in metadata requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// URL of the Credential Issuer's Credential Endpoint. MAY contain port,
    /// path and query parameter components.
    pub credential_endpoint: String,

    /// URL of the Credential Issuer's Nonce Endpoint. MUST use the https
    /// scheme and MAY contain port, path, and query parameter components.
    /// If omitted, the Credential Issuer does not support the Nonce
    /// Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,

    /// URL of the Credential Issuer's Deferred Credential Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components. If omitted, the Credential Issuer does not
    /// support the Deferred Credential Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// URL of the Credential Issuer's Notification Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components.  If omitted, the Credential Issuer does not
    /// support the Notification Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,

    /// Specifies whether (and how) the Credential Issuer supports encryption of
    /// the Credential and Batch Credential Response on top of TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<SupportedCredentialResponseEncryption>,

    /// Information about the Issuer's support for batch issuance of
    /// Credentials. The presence of this parameter means that the issuer
    /// supports the proofs parameter in the Credential Request so can issue
    /// more than one Verifiable Credential for the same Credential Dataset in a
    /// single request/response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// A signed JWT containing Credential Issuer metadata parameters as claims.
    /// The signed metadata MUST be secured using JSON Web Signature (JWS)
    /// [RFC7515] and MUST contain an iat (Issued At) claim, an iss (Issuer)
    /// claim denoting the party attesting to the claims in the signed
    /// metadata, and sub (Subject) claim matching the Credential Issuer
    /// identifier. If the Wallet supports signed metadata, metadata values
    /// conveyed in the signed JWT MUST take precedence over the
    /// corresponding values conveyed using plain JSON elements. If the
    /// Credential Issuer wants to enforce use of signed metadata, it omits
    /// the respective metadata parameters from the unsigned part of the
    /// Credential Issuer metadata. A signed_ metadata metadata value MUST
    /// NOT appear as a claim in the JWT. The Wallet MUST establish trust in
    /// the signer of the metadata, and obtain the keys to validate
    /// the signature before processing the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// Credential Issuer display properties for supported languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// A list of name/value pairs of credentials supported by the Credential
    /// Issuer. Each name is a unique identifier for the supported
    /// credential described. The identifier is used in the Credential Offer
    /// to communicate to the Wallet which Credential is being offered. The
    /// value is a Credential object containing metadata about specific
    /// credential.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
}

impl Issuer {
    /// Returns the `credential_configuration_id` for a given format.
    ///
    /// # Errors
    ///
    /// TODO: add error handling
    pub fn credential_configuration(
        &self, credential_configuration_id: &str,
    ) -> Result<&CredentialConfiguration> {
        self.credential_configurations_supported
            .get(credential_configuration_id)
            .ok_or_else(|| anyhow!("Credential Configuration not found"))
    }

    /// Returns the `credential_configuration_id` for a given format.
    ///
    /// # Errors
    ///
    /// TODO: add error handling
    pub fn credential_configuration_id(&self, fmt: &Format) -> Result<&String> {
        self.credential_configurations_supported
            .iter()
            .find(|(_, cfg)| &cfg.format == fmt)
            .map(|(id, _)| id)
            .ok_or_else(|| anyhow!("Credential Configuration not found"))
    }

    /// Convenience method to provide the issuer's display name (if configured).
    ///
    /// TODO: The field is optional and contains locale information but because
    /// it is not a vec, only one locale is possible. Keep an eye on the spec
    /// and implement locale support if needed.
    #[must_use]
    pub fn display_name(&self, _locale: Option<&str>) -> Option<String> {
        self.display.as_ref().map(|d| d.name.clone())
    }
}

/// Contains information about whether the Credential Issuer supports encryption
/// of the Credential and Batch Credential Response on top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupportedCredentialResponseEncryption {
    /// JWE [RFC7516] alg algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg_values_supported: Vec<String>,

    /// JWE [RFC7516] enc algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If `credential_response_encryption_alg` is specified, the
    /// default for this value is "`A256GCM`".
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc_values_supported: Vec<String>,

    /// Specifies whether the Credential Issuer requires the additional
    /// encryption on top of TLS for the Credential Response. If the value
    /// is true, the Credential Issuer requires encryption for every
    /// Credential Response and therefore the Wallet MUST provide encryption
    /// keys in the Credential Request. If the value is false, the Wallet
    /// MAY chose whether it provides encryption keys or not.
    pub encryption_required: bool,
}

/// Contains information about the Credential Issuer's support for batch
/// issuance of Credentials on the Credential Endpoint.
///
/// The presence of this parameter means that the issuer supports the proofs
/// parameter in the Credential Request so can issue more than one Verifiable
/// Credential for the same Credential Dataset in a single request/response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BatchCredentialIssuance {
    /// The maximum array size for the proofs parameter in a Credential Request.
    pub batch_size: i64,
}

/// Language-based display properties for Issuer or `ClaimsDescription`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Display {
    /// The name to use when displaying the name of the `Issuer` or `ClaimsDescription` for
    /// the specified locale. If no locale is set, then this value is the
    /// default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Credential configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialConfiguration {
    /// Identifies the format of the credential, e.g. "`jwt_vc_json`" or
    /// "`ldp_vc`". Each object will contain further elements defining the
    /// type and claims the credential MAY contain, as well as information
    /// on how to display the credential.
    ///
    /// See OpenID4VCI [Credential Format Profiles] for more detail.
    ///
    /// [Credential Format Profiles]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles
    #[serde(flatten)]
    pub format: Format,

    /// The `scope` value that this Credential Issuer supports for this
    /// credential. The value can be the same accross multiple
    /// `credential_configurations_supported` objects. The Authorization
    /// Server MUST be able to uniquely identify the Credential Issuer based
    /// on the scope value. The Wallet can use this value in
    /// the Authorization Request Scope values in this Credential Issuer
    /// metadata MAY duplicate those in the `scopes_supported` parameter of
    /// the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Identifies how the Credential should be bound to the identifier of the
    /// End-User who possesses the Credential. Is case sensitive.
    ///
    /// Support for keys in JWK format [RFC7517] is indicated by the value
    /// "`jwk`". Support for keys expressed as a COSE Key object [RFC8152]
    /// (for example, used in [ISO.18013-5]) is indicated by the value
    /// "`cose_key`".
    ///
    /// When Cryptographic Binding Method is a DID, valid values MUST be a
    /// "did:" prefix followed by a method-name using a syntax as defined in
    /// Section 3.1 of [DID-Core], but without a ":" and method-specific-id.
    /// For example, support for the DID method with a method-name "example"
    /// would be represented by "did:example". Support for all DID methods
    /// listed in Section 13 of [DID Specification Registries] is indicated
    /// by sending a DID without any method-name.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    /// [RFC8152]: (https://www.rfc-editor.org/rfc/rfc8152)
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    /// [DID-Core]: (https://www.w3.org/TR/did-core/)
    /// [DID Specification Registries]: (https://www.w3.org/TR/did-spec-registries/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Case sensitive strings that identify the cryptographic suites supported
    /// for the `cryptographic_binding_methods_supported`. Cryptographic
    /// algorithms for Credentials in `jwt_vc` format should use algorithm
    /// names defined in IANA JOSE Algorithms Registry. Cryptographic
    /// algorithms for Credentials in `ldp_vc` format should use signature
    /// suites names defined in Linked Data Cryptographic Suite Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// The key proof(s) that the Credential Issuer supports. This object
    /// contains a list of name/value pairs, where each name is a unique
    /// identifier of the supported proof type(s). Valid values are defined
    /// in Section 7.2.1, other values MAY be used. This identifier is also
    /// used by the Wallet in the Credential Request as defined in Section
    /// 7.2. The value in the name/value pair is an object that contains
    /// metadata about the key proof and contains the following parameters
    /// defined by this specification:
    ///
    ///  - `jwt`: A JWT [RFC7519] is used as proof of possession. A proof object
    ///    MUST include a jwt claim containing a JWT defined in Section 7.2.1.1.
    ///
    ///  - `cwt`: A CWT [RFC8392] is used as proof of possession. A proof object
    ///    MUST include a cwt claim containing a CWT defined in Section 7.2.1.3.
    ///
    ///  - `ldp_vp`: A W3C Verifiable Presentation object signed using the Data
    ///    Integrity Proof as defined in [VC_DATA_2.0] or [VC_DATA], and where
    ///    the proof of possession MUST be done in accordance with
    ///    [VC_Data_Integrity]. When `proof_type` is set to `ldp_vp`, the proof
    ///    object MUST include a `ldp_vp` claim containing a W3C Verifiable
    ///    Presentation defined in Section 7.2.1.2.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_types_supported": {
    ///     "jwt": {
    ///         "proof_signing_alg_values_supported": [
    ///             "ES256"
    ///         ]
    ///     }
    /// }
    /// ```
    ///
    /// [RFC7519]: (https://www.rfc-editor.org/rfc/rfc7519)
    /// [RFC8392]: (https://www.rfc-editor.org/rfc/rfc8392)
    /// [VC_DATA]: (https://www.w3.org/TR/vc-data-model/)
    /// [VC_DATA_2.0]: (https://www.w3.org/TR/vc-data-model-2.0/)
    /// [VC_Data_Integrity]: (https://www.w3.org/TR/vc-data-integrity/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypesSupported>>,

    /// Language-based display properties of the supported credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// One or more claims description objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsDescription>>,
}

impl CredentialConfiguration {
    /// Verifies that the `claimset` contains required claims and they are
    /// supported for the Credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the `claimset` contains unsupported claims or does
    /// not contain required (mandatory) claims.
    pub fn verify_claims(&self, claimset: &[ClaimsDescription]) -> Result<()> {
        // ensure `claimset` claims exist in the supported claims
        if !claimset.is_empty() {
            if let Some(claims) = &self.claims {
                let _ = Self::claims_supported(claimset, claims);
            }
        }

        // ensure all mandatory claims are present
        if let Some(claims) = &self.claims {
            return Self::claims_required(claimset, claims);
        }

        Ok(())
    }

    /// Verifies `claimset` claims are supported by the Credential
    fn claims_supported(
        requested: &[ClaimsDescription], supported: &[ClaimsDescription],
    ) -> Result<()> {
        for r in requested {
            for s in supported {
                if r.path == s.path {
                    continue;
                }
                return Err(anyhow!("{} claim is not supported", r.path.join(".")));
            }
        }
        Ok(())
    }

    /// Verifies `claimset` contains all required claims
    fn claims_required(
        requested: &[ClaimsDescription], supported: &[ClaimsDescription],
    ) -> Result<()> {
        for s in supported {
            if s.mandatory.unwrap_or_default() {
                // check if claim is present
                if requested.iter().any(|r| r.path == s.path) {
                    continue;
                }
                return Err(anyhow!("{} claim is required", s.path.join(".")));
            }
        }

        Ok(())
    }

    /// Convenience method to display the claims as a vector of strings.
    #[must_use]
    pub fn claims_display(&self, locale: Option<&str>) -> Vec<String> {
        let mut claim_set = Vec::new();

        if let Some(claims) = &self.claims {
            for claim in claims {
                let display = claim
                    .display
                    .as_ref()
                    .and_then(|display| display.iter().find(|d| d.locale.as_deref() == locale));

                match display {
                    Some(d) => claim_set.push(d.name.clone()),
                    None => claim_set.push(title_case(&claim.path.join("."))),
                }
            }
        }

        claim_set
    }
}

/// Credential Format defines supported Credential data models. Each profile
/// defines a specific set of parameters or claims used to support a particular
/// format.
///
/// [Credential Format Profiles]: (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles)
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "format")]
pub enum Format {
    /// A W3C Verifiable Credential.
    ///
    /// When this format is specified, Credential Offer, Authorization Details,
    /// Credential Request, and Credential Issuer metadata, including
    /// `credential_definition` object, MUST NOT be processed using JSON-LD
    /// rules.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(ProfileW3c),

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be
    /// used by the Wallet to check whether it supports a certain VC. If
    /// necessary, the Wallet could apply JSON-LD processing to the
    /// Credential issued.
    #[serde(rename = "ldp-vc")]
    LdpVc(ProfileW3c),

    /// A W3C Verifiable Credential.
    ///
    /// When using this format, data MUST NOT be processed using JSON-LD rules.
    ///
    /// N.B. The `@context` value in the `credential_definition` object can be
    /// used by the Wallet to check whether it supports a certain VC. If
    /// necessary, the Wallet could apply JSON-LD processing to the
    /// Credential issued.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd(ProfileW3c),

    /// ISO mDL.
    ///
    /// A Credential Format Profile for Credentials complying with [ISO.18013-5]
    /// — ISO-compliant driving licence specification.
    ///
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    #[serde(rename = "mso_mdoc")]
    IsoMdl(ProfileIsoMdl),

    /// IETF SD-JWT VC.
    ///
    /// A Credential Format Profile for Credentials complying with
    /// [I-D.ietf-oauth-sd-jwt-vc] — SD-JWT-based Verifiable Credentials for
    /// selective disclosure.
    ///
    /// [I-D.ietf-oauth-sd-jwt-vc]: (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01)
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt(ProfileSdJwt),
}

impl Default for Format {
    fn default() -> Self {
        Self::JwtVcJson(ProfileW3c::default())
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JwtVcJson(_) => write!(f, "jwt_vc_json"),
            Self::LdpVc(_) => write!(f, "ldp_vc"),
            Self::JwtVcJsonLd(_) => write!(f, "jwt_vc_json-ld"),
            Self::IsoMdl(_) => write!(f, "mso_mdoc"),
            Self::DcSdJwt(_) => write!(f, "dc+sd-jwt"),
        }
    }
}

/// Credential Format Profile for W3C Verifiable Credentials.
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileW3c {
    /// The detailed description of the W3C Credential type.
    pub credential_definition: CredentialDefinition,
}

impl PartialEq for ProfileW3c {
    fn eq(&self, other: &Self) -> bool {
        self.credential_definition.type_ == other.credential_definition.type_
    }
}

/// Credential Format Profile for `ISO.18013-5` (Mobile Driving License)
/// credentials.
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileIsoMdl {
    /// The Credential type, as defined in [ISO.18013-5].
    pub doctype: String,
}

impl PartialEq for ProfileIsoMdl {
    fn eq(&self, other: &Self) -> bool {
        self.doctype == other.doctype
    }
}

/// Credential Format Profile for Selective Disclosure JWT ([SD-JWT])
/// credentials.
///
/// [SD-JWT]: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-04>
#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq)]
pub struct ProfileSdJwt {
    /// The Verifiable Credential type. The `vct` value MUST be a
    /// case-sensitive String or URI serving as an identifier for
    /// the type of the SD-JWT VC.
    pub vct: String,
}

impl PartialEq for ProfileSdJwt {
    fn eq(&self, other: &Self) -> bool {
        self.vct == other.vct
    }
}

/// Claim entry. Either a set of nested `Claim`s or a single `ClaimDisplay`.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsDescription {
    /// Represents a claims path pointer specifying the path to a claim within
    /// the credential.
    ///
    /// For example, the path `["address", "street_address"]` points to the
    /// `street_address` claim within the `address` claim.
    pub path: Vec<String>,

    /// Indicates whether the Credential Issuer will include this claim in the
    /// issued Credential or not.
    ///
    /// When set to false, the claim is not included in the issued Credential
    /// if the wallet did not request the inclusion of  the claim, and/or if
    /// the Credential Issuer chose to not include the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// Display properties of the claim for specified languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<Display>>,
}

/// `ProofTypesSupported` describes specifics of the key proof(s) that the
/// Credential Issuer supports.
///
/// This object contains a list of name/value pairs, where each name is a unique
/// identifier of the supported proof type(s). Valid values are defined in
/// Section 7.2.1, other values MAY be used. This identifier is also used by the
/// Wallet in the Credential Request as defined in Section 7.2. The value in the
/// name/value pair is an object that contains metadata about the key proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofTypesSupported {
    /// One or more case sensitive strings that identify the algorithms that the
    /// Issuer supports for this proof type. The Wallet uses one of them to
    /// sign the proof. Algorithm names used are determined by the key proof
    /// type.
    ///
    /// For example, for JWT, the algorithm names are defined in IANA JOSE
    /// Algorithms Registry.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
    /// ```
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// `CredentialDisplay` holds language-based display properties of the supported
/// credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDisplay {
    /// The value to use when displaying the name of the `Credential` for the
    /// specified locale. If no locale is set, then this is the default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Information about the logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Image>,

    /// Description of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Background color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Information about the background image of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Image>,

    /// Text color color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Image contains information about the logo of the Credential.
/// N.B. The list is non-exhaustive and may be extended in the future.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Image {
    /// URL where the Wallet can obtain a logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Alternative text of a logo image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// TODO: split into 2 types or use enum for variations based on format

/// `CredentialDefinition` defines a Supported Credential that may requested by
/// Wallets.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDefinition {
    /// The @context property is used to map property URIs into short-form
    /// aliases, in accordance with the W3C Verifiable Credentials Data
    /// Model.
    ///
    /// REQUIRED when `format` is "`jwt_vc_json-ld`" or "`ldp_vc`".
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,

    /// Contains the type values the Wallet requests authorization for at the
    /// Credential Issuer. It MUST be present if the claim format is present in
    /// the root of the authorization details object. It MUST not be present
    /// otherwise.
    #[serde(rename = "type")]
    pub type_: Vec<String>,
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
pub struct Client {
    /// OAuth 2.0 Client
    #[serde(flatten)]
    pub oauth: OAuthClient,

    /// Used by the Wallet to publish its Credential Offer endpoint. The
    /// Credential Issuer should use "`openid-credential-offer://`" if
    /// unable to perform discovery of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Server {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Indicates whether the issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a client id. Defaults to false.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

#[cfg(test)]
mod tests {}
