//! # JOSE Proofs

use std::fmt::Debug;
use std::str;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::core::vc::VerifiableCredential;
use crate::core::vp::VerifiablePresentation;
use crate::core::{Kind, OneMany};

/// Claims used for Verifiable Credential issuance when format is
/// "`jwt_vc_json`".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct VcClaims {
    /// The Holder ID the Credential is intended for. Typically, the DID of the
    /// Holder from the Credential's `credentialSubject.id` property.
    ///
    /// For example, "did:example:ebfeb1f712ebc6f1c276e12ec21".
    pub sub: String,

    /// The `issuer` property of the Credential.
    ///
    /// For example, "did:example:123456789abcdefghi#keys-1".
    pub iss: String,

    /// The Credential's issuance date, encoded as a UNIX timestamp.
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The `id` property of the Credential.
    pub jti: String,

    /// The expiration time of the signature, encoded as a UNIX timestamp. This
    /// is NOT the same as the Credential `validUntil`property.
    #[serde(with = "ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exp: Option<DateTime<Utc>>,

    /// The Credential.
    pub vc: VerifiableCredential,
}

impl VcClaims {
    /// Create Verifiable Credential JWT payload from a W3C Verifiable
    /// Credential.
    #[must_use]
    pub fn from_vc(vc: VerifiableCredential, issued_at: DateTime<Utc>) -> Self {
        let subject = match &vc.credential_subject {
            OneMany::One(sub) => sub,
            OneMany::Many(subs) => &subs[0],
        };

        let issuer_id = match &vc.issuer {
            Kind::String(id) => id,
            Kind::Object(issuer) => &issuer.id,
        };

        Self {
            // TODO: find better way to set sub (shouldn't need to be in vc)
            sub: subject.id.clone().unwrap_or_default(),
            iss: issuer_id.clone(),
            iat: issued_at,
            jti: vc.id.clone().unwrap_or_default(),
            exp: vc.valid_until,
            vc,
        }
    }
}

/// To sign, or sign and encrypt the Authorization Response, implementations MAY
/// use JWT Secured Authorization Response Mode for OAuth 2.0
/// ([JARM](https://openid.net/specs/oauth-v2-jarm-final.html)).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VpClaims {
    /// The `holder` property of the Presentation.
    /// For example, "did:example:123456789abcdefghi".
    pub iss: String,

    /// The `id` property of the Presentation.
    ///
    /// For example, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5".
    pub jti: String,

    /// The `client_id` value from the Verifier's Authorization Request.
    pub aud: String,

    /// The `nonce` value from the Verifier's Authorization Request.
    pub nonce: String,

    /// The time the Presentation was created, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,

    /// The time the Presentation was created, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// The time the Presentation will expire, encoded as a UNIX timestamp
    /// ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,

    /// The Verifiable Presentation.
    pub vp: VerifiablePresentation,
}

impl From<VerifiablePresentation> for VpClaims {
    fn from(vp: VerifiablePresentation) -> Self {
        Self {
            iss: vp.holder.clone().unwrap_or_default(),
            jti: vp.id.clone().unwrap_or_default(),
            nbf: Utc::now(),
            iat: Utc::now(),

            // TODO: configure `exp` time
            exp: Utc::now()
                .checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default())
                .unwrap_or_default(),
            vp,

            ..Self::default()
        }
    }
}
