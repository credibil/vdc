//! # Request Builder

//  use crate::oid4vp::types::GenerateRequest;

// impl GenerateRequest {
//     /// Create a new `CreateRequestRequestBuilder`.
//     #[must_use]
//     pub fn builder() -> CreateRequestRequestBuilder<NoCredential, NoSubjectId, PreAuthorized> {
//         CreateRequestRequestBuilder::new()
//     }
// }

/// Build an Authorization Request Object for a Verifiable Presentation.
#[derive(Default, Debug)]
pub struct CreateRequestRequestBuilder {
    //     credential_configuration_ids: C,
    //     subject_id: S,
    //     pre_authorized: P,
    //     grant_types: Vec<GrantType>,
    //     tx_code: bool,
    //     by_ref: bool,
}

// /// No credential configuration id is set.
// #[doc(hidden)]
// pub struct NoCredential;
// /// At least one credential configuration id is set.
// #[doc(hidden)]
// pub struct Credential(Vec<String>);

// /// No pre-authorized grant is specified.
// #[doc(hidden)]
// pub struct NoPreAuthorized;
// /// Pre-authorized grant is specified.
// #[doc(hidden)]
// pub struct PreAuthorized;

// /// No subject id is set.
// #[doc(hidden)]
// pub struct NoSubjectId;
// /// Subject id is set.
// #[doc(hidden)]
// pub struct SubjectId(String);

// impl CreateRequestRequestBuilder<NoCredential, NoSubjectId, PreAuthorized> {
//     /// Create a new `CreateRequestRequestBuilder`.
//     #[must_use]
//     pub fn new() -> Self {
//         Self {
//             subject_id: NoSubjectId,
//             credential_configuration_ids: NoCredential,
//             pre_authorized: PreAuthorized,
//             grant_types: vec![GrantType::PreAuthorizedCode],
//             tx_code: true,
//             by_ref: false,
//         }
//     }
// }

// impl<S, P> CreateRequestRequestBuilder<NoCredential, S, P> {
//     /// Specify one or more credentials to include in the offer using the
//     /// `credential_configurations_id`.
//     #[must_use]
//     pub fn with_credential(
//         self, configuration_id: impl Into<String>,
//     ) -> CreateRequestRequestBuilder<Credential, S, P> {
//         CreateRequestRequestBuilder {
//             subject_id: self.subject_id,
//             credential_configuration_ids: Credential(vec![configuration_id.into()]),
//             pre_authorized: self.pre_authorized,
//             grant_types: self.grant_types,
//             tx_code: self.tx_code,
//             by_ref: self.by_ref,
//         }
//     }
// }

// impl<C, P> CreateRequestRequestBuilder<C, NoSubjectId, P> {
//     /// Specify the (previously authenticated) Holder for the Issuer to use
//     /// when building Credential Dataset(s) for credential issuance.
//     #[must_use]
//     pub fn subject_id(
//         self, subject_id: impl Into<String>,
//     ) -> CreateRequestRequestBuilder<C, SubjectId, P> {
//         CreateRequestRequestBuilder {
//             subject_id: SubjectId(subject_id.into()),
//             credential_configuration_ids: self.credential_configuration_ids,
//             pre_authorized: self.pre_authorized,
//             grant_types: self.grant_types,
//             tx_code: self.tx_code,
//             by_ref: self.by_ref,
//         }
//     }
// }

// impl<C, S> CreateRequestRequestBuilder<C, S, NoPreAuthorized> {
//     /// Specify the (previously authenticated) Holder for the Issuer to use
//     /// when building Credential Dataset(s) for credential issuance.
//     #[must_use]
//     pub fn with_grant(self, grant: GrantType) -> CreateRequestRequestBuilder<C, S, PreAuthorized> {
//         CreateRequestRequestBuilder {
//             subject_id: self.subject_id,
//             credential_configuration_ids: self.credential_configuration_ids,
//             pre_authorized: PreAuthorized,
//             grant_types: vec![grant],
//             tx_code: self.tx_code,
//             by_ref: self.by_ref,
//         }
//     }
// }

// impl<C, S, P> CreateRequestRequestBuilder<C, S, P> {
//     /// Specify whether a Transaction Code (PIN) will be required by the token
//     /// endpoint.
//     #[must_use]
//     pub const fn use_tx_code(mut self, tx_code_required: bool) -> Self {
//         self.tx_code = tx_code_required;
//         self
//     }

//     /// Specify whether Credential Offer should be an object or a URI.
//     #[must_use]
//     pub const fn by_ref(mut self, by_ref: bool) -> Self {
//         self.by_ref = by_ref;
//         self
//     }
// }

// impl<S, P> CreateRequestRequestBuilder<Credential, S, P> {
//     /// Specify one or more credentials to include in the offer using the
//     /// `credential_configurations_id`.
//     #[must_use]
//     pub fn with_credential(mut self, configuration_id: impl Into<String>) -> Self {
//         self.credential_configuration_ids.0.push(configuration_id.into());
//         self
//     }
// }

// impl CreateRequestRequestBuilder<Credential, SubjectId, PreAuthorized> {
//     /// Build the Create Offer request with a pre-authorized code grant.
//     #[must_use]
//     pub fn build(self) -> CreateOfferRequest {
//         let send_type = if self.by_ref { SendType::ByRef } else { SendType::ByVal };

//         CreateOfferRequest {
//             subject_id: Some(self.subject_id.0),
//             credential_configuration_ids: self.credential_configuration_ids.0,
//             grant_types: Some(self.grant_types),
//             tx_code_required: self.tx_code,
//             send_type,
//         }
//     }
// }

// impl<P> CreateRequestRequestBuilder<Credential, NoSubjectId, P> {
//     /// Build the Create Offer request without a pre-authorized code grant.
//     #[must_use]
//     pub fn build(self) -> GenerateRequest {
//         let send_type = if self.by_ref { SendType::ByRef } else { SendType::ByVal };

//         let mut request = GenerateRequest {
//             subject_id: None,
//             credential_configuration_ids: self.credential_configuration_ids.0,
//             grant_types: None,
//             tx_code_required: self.tx_code,
//             send_type,
//         };

//         // only use Authorization Code grant type
//         if !self.grant_types.is_empty() {
//             for i in 0..self.grant_types.len() {
//                 if self.grant_types[i] == GrantType::AuthorizationCode {
//                     request.grant_types = Some(vec![self.grant_types[i].clone()]);
//                     break;
//                 }
//             }
//         }

//         request
//     }
// }
