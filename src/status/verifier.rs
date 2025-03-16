//! # Status (Verifier)
//!
//! Traits and type for managing the verification of a credential status as a
//! verifier.

use std::future::Future;

use super::error::Error;
use super::provider;
use crate::w3c_vc::vc::CredentialStatus;

/// The `Status` trait is used to proxy the resolution of a credential status.
///
/// Given a credential's status look-up information, the implementer should use
/// that to retrieve a published credential status list and look into that for
/// the current status of the credential.
pub trait Status: Send + Sync {
    /// Returns `true` if the credential currently has the requested status,
    /// `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the status list cannot be retrieved or the status
    /// for the given credential cannot be resolved from the list.
    fn status(
        &self, status: &CredentialStatus, credential_identifier: &str,
    ) -> impl Future<Output = provider::Result<bool>> + Send;
}

/// Validates a credential from the status information contained inside it.
///
/// Uses a provider to retrieve the status list, which is assumed to be in
/// bitstring format.
///
/// # Errors
///
/// Will return a specific `ValidationError` if the status list is not resolved
/// or processing the status list fails for the given `CredentialStatus`.
pub fn validate(_resolver: &impl Status, _status: &CredentialStatus) -> Result<bool, Error> {
    // The following process, or one generating the exact output, MUST be followed
    // when validating a verifiable credential that is contained in a
    // BitstringStatusListCredential. The algorithm takes a status list verifiable
    // credential as input and either throws an error or returns a status list
    // credential as output.

    // Let credentialToValidate be a verifiable credential containing a
    // credentialStatus entry that is a BitstringStatusListEntry.
    // Let minimumNumberOfEntries be 131,072 unless a different lower bound is
    // established by a specific ecosystem specification. Let status purpose be
    // the value of statusPurpose in the credentialStatus entry in the
    // credentialToValidate. Dereference the statusListCredential URL, and
    // ensure that all proofs verify successfully. If the dereference fails, raise a
    // STATUS_RETRIEVAL_ERROR. If any of the proof verifications fail, raise a
    // STATUS_VERIFICATION_ERROR. Verify that the status purpose is equal to a
    // statusPurpose value in the statusListCredential. Note: The
    // statusListCredential might contain multiple status purposes in a single list.
    // If the values are not equal, raise a STATUS_VERIFICATION_ERROR.
    // Let compressed bitstring be the value of the encodedList property of the
    // BitstringStatusListCredential. Let credentialIndex be the value of the
    // statusListIndex property of the BitstringStatusListEntry. Generate a
    // revocation bitstring by passing compressed bitstring to the Bitstring
    // Expansion Algorithm. If the length of the revocation bitstring divided by
    // statusSize is less than minimumNumberOfEntries, raise a
    // STATUS_LIST_LENGTH_ERROR. Let status be the value in the bitstring at the
    // position indicated by the credentialIndex multiplied by the size. If the
    // credentialIndex multiplied by the size is a value outside of the range of the
    // bitstring, a RANGE_ERROR MUST be raised. Let result be an empty map.
    // Set the status key in result to status, and set the purpose key in result to
    // the value of statusPurpose. If status is 0, set the valid key in result
    // to true; otherwise, set it to false. If the statusPurpose is message, set
    // the message key in result to the corresponding message of the value as
    // indicated in the statusMessages array. Return result.
    // When a statusListCredential URL is dereferenced, server implementations MAY
    // provide a mechanism to dereference the status list as of a particular point
    // in time. When an issuer provides such a mechanism, it enables a verifier to
    // determine changes in status to a precision chosen by the issuer, such as
    // hourly, daily, or weekly. If such a feature is supported, and if query
    // parameters are supported by the URL scheme, then the name of the query
    // parameter MUST be timestamp and the value MUST be a valid URL-encoded
    // [XMLSCHEMA11-2] dateTimeStamp string value. The result of dereferencing such
    // a timestamp-parameterized URL MUST be either a status list credential
    // containing the status list as it existed at the given point in time, or a
    // STATUS_RETRIEVAL_ERROR. If the result is an error, implementations MAY
    // attempt the retrieval again with a different timestamp value, or without a
    // timestamp value, as long as the verifier's validation rules permit such an
    // action.

    // Verifiers SHOULD cache the retrieved status list and SHOULD use proxies or
    // other mechanisms, such as Oblivious HTTP, that hide retrieval behavior from
    // the issuer.

    // Note: Issuer validation is use case dependent
    // It is expected that a verifier will ensure that it trusts the issuer of a
    // verifiable credential, as well as the issuer of the associated
    // BitstringStatusListCredential, before using the information contained in
    // either credential for further decision making purposes. Implementers are
    // advised that the issuers of these credential might differ, such as when the
    // original issuer of the verifiable credential does not maintain a record of
    // its validity.

    todo!()
}
