//! # Status
//!
//! The `status` module provides a trait for looking up the status of a
//! credential. There are provider traits that need to be implemented by an
//! issuer and/or verifier implementations, and helper functions for dealing
//! with supported status endpoint formats.
//!
//! [Status section of Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/#status)

pub mod bitstring;

