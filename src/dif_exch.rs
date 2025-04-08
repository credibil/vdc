//! # Distributed Identity Foundation Presentation Exchange
//!
//! Specifications:
//! - <https://identity.foundation/presentation-exchange/spec/v2.0.0>
//! - <https://identity.foundation/jwt-vc-presentation-profile>
//! - <https://identity.foundation/claim-format-registry>

pub mod matcher;

use std::collections::HashMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Used to provide `serde`-compatible set of Claims  serialized as JSON (as
/// [`serde_json::Value`]).
///
/// Per the Presentation Exchange specification, this trait
/// can be implemented for a variety of `Claim` formats.
pub trait Claims {
    /// Serialize Claims as a JSON object.
    ///
    /// # Errors
    ///
    /// The implementation should return an error if the Claims cannot be
    /// serialized to JSON.
    fn to_json(&self) -> anyhow::Result<serde_json::Value>;
}

/// A Presentation Definition is used by a Verifier to articulate proofs
/// required. The proofs help the Verifier decide how to interact with the
/// Holder providing the proofs.
///
/// <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PresentationDefinition {
    /// A unique ID for the desired context. For example, a UUID is unique in a
    /// global context, while a simple string could be suitably unique in a
    /// local context.
    pub id: String,

    /// Input Descriptors describe the information a Verifier requires from the
    /// Holder.
    pub input_descriptors: Vec<InputDescriptor>,

    /// If present, a human-friendly, distinctive designation for the
    /// Presentation Definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, it MUST describe the purpose for which the Presentation
    /// Definition is being used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// One or more registered Claim Format Profile Designation objects (e.g., `jwt`,
    /// `jwt_vc`, `jwt_vp`, etc.). Used to inform the Holder of the Claim
    /// formats the Verifier can process. For example,
    ///
    /// ```json
    ///   "jwt": {
    ///     "alg": ["EdDSA", "ES256K", "ES384"]
    ///   },
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, ClaimFormat>>,
}

/// Input Descriptors describe the information a Verifier requires from the
/// Holder. All Input Descriptors MUST be satisfied, unless otherwise specified.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InputDescriptor {
    /// An identifier that does not conflict with the id of any other Input
    /// Descriptor in the same Presentation Definition.
    pub id: String,

    /// If set, it SHOULD be a human-friendly name that describes what the
    /// target schema represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, its value MUST describe the purpose for which the Claim's
    /// data is being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// If present, its MUST be an object with one or more properties matching
    /// registered Claim Format Profile Designations (e.g., `jwt`, `jwt_vc`, `jwt_vp`,
    /// etc.). This property can be used to specifically constrain
    /// submission of a single input to a subset of the top-level formats or
    /// algorithms specified in the Presentation Definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, ClaimFormat>>,

    /// Contraints specify constraints on data values, and an explanation why a
    /// certain item or set of data is being requested.
    pub constraints: Constraints,
}

// TODO: create enum for ClaimFormat

/// A registered Claim Format Profile Designation object (e.g., `jwt`, `jwt_vc`,
/// `jwt_vp`, etc.) used to inform the Holder of a Claim format the Verifier can
/// process.
///
/// A Format object MUST include one of the format-specific properties (i.e.,
/// `alg`, `proof_type`) that specify which algorithms the Verifier supports for
/// the format.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimFormat {
    /// An array of one or more algorithmic identifiers,
    /// e.g. `["Ed2219", "ES256K"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,

    /// An array of one or more proof type identifiers,
    /// e.g. `["JsonWebSignature2020", "EcdsaSecp256k1Signature2019"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<Vec<String>>,
}

/// Contraints specify constraints on data values, and an explanation why a
/// certain item or set of data is being requested.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Constraints {
    /// Fields are used to specify attributes of credential data the Verifier
    /// requires. They are processed in order, meaning processing can be
    /// reduced by checking the most defining characteristics of a
    /// credential (e.g the type or schema of a credential) earlier.
    /// Implementers SHOULD order field checks to ensure earliest termination of
    /// evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,

    ///If present, `limit_disclosure` MUST be one of the following strings:
    /// "required" - indicates that the Conformant Consumer MUST limit submitted
    /// fields  to those listed in the fields array (if present). Conformant
    /// Consumers are not required  to implement support for this value, but
    /// they MUST understand this value sufficiently  to return nothing (or
    /// cease the interaction with the Verifier) if they do not implement it.
    ///
    /// "preferred" - indicates that the Conformant Consumer SHOULD limit
    /// submitted fields to those listed in the fields array (if present).
    ///
    /// Omission of this property indicates the Conformant Consumer MAY submit a
    /// response that contains more than the data described in the fields
    /// array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<String>,
}

/// Fields are used to specify attributes of credential data the Verifier
/// requires.
/// See <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition-in-an-envelope>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Field {
    /// If present, it MUST be unique from every other field object’s id
    /// property, including those contained in other Input Descriptor
    /// Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// One or more `JSONPath` expressions that select a target value from the
    /// input. The array MUST be evaluated in order, breaking as soon as a
    /// Field Query Result is found. The ability to use multiple expressions
    /// allows the Verifier to account for differences in credential
    /// formats.
    /// see <https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition>
    pub path: Vec<String>,

    /// If present, it MUST be a JSON Schema descriptor used to filter against
    /// the values returned from evaluation of the `JSONPath` expressions in
    /// the path array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,

    /// The predicate Feature enables the Verifier to request that Wallet apply
    /// a predicate and return a boolean rather than the matching
    /// credential.
    ///
    /// If `predicate` is present:
    ///  - it MUST be one of "required" or "preferred"
    ///  - the `filter` field containing the predicate MUST also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,

    /// If present, its MUST describe the purpose for which the field is being
    /// requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// If present, it SHOULD be a human-friendly name that describes what the
    /// target field represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, it MUST indicate whether the field is optional or not.
    /// Defaults to false. Even when set to `true`, the path value MUST
    /// validate against the JSON Schema filter, if a filter is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    /// If present, MUST be a boolean that indicates the Verifier intends to
    /// retain the Claim's data being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

/// A JSON Schema descriptor used to filter against the values returned from
/// evaluation of the `JSONPath` expressions in the path array.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// The type of filter to apply.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the filter to apply.
    #[serde(flatten)]
    pub value: FilterValue,
}

/// `FilterValue` represents the type and value of a `JSONPath` filter.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterValue {
    /// The value of the filter is a constant.
    Const(String),

    /// The value of the filter is a regular expression.
    Pattern(String),

    /// The value of the filter is a JSON Schema type format. For example,
    /// "date-time".
    Format(String),
}

impl Default for FilterValue {
    fn default() -> Self {
        Self::Const(String::new())
    }
}

/// A Presentation Submission expresses how proofs presented to the Verifier, in
/// accordance with the requirements specified in a Presentation Definition.
///
/// <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PresentationSubmission {
    /// The `id` MUST be a unique identifier, such as a UUID.
    pub id: String,

    /// The value of this property MUST be the id value of the Presentation
    /// Definition this submission fulfills.
    pub definition_id: String,

    /// An array of Input Descriptor Mapping Objects.
    pub descriptor_map: Vec<DescriptorMap>,
}

impl FromStr for PresentationSubmission {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        Ok(serde_json::from_str::<Self>(s)?)
    }
}

/// An Input Descriptor Mapping Object is used to map an Input Descriptor to a
/// Verifiable Credential or a JSON Web Token.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DescriptorMap {
    /// MUST match the Input Descriptor id in the Presentation Definition this
    /// Presentation Submission is related to.
    pub id: String,

    /// Denotes the data format of the Claim. MUST match one of the Claim Format Profile
    /// Designations specified in the Input Descriptor.
    pub format: String,

    /// A `JSONPath` string expression that indicates the Claim submitted in
    /// relation to the Input Descriptor, when executed against the
    /// top-level of the object the Presentation Submission.
    /// For the `OpenID4VP` specification, this value MUST be:
    ///  - $ when only one Verifiable Presentation
    ///  - $\[n\] when there are multiple Verifiable Presentations, where n is
    ///    the vp's index.
    pub path: String,

    /// Refers to the actual Credential carried in the respective Verifiable
    /// Presentation. Used to describe how to find a returned Credential
    /// within a Verifiable Presentation.
    pub path_nested: PathNested, // Option<Box<DescriptorMap>>,
}

/// A nested path object is used to describe how to find a returned Credential
/// within the Verifiable Presentation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PathNested {
    /// Format of the credential returned in the Verifiable Presentation.
    pub format: String,

    /// Describes how to find a returned Credential within a Verifiable
    /// Presentation. The value depends on the credential format.
    pub path: String,
}
