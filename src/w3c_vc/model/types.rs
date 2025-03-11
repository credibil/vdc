//! # Shared Types
//!
//! This module contains lower-level types that are shared across the data
//! models for Verifiable Credentials (`vc`) and Verifiable Presentations
//! (`vp`).

use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::core::{Kind, OneMany};

/// `LangString` is a string that has one or more language representations.
///
/// <https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct LangString(Kind<OneMany<LangValue>>);

impl LangString {
    /// Create a new `LangString` from a simple string.
    #[must_use]
    pub fn new_string(value: &str) -> Self {
        Self(Kind::String(value.to_string()))
    }

    /// Create a new `LangString` from a single language object.
    #[must_use]
    pub const fn new_object(value: LangValue) -> Self {
        Self(Kind::Object(OneMany::One(value)))
    }

    /// Add a language object to the `LangString`.
    pub fn add(&mut self, value: LangValue) {
        match &self.0 {
            Kind::String(s) => {
                let existing = LangValue {
                    value: s.clone(),
                    ..LangValue::default()
                };
                self.0 = Kind::Object(OneMany::Many(vec![existing, value]));
            }
            Kind::Object(lang_values) => {
                let mut new_values = lang_values.clone();
                new_values.add(value);
                self.0 = Kind::Object(new_values.clone());
            }
        }
    }

    /// Length of the `LangString` is the number of language objects.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.0 {
            Kind::String(_) => 1,
            Kind::Object(lang_values) => lang_values.len(),
        }
    }

    /// Check if the `LangString` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Extract a value for the provided language tag.
    ///
    /// If the language string is a simple string, the value is returned as is.
    /// If the language string is an object, the value for the provided language
    /// tag is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the language tag is not found.
    pub fn value(&self, language: &str) -> anyhow::Result<String> {
        match &self.0 {
            Kind::String(s) => Ok(s.to_string()),
            Kind::Object(lang_values) => match lang_values {
                OneMany::One(lang_value) => {
                    if lang_value.language == Some(language.to_string()) {
                        Ok(lang_value.value.clone())
                    } else {
                        Err(anyhow::anyhow!("Language tag not found"))
                    }
                }
                OneMany::Many(lang_values) => {
                    for lang_value in lang_values {
                        if lang_value.language == Some(language.to_string()) {
                            return Ok(lang_value.value.clone());
                        }
                    }
                    Err(anyhow::anyhow!("Language tag not found"))
                }
            },
        }
    }
}

impl Deref for LangString {
    type Target = Kind<OneMany<LangValue>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// `LangValue` is a description of a string in a specific language.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LangValue {
    /// Value of the string
    #[serde(rename = "@value")]
    pub value: String,

    /// Language-tag as defined in [rfc5646](https://www.rfc-editor.org/rfc/rfc5646)
    ///
    /// A missing language tag implies that the string is in the default language.
    #[serde(rename = "@language")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// Base direction of the text when bidirectional text is displayed.
    #[serde(rename = "@direction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
}

/// Base direction of the text when bidirectional text is displayed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Direction {
    /// Left-to-right
    #[serde(rename = "ltr")]
    Ltr,

    /// Right-to-left
    #[serde(rename = "rtl")]
    Rtl,
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;

    use super::*;

    #[derive(Deserialize, Serialize)]
    struct Info {
        name: LangString,
        description: LangString,
        other: Option<LangString>,
    }

    fn info_sample() -> serde_json::Value {
        json!(
            {
                "name": {
                    "@value": "Alice",
                    "@language": "en",
                },
                "description": [
                    {
                        "@value": "HTML and CSS: Designing and Creating Websites",
                        "@language": "en"
                    },
                    {
                        "@value": "HTML و CSS: تصميم و إنشاء مواقع الويب",
                        "@language": "ar",
                        "@direction": "rtl"
                    }
                ],
                "other": "Just a string"
            }
        )
    }

    #[test]
    fn language_string_serialization() {
        let info = info_sample();
        let hydrated: Info = serde_json::from_value(info).unwrap();
        assert_snapshot!("language_string_serialization", hydrated, {
            ".description" => insta::sorted_redaction(),
        });
        let serialized = serde_json::to_value(&hydrated).unwrap();
        assert_snapshot!("language_string_serialization_json", serialized);
    }

    #[test]
    fn language_string_value() {
        let json = info_sample();
        let info: Info = serde_json::from_value(json).unwrap();
        assert_eq!(info.name.value("en").unwrap(), "Alice");
        assert_eq!(
            info.other.expect("option should be some").value("en").unwrap(),
            "Just a string"
        );
        info.description.value("es").expect_err("Spanish language tag should not be found");
    }
}
