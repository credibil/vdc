//! # Core

pub mod api;
pub mod datastore;
pub mod http;
pub mod urlencode;

mod did;

pub use did::*;
use serde::{Deserialize, Serialize};

/// `Kind` allows serde to serialize/deserialize a string or an object.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Simple string value
    String(String),

    /// Complex object value
    Object(T),
}

impl<T> Default for Kind<T> {
    fn default() -> Self {
        Self::String(String::new())
    }
}

impl<T> From<String> for Kind<T> {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl<T> Kind<T> {
    /// Returns `true` if the quota is a single object.
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            Self::Object(_) => None,
        }
    }

    /// Returns `true` if the quota contains an array of objects.
    pub const fn as_object(&self) -> Option<&T> {
        match self {
            Self::String(_) => None,
            Self::Object(o) => Some(o),
        }
    }
}

/// `OneMany` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneMany<T> {
    /// Single object
    One(T),

    /// Set of objects
    Many(Vec<T>),
}

impl<T: Default> Default for OneMany<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T> From<T> for OneMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T: Clone + Default + PartialEq> OneMany<T> {
    /// Returns `true` if the quota is a single object.
    pub const fn as_one(&self) -> Option<&T> {
        match self {
            Self::One(o) => Some(o),
            Self::Many(_) => None,
        }
    }

    /// Returns the `OneMany` as a Vec regardless of contents.
    pub fn to_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }

    /// Adds an object to the quota. If the quota is a single object, it is
    /// converted to a set of objects.
    pub fn add(&mut self, item: T) {
        match self {
            Self::One(one) => {
                *self = Self::Many(vec![one.clone(), item]);
            }
            Self::Many(many) => {
                many.push(item);
            }
        }
    }

    /// Returns the length of the quota.
    pub const fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(many) => many.len(),
        }
    }

    /// Returns `true` if the quota is an empty `Many`.
    pub const fn is_empty(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(many) => many.is_empty(),
        }
    }
}
