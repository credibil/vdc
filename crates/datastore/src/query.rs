//! # Store
//!
//! The `store` module provides utilities for storing and retrieving messages
//! and associated data.
//!
//! The two primary types exposed by this module are [`Storable`] and [`Query`].
//!
//! [`Storable`] wraps each message with a unifying type used to simplify storage
//! and retrieval as well as providing a vehicle for attaching addtional data
//! alongside the message (i.e. indexes).
//!
//! [`Query`] wraps store-specific query options for querying the underlying
//! store.

use std::fmt::Display;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::serde::rfc3339_micros_opt;

/// The top-level query data structure used for both
/// [`crate::provider::MessageStore`] and [`crate::provider::EventLog`]
/// queries.
///
/// The query is composed of one or more [`MatchSet`]s derived from filters
/// associated with the messagetype being queried. [`MatchSet`]s are 'OR-ed'
/// together to form the query.
///
/// Sorting and pagination options are also included although not always
/// used.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// One or more sets of events to match.
    pub match_sets: Vec<MatchSet>,

    /// Sort options.
    pub sort: Sort,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl Query {
    /// Determine whether the query can be expressed in a concise form.
    #[must_use]
    pub(crate) fn is_concise(&self) -> bool {
        if self.match_sets.is_empty() {
            return false;
        }

        for ms in &self.match_sets {
            let Some((_, value)) = &ms.index else {
                return false;
            };
            if value.is_empty() {
                return false;
            }
        }

        true
    }
}

/// A `MatchSet` contains a set of [`Matcher`]s derived from the underlying
/// filter object. [`Matcher`]s are 'AND-ed' together for a successful match.
#[derive(Clone, Debug, Default)]
pub struct MatchSet {
    /// The set of matchers.
    pub inner: Vec<Matcher>,

    /// The index to use for the query.
    pub index: Option<(String, String)>,
}

/// A `Matcher` is used to match the `field`/`value` pair to a proovided index
/// value during the process of executing a query.
#[derive(Clone, Debug)]
pub struct Matcher {
    /// The name of the field this matcher applies to.
    pub field: String,

    /// The value and strategy to use for a successful match.
    pub value: MatchOn,
}

impl Matcher {
    /// Check if the field value matches the filter value.
    ///
    /// # Errors
    ///
    /// The `Matcher` may fail to parse the provided value to the correct type
    /// and will return an error in this case.
    pub(crate) fn is_match(&self, value: &str) -> Result<bool> {
        let matched = match &self.value {
            MatchOn::Equal(filter_val) => value == filter_val,
            MatchOn::StartsWith(filter_val) => value.starts_with(filter_val),
            MatchOn::OneOf(values) => values.contains(&value.to_string()),
            MatchOn::Range(range) => {
                let int_val = value
                    .parse()
                    .map_err(|e| anyhow!("issue converting match value to usize: {e}"))?;
                range.contains(&int_val)
            }
            MatchOn::DateRange(range) => {
                let date_val = DateTime::parse_from_rfc3339(value)
                    .map_err(|e| anyhow!("issue converting match value to date: {e}"))?;
                range.contains(&date_val.into())
            }
        };
        Ok(matched)
    }
}

/// The [`MatchOn`] enum is used to specify the matching strategy to be
/// employed by the `Matcher`.
#[derive(Clone, Debug)]
pub enum MatchOn {
    /// The match must be equal.
    Equal(String),

    /// The match must start with the specified value.
    StartsWith(String),

    /// The match must be with at least one of the items specified.
    OneOf(Vec<String>),

    /// The match must be in the specified range.
    Range(Range<usize>),

    /// The match must be in the specified date range.
    DateRange(DateRange),
}

/// Range to use in filters.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Range<T: PartialEq> {
    /// The filter's lower bound.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lower: Option<Lower<T>>,

    /// The filter's upper bound.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper: Option<Upper<T>>,
}

/// Range lower bound comparision options.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Lower<T: PartialEq> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "gt")]
    Exclusive(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "gte")]
    Inclusive(T),
}

impl<T: PartialEq + Default> Default for Lower<T> {
    fn default() -> Self {
        Self::Exclusive(T::default())
    }
}

/// Range upper bound comparision options.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Upper<T: PartialEq> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "lt")]
    Exclusive(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "lte")]
    Inclusive(T),
}

impl<T: PartialEq + Default> Default for Upper<T> {
    fn default() -> Self {
        Self::Exclusive(T::default())
    }
}

impl<T: PartialEq> Range<T> {
    /// Create a new range filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    /// Specify a 'greater-than' lower bound for the filter.
    #[must_use]
    pub fn gt(mut self, gt: T) -> Self {
        self.lower = Some(Lower::Exclusive(gt));
        self
    }

    /// Specify a 'greater-than-or-equal' lower bound for the filter.
    #[must_use]
    pub fn ge(mut self, ge: T) -> Self {
        self.lower = Some(Lower::Inclusive(ge));
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub fn lt(mut self, lt: T) -> Self {
        self.upper = Some(Upper::Exclusive(lt));
        self
    }

    /// Specify a 'less-than-or-equal' upper bound for the filter.
    #[must_use]
    pub fn le(mut self, le: T) -> Self {
        self.upper = Some(Upper::Inclusive(le));
        self
    }

    /// Check if the range contains the value.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialOrd,
    {
        let lower_ok = match &self.lower {
            Some(Lower::Exclusive(lower)) => value > lower,
            Some(Lower::Inclusive(lower)) => value >= lower,
            None => true,
        };
        if !lower_ok {
            return false;
        }

        match &self.upper {
            Some(Upper::Exclusive(upper)) => value < upper,
            Some(Upper::Inclusive(upper)) => value <= upper,
            None => true,
        }
    }
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DateRange {
    /// The filter's lower bound.
    #[serde(rename = "from")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub lower: Option<DateTime<Utc>>,

    /// The filter's upper bound.
    #[serde(rename = "to")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub upper: Option<DateTime<Utc>>,
}

impl DateRange {
    /// Create a new range filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    /// Specify a 'greater-than' lower bound for the filter.
    #[must_use]
    pub const fn gt(mut self, gt: DateTime<Utc>) -> Self {
        self.lower = Some(gt);
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub const fn lt(mut self, lt: DateTime<Utc>) -> Self {
        self.upper = Some(lt);
        self
    }

    /// Check if the range contains the value.
    #[must_use]
    pub fn contains(&self, value: &DateTime<Utc>) -> bool {
        if let Some(lower) = &self.lower {
            if value < lower {
                return false;
            }
        }
        if let Some(upper) = &self.upper {
            if value >= upper {
                return false;
            }
        }

        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Sort {
    /// Sort by the specified field in ascending order.
    Ascending(String),

    /// Sort by the specified field in descending order.
    Descending(String),
}

impl Sort {
    /// Short-circuit testing for ascending/descending sort.
    #[must_use]
    pub const fn is_ascending(&self) -> bool {
        matches!(self, Self::Ascending(_))
    }
}

impl Default for Sort {
    fn default() -> Self {
        Self::Ascending("messageTimestamp".to_string())
    }
}

impl Display for Sort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ascending(s) | Self::Descending(s) => write!(f, "{s}"),
        }
    }
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Cursor created form the previous page of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

impl Pagination {
    /// Create a new `Pagination` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limit: None,
            cursor: None,
            // offinner: None,
        }
    }

    /// Set the limit.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the cursor.
    #[must_use]
    pub fn cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

/// Pagination cursor containing data from the last entry returned in the
/// previous page of results.
///
/// Message CID ensures result cursor compatibility irrespective of DWN
/// implementation. Meaning querying with the same cursor yields identical
/// results regardless of DWN queried.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    /// Message CID from the last entry in the previous page of results.
    pub message_cid: String,

    /// The value (from sort field) of the last entry in the previous page of
    /// results.
    pub value: String,
}
