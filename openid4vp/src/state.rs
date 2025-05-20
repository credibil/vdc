//! State is used by the library to persist request information between steps
//! in the issuance process.

use chrono::TimeDelta;

/// The duration for which a state item is valid.
pub enum Expire {
    /// The state item expires after the request is created.
    Request,
}

impl Expire {
    /// Returns the duration for which the state item is valid.
    #[must_use]
    pub fn duration(&self) -> TimeDelta {
        match self {
            Self::Request => TimeDelta::try_minutes(5).unwrap_or_default(),
        }
    }
}
