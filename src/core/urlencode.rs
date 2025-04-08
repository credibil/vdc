//! # Url Encoder/Decoder

mod error;
mod ser;

use error::{Error, Result};
use percent_encoding::percent_decode_str;
pub use ser::{Serializer, to_string};
use serde::Deserialize;

/// Deserializes a url-encoded string to a value.
///
/// ```rust,ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct TopLevel {
///     field_1: String,
///     field_2: Nested,
/// }
///
/// #[derive(Serialize, Deserialize)]
/// struct Nested {
///     field_3: String,
///     field_4: String,
/// }
///
/// let encoded =
///     r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22value3%22%2C%22field_4%22%3A%22value4%22%7D"#;
/// let deserialized: TopLevel = urlencode::from_str(&encoded).unwrap();
///
/// let expected = TopLevel {
///     field_1: "value1".to_owned(),
///     field_2: "value2".to_owned(),
///     nested: Nested {
///         field_3: "value3".to_owned(),
///         field_4: "value4".to_owned(),
///     },
/// };
///
/// assert_eq!(deserialized, expected);
/// ```
///
/// # Errors
/// // TODO: Add errors
pub fn from_str<T>(s: &str) -> Result<T>
where
    T: for<'a> Deserialize<'a>,
{
    // HACK: deserializing with `serde_json` makes decoding trivial and takes ~60µs
    let decoded = percent_decode_str(s).decode_utf8_lossy();
    let decoded = format!("{{\"{decoded}\"}}");
    let decoded = decoded
        .replace('=', "\":\"")
        .replace('&', "\",\"")
        .replace("\"[", "[")
        .replace("]\"", "]")
        .replace("\"{", "{")
        .replace("}\"", "}");

    serde_json::from_str(&decoded).map_err(|e| Error::Message(e.to_string()))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::ser;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TopLevel {
        field_1: String,
        field_2: String,
        nested: Nested,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Nested {
        field_3: String,
        field_4: String,
    }

    #[test]
    fn encode_struct() {
        let data = TopLevel {
            field_1: "value1".to_owned(),
            field_2: "value2".to_owned(),
            nested: Nested {
                field_3: "value3".to_owned(),
                field_4: "value4".to_owned(),
            },
        };

        let serialized = super::to_string(&data).expect("should serialize");
        let expected = r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22value3%22%2C%22field_4%22%3A%22value4%22%7D"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn encode_enum() {
        #[derive(Serialize)]
        enum E {
            Unit,
            Newtype(u32),
            Tuple(u32, u32),
            Struct { a: u32 },
        }

        let u = E::Unit;
        let expected = r#"Unit"#;
        assert_eq!(ser::to_string(&u).unwrap(), expected);

        let n = E::Newtype(1);
        let expected = r#"Newtype=1"#;
        assert_eq!(ser::to_string(&n).unwrap(), expected);

        let t = E::Tuple(1, 2);
        let expected = r#"Tuple=%5B1%2C2%5D"#;
        assert_eq!(ser::to_string(&t).unwrap(), expected);

        let s = E::Struct { a: 1 };
        let expected = r#"Struct=%7Ba%3A1%7D"#;
        assert_eq!(ser::to_string(&s).unwrap(), expected);
    }

    #[test]
    fn decode_struct() {
        let url = r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22value3%22%2C%22field_4%22%3A%22value4%22%7D"#;

        let deserialized: TopLevel = super::from_str(&url).expect("should deserialize");
        let expected = TopLevel {
            field_1: "value1".to_owned(),
            field_2: "value2".to_owned(),
            nested: Nested {
                field_3: "value3".to_owned(),
                field_4: "value4".to_owned(),
            },
        };
        assert_eq!(deserialized, expected);
    }
}
