//! # Url Encoder/Decoder
//!
//! provides encoding and decoding of `application/x-www-form-urlencoded`
//! HTML query strings and forms.

use anyhow::{Result, anyhow};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.').remove(b'_').remove(b'-').remove(b'~');

/// Create an `application/x-www-form-urlencoded` representation of the
/// provided value suitable for use in an HTML query strings or form post.
///
/// # Errors
///
/// Will return an error if any of the object-type fields cannot be
/// serialized to JSON and URL-encoded.
pub fn encode<T: Serialize>(value: &T) -> Result<String> {
    let encoded = match serde_json::to_value(value)? {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let s = if let Value::String(s) = v { s } else { &v.to_string() };
                format!("{k}={}", utf8_percent_encode(s, UNRESERVED))
            })
            .collect::<Vec<String>>(),
        Value::String(s) => {
            vec![format!("{}", utf8_percent_encode(&s, UNRESERVED))]
        }
        _ => return Err(anyhow!("unsupported value")),
    };
    Ok(encoded.join("&"))
}

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
pub fn decode<T: DeserializeOwned>(s: &str) -> Result<T> {
    let mut map = Map::new();

    for part in s.split('&') {
        let mut kv = part.split('=');
        let key = kv.next().ok_or_else(|| anyhow!("missing key"))?;
        let encoded = kv.next().ok_or_else(|| anyhow!("missing value"))?;
        let decoded = percent_decode_str(encoded).decode_utf8_lossy();
        let value = if decoded.starts_with('[') || decoded.starts_with('{') {
            serde_json::from_str(&decoded)?
        } else {
            Value::String(decoded.to_string())
        };
        map.insert(key.to_string(), value);
    }

    Ok(serde_json::from_value(Value::Object(map))?)
}

/// Serializes a value to a url-encoded string.
///
/// # Errors
///
/// Will return an error if the value cannot be serialized to JSON.
pub fn to_string<T: Serialize>(value: &T) -> Result<String> {
    encode(value)
}

/// Create an `application/x-www-form-urlencoded` representation of the
/// provided value suitable for use in an HTML query strings or form post.
///
/// # Errors
///
/// Will return an error if any of the object-type fields cannot be
/// serialized to JSON and URL-encoded.
pub fn to_map<T: Serialize>(value: &T) -> Result<Vec<(String, String)>> {
    let val = serde_json::to_value(value)?;
    let map = val.as_object().ok_or_else(|| anyhow!("expected an object"))?;
    let encoded = map
        .iter()
        .map(|(k, v)| {
            let s = if let Value::String(s) = v { s } else { &v.to_string() };
            (k.to_string(), utf8_percent_encode(s, UNRESERVED).to_string())
        })
        .collect::<Vec<(String, String)>>();
    Ok(encoded)
}

/// Deserializes a url-encoded string to a value.
///
/// # Errors
///
/// Will return an error if the string cannot be deserialized to the specified
/// type.
pub fn from_str<T: DeserializeOwned>(s: &str) -> Result<T> {
    decode(s)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TopLevel {
        field_1: Option<String>,
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
            field_1: Some("value1".to_string()),
            field_2: "value2".to_string(),
            nested: Nested {
                field_3: "value3".to_string(),
                field_4: "value4".to_string(),
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
        assert_eq!(super::to_string(&u).unwrap(), expected);

        let n = E::Newtype(1);
        let expected = r#"Newtype=1"#;
        assert_eq!(super::to_string(&n).unwrap(), expected);

        let t = E::Tuple(1, 2);
        let expected = r#"Tuple=%5B1%2C2%5D"#;
        assert_eq!(super::to_string(&t).unwrap(), expected);

        let s = E::Struct { a: 1 };
        let expected = r#"Struct=%7B%22a%22%3A1%7D"#;
        assert_eq!(super::to_string(&s).unwrap(), expected);
    }

    #[test]
    fn decode_struct() {
        let url = r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22value3%22%2C%22field_4%22%3A%22value4%22%7D"#;

        let deserialized: TopLevel = super::from_str(&url).expect("should deserialize");
        let expected = TopLevel {
            field_1: Some("value1".to_string()),
            field_2: "value2".to_string(),
            nested: Nested {
                field_3: "value3".to_string(),
                field_4: "value4".to_string(),
            },
        };
        assert_eq!(deserialized, expected);
    }
}
