//! # URL Encoding Serializer

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Serialize, ser};

use super::error::{Error, Result};

const TOP_LEVEL: usize = 1;
const UNRESERVED: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'&').remove(b'=').remove(b'.').remove(b'_').remove(b'-').remove(b'~');

/// Serializes a value to a url-encoded string.
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
/// let data = TopLevel {
///     field_1: "value1".to_owned(),
///     field_2: "value2".to_owned(),
///     nested: Nested {
///         field_3: "value3".to_owned(),
///         field_4: "value4".to_owned(),
///     },
/// };
///
/// let serialized = urlencode::to_string(&data).expect("should serialize");
/// let expected =
///     r#"field_1=value1&field_2=value2&nested=%7B%22field_3%22%3A%22value3%22%2C%22field_4%22%3A%22value4%22%7D"#;
/// assert_eq!(serialized, expected);
/// ```
///
/// # Errors
/// TODO: Add error handling
pub fn to_string<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: String::new(),
        level: 0,
    };
    value.serialize(&mut serializer)?;

    let encoded = utf8_percent_encode(&serializer.output, UNRESERVED).to_string();
    Ok(encoded)
}

/// A serializer for url encoding.
///
/// * Supported top-level inputs are structs, maps and sequences of pairs, with
///   or without a given length.
///
/// * Supported keys and values are integers, bytes (if convertible to strings),
///   unit structs and unit variants.
///
/// * Newtype structs defer to their inner values.
pub struct Serializer {
    output: String,
    level: usize,
}

impl ser::Serializer for &mut Serializer {
    type Error = Error;
    type Ok = ();
    type SerializeMap = Self;
    type SerializeSeq = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.output += if v { "true" } else { "false" };
        Ok(())
    }

    // JSON does not distinguish between different sizes of integers.
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        if self.level > TOP_LEVEL {
            self.output += "\"";
            self.output += v;
            self.output += "\"";
        } else {
            self.output += v;
        }
        Ok(())
    }

    // Serialize a byte array as an array of bytes.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        use serde::ser::SerializeSeq;
        let mut seq = self.serialize_seq(Some(v.len()))?;
        for byte in v {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        self.serialize_unit()
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`.
    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        self.output += "null";
        Ok(())
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name.
    fn serialize_unit_variant(
        self, _name: &'static str, _variant_index: u32, variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    // Treat newtype structs as insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to JSON in externally tagged form as `{ NAME: VALUE }`.
    fn serialize_newtype_variant<T>(
        self, _name: &'static str, _variant_index: u32, variant: &'static str, value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.level += 1;

        if self.level > TOP_LEVEL {
            self.output += "{";
            variant.serialize(&mut *self)?;
            self.output += ":";
            value.serialize(&mut *self)?;
            self.output += "}";
        } else {
            variant.serialize(&mut *self)?;
            self.output += "=";
            value.serialize(&mut *self)?;
        }

        self.level -= 1;
        Ok(())
    }

    // Serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start,
    // which in JSON is `[`.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        self.level += 1;
        self.output += "[";
        Ok(self)
    }

    // Tuples look just like sequences in JSON.
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.level += 1;
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self, _name: &'static str, len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. This
    // method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self, _name: &'static str, _variant_index: u32, variant: &'static str, _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.level += 1;

        if self.level > TOP_LEVEL {
            self.output += "{";
            variant.serialize(&mut *self)?;
            self.output += ":[";
        } else {
            variant.serialize(&mut *self)?;
            self.output += "=[";
        }

        Ok(self)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        self.level += 1;

        if self.level > TOP_LEVEL {
            self.output += "{";
        }

        Ok(self)
    }

    // Structs look just like maps in JSON.
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        self.serialize_map(Some(len))
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self, _name: &'static str, _variant_index: u32, variant: &'static str, _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.level += 1;

        if self.level > TOP_LEVEL {
            self.output += "{";
            variant.serialize(&mut *self)?;
            self.output += ":{";
        } else {
            variant.serialize(&mut *self)?;
            self.output += "={";
        }
        Ok(self)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// `SerializeSeq` methods are called after the `serialize_seq` function.
// is called on the Serializer.
impl ser::SerializeSeq for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('[') {
            self.output += ",";
        }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        self.output += "]";
        self.level -= 1;
        Ok(())
    }
}

impl ser::SerializeTuple for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('[') {
            self.output += ",";
        }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        self.output += "]";
        self.level -= 1;
        Ok(())
    }
}

impl ser::SerializeTupleStruct for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('[') {
            self.output += ",";
        }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        self.output += "]";
        self.level -= 1;
        Ok(())
    }
}

// Tuple variants are a little different as the `end` method in this impl is
// responsible for closing both the `]` and the `}`.
//
// See the `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
impl ser::SerializeTupleVariant for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('[') {
            self.output += ",";
        }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        if self.level > TOP_LEVEL {
            self.output += "]}";
        } else {
            self.output += "]";
        }
        self.level -= 1;
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl ser::SerializeMap for &mut Serializer {
    type Error = Error;
    type Ok = ();

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('{') {
            self.output += ",";
        }
        key.serialize(&mut **self)
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        self.output += "}";
        self.level -= 1;
        Ok(())
    }
}

impl ser::SerializeStruct for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if self.level > TOP_LEVEL {
            if !self.output.ends_with('{') {
                self.output += ",";
            }
        } else if !self.output.is_empty() {
            self.output += "&";
        }

        key.serialize(&mut **self)?;
        if self.level > TOP_LEVEL {
            self.output += ":";
        } else {
            self.output += "=";
        }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        if self.level > TOP_LEVEL {
            self.output += "}";
            self.level -= 1;
        }
        Ok(())
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl ser::SerializeStructVariant for &mut Serializer {
    type Error = Error;
    type Ok = ();

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if !self.output.ends_with('{') {
            self.output += ",";
        }
        key.serialize(&mut **self)?;
        self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        if self.level > TOP_LEVEL {
            self.output += "}}";
        } else {
            self.output += "}";
        }
        self.level -= 1;
        Ok(())
    }
}
