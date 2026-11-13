/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use crate::value::Value;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ciborium::Value as CborValue;
use flate2::read::ZlibDecoder;
use std::{
    fmt::{Display, Formatter},
    io::Read,
};
pub mod log;
pub mod metadata;
pub mod network;
pub mod value;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CborParseError {
    InvalidEncoding,
    NoCbor,
    NoIssuerAuth,
    NoNamespaces,
    NamespaceNotMap,
}
impl Display for CborParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum DeflateError {
    BufferOverflow,
    Other,
}
impl Display for DeflateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

const MAX_SIZE: u64 = 32 * 1024 * 1024;

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn deflate(input: Vec<u8>) -> Vec<u8> {
    deflate_upto_max_size(input, MAX_SIZE).unwrap_or_default()
}
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn deflate_upto_max_size(input: Vec<u8>, max_size: u64) -> Result<Vec<u8>, DeflateError> {
    let mut zliber = ZlibDecoder::new(&input[..]);
    let mut output = vec![];
    let mut buf = vec![0; 32 * 1024];
    loop {
        match zliber.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                output.extend_from_slice(&buf[..n]);
                if output.len() > max_size as usize {
                    return Err(DeflateError::BufferOverflow);
                }
            }
            Err(_) => return Err(DeflateError::Other),
        }
    }

    Ok(output)
}
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn deflate_string(input: String) -> Vec<u8> {
    let Ok(input) = BASE64_URL_SAFE_NO_PAD.decode(&input) else {
        return vec![];
    };
    deflate(input)
}

#[cfg(test)]
mod test_deflate {
    use std::io::{Read, Write};

    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use flate2::{read::GzDecoder, write::ZlibEncoder, Compression};

    use crate::{deflate, deflate_upto_max_size, DeflateError, MAX_SIZE};

    #[test]
    fn deflater() {
        let lst = "eNrtwSEBAAAAAiAn-H-tI6xAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAywAP4AAR";
        let lst = BASE64_URL_SAFE_NO_PAD.decode(lst).unwrap();
        let output = deflate(lst);
        assert!(!output.is_empty());
    }
    #[test]
    fn test_zip_bomb() {
        let zip_bomb = include_bytes!("../bomb.gz");
        let mut gzdecoder = GzDecoder::new(&zip_bomb[..]);
        let mut gz_bytes = vec![];
        gzdecoder.read_to_end(&mut gz_bytes).unwrap();
        let mut compressed = ZlibEncoder::new(vec![], Compression::best());
        compressed.write_all(&gz_bytes[..]).unwrap();
        let zlib_stream = compressed.finish().unwrap();
        let output = deflate(zlib_stream.to_vec());
        println!("{}", zlib_stream.len());
        println!("{}", output.len());
        assert!(output.len() <= 32 * 1024);
        let output = deflate_upto_max_size(zlib_stream.to_vec(), MAX_SIZE)
            .err()
            .unwrap();
        assert!(matches!(output, DeflateError::BufferOverflow));
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encode_cbor(cbor: Value) -> Result<Vec<u8>, CborParseError> {
    let cbor_val: CborValue = cbor.into();
    let mut result = vec![];
    ciborium::into_writer(&cbor_val, &mut result).map_err(|_| CborParseError::InvalidEncoding)?;
    Ok(result)
}

/// Encodes a value deterministically by sorting map entries by their encoded keys.
///
/// Maps inside keys, arrays and tags are also sorted. Identically encoded keys
/// are ordered by their encoded values to make duplicate entries deterministic.
/// This uses the same `Value` conversion and serialization as [`encode_cbor`],
/// including its handling of malformed tags, duplicate keys and NaN payloads.
/// It does not guarantee RFC 8949 deterministic encoding compliance or validate
/// CBOR. Byte strings, including CBOR inside tag 24, are not decoded or reordered.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encode_cbor_canonical(cbor: Value) -> Result<Vec<u8>, CborParseError> {
    let cbor_val = canonicalize_cbor(cbor.into())?;
    let mut result = vec![];
    ciborium::into_writer(&cbor_val, &mut result).map_err(|_| CborParseError::InvalidEncoding)?;
    Ok(result)
}

fn canonicalize_cbor(value: CborValue) -> Result<CborValue, CborParseError> {
    Ok(match value {
        CborValue::Array(values) => CborValue::Array(
            values
                .into_iter()
                .map(canonicalize_cbor)
                .collect::<Result<_, _>>()?,
        ),
        CborValue::Map(entries) => {
            let mut entries = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = canonicalize_cbor(key)?;
                    let value = canonicalize_cbor(value)?;
                    let mut key_bytes = vec![];
                    ciborium::into_writer(&key, &mut key_bytes)
                        .map_err(|_| CborParseError::InvalidEncoding)?;
                    let mut value_bytes = vec![];
                    ciborium::into_writer(&value, &mut value_bytes)
                        .map_err(|_| CborParseError::InvalidEncoding)?;
                    Ok((key_bytes, value_bytes, key, value))
                })
                .collect::<Result<Vec<_>, CborParseError>>()?;
            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            CborValue::Map(
                entries
                    .into_iter()
                    .map(|(_, _, key, value)| (key, value))
                    .collect(),
            )
        }
        CborValue::Tag(tag, value) => CborValue::Tag(tag, Box::new(canonicalize_cbor(*value)?)),
        other => other,
    })
}

#[cfg(test)]
mod test_deterministic_cbor {
    use crate::{
        encode_cbor, encode_cbor_canonical,
        value::{JsonNumber, OrderedMap, Value},
    };

    fn integer(value: i64) -> Value {
        Value::Number(JsonNumber::Integer(value))
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        let mut map = OrderedMap::new();
        for (key, value) in entries {
            map.insert(key, value);
        }
        Value::OrderedObject(map)
    }

    #[test]
    fn equivalent_maps_encode_deterministically() {
        let first = map(vec![(integer(1), integer(2)), (integer(3), integer(4))]);
        let second = map(vec![(integer(3), integer(4)), (integer(1), integer(2))]);

        let first_legacy = encode_cbor(first.clone()).unwrap();
        let second_legacy = encode_cbor(second.clone()).unwrap();
        assert_eq!(first_legacy, [0xa2, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(second_legacy, [0xa2, 0x03, 0x04, 0x01, 0x02]);
        assert_ne!(first_legacy, second_legacy);

        let first_canonical = encode_cbor_canonical(first).unwrap();
        let second_canonical = encode_cbor_canonical(second).unwrap();
        assert_eq!(first_canonical, [0xa2, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(first_canonical, second_canonical);
    }

    #[test]
    fn core_order_differs_from_legacy_length_first_order() {
        let input = map(vec![(integer(-1), integer(3)), (integer(24), integer(2))]);
        let legacy_length_first = [0xa2, 0x20, 0x03, 0x18, 0x18, 0x02];
        let core_deterministic = [0xa2, 0x18, 0x18, 0x02, 0x20, 0x03];
        assert_eq!(encode_cbor(input.clone()).unwrap(), legacy_length_first);
        let encoded = encode_cbor_canonical(input).unwrap();
        assert_ne!(encoded, legacy_length_first);
        assert_eq!(encoded, core_deterministic);
    }

    #[test]
    fn sorts_nested_maps_in_keys_arrays_and_tags() {
        let inner = map(vec![(integer(2), Value::Null), (integer(1), Value::Null)]);
        let input = map(vec![
            (Value::Array(vec![inner.clone()]), Value::Boolean(true)),
            (
                Value::Tag {
                    tag: 1000,
                    value: vec![inner.clone()],
                },
                inner,
            ),
        ]);
        assert_eq!(
            encode_cbor_canonical(input).unwrap(),
            [
                0xa2, 0x81, 0xa2, 0x01, 0xf6, 0x02, 0xf6, 0xf5, 0xd9, 0x03, 0xe8, 0xa2, 0x01, 0xf6,
                0x02, 0xf6, 0xa2, 0x01, 0xf6, 0x02, 0xf6,
            ]
        );
    }

    #[test]
    fn duplicate_keys_are_accepted_and_ordered_by_value() {
        let first = map(vec![(integer(1), integer(3)), (integer(1), integer(2))]);
        let second = map(vec![(integer(1), integer(2)), (integer(1), integer(3))]);
        assert!(encode_cbor(first.clone()).is_ok());
        assert_eq!(
            encode_cbor_canonical(first).unwrap(),
            [0xa2, 0x01, 0x02, 0x01, 0x03]
        );
        assert_eq!(
            encode_cbor_canonical(second).unwrap(),
            [0xa2, 0x01, 0x02, 0x01, 0x03]
        );
    }

    #[test]
    fn uses_existing_conversion_and_float_serialization() {
        let input = Value::Array(vec![
            Value::Tag {
                tag: 24,
                value: vec![],
            },
            Value::Tag {
                tag: 24,
                value: vec![Value::Null, Value::Null],
            },
            Value::Number(JsonNumber::Float(-0.0)),
            Value::Number(JsonNumber::Float(f64::from_bits(0xfff8000000000001))),
        ]);
        assert_eq!(
            encode_cbor_canonical(input.clone()).unwrap(),
            encode_cbor(input).unwrap()
        );
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn decode_cbor(cbor: Vec<u8>) -> Result<Value, CborParseError> {
    ciborium::from_reader::<CborValue, _>(cbor.as_slice())
        .map(Value::from)
        .map_err(|_| CborParseError::NoCbor)
}

#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __deregister_frame() {}

#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __register_frame() {}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
