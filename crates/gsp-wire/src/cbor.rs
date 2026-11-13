//! Deterministic CBOR (RFC 8949 section 4.2.1, "core deterministic encoding").
//!
//! Everything on the wire goes through [`Value`]: typed structures convert to a
//! `Value`, and `Value::encode` is the only place bytes are produced. Decoding
//! is strict: [`Value::decode`] parses, then re-encodes and requires the result
//! to equal the input byte for byte, so any non-canonical encoding (non-shortest
//! integer or float, unsorted or duplicate map keys, indefinite lengths,
//! trailing bytes, NaN payloads) is rejected.
//!
//! The accepted subset: unsigned/negative integers (full CBOR range), floats,
//! byte strings, text strings, arrays, maps with **text keys only**, `false`,
//! `true`, `null`. No tags, no `undefined`, no other simple values.

use alloc::{string::String, vec::Vec};
use core::fmt;
use minicbor::data::{Int, Type};
use minicbor::{Decoder, Encoder};

/// Maximum nesting depth accepted by the decoder and the encoder.
pub const MAX_DEPTH: usize = 32;

/// A CBOR data item in the subset GSP uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// Integer in the CBOR range `-2^64 ..= 2^64 - 1`.
    Int(i128),
    /// IEEE 754 double; encoded in the shortest of f16/f32/f64 that is exact.
    Float(f64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map with text keys. In-memory order is irrelevant: encoding sorts.
    Map(Vec<(String, Value)>),
}

/// Why a value could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A map holds the same key twice.
    DuplicateKey,
    /// An integer is outside `-2^64 ..= 2^64 - 1`.
    IntRange,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A structural limit of a GSP type was violated (named).
    Limit(&'static str),
}

/// Why bytes could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not well-formed CBOR, or truncated.
    Cbor,
    /// Well-formed but uses a CBOR feature outside the GSP subset.
    UnsupportedType,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Bytes remain after the top-level item.
    Trailing,
    /// Not the deterministic encoding of the value it decodes to.
    NonCanonical,
    /// A map holds the same key twice.
    DuplicateKey,
    /// Valid CBOR, wrong shape for the GSP type being read (named).
    Shape(&'static str),
    /// The `format` field names a structure version this code does not know.
    UnsupportedFormat(u64),
    /// A discriminant (message type, key-log action...) this code does not know.
    UnsupportedKind(u64),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gsp encode error: {self:?}")
    }
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gsp decode error: {self:?}")
    }
}
impl core::error::Error for EncodeError {}
impl core::error::Error for DecodeError {}

impl From<minicbor::decode::Error> for DecodeError {
    fn from(_: minicbor::decode::Error) -> Self {
        DecodeError::Cbor
    }
}

fn text_key(k: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(k.len() + 9);
    // Writing to a Vec cannot fail.
    let _ = Encoder::new(&mut out).str(k);
    out
}

impl Value {
    /// Convenience constructor for unsigned integers.
    pub fn uint(n: u64) -> Value {
        Value::Int(i128::from(n))
    }

    /// Deterministic encoding of this value.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        self.encode_into(&mut out, 0)?;
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>, depth: usize) -> Result<(), EncodeError> {
        if depth > MAX_DEPTH {
            return Err(EncodeError::TooDeep);
        }
        // minicbor's integer/length writers always pick the shortest head, and
        // writing to a Vec is infallible, hence the discarded results.
        match self {
            Value::Null => {
                let _ = Encoder::new(&mut *out).null();
            }
            Value::Bool(b) => {
                let _ = Encoder::new(&mut *out).bool(*b);
            }
            Value::Int(n) => {
                let i = Int::try_from(*n).map_err(|_| EncodeError::IntRange)?;
                let _ = Encoder::new(&mut *out).int(i);
            }
            Value::Float(v) => encode_float(*v, out),
            Value::Bytes(b) => {
                let _ = Encoder::new(&mut *out).bytes(b);
            }
            Value::Text(s) => {
                let _ = Encoder::new(&mut *out).str(s);
            }
            Value::Array(items) => {
                let _ = Encoder::new(&mut *out).array(items.len() as u64);
                for it in items {
                    it.encode_into(out, depth + 1)?;
                }
            }
            Value::Map(entries) => {
                // RFC 8949 4.2.1: keys sorted by the bytewise lexicographic
                // order of their deterministic encodings.
                let mut keyed: Vec<(Vec<u8>, &Value)> =
                    entries.iter().map(|(k, v)| (text_key(k), v)).collect();
                keyed.sort_by(|a, b| a.0.cmp(&b.0));
                if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                    return Err(EncodeError::DuplicateKey);
                }
                let _ = Encoder::new(&mut *out).map(keyed.len() as u64);
                for (k, v) in keyed {
                    out.extend_from_slice(&k);
                    v.encode_into(out, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// Strict decode: exactly one item, canonical, nothing trailing.
    ///
    /// Map keys are checked for canonical order while decoding, so input
    /// with duplicate or unsorted keys fails at the first offending key.
    /// Memory use is bounded by the input: every array element and map
    /// entry takes at least one input byte, and the result holds at most
    /// one [`Value`] per input byte (plus the bytes of strings, which are
    /// copied once). For input that has not been authenticated, prefer
    /// [`Value::decode_limited`], which also bounds the number of items.
    pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
        Value::decode_limited(bytes, usize::MAX)
    }

    /// [`Value::decode`], failing as soon as the input turns out to hold
    /// more than `max_items` data items in total (every array, map, map
    /// value and scalar counts as one). A [`Value`] takes several times the
    /// memory of a one-byte item, so this is what keeps the cost of decoding
    /// hostile input proportional to what a well-formed message of the
    /// expected kind needs. The error is `Shape("too many items")`.
    pub fn decode_limited(bytes: &[u8], max_items: usize) -> Result<Value, DecodeError> {
        let mut d = Decoder::new(bytes);
        let mut budget = max_items;
        let v = decode_item(&mut d, 0, &mut budget)?;
        if d.position() != bytes.len() {
            return Err(DecodeError::Trailing);
        }
        match v.encode() {
            Ok(re) if re == bytes => Ok(v),
            Ok(_) => Err(DecodeError::NonCanonical),
            Err(EncodeError::DuplicateKey) => Err(DecodeError::DuplicateKey),
            Err(_) => Err(DecodeError::NonCanonical),
        }
    }
}

/// Shortest exact float (RFC 8949 4.2.1); every NaN becomes `f9 7e 00`.
fn encode_float(v: f64, out: &mut Vec<u8>) {
    if v.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    let h = half::f16::from_f64(v);
    if h.to_f64().to_bits() == v.to_bits() {
        out.push(0xf9);
        out.extend_from_slice(&h.to_bits().to_be_bytes());
        return;
    }
    let s = v as f32;
    if f64::from(s).to_bits() == v.to_bits() {
        out.push(0xfa);
        out.extend_from_slice(&s.to_bits().to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&v.to_bits().to_be_bytes());
}

fn decode_item(
    d: &mut Decoder<'_>,
    depth: usize,
    budget: &mut usize,
) -> Result<Value, DecodeError> {
    if depth > MAX_DEPTH {
        return Err(DecodeError::TooDeep);
    }
    *budget = budget
        .checked_sub(1)
        .ok_or(DecodeError::Shape("too many items"))?;
    Ok(match d.datatype()? {
        Type::Null => {
            d.null()?;
            Value::Null
        }
        Type::Bool => Value::Bool(d.bool()?),
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int => Value::Int(i128::from(d.int()?)),
        Type::F16 => Value::Float(f64::from(d.f16()?)),
        Type::F32 => Value::Float(f64::from(d.f32()?)),
        Type::F64 => Value::Float(d.f64()?),
        Type::Bytes => Value::Bytes(d.bytes()?.to_vec()),
        Type::String => Value::Text(d.str()?.into()),
        Type::Array => {
            let n = d.array()?.ok_or(DecodeError::UnsupportedType)?;
            // Every element takes at least one byte and one unit of budget:
            // bound before allocating, and allocate exactly once.
            let n = claimed_len(n, d, *budget)?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(decode_item(d, depth + 1, budget)?);
            }
            Value::Array(items)
        }
        Type::Map => {
            let n = d.map()?.ok_or(DecodeError::UnsupportedType)?;
            let n = claimed_len(n, d, *budget)?;
            let mut entries = Vec::with_capacity(n);
            // Encoded form of the previous key. Keys must be strictly
            // ascending in this order (RFC 8949 4.2.1), which also rules out
            // duplicates, and is checked here so that a hostile map fails at
            // its first misplaced key, not after it has been built.
            let mut last: Option<&[u8]> = None;
            for _ in 0..n {
                if d.datatype()? != Type::String {
                    return Err(DecodeError::UnsupportedType);
                }
                let start = d.position();
                let k: String = d.str()?.into();
                let enc = d.input().get(start..d.position()).ok_or(DecodeError::Cbor)?;
                match last.map(|l| l.cmp(enc)) {
                    Some(core::cmp::Ordering::Equal) => return Err(DecodeError::DuplicateKey),
                    Some(core::cmp::Ordering::Greater) => return Err(DecodeError::NonCanonical),
                    _ => {}
                }
                last = Some(enc);
                entries.push((k, decode_item(d, depth + 1, budget)?));
            }
            Value::Map(entries)
        }
        _ => return Err(DecodeError::UnsupportedType),
    })
}

/// A claimed element count, checked against what the rest of the input and
/// the item budget can possibly hold.
fn claimed_len(n: u64, d: &Decoder<'_>, budget: usize) -> Result<usize, DecodeError> {
    let left = d.input().len().saturating_sub(d.position());
    let n = usize::try_from(n).map_err(|_| DecodeError::Cbor)?;
    if n > left {
        return Err(DecodeError::Cbor);
    }
    if n > budget {
        return Err(DecodeError::Shape("too many items"));
    }
    Ok(n)
}

/// Cursor over the elements of a fixed-shape array, used by typed decoders.
pub(crate) struct Fields<'a> {
    items: core::slice::Iter<'a, Value>,
    what: &'static str,
}

impl<'a> Fields<'a> {
    /// `v` must be an array of exactly `len` elements.
    pub(crate) fn exact(v: &'a Value, len: usize, what: &'static str) -> Result<Self, DecodeError> {
        let f = Self::open(v, what)?;
        if f.items.len() != len {
            return Err(DecodeError::Shape(what));
        }
        Ok(f)
    }
    /// `v` must be an array; the caller checks the length via [`Fields::end`].
    pub(crate) fn open(v: &'a Value, what: &'static str) -> Result<Self, DecodeError> {
        match v {
            Value::Array(a) => Ok(Fields {
                items: a.iter(),
                what,
            }),
            _ => Err(DecodeError::Shape(what)),
        }
    }
    pub(crate) fn end(mut self) -> Result<(), DecodeError> {
        match self.items.next() {
            None => Ok(()),
            Some(_) => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn value(&mut self) -> Result<&'a Value, DecodeError> {
        self.items.next().ok_or(DecodeError::Shape(self.what))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        match self.value()? {
            Value::Int(n) => u64::try_from(*n).map_err(|_| DecodeError::Shape(self.what)),
            _ => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        u32::try_from(self.u64()?).map_err(|_| DecodeError::Shape(self.what))
    }
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        u16::try_from(self.u64()?).map_err(|_| DecodeError::Shape(self.what))
    }
    pub(crate) fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.value()? {
            Value::Bool(b) => Ok(*b),
            _ => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        match self.value()? {
            Value::Bytes(b) => Ok(b),
            _ => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn text(&mut self) -> Result<&'a str, DecodeError> {
        match self.value()? {
            Value::Text(s) => Ok(s),
            _ => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn array(&mut self) -> Result<&'a [Value], DecodeError> {
        match self.value()? {
            Value::Array(a) => Ok(a),
            _ => Err(DecodeError::Shape(self.what)),
        }
    }
    pub(crate) fn u16_list(&mut self) -> Result<Vec<u16>, DecodeError> {
        let what = self.what;
        self.array()?
            .iter()
            .map(|v| match v {
                Value::Int(n) => u16::try_from(*n).map_err(|_| DecodeError::Shape(what)),
                _ => Err(DecodeError::Shape(what)),
            })
            .collect()
    }
}

pub(crate) fn u16_list(xs: &[u16]) -> Value {
    Value::Array(xs.iter().map(|x| Value::uint(u64::from(*x))).collect())
}
