//! A small strict reader over [`gsp_wire::Value`] arrays, used by the payload
//! and state decoders. Every accessor returns `None` on a shape mismatch, so
//! decoders never index or unwrap data that came from outside.

use gsp_wire::Value;

/// Cursor over the elements of an array.
pub(crate) struct Fields<'a>(core::slice::Iter<'a, Value>);

impl<'a> Fields<'a> {
    pub(crate) fn open(v: &'a Value) -> Option<Self> {
        match v {
            Value::Array(a) => Some(Fields(a.iter())),
            _ => None,
        }
    }
    pub(crate) fn exact(v: &'a Value, len: usize) -> Option<Self> {
        let f = Self::open(v)?;
        (f.0.len() == len).then_some(f)
    }
    pub(crate) fn remaining(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn end(mut self) -> Option<()> {
        self.0.next().is_none().then_some(())
    }
    pub(crate) fn value(&mut self) -> Option<&'a Value> {
        self.0.next()
    }
    pub(crate) fn u64(&mut self) -> Option<u64> {
        as_u64(self.value()?)
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        u32::try_from(self.u64()?).ok()
    }
    pub(crate) fn u16(&mut self) -> Option<u16> {
        u16::try_from(self.u64()?).ok()
    }
    pub(crate) fn bool(&mut self) -> Option<bool> {
        match self.value()? {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub(crate) fn bytes(&mut self) -> Option<&'a [u8]> {
        match self.value()? {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub(crate) fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes()?.try_into().ok()
    }
    /// `v` itself as a byte string of exactly `N` bytes.
    pub(crate) fn fixed_of<const N: usize>(v: &Value) -> Option<[u8; N]> {
        match v {
            Value::Bytes(b) => b.as_slice().try_into().ok(),
            _ => None,
        }
    }
    pub(crate) fn text(&mut self) -> Option<&'a str> {
        match self.value()? {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
    pub(crate) fn array(&mut self) -> Option<&'a [Value]> {
        match self.value()? {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub(crate) fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Int(n) => u64::try_from(*n).ok(),
        _ => None,
    }
}

pub(crate) fn uint(n: u64) -> Value {
    Value::uint(n)
}

pub(crate) fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Structural equality that treats floats by bit pattern after NaN
/// normalisation, so `NaN == NaN` and `0.0 != -0.0`: exactly the equality of
/// the deterministic encodings. Maps are compared as sets of entries.
pub(crate) fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => {
            (x.is_nan() && y.is_nan()) || x.to_bits() == y.to_bits()
        }
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Text(x), Value::Text(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| value_eq(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, p)| {
                    y.iter()
                        .find(|(k2, _)| k2 == k)
                        .is_some_and(|(_, q)| value_eq(p, q))
                })
        }
        _ => false,
    }
}
