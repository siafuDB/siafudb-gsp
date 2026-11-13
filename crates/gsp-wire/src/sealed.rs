//! Sign-then-encrypt: what a relay stores and forwards.
//!
//! A relay sees only the header (`fragment_id`, nonce) and ciphertext length.
//! Author, `seq`, clocks, signatures and payload are all inside the AEAD.

use crate::cbor::{DecodeError, EncodeError, Fields, Value};
use crate::registry::AeadAlg;
use crate::types::{FORMAT_V0, check_fragment_id};
use alloc::{vec, vec::Vec};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;

/// A 32-byte symmetric fragment key. Zeroized on drop. How peers agree on it
/// (hybrid X25519 + ML-KEM-768) is out of scope for this crate.
pub struct FragmentKey(Zeroizing<[u8; 32]>);

impl FragmentKey {
    /// Wrap raw key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        FragmentKey(Zeroizing::new(bytes))
    }
}

/// What is inside a sealed op. CBOR: `[kind: uint, bytes: bstr]`,
/// kind 1 = signed op, kind 2 = signed batch, kind 3 = signed key-log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plain {
    /// A signed op (wire bytes) for [`verify`](crate::verify).
    Op(Vec<u8>),
    /// A signed batch (wire bytes) for [`verify_batch`](crate::verify_batch).
    Batch(Vec<u8>),
    /// A signed key-log entry (wire bytes) for
    /// [`KeyLog::genesis`](crate::KeyLog::genesis) /
    /// [`KeyLog::append`](crate::KeyLog::append).
    KeyLog(Vec<u8>),
}

/// Why sealing or opening failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The header names an AEAD this build does not implement.
    UnsupportedAead,
    /// The sealed op is for a different fragment than expected.
    WrongFragment,
    /// Authentication failed: wrong key, or header/ciphertext was modified.
    Decrypt,
    /// The plaintext is not a well-formed [`Plain`].
    Malformed(DecodeError),
    /// Could not encode.
    Encode(EncodeError),
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp seal error: {self:?}")
    }
}
impl core::error::Error for SealError {}

/// Relay-facing ciphertext.
///
/// CBOR: `[format, aead_alg, fragment_id: bstr, nonce: bstr(24), ciphertext: bstr]`.
/// Associated data: `CBOR(["gsp/v0/sealed", format, aead_alg, fragment_id])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedOp {
    /// [`AeadAlg`] registry id.
    pub aead_alg: u16,
    /// Fragment the ciphertext is addressed to (relay routing key).
    pub fragment_id: Vec<u8>,
    /// Nonce. Must never repeat under one key; use 24 random bytes.
    pub nonce: Vec<u8>,
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

fn aad(aead_alg: u16, fragment_id: &[u8]) -> Result<Vec<u8>, EncodeError> {
    Value::Array(vec![
        Value::Text("gsp/v0/sealed".into()),
        Value::uint(u64::from(FORMAT_V0)),
        Value::uint(u64::from(aead_alg)),
        Value::Bytes(fragment_id.to_vec()),
    ])
    .encode()
}

impl SealedOp {
    /// Encrypt `plain` for `fragment_id`. The caller supplies the nonce (this
    /// crate has no RNG): 24 fresh random bytes per call.
    pub fn seal(
        key: &FragmentKey,
        fragment_id: &[u8],
        nonce: [u8; NONCE_LEN],
        plain: &Plain,
    ) -> Result<SealedOp, SealError> {
        if !check_fragment_id(fragment_id) {
            return Err(SealError::Encode(EncodeError::Limit("fragment_id")));
        }
        let (kind, bytes) = match plain {
            Plain::Op(b) => (1, b),
            Plain::Batch(b) => (2, b),
            Plain::KeyLog(b) => (3, b),
        };
        let pt = Zeroizing::new(
            Value::Array(vec![Value::uint(kind), Value::Bytes(bytes.clone())])
                .encode()
                .map_err(SealError::Encode)?,
        );
        let alg = AeadAlg::XChaCha20Poly1305.id();
        let aad = aad(alg, fragment_id).map_err(SealError::Encode)?;
        let cipher = XChaCha20Poly1305::new((&*key.0).into());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Decrypt)?;
        Ok(SealedOp {
            aead_alg: alg,
            fragment_id: fragment_id.to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Decrypt. `expected_fragment` is the fragment the receiver asked for.
    /// The result is still unverified: pass it to `verify` / `verify_batch`.
    pub fn open(&self, key: &FragmentKey, expected_fragment: &[u8]) -> Result<Plain, SealError> {
        if AeadAlg::from_id(self.aead_alg) != Some(AeadAlg::XChaCha20Poly1305) {
            return Err(SealError::UnsupportedAead);
        }
        if self.fragment_id != expected_fragment {
            return Err(SealError::WrongFragment);
        }
        let nonce: [u8; NONCE_LEN] = self
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SealError::Decrypt)?;
        let aad = aad(self.aead_alg, &self.fragment_id).map_err(SealError::Encode)?;
        let cipher = XChaCha20Poly1305::new((&*key.0).into());
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| SealError::Decrypt)?,
        );
        let v = Value::decode(&pt).map_err(SealError::Malformed)?;
        let mut f = Fields::exact(&v, 2, "sealed plaintext").map_err(SealError::Malformed)?;
        let kind = f.u64().map_err(SealError::Malformed)?;
        let bytes = f.bytes().map_err(SealError::Malformed)?.to_vec();
        match kind {
            1 => Ok(Plain::Op(bytes)),
            2 => Ok(Plain::Batch(bytes)),
            3 => Ok(Plain::KeyLog(bytes)),
            k => Err(SealError::Malformed(DecodeError::UnsupportedKind(k))),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::uint(u64::from(FORMAT_V0)),
            Value::uint(u64::from(self.aead_alg)),
            Value::Bytes(self.fragment_id.clone()),
            Value::Bytes(self.nonce.clone()),
            Value::Bytes(self.ciphertext.clone()),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<SealedOp, DecodeError> {
        const W: &str = "sealed op";
        let mut f = Fields::open(v, W)?;
        let format = f.u64()?;
        if format != u64::from(FORMAT_V0) {
            return Err(DecodeError::UnsupportedFormat(format));
        }
        let s = SealedOp {
            aead_alg: f.u16()?,
            fragment_id: f.bytes()?.to_vec(),
            nonce: f.bytes()?.to_vec(),
            ciphertext: f.bytes()?.to_vec(),
        };
        f.end()?;
        if s.aead_alg == 0
            || !check_fragment_id(&s.fragment_id)
            || s.nonce.is_empty()
            || s.nonce.len() > 64
        {
            return Err(DecodeError::Shape(W));
        }
        Ok(s)
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        self.to_value().encode()
    }

    /// Strict parse (no decryption).
    pub fn from_bytes(bytes: &[u8]) -> Result<SealedOp, DecodeError> {
        SealedOp::from_value(&Value::decode(bytes)?)
    }
}
