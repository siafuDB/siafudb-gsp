//! Hashes, keys, signatures and the signed envelope shared by ops, key-log
//! entries and batches.

use crate::cbor::{DecodeError, EncodeError, Fields, Value};
use crate::registry::{HashAlg, SigAlg};
use alloc::{boxed::Box, vec, vec::Vec};
use ml_dsa::MlDsa65;

/// Wire structure version implemented by this crate.
pub const FORMAT_V0: u16 = 0;

/// Maximum length of a fragment id, in bytes.
pub const MAX_FRAGMENT_ID: usize = 64;

/// A digest tagged with the algorithm that produced it.
///
/// CBOR: `[alg: uint, digest: bstr]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Multihash {
    /// [`HashAlg`] registry id (raw, may be unknown to this build).
    pub alg: u16,
    /// Digest bytes (32 for every algorithm currently registered).
    pub digest: Vec<u8>,
}

impl Multihash {
    /// Hash `data` with a known algorithm. `None` if this build has no
    /// implementation for `alg`.
    pub fn compute(alg: u16, data: &[u8]) -> Option<Multihash> {
        let digest = match HashAlg::from_id(alg)? {
            HashAlg::Blake3_256 => blake3::hash(data).as_bytes().to_vec(),
            HashAlg::Sha3_256 => {
                use sha3::Digest;
                sha3::Sha3_256::digest(data).to_vec()
            }
            HashAlg::Sha256 => return None,
        };
        Some(Multihash { alg, digest })
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::uint(u64::from(self.alg)),
            Value::Bytes(self.digest.clone()),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Multihash, DecodeError> {
        let mut f = Fields::exact(v, 2, "multihash")?;
        let alg = f.u16()?;
        let digest = f.bytes()?;
        let ok = match HashAlg::from_id(alg) {
            Some(_) => digest.len() == 32,
            None => alg != 0 && !digest.is_empty() && digest.len() <= 64,
        };
        if !ok {
            return Err(DecodeError::Shape("multihash"));
        }
        Ok(Multihash {
            alg,
            digest: digest.to_vec(),
        })
    }

    pub(crate) fn opt_to_value(m: &Option<Multihash>) -> Value {
        m.as_ref().map_or(Value::Null, Multihash::to_value)
    }

    pub(crate) fn opt_from_value(v: &Value) -> Result<Option<Multihash>, DecodeError> {
        match v {
            Value::Null => Ok(None),
            other => Multihash::from_value(other).map(Some),
        }
    }
}

/// A public key tagged with its signature algorithm.
///
/// CBOR: `[alg: uint, key: bstr]`. Ed25519: 32 bytes. ML-DSA-65: 1952 bytes
/// (FIPS 204 `pkEncode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// [`SigAlg`] registry id.
    pub alg: u16,
    /// Encoded public key.
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Key fingerprint: `hash_alg(CBOR(["gsp/v0/key", alg, key]))`.
    pub fn key_id(&self, hash_alg: u16) -> Option<Multihash> {
        let v = Value::Array(vec![
            Value::Text("gsp/v0/key".into()),
            Value::uint(u64::from(self.alg)),
            Value::Bytes(self.bytes.clone()),
        ]);
        Multihash::compute(hash_alg, &v.encode().ok()?)
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::uint(u64::from(self.alg)),
            Value::Bytes(self.bytes.clone()),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<PublicKey, DecodeError> {
        let mut f = Fields::exact(v, 2, "public key")?;
        let alg = f.u16()?;
        let bytes = f.bytes()?;
        if alg == 0 || bytes.is_empty() || bytes.len() > 8192 {
            return Err(DecodeError::Shape("public key"));
        }
        Ok(PublicKey {
            alg,
            bytes: bytes.to_vec(),
        })
    }
}

/// Outcome of checking one raw signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawCheck {
    Good,
    Bad,
    UnknownAlg,
}

pub(crate) fn verify_raw(key: &PublicKey, msg: &[u8], sig: &[u8]) -> RawCheck {
    let Some(alg) = SigAlg::from_id(key.alg) else {
        return RawCheck::UnknownAlg;
    };
    let good = match alg {
        SigAlg::Ed25519 => (|| {
            let pk: &[u8; 32] = key.bytes.as_slice().try_into().ok()?;
            let sg: &[u8; 64] = sig.try_into().ok()?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).ok()?;
            let sg = ed25519_dalek::Signature::from_bytes(sg);
            // verify_strict: rejects small-order keys and non-canonical R/S,
            // so one (key, message) pair has no malleable signatures.
            vk.verify_strict(msg, &sg).ok()
        })()
        .is_some(),
        SigAlg::MlDsa65 => (|| {
            let pk = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(key.bytes.as_slice()).ok()?;
            let sg = ml_dsa::EncodedSignature::<MlDsa65>::try_from(sig).ok()?;
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pk);
            let sg = ml_dsa::Signature::<MlDsa65>::decode(&sg)?;
            vk.verify_with_context(msg, &[], &sg).then_some(())
        })()
        .is_some(),
    };
    if good { RawCheck::Good } else { RawCheck::Bad }
}

/// A secret signing key. Built from a 32-byte seed supplied by the caller:
/// this crate never touches an RNG. Secret material is zeroized on drop by the
/// underlying crates.
pub enum SigningKey {
    /// Ed25519.
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// ML-DSA-65 (seed form, FIPS 204 `ML-DSA.KeyGen_internal(xi)`).
    MlDsa65(Box<ml_dsa::SigningKey<MlDsa65>>),
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({:?}, <secret>)", self.alg())
    }
}

impl SigningKey {
    /// Derive a key pair from a 32-byte secret seed.
    pub fn from_seed(alg: SigAlg, seed: &[u8; 32]) -> SigningKey {
        match alg {
            SigAlg::Ed25519 => {
                SigningKey::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed)))
            }
            SigAlg::MlDsa65 => {
                let seed = ml_dsa::Seed::from(*seed);
                SigningKey::MlDsa65(Box::new(ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed)))
            }
        }
    }

    /// Algorithm of this key.
    pub fn alg(&self) -> SigAlg {
        match self {
            SigningKey::Ed25519(_) => SigAlg::Ed25519,
            SigningKey::MlDsa65(_) => SigAlg::MlDsa65,
        }
    }

    /// The matching public key.
    pub fn public(&self) -> PublicKey {
        match self {
            SigningKey::Ed25519(k) => PublicKey {
                alg: SigAlg::Ed25519.id(),
                bytes: k.verifying_key().to_bytes().to_vec(),
            },
            SigningKey::MlDsa65(k) => {
                use ml_dsa::signature::Keypair;
                PublicKey {
                    alg: SigAlg::MlDsa65.id(),
                    bytes: k.verifying_key().encode().to_vec(),
                }
            }
        }
    }

    /// Raw signature over `msg`. Both algorithms sign deterministically.
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(msg).to_bytes().to_vec()
            }
            SigningKey::MlDsa65(k) => k
                .expanded_key()
                .sign_deterministic(msg, &[])
                // Only fails for a context longer than 255 bytes; ours is empty.
                .map(|s| s.encode().to_vec())
                .unwrap_or_default(),
        }
    }
}

/// One signature. Hybrid signing is two of these, one per algorithm.
///
/// CBOR: `[alg: uint, key_id: Multihash, sig: bstr]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// [`SigAlg`] registry id.
    pub alg: u16,
    /// Fingerprint of the signing public key ([`PublicKey::key_id`]).
    pub key_id: Multihash,
    /// Raw signature bytes.
    pub bytes: Vec<u8>,
}

impl Signature {
    pub(crate) fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::uint(u64::from(self.alg)),
            self.key_id.to_value(),
            Value::Bytes(self.bytes.clone()),
        ])
    }
    pub(crate) fn from_value(v: &Value) -> Result<Signature, DecodeError> {
        let mut f = Fields::exact(v, 3, "signature")?;
        let alg = f.u16()?;
        let key_id = Multihash::from_value(f.value()?)?;
        let bytes = f.bytes()?;
        if alg == 0 || bytes.is_empty() || bytes.len() > 16384 {
            return Err(DecodeError::Shape("signature"));
        }
        Ok(Signature {
            alg,
            key_id,
            bytes: bytes.to_vec(),
        })
    }
}

/// What kind of object a signature is over. Part of the signed bytes, so a
/// signature on one kind can never be replayed as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// A mutation op.
    Op,
    /// A key-log entry.
    KeyLog,
    /// A batch.
    Batch,
}

impl Domain {
    /// The domain-separation string.
    pub const fn tag(self) -> &'static str {
        match self {
            Domain::Op => "gsp/v0/op",
            Domain::KeyLog => "gsp/v0/keylog",
            Domain::Batch => "gsp/v0/batch",
        }
    }
}

/// The exact bytes a signature is computed over:
///
/// `CBOR([domain: tstr, audience: bstr, id: Multihash, alg: uint, key_id: Multihash])`
///
/// `audience` is the fragment id (empty for key-log entries, whose genesis
/// carries the fragment id inside the hashed body). CBOR's own length prefixes
/// make the framing unambiguous; nothing is concatenated raw.
pub fn sig_input(
    domain: Domain,
    audience: &[u8],
    id: &Multihash,
    alg: u16,
    key_id: &Multihash,
) -> Vec<u8> {
    Value::Array(vec![
        Value::Text(domain.tag().into()),
        Value::Bytes(audience.to_vec()),
        id.to_value(),
        Value::uint(u64::from(alg)),
        key_id.to_value(),
    ])
    .encode()
    // No maps, depth 2, small ints: cannot fail.
    .unwrap_or_default()
}

/// Body bytes plus signatures: the envelope for ops, key-log entries and
/// batches.
///
/// CBOR: `[body: bstr, sigs: [* Signature]]`. `body` is carried as an opaque
/// byte string so the receiver hashes exactly the bytes the author signed.
/// `sigs` are sorted by the bytewise order of their encodings and no two share
/// `(alg, key_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Canonical CBOR of the body, verbatim.
    pub body: Vec<u8>,
    /// Signatures over [`sig_input`].
    pub sigs: Vec<Signature>,
}

impl Signed {
    /// Sign `body` with every key in `keys`. `id` is the content id of `body`.
    pub(crate) fn sign(
        domain: Domain,
        audience: &[u8],
        id: &Multihash,
        body: Vec<u8>,
        keys: &[&SigningKey],
    ) -> Result<Signed, EncodeError> {
        let mut sigs = Vec::with_capacity(keys.len());
        for k in keys {
            let public = k.public();
            let key_id = public
                .key_id(id.alg)
                .ok_or(EncodeError::Limit("hash algorithm"))?;
            let bytes = k.sign_raw(&sig_input(domain, audience, id, public.alg, &key_id));
            sigs.push(Signature {
                alg: public.alg,
                key_id,
                bytes,
            });
        }
        Ok(Signed { body, sigs })
    }

    /// Canonical bytes. Sorts the signatures.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut enc: Vec<Vec<u8>> = Vec::new();
        for s in &self.sigs {
            enc.push(s.to_value().encode()?);
        }
        let mut order: Vec<usize> = (0..enc.len()).collect();
        order.sort_by(|a, b| enc[*a].cmp(&enc[*b]));
        let sigs: Vec<Value> = order.iter().map(|i| self.sigs[*i].to_value()).collect();
        Value::Array(vec![Value::Bytes(self.body.clone()), Value::Array(sigs)]).encode()
    }

    /// Strict parse. Does **not** verify anything.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signed, DecodeError> {
        // body, sigs, and at most 16 signatures of 6 items each.
        let v = Value::decode_limited(bytes, 128)?;
        let mut f = Fields::exact(&v, 2, "signed envelope")?;
        let body = f.bytes()?.to_vec();
        let raw = f.array()?;
        if raw.len() > 16 {
            return Err(DecodeError::Shape("too many signatures"));
        }
        let mut sigs = Vec::with_capacity(raw.len());
        let mut prev: Option<Vec<u8>> = None;
        for s in raw {
            let sig = Signature::from_value(s)?;
            let enc = s.encode().map_err(|_| DecodeError::NonCanonical)?;
            if prev.as_ref().is_some_and(|p| *p >= enc) {
                return Err(DecodeError::NonCanonical);
            }
            if sigs
                .iter()
                .any(|o: &Signature| o.alg == sig.alg && o.key_id == sig.key_id)
            {
                return Err(DecodeError::Shape("duplicate signature"));
            }
            prev = Some(enc);
            sigs.push(sig);
        }
        Ok(Signed { body, sigs })
    }
}

pub(crate) fn check_fragment_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= MAX_FRAGMENT_ID
}
