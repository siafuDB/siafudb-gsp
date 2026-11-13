//! Ops: the signed unit of replication, plus stateless verification.

use crate::cbor::{DecodeError, EncodeError, Fields, Value};
use crate::keylog::KeyLogs;
use crate::types::{
    Domain, FORMAT_V0, Multihash, Signature, Signed, SigningKey, check_fragment_id,
};
use crate::verdict::{InvalidReason, Resolved, UnverifiableReason, Verdict, eval_sigs, retype};
use alloc::{vec, vec::Vec};

/// Maximum number of `deps` on one op.
pub const MAX_DEPS: usize = 64;

/// Default bound on how far a remote HLC may run ahead of local time.
pub const DEFAULT_MAX_DRIFT_MS: u64 = 5 * 60 * 1000;

/// Hybrid logical clock. CBOR: `[wall_ms: uint, counter: uint]`.
///
/// Ordering is `(wall_ms, counter)`; ties between authors are broken by the
/// caller with the op id. The HLC orders concurrent writes; causality is
/// carried by `prev` and `deps`, not by the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc {
    /// Milliseconds since the Unix epoch (physical part).
    pub wall_ms: u64,
    /// Logical counter within one millisecond.
    pub counter: u32,
}

impl Hlc {
    /// Next timestamp for a local event, given the local clock reading.
    pub fn tick(self, now_ms: u64) -> Hlc {
        if now_ms > self.wall_ms {
            Hlc {
                wall_ms: now_ms,
                counter: 0,
            }
        } else {
            self.bump()
        }
    }

    /// Merge a remote timestamp. `None` if the remote clock is more than
    /// `max_drift_ms` ahead of `now_ms`: the caller must not adopt it.
    pub fn observe(self, remote: Hlc, now_ms: u64, max_drift_ms: u64) -> Option<Hlc> {
        if remote.wall_ms > now_ms.saturating_add(max_drift_ms) {
            return None;
        }
        let top = self.max(remote);
        Some(if now_ms > top.wall_ms {
            Hlc {
                wall_ms: now_ms,
                counter: 0,
            }
        } else {
            top.bump()
        })
    }

    fn bump(self) -> Hlc {
        match self.counter.checked_add(1) {
            Some(counter) => Hlc {
                wall_ms: self.wall_ms,
                counter,
            },
            None => Hlc {
                wall_ms: self.wall_ms.saturating_add(1),
                counter: 0,
            },
        }
    }
}

/// The signed content of an op.
///
/// CBOR (array of 9):
/// `[format, hash_alg, fragment_id, author, seq, prev, hlc, deps, payload]`.
#[derive(Debug, Clone, PartialEq)]
pub struct OpBody {
    /// Hash algorithm of this op's id, of `prev` and of the signers' key ids.
    pub hash_alg: u16,
    /// The fragment (audience) this op belongs to. 1 to 64 bytes.
    pub fragment_id: Vec<u8>,
    /// Author id: content id of the author's key-log genesis entry.
    pub author: Multihash,
    /// Position in the author's chain within this fragment, starting at 1.
    pub seq: u64,
    /// Id of the author's op at `seq - 1`. `None` exactly when `seq == 1`.
    pub prev: Option<Multihash>,
    /// Hybrid logical clock.
    pub hlc: Hlc,
    /// Causal dependencies: the heads (any author) this op was written on top
    /// of. Encoded sorted and de-duplicated.
    pub deps: Vec<Multihash>,
    /// The mutation itself. Opaque to this crate.
    pub payload: Value,
}

impl OpBody {
    /// Canonical bytes. `deps` are sorted and de-duplicated here, so two
    /// logically equal bodies always encode identically.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if !check_fragment_id(&self.fragment_id) {
            return Err(EncodeError::Limit("fragment_id"));
        }
        if self.seq == 0 || (self.seq == 1) != self.prev.is_none() {
            return Err(EncodeError::Limit("seq/prev"));
        }
        let mut deps: Vec<(Vec<u8>, &Multihash)> = Vec::new();
        for d in &self.deps {
            deps.push((d.to_value().encode()?, d));
        }
        deps.sort_by(|a, b| a.0.cmp(&b.0));
        deps.dedup_by(|a, b| a.0 == b.0);
        if deps.len() > MAX_DEPS {
            return Err(EncodeError::Limit("deps"));
        }
        Value::Array(vec![
            Value::uint(u64::from(FORMAT_V0)),
            Value::uint(u64::from(self.hash_alg)),
            Value::Bytes(self.fragment_id.clone()),
            self.author.to_value(),
            Value::uint(self.seq),
            Multihash::opt_to_value(&self.prev),
            Value::Array(vec![
                Value::uint(self.hlc.wall_ms),
                Value::uint(u64::from(self.hlc.counter)),
            ]),
            Value::Array(deps.iter().map(|(_, d)| d.to_value()).collect()),
            self.payload.clone(),
        ])
        .encode()
    }

    /// Strict parse of body bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<OpBody, DecodeError> {
        const W: &str = "op body";
        let v = Value::decode(bytes)?;
        let mut f = Fields::open(&v, W)?;
        let format = f.u64()?;
        if format != u64::from(FORMAT_V0) {
            return Err(DecodeError::UnsupportedFormat(format));
        }
        let hash_alg = f.u16()?;
        let fragment_id = f.bytes()?.to_vec();
        let author = Multihash::from_value(f.value()?)?;
        let seq = f.u64()?;
        let prev = Multihash::opt_from_value(f.value()?)?;
        let mut h = Fields::exact(f.value()?, 2, W)?;
        let hlc = Hlc {
            wall_ms: h.u64()?,
            counter: h.u32()?,
        };
        let raw_deps = f.array()?;
        let payload = f.value()?.clone();
        f.end()?;
        if hash_alg == 0
            || !check_fragment_id(&fragment_id)
            || seq == 0
            || (seq == 1) != prev.is_none()
            || raw_deps.len() > MAX_DEPS
        {
            return Err(DecodeError::Shape(W));
        }
        let mut deps = Vec::with_capacity(raw_deps.len());
        let mut last: Option<Vec<u8>> = None;
        for d in raw_deps {
            let enc = d.encode().map_err(|_| DecodeError::NonCanonical)?;
            if last.as_ref().is_some_and(|l| *l >= enc) {
                return Err(DecodeError::NonCanonical);
            }
            last = Some(enc);
            deps.push(Multihash::from_value(d)?);
        }
        Ok(OpBody {
            hash_alg,
            fragment_id,
            author,
            seq,
            prev,
            hlc,
            deps,
            payload,
        })
    }
}

/// A signed op as parsed from the wire. **Not verified**: use [`verify`] and
/// only ever apply a [`VerifiedOp`].
#[derive(Debug, Clone, PartialEq)]
pub struct Op {
    id: Multihash,
    body: OpBody,
    signed: Signed,
}

impl Op {
    /// Encode `body`, compute its id and sign it with every key in `keys`
    /// (pass both an Ed25519 and an ML-DSA-65 key for a hybrid author).
    pub fn sign(body: &OpBody, keys: &[&SigningKey]) -> Result<Op, EncodeError> {
        let bytes = body.to_bytes()?;
        let id = Multihash::compute(body.hash_alg, &bytes)
            .ok_or(EncodeError::Limit("hash algorithm"))?;
        let signed = Signed::sign(Domain::Op, &body.fragment_id, &id, bytes, keys)?;
        // Keep the normalised body (sorted deps) so `body()` matches the bytes.
        let body = OpBody::from_bytes(&signed.body).map_err(|_| EncodeError::Limit("op body"))?;
        Ok(Op { id, body, signed })
    }

    /// Wire bytes: `[body: bstr, sigs]`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        self.signed.to_bytes()
    }

    /// Strict parse. The id is the hash of the received body bytes.
    /// Structure only: signatures and policy are **not** checked.
    pub fn from_bytes(bytes: &[u8]) -> Result<Op, DecodeError> {
        let signed = Signed::from_bytes(bytes)?;
        let body = OpBody::from_bytes(&signed.body)?;
        let id = Multihash::compute(body.hash_alg, &signed.body)
            .ok_or(DecodeError::UnsupportedKind(u64::from(body.hash_alg)))?;
        Ok(Op { id, body, signed })
    }

    /// Content id: `hash_alg(body bytes)`.
    pub fn id(&self) -> &Multihash {
        &self.id
    }
    /// The (unverified) body.
    pub fn body(&self) -> &OpBody {
        &self.body
    }
    /// The exact signed body bytes.
    pub fn body_bytes(&self) -> &[u8] {
        &self.signed.body
    }
    /// The signatures.
    pub fn sigs(&self) -> &[Signature] {
        &self.signed.sigs
    }
    /// Mutable access to the envelope, for tests and tooling that need to
    /// build deliberately malformed ops.
    pub fn signed_mut(&mut self) -> &mut Signed {
        &mut self.signed
    }
}

/// An op that passed [`verify`]. Cannot be constructed any other way.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedOp {
    op: Op,
    bytes: Vec<u8>,
}

impl VerifiedOp {
    /// Content id.
    pub fn id(&self) -> &Multihash {
        &self.op.id
    }
    /// The verified body.
    pub fn body(&self) -> &OpBody {
        &self.op.body
    }
    /// The signed op.
    pub fn op(&self) -> &Op {
        &self.op
    }
    /// The wire bytes that were verified.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Everything a verifier brings to the table.
pub struct VerifyCtx<'a> {
    /// The fragment the op was received in (the expected audience).
    pub fragment_id: &'a [u8],
    /// Authenticated key logs, by author.
    pub keylogs: &'a dyn KeyLogs,
    /// Local clock in Unix milliseconds. `None` skips the HLC drift check
    /// (use for historical replay and for checking third-party proofs).
    pub now_ms: Option<u64>,
    /// Allowed HLC lead over `now_ms`.
    pub max_drift_ms: u64,
}

impl<'a> VerifyCtx<'a> {
    /// Context with no clock check and the default drift bound.
    pub fn new(fragment_id: &'a [u8], keylogs: &'a dyn KeyLogs) -> Self {
        VerifyCtx {
            fragment_id,
            keylogs,
            now_ms: None,
            max_drift_ms: DEFAULT_MAX_DRIFT_MS,
        }
    }
    /// Enable the HLC drift check against this local time.
    pub fn at(mut self, now_ms: u64) -> Self {
        self.now_ms = Some(now_ms);
        self
    }
}

/// Verify one signed op (wire bytes) for the fragment in `ctx`.
///
/// Stateless: checks encoding, audience, the author's key log and policy at
/// the op's `seq`, every signature, and HLC drift. Chain position (`prev`,
/// equivocation) needs history: feed valid ops to
/// [`AuthorChain`](crate::chain::AuthorChain).
pub fn verify(signed_op: &[u8], ctx: &VerifyCtx<'_>) -> Verdict<VerifiedOp> {
    let malformed = |e| Verdict::Invalid {
        reason: InvalidReason::Malformed(e),
    };
    let signed = match Signed::from_bytes(signed_op) {
        Ok(s) => s,
        Err(e) => return malformed(e),
    };
    let body = match OpBody::from_bytes(&signed.body) {
        Ok(b) => b,
        Err(DecodeError::UnsupportedFormat(_)) => {
            return Verdict::Unverifiable {
                reason: UnverifiableReason::UnknownFormat,
            };
        }
        Err(e) => return malformed(e),
    };
    // Recomputed from the received bytes; never from a re-encoding.
    let Some(id) = Multihash::compute(body.hash_alg, &signed.body) else {
        return Verdict::Unverifiable {
            reason: UnverifiableReason::UnknownHashAlg,
        };
    };
    if body.fragment_id != ctx.fragment_id {
        return Verdict::Invalid {
            reason: InvalidReason::WrongFragment,
        };
    }
    let Some(log) = ctx.keylogs.get(&body.author) else {
        return Verdict::Unverifiable {
            reason: UnverifiableReason::UnknownAuthor,
        };
    };
    if log.fragment_id() != ctx.fragment_id {
        return Verdict::Invalid {
            reason: InvalidReason::WrongFragment,
        };
    }
    let seq = body.seq;
    let checked = eval_sigs(
        &signed.sigs,
        log.policy_at(seq),
        Domain::Op,
        &body.fragment_id,
        &id,
        |sig| match log.find_key(&sig.key_id) {
            Some(k) if k.valid_at(seq) => Resolved::Key(&k.key),
            Some(_) => Resolved::NotValid,
            None => Resolved::Unknown,
        },
    );
    if let Err(v) = checked {
        return retype(v);
    }
    if let Some(now) = ctx.now_ms
        && body.hlc.wall_ms > now.saturating_add(ctx.max_drift_ms)
    {
        return Verdict::Unverifiable {
            reason: UnverifiableReason::HlcTooFarAhead,
        };
    }
    Verdict::Valid(VerifiedOp {
        op: Op { id, body, signed },
        bytes: signed_op.to_vec(),
    })
}
