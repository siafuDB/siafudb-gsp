//! Per-author chain tracking and equivocation proofs.

use crate::cbor::{DecodeError, EncodeError, Fields, Value};
use crate::op::{Hlc, VerifiedOp, VerifyCtx, verify};
use crate::types::Multihash;
use alloc::{collections::BTreeMap, vec, vec::Vec};

/// Two validly signed ops by one author at the same `seq` in one fragment.
/// Anyone holding the author's key log can check it.
///
/// CBOR: `[a: bstr, b: bstr]` (two signed-op wire encodings, `a < b` bytewise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    /// One signed op (wire bytes).
    pub a: Vec<u8>,
    /// The conflicting signed op (wire bytes).
    pub b: Vec<u8>,
}

impl EquivocationProof {
    /// `true` iff both ops verify as valid in `ctx` and share author and `seq`
    /// while having different ids. (Leave `ctx.now_ms` unset.)
    pub fn verify(&self, ctx: &VerifyCtx<'_>) -> bool {
        let (Some(a), Some(b)) = (verify(&self.a, ctx).valid(), verify(&self.b, ctx).valid())
        else {
            return false;
        };
        a.body().author == b.body().author && a.body().seq == b.body().seq && a.id() != b.id()
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let (a, b) = if self.a <= self.b {
            (&self.a, &self.b)
        } else {
            (&self.b, &self.a)
        };
        Value::Array(vec![Value::Bytes(a.clone()), Value::Bytes(b.clone())]).encode()
    }

    /// Strict parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let v = Value::decode(bytes)?;
        let mut f = Fields::exact(&v, 2, "equivocation proof")?;
        let p = EquivocationProof {
            a: f.bytes()?.to_vec(),
            b: f.bytes()?.to_vec(),
        };
        if p.a >= p.b {
            return Err(DecodeError::NonCanonical);
        }
        Ok(p)
    }
}

/// What happened when an op was offered to an [`AuthorChain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    /// New op, consistent with everything seen so far. Recorded.
    Accepted,
    /// Already recorded (same id).
    Duplicate,
    /// A different op is already recorded at this `seq`. Not recorded.
    Equivocation(EquivocationProof),
    /// `prev` does not match the recorded neighbour. The author has forked
    /// its chain, but this pair alone is not a same-`seq` proof. Not recorded.
    PrevMismatch,
    /// HLC does not strictly increase along the chain. Not recorded.
    HlcNotMonotonic,
    /// The op belongs to another author or fragment. Not recorded.
    WrongChain,
}

struct Link {
    id: Multihash,
    prev: Option<Multihash>,
    hlc: Hlc,
    bytes: Vec<u8>,
}

/// The ops seen from one author in one fragment, indexed by `seq`.
/// Ops may arrive in any order; gaps are allowed.
pub struct AuthorChain {
    author: Multihash,
    fragment_id: Vec<u8>,
    links: BTreeMap<u64, Link>,
}

impl AuthorChain {
    /// Empty chain for `author` in `fragment_id`.
    pub fn new(author: Multihash, fragment_id: Vec<u8>) -> Self {
        AuthorChain {
            author,
            fragment_id,
            links: BTreeMap::new(),
        }
    }

    /// Offer a verified op.
    pub fn observe(&mut self, op: &VerifiedOp) -> ChainOutcome {
        let b = op.body();
        if b.author != self.author || b.fragment_id != self.fragment_id {
            return ChainOutcome::WrongChain;
        }
        if let Some(have) = self.links.get(&b.seq) {
            if have.id == *op.id() {
                return ChainOutcome::Duplicate;
            }
            return ChainOutcome::Equivocation(EquivocationProof {
                a: have.bytes.clone(),
                b: op.bytes().to_vec(),
            });
        }
        if let Some(before) = b.seq.checked_sub(1).and_then(|s| self.links.get(&s)) {
            if b.prev.as_ref() != Some(&before.id) {
                return ChainOutcome::PrevMismatch;
            }
            if b.hlc <= before.hlc {
                return ChainOutcome::HlcNotMonotonic;
            }
        }
        if let Some(after) = b.seq.checked_add(1).and_then(|s| self.links.get(&s)) {
            if after.prev.as_ref() != Some(op.id()) {
                return ChainOutcome::PrevMismatch;
            }
            if after.hlc <= b.hlc {
                return ChainOutcome::HlcNotMonotonic;
            }
        }
        self.links.insert(
            b.seq,
            Link {
                id: op.id().clone(),
                prev: b.prev.clone(),
                hlc: b.hlc,
                bytes: op.bytes().to_vec(),
            },
        );
        ChainOutcome::Accepted
    }

    /// Highest `seq` such that every op from 1 up to it has been recorded;
    /// `0` if op 1 is missing. Ops beyond it must wait for the gap to fill.
    pub fn contiguous_head(&self) -> u64 {
        let mut n = 0;
        for seq in self.links.keys() {
            if *seq != n + 1 {
                break;
            }
            n = *seq;
        }
        n
    }

    /// Id of the recorded op at `seq`.
    pub fn id_at(&self, seq: u64) -> Option<&Multihash> {
        self.links.get(&seq).map(|l| &l.id)
    }
}
