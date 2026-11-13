//! Batches: a set of signed ops authenticated as one unit by the sender.

use crate::cbor::{DecodeError, EncodeError, Fields, Value};
use crate::op::{VerifiedOp, VerifyCtx, verify};
use crate::types::{Domain, FORMAT_V0, Multihash, Signed, SigningKey, check_fragment_id};
use crate::verdict::{InvalidReason, Resolved, UnverifiableReason, Verdict, eval_sigs, retype};
use alloc::{vec, vec::Vec};

/// Maximum number of ops in one batch.
pub const MAX_BATCH_OPS: usize = 1024;

/// Signed content of a batch.
///
/// CBOR: `[format, hash_alg, fragment_id, sender, sender_seq, [* bstr]]`,
/// each `bstr` being a complete signed op. Order is significant and signed.
///
/// The batch signature authenticates *who sent this set, in this order, for
/// this fragment*. It does not replace the ops' own signatures: ops inside may
/// be by other authors and each is verified on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchBody {
    /// Hash algorithm of the batch id.
    pub hash_alg: u16,
    /// Fragment (audience).
    pub fragment_id: Vec<u8>,
    /// Sender's author id.
    pub sender: Multihash,
    /// `seq` of the sender's latest op when the batch was made (1 if none).
    /// The sender's keys and policy are evaluated at this position.
    pub sender_seq: u64,
    /// Signed ops, wire bytes.
    pub ops: Vec<Vec<u8>>,
}

impl BatchBody {
    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if !check_fragment_id(&self.fragment_id)
            || self.sender_seq == 0
            || self.ops.len() > MAX_BATCH_OPS
        {
            return Err(EncodeError::Limit("batch"));
        }
        Value::Array(vec![
            Value::uint(u64::from(FORMAT_V0)),
            Value::uint(u64::from(self.hash_alg)),
            Value::Bytes(self.fragment_id.clone()),
            self.sender.to_value(),
            Value::uint(self.sender_seq),
            Value::Array(self.ops.iter().map(|o| Value::Bytes(o.clone())).collect()),
        ])
        .encode()
    }

    /// Strict parse of body bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BatchBody, DecodeError> {
        const W: &str = "batch body";
        let v = Value::decode(bytes)?;
        let mut f = Fields::open(&v, W)?;
        let format = f.u64()?;
        if format != u64::from(FORMAT_V0) {
            return Err(DecodeError::UnsupportedFormat(format));
        }
        let hash_alg = f.u16()?;
        let fragment_id = f.bytes()?.to_vec();
        let sender = Multihash::from_value(f.value()?)?;
        let sender_seq = f.u64()?;
        let ops = f
            .array()?
            .iter()
            .map(|o| match o {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(DecodeError::Shape(W)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        f.end()?;
        if hash_alg == 0
            || !check_fragment_id(&fragment_id)
            || sender_seq == 0
            || ops.len() > MAX_BATCH_OPS
        {
            return Err(DecodeError::Shape(W));
        }
        Ok(BatchBody {
            hash_alg,
            fragment_id,
            sender,
            sender_seq,
            ops,
        })
    }
}

/// Namespace for batch signing.
pub struct Batch;

impl Batch {
    /// Encode and sign a batch; returns wire bytes `[body: bstr, sigs]`.
    pub fn sign(body: &BatchBody, keys: &[&SigningKey]) -> Result<Vec<u8>, EncodeError> {
        let bytes = body.to_bytes()?;
        let id = Multihash::compute(body.hash_alg, &bytes)
            .ok_or(EncodeError::Limit("hash algorithm"))?;
        Signed::sign(Domain::Batch, &body.fragment_id, &id, bytes, keys)?.to_bytes()
    }
}

/// A batch whose own signature set is valid. Each op carries its own verdict:
/// a valid batch can still contain ops that must not be applied.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedBatch {
    /// Content id of the batch body.
    pub id: Multihash,
    /// Sender's author id.
    pub sender: Multihash,
    /// Per-op verdicts, in batch order.
    pub ops: Vec<Verdict<VerifiedOp>>,
}

/// Verify a signed batch, then each op in it, for the fragment in `ctx`.
/// Ops are not examined unless the batch itself is valid.
pub fn verify_batch(signed_batch: &[u8], ctx: &VerifyCtx<'_>) -> Verdict<VerifiedBatch> {
    let malformed = |e| Verdict::Invalid {
        reason: InvalidReason::Malformed(e),
    };
    let signed = match Signed::from_bytes(signed_batch) {
        Ok(s) => s,
        Err(e) => return malformed(e),
    };
    let body = match BatchBody::from_bytes(&signed.body) {
        Ok(b) => b,
        Err(DecodeError::UnsupportedFormat(_)) => {
            return Verdict::Unverifiable {
                reason: UnverifiableReason::UnknownFormat,
            };
        }
        Err(e) => return malformed(e),
    };
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
    let Some(log) = ctx.keylogs.get(&body.sender) else {
        return Verdict::Unverifiable {
            reason: UnverifiableReason::UnknownAuthor,
        };
    };
    if log.fragment_id() != ctx.fragment_id {
        return Verdict::Invalid {
            reason: InvalidReason::WrongFragment,
        };
    }
    let seq = body.sender_seq;
    let checked = eval_sigs(
        &signed.sigs,
        log.policy_at(seq),
        Domain::Batch,
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
    let ops = body.ops.iter().map(|o| verify(o, ctx)).collect();
    Verdict::Valid(VerifiedBatch {
        id,
        sender: body.sender,
        ops,
    })
}
