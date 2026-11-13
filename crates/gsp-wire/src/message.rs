//! v0 wire frames between a peer and a relay (or another peer). Types and
//! CBOR only: no transport, no state machine.
//!
//! Every frame is `[type: uint, ...fields]`. Cursors are relay-assigned,
//! per-fragment, strictly increasing positions in the relay's log of sealed
//! ops; they carry no meaning between relays.

use crate::cbor::{DecodeError, EncodeError, Fields, Value, u16_list};
use crate::sealed::SealedOp;
use crate::types::{Multihash, Signature};
use alloc::{string::String, vec, vec::Vec};

/// Most CBOR data items one frame may hold (arrays, strings and numbers all
/// count). A `Batch` of 256 sealed ops has about 1 600; this leaves room for
/// relays configured with much larger batches while keeping the memory a
/// hostile frame can make a decoder allocate to a few MiB.
pub const MAX_FRAME_ITEMS: usize = 65_536;

/// A v0 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Type 1: First frame in each direction: what the sender supports.
    /// `[1, versions, sig_algs, hash_algs, kem_algs, aead_algs, nonce]`.
    Hello {
        /// Wire format versions offered (this crate: `[0]`).
        versions: Vec<u16>,
        /// Supported `SigAlg` ids.
        sig_algs: Vec<u16>,
        /// Supported `HashAlg` ids.
        hash_algs: Vec<u16>,
        /// Supported `KemAlg` ids (reserved; no key exchange in v0).
        kem_algs: Vec<u16>,
        /// Supported `AeadAlg` ids.
        aead_algs: Vec<u16>,
        /// Fresh random challenge for the peer's `Auth`.
        nonce: Vec<u8>,
    },
    /// Type 2: Proof of key possession for a fragment.
    /// `[2, fragment_id, author, sender_seq, sigs]`.
    /// The signing input is not fixed by this crate yet (see WIRE-V0.md).
    Auth {
        /// Fragment being joined.
        fragment_id: Vec<u8>,
        /// Claimed author id.
        author: Multihash,
        /// Position at which the author's keys/policy are evaluated.
        sender_seq: u64,
        /// Signatures over the peer's `Hello.nonce`.
        sigs: Vec<Signature>,
    },
    /// Type 3: Upload sealed ops. `[3, fragment_id, [* SealedOp]]`.
    Push {
        /// Fragment.
        fragment_id: Vec<u8>,
        /// Sealed ops or batches.
        sealed: Vec<SealedOp>,
    },
    /// Type 4: Ask for sealed ops after a cursor. `[4, fragment_id, after, limit]`.
    Pull {
        /// Fragment.
        fragment_id: Vec<u8>,
        /// Exclusive lower bound; `0` means from the beginning.
        after: u64,
        /// Maximum number of items wanted.
        limit: u32,
    },
    /// Type 5: Reply to `Pull`. `[5, fragment_id, next, more, [* SealedOp]]`.
    Batch {
        /// Fragment.
        fragment_id: Vec<u8>,
        /// Cursor of the last item in this frame (use as the next `after`).
        next: u64,
        /// `true` if more items exist beyond `next`.
        more: bool,
        /// Sealed ops in cursor order.
        sealed: Vec<SealedOp>,
    },
    /// Type 6: Reply to `Push`. `[6, fragment_id, cursor, count]`.
    Ack {
        /// Fragment.
        fragment_id: Vec<u8>,
        /// Cursor of the last item stored.
        cursor: u64,
        /// Number of items accepted from the push.
        count: u32,
    },
    /// Type 7: The relay's latest cursor for a fragment. `[7, fragment_id, cursor]`.
    Head {
        /// Fragment.
        fragment_id: Vec<u8>,
        /// Latest cursor (`0` if empty).
        cursor: u64,
    },
    /// Type 8: Failure. `[8, code, message]`.
    Error {
        /// Numeric code (registry to be defined; see WIRE-V0.md).
        code: u16,
        /// Human-readable detail. Never parse it.
        message: String,
    },
}

fn sealed_list(v: &[SealedOp]) -> Value {
    Value::Array(v.iter().map(SealedOp::to_value).collect())
}
fn sealed_from(v: &[Value]) -> Result<Vec<SealedOp>, DecodeError> {
    v.iter().map(SealedOp::from_value).collect()
}

impl Message {
    /// Canonical bytes of the frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let b = |x: &Vec<u8>| Value::Bytes(x.clone());
        let items = match self {
            Message::Hello {
                versions,
                sig_algs,
                hash_algs,
                kem_algs,
                aead_algs,
                nonce,
            } => vec![
                Value::uint(1),
                u16_list(versions),
                u16_list(sig_algs),
                u16_list(hash_algs),
                u16_list(kem_algs),
                u16_list(aead_algs),
                b(nonce),
            ],
            Message::Auth {
                fragment_id,
                author,
                sender_seq,
                sigs,
            } => vec![
                Value::uint(2),
                b(fragment_id),
                author.to_value(),
                Value::uint(*sender_seq),
                Value::Array(sigs.iter().map(Signature::to_value).collect()),
            ],
            Message::Push {
                fragment_id,
                sealed,
            } => {
                vec![Value::uint(3), b(fragment_id), sealed_list(sealed)]
            }
            Message::Pull {
                fragment_id,
                after,
                limit,
            } => vec![
                Value::uint(4),
                b(fragment_id),
                Value::uint(*after),
                Value::uint(u64::from(*limit)),
            ],
            Message::Batch {
                fragment_id,
                next,
                more,
                sealed,
            } => vec![
                Value::uint(5),
                b(fragment_id),
                Value::uint(*next),
                Value::Bool(*more),
                sealed_list(sealed),
            ],
            Message::Ack {
                fragment_id,
                cursor,
                count,
            } => vec![
                Value::uint(6),
                b(fragment_id),
                Value::uint(*cursor),
                Value::uint(u64::from(*count)),
            ],
            Message::Head {
                fragment_id,
                cursor,
            } => {
                vec![Value::uint(7), b(fragment_id), Value::uint(*cursor)]
            }
            Message::Error { code, message } => {
                vec![
                    Value::uint(8),
                    Value::uint(u64::from(*code)),
                    Value::Text(message.clone()),
                ]
            }
        };
        Value::Array(items).encode()
    }

    /// Strict parse of one frame.
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, DecodeError> {
        // Frames arrive before anything is authenticated: bound the work.
        let v = Value::decode_limited(bytes, MAX_FRAME_ITEMS)?;
        let mut f = Fields::open(&v, "message")?;
        let m = match f.u64()? {
            1 => Message::Hello {
                versions: f.u16_list()?,
                sig_algs: f.u16_list()?,
                hash_algs: f.u16_list()?,
                kem_algs: f.u16_list()?,
                aead_algs: f.u16_list()?,
                nonce: f.bytes()?.to_vec(),
            },
            2 => Message::Auth {
                fragment_id: f.bytes()?.to_vec(),
                author: Multihash::from_value(f.value()?)?,
                sender_seq: f.u64()?,
                sigs: f
                    .array()?
                    .iter()
                    .map(Signature::from_value)
                    .collect::<Result<_, _>>()?,
            },
            3 => Message::Push {
                fragment_id: f.bytes()?.to_vec(),
                sealed: sealed_from(f.array()?)?,
            },
            4 => Message::Pull {
                fragment_id: f.bytes()?.to_vec(),
                after: f.u64()?,
                limit: f.u32()?,
            },
            5 => Message::Batch {
                fragment_id: f.bytes()?.to_vec(),
                next: f.u64()?,
                more: f.bool()?,
                sealed: sealed_from(f.array()?)?,
            },
            6 => Message::Ack {
                fragment_id: f.bytes()?.to_vec(),
                cursor: f.u64()?,
                count: f.u32()?,
            },
            7 => Message::Head {
                fragment_id: f.bytes()?.to_vec(),
                cursor: f.u64()?,
            },
            8 => Message::Error {
                code: f.u16()?,
                message: f.text()?.into(),
            },
            other => return Err(DecodeError::UnsupportedKind(other)),
        };
        f.end()?;
        Ok(m)
    }
}
