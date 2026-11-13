//! The replica state machine: ingest, local commits, outbox, cursor, state.

use crate::change::{Change, Gid, PayloadError, decode_payload, encode_payload};
use crate::cv::{Fields, bytes, uint};
use crate::merge::{EdgeView, Merge, NodeView, OpKey, Stamp};
use crate::pairing::{FRAGMENT_ID_LEN, Pairing};
use gsp_wire::op::MAX_DEPS;
use gsp_wire::{
    DecodeError, EncodeError, EquivocationProof, FragmentKey, HashAlg, Hlc, InvalidReason, KeyLog,
    KeyLogAction, KeyLogEntry, KeyLogError, Multihash, Op, OpBody, Plain, SealError, SealedOp,
    SigAlg, SigningKey, Value, Verdict, VerifyCtx, verify,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::{Zeroize, Zeroizing};

/// Largest sealed item a replica accepts or produces (the relay's default
/// per-item limit).
pub const MAX_SEALED_BYTES: usize = 256 * 1024;

/// Most equivocation records a replica keeps. Later ones are still rejected
/// and counted.
pub const MAX_EQUIVOCATIONS: usize = 64;

const STATE_TAG: &str = "gsp-sync-state";
const STATE_VERSION: u64 = 0;

/// Tunable limits. Not part of the serialised state: pass the same values to
/// [`Replica::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How far an op's HLC may lead the local clock before the op is held
    /// back. Default 300 000 ms (WIRE-V0 section 4).
    pub max_drift_ms: u64,
    /// Most ops held as pending.
    pub max_pending_items: usize,
    /// Most bytes of signed ops held as pending.
    pub max_pending_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_drift_ms: gsp_wire::op::DEFAULT_MAX_DRIFT_MS,
            max_pending_items: 4096,
            max_pending_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Why a call on a replica failed. Nothing changed in the replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The changes of a local commit break a payload rule.
    Payload(PayloadError),
    /// Encoding failed.
    Encode(EncodeError),
    /// Sealing failed.
    Seal(SealError),
    /// The sealed op would exceed [`MAX_SEALED_BYTES`].
    TooLarge,
    /// State bytes are not a canonical replica state (what was wrong).
    State(&'static str),
    /// State bytes are from a state version this build does not know.
    StateVersion(u64),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp replica error: {self:?}")
    }
}
impl core::error::Error for Error {}

impl From<PayloadError> for Error {
    fn from(e: PayloadError) -> Self {
        Error::Payload(e)
    }
}
impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Error::Encode(e)
    }
}
impl From<SealError> for Error {
    fn from(e: SealError) -> Self {
        Error::Seal(e)
    }
}

/// Why a sealed item was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// Larger than [`MAX_SEALED_BYTES`].
    TooLarge,
    /// Not a well-formed sealed op, or its plaintext is not a `Plain`.
    Malformed(DecodeError),
    /// Addressed to (or signed for) another fragment.
    WrongFragment,
    /// Authentication failed: wrong key or modified bytes.
    Decrypt,
    /// Well-formed, but uses something this build or v0 cannot evaluate: an
    /// unknown format, hash, AEAD or signature algorithm, a batch (kind 2),
    /// a key-log entry other than a genesis, or a signature by a key the
    /// author's log does not hold.
    Unsupported,
    /// The signed op failed verification.
    Op(InvalidReason),
    /// The op's payload breaks a rule of SYNC-V0 section 4.
    Payload(PayloadError),
    /// `prev` does not name the author's op at `seq - 1`.
    ChainFork,
    /// The HLC does not increase along the author's chain.
    HlcNotMonotonic,
    /// A different op by the same author at the same `seq` was applied first.
    /// See [`Replica::equivocations`].
    Equivocation,
    /// The key-log entry was not accepted.
    KeyLog(KeyLogError),
}

/// Why an op is held back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    /// The author's key log (genesis) has not arrived.
    UnknownAuthor,
    /// The author's op at `seq - 1` has not been applied.
    MissingPrev,
    /// An op named in `deps` has not been applied.
    MissingDep,
    /// The op's HLC is more than `max_drift_ms` ahead of the local clock. It
    /// is applied by a later call once local time has caught up.
    ClockAhead,
}

/// What happened to the item handed to [`Replica::ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestStatus {
    /// An op, now applied.
    Applied,
    /// A genesis key-log entry of a new author, now known.
    KeyLog,
    /// Already applied, already pending, or an already known key log. This
    /// is also what a replica's own items look like when the relay echoes
    /// them.
    Duplicate,
    /// A valid-looking op that cannot be applied yet. It is kept and applied
    /// automatically when what it waits for arrives.
    Pending(PendingReason),
    /// Dropped.
    Rejected(Reject),
    /// The op would have to wait, but pending storage is full. It was **not**
    /// kept and the pull cursor was **not** advanced past it: stop, and pull
    /// again from [`Replica::cursor`] later.
    PendingFull,
}

/// Result of [`Replica::ingest`].
#[derive(Debug, Clone, PartialEq)]
pub struct IngestOutcome {
    /// What happened to the item itself.
    pub status: IngestStatus,
    /// Ops applied by this call: the item, ops that were waiting for it, and
    /// ops whose clock hold ran out.
    pub applied: usize,
    /// The change in visible state, for the engine adapter to apply in order.
    pub effects: Vec<Change>,
}

/// Evidence that an author signed two different ops at one `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// The author.
    pub author: Multihash,
    /// The position both ops claim.
    pub seq: u64,
    /// Id of the op that was applied first and stays.
    pub kept: Multihash,
    /// The rejected signed op (wire bytes). It verifies against the author's
    /// key log.
    pub rejected: Vec<u8>,
    /// A self-contained proof, when the kept op's bytes were still at hand:
    /// that is, when the conflict is at the author's latest applied op. A
    /// replica does not retain older op bytes; for those, `kept` names the
    /// other half.
    pub proof: Option<EquivocationProof>,
}

/// Counters and sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Remote ops applied.
    pub applied: u64,
    /// Local commits made.
    pub local: u64,
    /// Ops currently pending.
    pub pending: usize,
    /// Bytes of signed ops currently pending.
    pub pending_bytes: usize,
    /// Items dropped as invalid: bad signature, bad payload, forked chain,
    /// bad key log, addressed to or signed for another fragment.
    pub invalid: u64,
    /// Items that never got as far as a plaintext: oversized, malformed, or
    /// failing authentication (wrong key, modified bytes).
    pub undecryptable: u64,
    /// Items dropped as [`Reject::Unsupported`].
    pub unsupported: u64,
    /// Equivocating ops rejected.
    pub equivocations: u64,
    /// Items seen again.
    pub duplicates: u64,
    /// Items refused because pending storage was full.
    pub refused: u64,
    /// Authors whose key log is known, this device included.
    pub authors: usize,
    /// Sealed items waiting in the outbox.
    pub outbox: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Counters {
    applied: u64,
    local: u64,
    invalid: u64,
    undecryptable: u64,
    unsupported: u64,
    equivocations: u64,
    duplicates: u64,
    refused: u64,
}

struct Author {
    log: KeyLog,
    /// Applied op ids; index `i` is `seq = i + 1`.
    ops: Vec<OpKey>,
    /// HLC and signed bytes of the op at `ops.last()`.
    head_hlc: Hlc,
    head_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Blocker {
    Author(OpKey),
    Op(OpKey),
}

struct Pending {
    /// Signed op (wire bytes).
    bytes: Vec<u8>,
    /// BLAKE3 of `bytes`: pending items are distinguished by their exact
    /// bytes, not by op id, because signatures are outside the id and a copy
    /// with a junk signature must not shadow the good one.
    hash: [u8; 32],
    /// Signatures already checked against the author's key log.
    verified: bool,
}

struct Ready {
    id: OpKey,
    author: OpKey,
    hlc: Hlc,
    changes: Vec<Change>,
}

enum Eval {
    Apply(Ready),
    Wait(Blocker, PendingReason),
    Later(u64),
    Duplicate,
    Equivocation { author: OpKey, seq: u64 },
    Drop(Reject),
}

enum Step {
    Applied,
    Waiting(PendingReason),
    Duplicate,
    Dropped(Reject),
}

/// One device's replica of one fragment. No I/O, no clock, no RNG: the
/// caller passes the time and the random bytes.
///
/// See the [crate documentation](crate) for how an engine adapter and a
/// transport drive it.
pub struct Replica {
    config: Config,
    pairing: Pairing,
    seed: Zeroizing<[u8; 32]>,
    fragment_id: [u8; FRAGMENT_ID_LEN],
    key: FragmentKey,
    signer: SigningKey,
    me: OpKey,
    clock: Hlc,
    cursor: u64,
    /// Lowest relay position refused for lack of pending space; the cursor
    /// stays below it. Not persisted.
    hold: Option<u64>,
    authors: BTreeMap<OpKey, Author>,
    applied: BTreeSet<OpKey>,
    merge: Merge,
    pending: BTreeMap<u64, Pending>,
    pending_hashes: BTreeSet<[u8; 32]>,
    pending_bytes: usize,
    next_order: u64,
    waiting: BTreeMap<Blocker, Vec<u64>>,
    /// `(wall_ms, order)` of ops held for clock drift.
    timed: BTreeSet<(u64, u64)>,
    /// Pending items not yet indexed (after a restore): evaluated by the next
    /// call that carries a clock.
    recheck: BTreeSet<u64>,
    outbox: VecDeque<Vec<u8>>,
    counters: Counters,
    equivocations: Vec<Equivocation>,
}

impl core::fmt::Debug for Replica {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Replica")
            .field("fragment_id", &self.fragment_id)
            .field("author", &self.me)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

fn hlc_value(h: Hlc) -> Value {
    Value::Array(vec![uint(h.wall_ms), uint(u64::from(h.counter))])
}

fn hlc_from(v: &Value) -> Option<Hlc> {
    let mut f = Fields::exact(v, 2)?;
    Some(Hlc {
        wall_ms: f.u64()?,
        counter: f.u32()?,
    })
}

impl Replica {
    /// A replica with this device's identity and nothing else.
    fn base(root: [u8; 32], device_seed: [u8; 32], config: Config) -> Result<Replica, Error> {
        let pairing = Pairing::from_root(root);
        let seed = Zeroizing::new(device_seed);
        let fragment_id = pairing.fragment_id();
        let signer = SigningKey::from_seed(SigAlg::Ed25519, &seed);
        let genesis = KeyLogEntry {
            hash_alg: HashAlg::Blake3_256.id(),
            prev: None,
            action: KeyLogAction::Genesis {
                fragment_id: fragment_id.to_vec(),
                keys: vec![signer.public()],
                policy: vec![SigAlg::Ed25519.id()],
            },
        }
        .sign(&[&signer])?;
        let log = KeyLog::genesis(&genesis).map_err(|_| Error::State("genesis"))?;
        let me = OpKey::from_multihash(log.author()).ok_or(Error::State("genesis"))?;
        let mut authors = BTreeMap::new();
        authors.insert(
            me,
            Author {
                log,
                ops: Vec::new(),
                head_hlc: Hlc::default(),
                head_bytes: Vec::new(),
            },
        );
        Ok(Replica {
            config,
            key: pairing.fragment_key(),
            pairing,
            seed,
            fragment_id,
            signer,
            me,
            clock: Hlc::default(),
            cursor: 0,
            hold: None,
            authors,
            applied: BTreeSet::new(),
            merge: Merge::default(),
            pending: BTreeMap::new(),
            pending_hashes: BTreeSet::new(),
            pending_bytes: 0,
            next_order: 0,
            waiting: BTreeMap::new(),
            timed: BTreeSet::new(),
            recheck: BTreeSet::new(),
            outbox: VecDeque::new(),
            counters: Counters::default(),
            equivocations: Vec::new(),
        })
    }

    /// Create this device's replica of the fragment with root secret `root`.
    ///
    /// The same call serves the device that creates a fragment (with a fresh
    /// random `root`) and a device that joins one (with the `root` it was
    /// shown, see [`Pairing::parse`]). `device_seed` is 32 random bytes that
    /// belong to this device alone; the Ed25519 author key is derived from
    /// it. `genesis_nonce` is 24 fresh random bytes.
    ///
    /// The device's genesis key-log entry (policy `[Ed25519]`) is sealed and
    /// queued as the first outbox item.
    pub fn create(
        root: [u8; 32],
        device_seed: [u8; 32],
        genesis_nonce: [u8; 24],
        config: Config,
    ) -> Result<Replica, Error> {
        let mut r = Replica::base(root, device_seed, config)?;
        let genesis = r
            .authors
            .get(&r.me)
            .and_then(|a| a.log.entries().first())
            .ok_or(Error::State("genesis"))?
            .clone();
        let sealed = SealedOp::seal(
            &r.key,
            &r.fragment_id,
            genesis_nonce,
            &Plain::KeyLog(genesis),
        )?
        .to_bytes()?;
        r.outbox.push_back(sealed);
        Ok(r)
    }

    // ------------------------------------------------------------ identity

    /// Public routing id of the fragment.
    pub fn fragment_id(&self) -> &[u8; FRAGMENT_ID_LEN] {
        &self.fragment_id
    }

    /// Bearer token for the relay.
    pub fn relay_token(&self) -> Zeroizing<[u8; 32]> {
        self.pairing.relay_token()
    }

    /// The pairing secret, to show to another device.
    pub fn pairing(&self) -> &Pairing {
        &self.pairing
    }

    /// This device's author id (content id of its genesis key-log entry).
    pub fn author(&self) -> Multihash {
        self.me.to_multihash()
    }

    // ------------------------------------------------------------ local writes

    /// Record a local commit: validate `changes`, stamp them with the next
    /// HLC, merge them, sign one op and queue it sealed in the outbox.
    /// `nonce` is 24 fresh random bytes.
    ///
    /// The adapter calls this for every engine commit, **before** applying
    /// any effects of a later [`ingest`](Replica::ingest).
    ///
    /// # What is returned
    ///
    /// The engine has already applied `changes` itself. The return value is
    /// what the engine must apply *in addition* so that it equals the
    /// replica's visible state. It is empty unless the commit ran into a merge
    /// rule the engine does not know:
    ///
    /// - a put for a gid that is tombstoned: the entity is deleted again
    ///   (`NodeDel` / `EdgeDel`);
    /// - an `EdgePut` whose endpoints are not both visible: `EdgeDel`;
    /// - an `EdgePut` for an existing edge with other endpoints or another
    ///   type than the edge has: `EdgeDel` followed by an `EdgePut` restoring
    ///   the real one;
    /// - a `NodeDel` of a node that still has visible edges: `EdgeDel` for
    ///   each of them (already gone in an engine that cascades; deletes are
    ///   idempotent).
    /// - a `NodePut` that creates the last missing endpoint of an edge the
    ///   replica holds but could not show yet: an `EdgePut` for that edge.
    ///
    /// "Already applied" means the plain reading of each change: a put
    /// creates the entity if needed and writes what it carries, a delete
    /// removes the entity and nothing else.
    ///
    /// On error nothing has changed and nothing was queued.
    pub fn local_commit(
        &mut self,
        changes: &[Change],
        now_ms: u64,
        nonce: [u8; 24],
    ) -> Result<Vec<Change>, Error> {
        let payload = encode_payload(changes)?;
        let hlc = self.clock.tick(now_ms);
        let me = self.authors.get(&self.me).ok_or(Error::State("author"))?;
        // Heads of the other authors; if there are too many, the most recent.
        let mut heads: Vec<(Hlc, OpKey)> = self
            .authors
            .iter()
            .filter(|(k, _)| **k != self.me)
            .filter_map(|(_, a)| a.ops.last().map(|id| (a.head_hlc, *id)))
            .collect();
        heads.sort_unstable_by(|a, b| b.cmp(a));
        heads.truncate(MAX_DEPS);
        let body = OpBody {
            hash_alg: HashAlg::Blake3_256.id(),
            fragment_id: self.fragment_id.to_vec(),
            author: self.me.to_multihash(),
            seq: me.ops.len() as u64 + 1,
            prev: me.ops.last().map(|k| k.to_multihash()),
            hlc,
            deps: heads.iter().map(|(_, id)| id.to_multihash()).collect(),
            payload,
        };
        let op = Op::sign(&body, &[&self.signer])?;
        let signed = op.to_bytes()?;
        let sealed = SealedOp::seal(
            &self.key,
            &self.fragment_id,
            nonce,
            &Plain::Op(signed.clone()),
        )?
        .to_bytes()?;
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(Error::TooLarge);
        }
        let id = OpKey::from_multihash(op.id()).ok_or(Error::State("op id"))?;
        // The changes exactly as every other replica will decode them.
        let canonical = decode_payload(&op.body().payload)?;

        // Nothing below can fail.
        let effects = self.merge.apply(&canonical, Stamp { hlc, id }, true);
        self.clock = hlc;
        if let Some(me) = self.authors.get_mut(&self.me) {
            me.ops.push(id);
            me.head_hlc = hlc;
            me.head_bytes = signed;
        }
        self.applied.insert(id);
        self.outbox.push_back(sealed);
        self.counters.local += 1;
        Ok(effects)
    }

    // ------------------------------------------------------------ ingest

    /// Take one sealed item received from a relay or a peer.
    ///
    /// `relay_seq` is the position the relay gave the item (`0` if it did not
    /// come from the relay this replica's cursor belongs to); the pull cursor
    /// moves up to it unless the status is [`IngestStatus::PendingFull`].
    /// `now_ms` is the local clock in Unix milliseconds.
    ///
    /// Never fails and never panics, whatever the bytes are: the outcome says
    /// what happened and carries the effects for the engine.
    pub fn ingest(&mut self, sealed: &[u8], relay_seq: u64, now_ms: u64) -> IngestOutcome {
        let mut effects = Vec::new();
        let mut applied = self.drain_due(now_ms, &mut effects);
        let status = self.ingest_item(sealed, now_ms, &mut effects, &mut applied);
        if status == IngestStatus::PendingFull {
            self.counters.refused += 1;
        }
        if relay_seq != 0 {
            if status == IngestStatus::PendingFull {
                self.hold = Some(self.hold.map_or(relay_seq, |h| h.min(relay_seq)));
            } else {
                if self.hold == Some(relay_seq) {
                    self.hold = None;
                }
                let limit = self.hold.map_or(u64::MAX, |h| h.saturating_sub(1));
                self.cursor = self.cursor.max(relay_seq.min(limit));
            }
        }
        IngestOutcome {
            status,
            applied,
            effects,
        }
    }

    /// Re-evaluate held ops against a newer clock without ingesting anything:
    /// ops held as [`PendingReason::ClockAhead`] are applied once `now_ms` has
    /// caught up. Returns the effects. ([`ingest`](Replica::ingest) does the
    /// same on every call.)
    pub fn poll(&mut self, now_ms: u64) -> Vec<Change> {
        let mut effects = Vec::new();
        self.drain_due(now_ms, &mut effects);
        effects
    }

    /// Count a dropped item and name the status.
    fn reject(&mut self, r: Reject) -> IngestStatus {
        match r {
            Reject::TooLarge | Reject::Malformed(_) | Reject::Decrypt => {
                self.counters.undecryptable += 1
            }
            Reject::Unsupported => self.counters.unsupported += 1,
            Reject::Equivocation => self.counters.equivocations += 1,
            Reject::WrongFragment
            | Reject::Op(_)
            | Reject::Payload(_)
            | Reject::ChainFork
            | Reject::HlcNotMonotonic
            | Reject::KeyLog(_) => self.counters.invalid += 1,
        }
        IngestStatus::Rejected(r)
    }

    fn duplicate(&mut self) -> IngestStatus {
        self.counters.duplicates += 1;
        IngestStatus::Duplicate
    }

    fn ingest_item(
        &mut self,
        sealed: &[u8],
        now_ms: u64,
        effects: &mut Vec<Change>,
        applied: &mut usize,
    ) -> IngestStatus {
        if sealed.len() > MAX_SEALED_BYTES {
            return self.reject(Reject::TooLarge);
        }
        let item = match SealedOp::from_bytes(sealed) {
            Ok(s) => s,
            Err(DecodeError::UnsupportedFormat(_)) => {
                return self.reject(Reject::Unsupported);
            }
            Err(e) => return self.reject(Reject::Malformed(e)),
        };
        let plain = match item.open(&self.key, &self.fragment_id) {
            Ok(p) => p,
            Err(e) => {
                return self.reject(match e {
                    SealError::WrongFragment => Reject::WrongFragment,
                    SealError::Decrypt => Reject::Decrypt,
                    SealError::UnsupportedAead => Reject::Unsupported,
                    SealError::Malformed(DecodeError::UnsupportedKind(_)) => Reject::Unsupported,
                    SealError::Malformed(d) => Reject::Malformed(d),
                    SealError::Encode(_) => Reject::Decrypt,
                });
            }
        };
        match plain {
            Plain::Op(signed) => self.ingest_op(signed, now_ms, effects, applied),
            Plain::KeyLog(signed) => self.ingest_keylog(&signed, now_ms, effects, applied),
            Plain::Batch(_) => self.reject(Reject::Unsupported),
        }
    }

    fn ingest_keylog(
        &mut self,
        signed: &[u8],
        now_ms: u64,
        effects: &mut Vec<Change>,
        applied: &mut usize,
    ) -> IngestStatus {
        let log = match KeyLog::genesis(signed) {
            Ok(l) => l,
            // v0 has no device revocation or key rotation: only genesis
            // entries travel. Anything else is left to a later version.
            Err(KeyLogError::Genesis | KeyLogError::Unsupported) => {
                return self.reject(Reject::Unsupported);
            }
            Err(e) => return self.reject(Reject::KeyLog(e)),
        };
        if log.fragment_id() != self.fragment_id {
            return self.reject(Reject::WrongFragment);
        }
        let Some(author) = OpKey::from_multihash(log.author()) else {
            return self.reject(Reject::Unsupported);
        };
        if self.authors.contains_key(&author) {
            return self.duplicate();
        }
        self.authors.insert(
            author,
            Author {
                log,
                ops: Vec::new(),
                head_hlc: Hlc::default(),
                head_bytes: Vec::new(),
            },
        );
        let work = self
            .waiting
            .remove(&Blocker::Author(author))
            .unwrap_or_default();
        *applied += self.run(work.into_iter().collect(), now_ms, effects);
        IngestStatus::KeyLog
    }

    fn ingest_op(
        &mut self,
        signed: Vec<u8>,
        now_ms: u64,
        effects: &mut Vec<Change>,
        applied: &mut usize,
    ) -> IngestStatus {
        let hash = *blake3::hash(&signed).as_bytes();
        if self.pending_hashes.contains(&hash) {
            return self.duplicate();
        }
        let order = self.next_order;
        self.next_order += 1;
        self.pending_bytes += signed.len();
        self.pending_hashes.insert(hash);
        self.pending.insert(
            order,
            Pending {
                bytes: signed,
                hash,
                verified: false,
            },
        );
        let mut work = BTreeSet::new();
        let step = self.step(order, now_ms, effects, &mut work);
        match step {
            Step::Applied => {
                *applied += 1 + self.run(work, now_ms, effects);
                IngestStatus::Applied
            }
            Step::Duplicate => IngestStatus::Duplicate,
            Step::Dropped(r) => IngestStatus::Rejected(r),
            Step::Waiting(why) => {
                if self.pending.len() > self.config.max_pending_items
                    || self.pending_bytes > self.config.max_pending_bytes
                {
                    self.unregister(order);
                    self.forget(order);
                    IngestStatus::PendingFull
                } else {
                    IngestStatus::Pending(why)
                }
            }
        }
    }

    /// Remove a pending item from the store (not from the wait indexes).
    fn forget(&mut self, order: u64) -> Option<Pending> {
        let item = self.pending.remove(&order)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(item.bytes.len());
        self.pending_hashes.remove(&item.hash);
        Some(item)
    }

    fn unregister(&mut self, order: u64) {
        self.waiting.retain(|_, v| {
            v.retain(|o| *o != order);
            !v.is_empty()
        });
        self.timed.retain(|(_, o)| *o != order);
        self.recheck.remove(&order);
    }

    /// Evaluate held ops whose reason to wait may have gone with the clock.
    fn drain_due(&mut self, now_ms: u64, effects: &mut Vec<Change>) -> usize {
        let mut work = core::mem::take(&mut self.recheck);
        let horizon = now_ms.saturating_add(self.config.max_drift_ms);
        while let Some(first) = self.timed.first().copied() {
            if first.0 > horizon {
                break;
            }
            self.timed.remove(&first);
            work.insert(first.1);
        }
        self.run(work, now_ms, effects)
    }

    /// Evaluate pending items, oldest first, following everything each
    /// applied op unblocks. Returns the number of ops applied.
    fn run(&mut self, mut work: BTreeSet<u64>, now_ms: u64, effects: &mut Vec<Change>) -> usize {
        let mut n = 0;
        while let Some(order) = work.pop_first() {
            if let Step::Applied = self.step(order, now_ms, effects, &mut work) {
                n += 1;
            }
        }
        n
    }

    /// Evaluate one pending item and act on the result, counting what is
    /// dropped. Items woken by an applied op are added to `work`.
    fn step(
        &mut self,
        order: u64,
        now_ms: u64,
        effects: &mut Vec<Change>,
        work: &mut BTreeSet<u64>,
    ) -> Step {
        let Some(item) = self.pending.get(&order) else {
            return Step::Duplicate;
        };
        let mut verified = item.verified;
        let eval = self.evaluate(&item.bytes, &mut verified, now_ms);
        if let Some(item) = self.pending.get_mut(&order) {
            item.verified = verified;
        }
        match eval {
            Eval::Wait(blocker, why) => {
                self.waiting.entry(blocker).or_default().push(order);
                Step::Waiting(why)
            }
            Eval::Later(wall_ms) => {
                self.timed.insert((wall_ms, order));
                Step::Waiting(PendingReason::ClockAhead)
            }
            Eval::Duplicate => {
                self.forget(order);
                self.duplicate();
                Step::Duplicate
            }
            Eval::Drop(r) => {
                self.forget(order);
                self.reject(r.clone());
                Step::Dropped(r)
            }
            Eval::Equivocation { author, seq } => {
                if let Some(item) = self.forget(order) {
                    self.record_equivocation(author, seq, item.bytes);
                }
                self.reject(Reject::Equivocation);
                Step::Dropped(Reject::Equivocation)
            }
            Eval::Apply(ready) => {
                let Some(item) = self.forget(order) else {
                    return Step::Duplicate;
                };
                // `evaluate` checked the drift bound, so this is `Some`.
                if let Some(c) = self
                    .clock
                    .observe(ready.hlc, now_ms, self.config.max_drift_ms)
                {
                    self.clock = c;
                }
                effects.extend(self.merge.apply(
                    &ready.changes,
                    Stamp {
                        hlc: ready.hlc,
                        id: ready.id,
                    },
                    false,
                ));
                if let Some(a) = self.authors.get_mut(&ready.author) {
                    a.ops.push(ready.id);
                    a.head_hlc = ready.hlc;
                    a.head_bytes = item.bytes;
                }
                self.applied.insert(ready.id);
                self.counters.applied += 1;
                if let Some(woken) = self.waiting.remove(&Blocker::Op(ready.id)) {
                    work.extend(woken);
                }
                Step::Applied
            }
        }
    }

    /// Decide what to do with a signed op. Pure: no state changes.
    fn evaluate(&self, signed: &[u8], verified: &mut bool, now_ms: u64) -> Eval {
        let op = match Op::from_bytes(signed) {
            Ok(op) => op,
            Err(DecodeError::UnsupportedFormat(_) | DecodeError::UnsupportedKind(_)) => {
                return Eval::Drop(Reject::Unsupported);
            }
            Err(e) => return Eval::Drop(Reject::Op(InvalidReason::Malformed(e))),
        };
        let body = op.body();
        if body.fragment_id != self.fragment_id {
            return Eval::Drop(Reject::WrongFragment);
        }
        let (Some(id), Some(author_key)) = (
            OpKey::from_multihash(op.id()),
            OpKey::from_multihash(&body.author),
        ) else {
            return Eval::Drop(Reject::Unsupported);
        };
        if self.applied.contains(&id) {
            return Eval::Duplicate;
        }
        let Some(author) = self.authors.get(&author_key) else {
            return Eval::Wait(Blocker::Author(author_key), PendingReason::UnknownAuthor);
        };
        if !*verified {
            // The drift check is done below, where it can hold the op back.
            match verify(signed, &VerifyCtx::new(&self.fragment_id, &author.log)) {
                Verdict::Valid(_) => *verified = true,
                Verdict::Unverifiable { .. } => return Eval::Drop(Reject::Unsupported),
                Verdict::Invalid { reason } => return Eval::Drop(Reject::Op(reason)),
            }
        }
        let head = author.ops.len() as u64;
        if body.seq <= head {
            // Every position up to `head` holds an applied op, and this is
            // not it: two validly signed ops at one `(author, seq)`.
            return Eval::Equivocation {
                author: author_key,
                seq: body.seq,
            };
        }
        let changes = match decode_payload(&body.payload) {
            Ok(c) => c,
            Err(e) => return Eval::Drop(Reject::Payload(e)),
        };
        if body.seq == head + 1 {
            let prev = body.prev.as_ref().map(OpKey::from_multihash);
            let linked = match (prev, author.ops.last()) {
                (None, None) => true,
                (Some(Some(p)), Some(last)) => p == *last,
                _ => false,
            };
            if !linked {
                return Eval::Drop(Reject::ChainFork);
            }
            if head > 0 && body.hlc <= author.head_hlc {
                return Eval::Drop(Reject::HlcNotMonotonic);
            }
        } else {
            match body.prev.as_ref().map(OpKey::from_multihash) {
                // Applied already, yet not this author's `seq - 1`: it never
                // will be.
                Some(Some(p)) if self.applied.contains(&p) => {
                    return Eval::Drop(Reject::ChainFork);
                }
                Some(Some(p)) => return Eval::Wait(Blocker::Op(p), PendingReason::MissingPrev),
                // An id this build cannot compute can never be applied here.
                Some(None) => return Eval::Drop(Reject::Unsupported),
                None => return Eval::Drop(Reject::ChainFork),
            }
        }
        for dep in &body.deps {
            match OpKey::from_multihash(dep) {
                Some(d) if self.applied.contains(&d) => {}
                Some(d) => return Eval::Wait(Blocker::Op(d), PendingReason::MissingDep),
                None => return Eval::Drop(Reject::Unsupported),
            }
        }
        if body.hlc.wall_ms > now_ms.saturating_add(self.config.max_drift_ms) {
            return Eval::Later(body.hlc.wall_ms);
        }
        Eval::Apply(Ready {
            id,
            author: author_key,
            hlc: body.hlc,
            changes,
        })
    }

    fn record_equivocation(&mut self, author: OpKey, seq: u64, rejected: Vec<u8>) {
        if self.equivocations.iter().any(|e| e.rejected == rejected)
            || self.equivocations.len() >= MAX_EQUIVOCATIONS
        {
            return;
        }
        let Some(a) = self.authors.get(&author) else {
            return;
        };
        let Some(kept) = usize::try_from(seq)
            .ok()
            .and_then(|s| s.checked_sub(1))
            .and_then(|i| a.ops.get(i))
        else {
            return;
        };
        let proof = (seq == a.ops.len() as u64).then(|| {
            let (x, y) = (a.head_bytes.clone(), rejected.clone());
            if x <= y {
                EquivocationProof { a: x, b: y }
            } else {
                EquivocationProof { a: y, b: x }
            }
        });
        self.equivocations.push(Equivocation {
            author: author.to_multihash(),
            seq,
            kept: kept.to_multihash(),
            rejected,
            proof,
        });
    }

    // ------------------------------------------------------------ transport

    /// Number of sealed items waiting to be pushed.
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// The next `max` sealed items to push, oldest first. Each is the
    /// canonical encoding of a `SealedOp`
    /// ([`SealedOp::from_bytes`](gsp_wire::SealedOp::from_bytes) gives the
    /// value for a `Push` frame). Peeking does not remove anything.
    pub fn outbox_peek(&self, max: usize) -> Vec<&[u8]> {
        self.outbox.iter().take(max).map(Vec::as_slice).collect()
    }

    /// Drop the first `count` outbox items after the relay acknowledged them.
    /// Returns how many were removed.
    pub fn outbox_ack(&mut self, count: usize) -> usize {
        let n = count.min(self.outbox.len());
        self.outbox.drain(..n);
        n
    }

    /// The pull cursor: ask the relay for items after this position.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Set the pull cursor, for example to `0` to replay a fragment from the
    /// start (ingest is idempotent), or to a `Batch.next` that covers items
    /// the transport chose not to hand over.
    pub fn set_cursor(&mut self, cursor: u64) {
        self.cursor = cursor;
        self.hold = None;
    }

    /// Discard every pending op and return how many there were. A way out
    /// when pending storage is full of ops that will never be applicable;
    /// follow it with `set_cursor(0)` so that the ones that are get fetched
    /// again.
    pub fn clear_pending(&mut self) -> usize {
        let n = self.pending.len();
        self.pending.clear();
        self.pending_hashes.clear();
        self.pending_bytes = 0;
        self.waiting.clear();
        self.timed.clear();
        self.recheck.clear();
        n
    }

    // ------------------------------------------------------------ reading

    /// A visible node.
    pub fn node(&self, gid: &Gid) -> Option<NodeView> {
        self.merge.node(gid)
    }

    /// A visible edge.
    pub fn edge(&self, gid: &Gid) -> Option<EdgeView> {
        self.merge.edge(gid)
    }

    /// All visible nodes, ordered by gid.
    pub fn nodes(&self) -> Vec<NodeView> {
        self.merge.nodes()
    }

    /// All visible edges, ordered by gid.
    pub fn edges(&self) -> Vec<EdgeView> {
        self.merge.edges()
    }

    /// `true` if the node gid is tombstoned.
    pub fn node_deleted(&self, gid: &Gid) -> bool {
        self.merge.node_tombstoned(gid)
    }

    /// `true` if the edge gid is tombstoned.
    pub fn edge_deleted(&self, gid: &Gid) -> bool {
        self.merge.edge_tombstoned(gid)
    }

    /// The whole visible graph as puts (nodes, then edges): what an empty
    /// engine must apply to match this replica.
    pub fn snapshot(&self) -> Vec<Change> {
        self.merge.snapshot()
    }

    /// Counters and sizes.
    pub fn stats(&self) -> Stats {
        let c = &self.counters;
        Stats {
            applied: c.applied,
            local: c.local,
            pending: self.pending.len(),
            pending_bytes: self.pending_bytes,
            invalid: c.invalid,
            undecryptable: c.undecryptable,
            unsupported: c.unsupported,
            equivocations: c.equivocations,
            duplicates: c.duplicates,
            refused: c.refused,
            authors: self.authors.len(),
            outbox: self.outbox.len(),
        }
    }

    /// Equivocation records, oldest first (at most [`MAX_EQUIVOCATIONS`]).
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    // ------------------------------------------------------------ state

    /// The whole replica state as deterministic CBOR (SYNC-V0 section 7).
    ///
    /// **The bytes contain the root secret and the device seed.** Store them
    /// encrypted, and in the same atomic write as the engine's data. The
    /// returned buffer is zeroized on drop.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let opt_bytes = |b: &[u8]| {
            if b.is_empty() { Value::Null } else { bytes(b) }
        };
        let authors = self
            .authors
            .values()
            .map(|a| {
                let genesis = a.log.entries().first().map_or(Value::Null, |g| bytes(g));
                Value::Array(vec![
                    genesis,
                    Value::Array(a.ops.iter().map(|k| k.to_value()).collect()),
                    if a.ops.is_empty() {
                        Value::Null
                    } else {
                        hlc_value(a.head_hlc)
                    },
                    opt_bytes(&a.head_bytes),
                ])
            })
            .collect();
        let c = &self.counters;
        let equivocations = self
            .equivocations
            .iter()
            .map(|e| {
                let id =
                    |m: &Multihash| Value::Array(vec![uint(u64::from(m.alg)), bytes(&m.digest)]);
                Value::Array(vec![
                    id(&e.author),
                    uint(e.seq),
                    id(&e.kept),
                    bytes(&e.rejected),
                    e.proof.as_ref().map_or(Value::Null, |p| {
                        Value::Array(vec![bytes(&p.a), bytes(&p.b)])
                    }),
                ])
            })
            .collect();
        let state = Zeroizing::new(StateValue(Value::Array(vec![
            Value::Text(STATE_TAG.into()),
            uint(STATE_VERSION),
            bytes(self.pairing.root()),
            bytes(&*self.seed),
            hlc_value(self.clock),
            uint(self.cursor),
            Value::Array(authors),
            self.merge.to_value()?,
            Value::Array(self.pending.values().map(|p| bytes(&p.bytes)).collect()),
            Value::Array(self.outbox.iter().map(|o| bytes(o)).collect()),
            Value::Array(
                [
                    c.applied,
                    c.local,
                    c.invalid,
                    c.undecryptable,
                    c.unsupported,
                    c.equivocations,
                    c.duplicates,
                    c.refused,
                ]
                .into_iter()
                .map(uint)
                .collect(),
            ),
            Value::Array(equivocations),
        ])));
        Ok(Zeroizing::new(state.0.encode()?))
    }

    /// Restore a replica from [`to_bytes`](Replica::to_bytes) output.
    ///
    /// Strict: the bytes must be exactly what `to_bytes` produces for the
    /// state they describe (the restored replica is re-encoded and compared),
    /// every key log must verify, and the device's own identity must be among
    /// them. Pending ops are re-evaluated by the next call that carries a
    /// clock.
    pub fn from_bytes(state: &[u8], config: Config) -> Result<Replica, Error> {
        const BAD: Error = Error::State("shape");
        let v = Zeroizing::new(StateValue(
            Value::decode(state).map_err(|_| Error::State("not canonical CBOR"))?,
        ));
        let mut f = Fields::open(&v.0).ok_or(BAD)?;
        if f.text() != Some(STATE_TAG) {
            return Err(Error::State("not a replica state"));
        }
        let version = f.u64().ok_or(BAD)?;
        if version != STATE_VERSION {
            return Err(Error::StateVersion(version));
        }
        if f.remaining() != 10 {
            return Err(BAD);
        }
        let root: Zeroizing<[u8; 32]> = Zeroizing::new(f.fixed().ok_or(BAD)?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(f.fixed().ok_or(BAD)?);
        let mut r = Replica::base(*root, *seed, config)?;
        r.clock = f.value().and_then(hlc_from).ok_or(BAD)?;
        r.cursor = f.u64().ok_or(BAD)?;

        let mut authors = BTreeMap::new();
        for a in f.array().ok_or(BAD)? {
            let mut a = Fields::exact(a, 4).ok_or(BAD)?;
            let log =
                KeyLog::genesis(a.bytes().ok_or(BAD)?).map_err(|_| Error::State("key log"))?;
            if log.fragment_id() != r.fragment_id {
                return Err(Error::State("key log of another fragment"));
            }
            let key = OpKey::from_multihash(log.author()).ok_or(Error::State("key log"))?;
            let mut ops = Vec::new();
            for id in a.array().ok_or(BAD)? {
                let id = OpKey::from_value(id).ok_or(BAD)?;
                if !r.applied.insert(id) {
                    return Err(Error::State("op listed twice"));
                }
                ops.push(id);
            }
            let (head_hlc, head_bytes) = match (a.value().ok_or(BAD)?, a.value().ok_or(BAD)?) {
                (Value::Null, Value::Null) if ops.is_empty() => (Hlc::default(), Vec::new()),
                (h, Value::Bytes(b)) if !ops.is_empty() => {
                    let hlc = hlc_from(h).ok_or(BAD)?;
                    let head = Op::from_bytes(b).map_err(|_| Error::State("head op"))?;
                    if OpKey::from_multihash(head.id()).as_ref() != ops.last()
                        || head.body().hlc != hlc
                    {
                        return Err(Error::State("head op"));
                    }
                    (hlc, b.clone())
                }
                _ => return Err(BAD),
            };
            authors.insert(
                key,
                Author {
                    log,
                    ops,
                    head_hlc,
                    head_bytes,
                },
            );
        }
        if !authors.contains_key(&r.me) {
            return Err(Error::State("own author missing"));
        }
        r.authors = authors;

        r.merge = f
            .value()
            .and_then(Merge::from_value)
            .ok_or(Error::State("merge state"))?;

        for p in f.array().ok_or(BAD)? {
            let Value::Bytes(b) = p else {
                return Err(BAD);
            };
            let hash = *blake3::hash(b).as_bytes();
            if !r.pending_hashes.insert(hash) {
                return Err(Error::State("pending op listed twice"));
            }
            r.pending_bytes += b.len();
            r.pending.insert(
                r.next_order,
                Pending {
                    bytes: b.clone(),
                    hash,
                    verified: false,
                },
            );
            r.recheck.insert(r.next_order);
            r.next_order += 1;
        }
        for o in f.array().ok_or(BAD)? {
            let Value::Bytes(b) = o else {
                return Err(BAD);
            };
            r.outbox.push_back(b.clone());
        }
        let mut c = Fields::exact(f.value().ok_or(BAD)?, 8).ok_or(BAD)?;
        let mut next = || c.u64().ok_or(BAD);
        r.counters = Counters {
            applied: next()?,
            local: next()?,
            invalid: next()?,
            undecryptable: next()?,
            unsupported: next()?,
            equivocations: next()?,
            duplicates: next()?,
            refused: next()?,
        };
        for e in f.array().ok_or(BAD)? {
            let mut e = Fields::exact(e, 5).ok_or(BAD)?;
            let author = e.value().and_then(OpKey::from_value).ok_or(BAD)?;
            let seq = e.u64().ok_or(BAD)?;
            let kept = e.value().and_then(OpKey::from_value).ok_or(BAD)?;
            let rejected = e.bytes().ok_or(BAD)?.to_vec();
            let proof = match e.value().ok_or(BAD)? {
                Value::Null => None,
                p => {
                    let mut p = Fields::exact(p, 2).ok_or(BAD)?;
                    Some(EquivocationProof {
                        a: p.bytes().ok_or(BAD)?.to_vec(),
                        b: p.bytes().ok_or(BAD)?.to_vec(),
                    })
                }
            };
            r.equivocations.push(Equivocation {
                author: author.to_multihash(),
                seq,
                kept: kept.to_multihash(),
                rejected,
                proof,
            });
        }
        if r.equivocations.len() > MAX_EQUIVOCATIONS {
            return Err(Error::State("too many equivocation records"));
        }
        f.end().ok_or(BAD)?;

        // One state, one encoding: whatever was unsorted, duplicated or
        // redundant in the input shows up as a difference here.
        if r.to_bytes()?.as_slice() != state {
            return Err(Error::State("not the canonical encoding"));
        }
        Ok(r)
    }
}

/// The decoded state tree, which holds the root secret and the device seed
/// as byte strings: wiped on drop.
struct StateValue(Value);

impl Zeroize for StateValue {
    fn zeroize(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::Bytes(b) => b.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                _ => {}
            }
        }
        // The secrets are top-level fields; the merge state below them is not
        // secret from whoever holds the fragment key, so one level is enough.
        if let Value::Array(items) = &mut self.0 {
            for item in items.iter_mut() {
                if let Value::Bytes(_) = item {
                    wipe(item);
                }
            }
        }
    }
}
