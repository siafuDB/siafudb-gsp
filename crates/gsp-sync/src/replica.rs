//! The replica state machine: ingest, local commits, outbox, cursor, state.

use crate::change::{Change, Gid, PayloadError, decode_payload, encode_payload};
use crate::cv::{Fields, bytes, uint};
use crate::merge::{EdgeView, Merge, NodeView, OpKey, Stamp};
use crate::pairing::{FRAGMENT_ID_LEN, OriginError, Pairing};
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
const STATE_VERSION: u64 = 2;
const CTX_RESET_NONCE: &str = "gsp/v0/reset-identity-nonce";

/// Tunable limits. Not part of the serialised state: pass the same values to
/// [`Replica::from_bytes`]. Build it from [`Config::default`] with struct
/// update syntax; fields may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How far an op's HLC may lead the local clock and still be applied at
    /// once. Beyond it the op is held. Default 300 000 ms (WIRE-V0 section 4).
    pub max_drift_ms: u64,
    /// How far an op's HLC may lead the local clock and still be *held*.
    /// Beyond it the op is rejected. Default 86 400 000 ms (24 hours).
    pub max_clock_ahead_ms: u64,
    /// Most ops held as pending, all authors together. Default 4096.
    pub max_pending_items: usize,
    /// Most bytes of signed ops held as pending, all authors together.
    /// Default 16 MiB.
    pub max_pending_bytes: usize,
    /// Most ops held as pending for one author. Default 256.
    pub max_pending_items_per_author: usize,
    /// Most bytes of signed ops held as pending for one author. Default 2 MiB.
    pub max_pending_bytes_per_author: usize,
    /// Most authors (devices) whose key log a replica accepts, this device
    /// included. Default 64.
    pub max_authors: usize,
    /// Most acknowledged outbox items kept until the relay echoes them back.
    /// Default 1024.
    pub max_unechoed_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_drift_ms: gsp_wire::op::DEFAULT_MAX_DRIFT_MS,
            max_clock_ahead_ms: 24 * 60 * 60 * 1000,
            max_pending_items: 4096,
            max_pending_bytes: 16 * 1024 * 1024,
            max_pending_items_per_author: 256,
            max_pending_bytes_per_author: 2 * 1024 * 1024,
            max_authors: 64,
            max_unechoed_items: 1024,
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
    /// This device's author chain has forked (see [`Replica::forked`]): the
    /// replica refuses to sign. Call [`Replica::reset_identity`].
    Forked,
    /// The replica has seen ops of this device's own author beyond the ones
    /// it has applied (its state was rolled back and it is still catching
    /// up, see [`Replica::forked`]). Signing now would reuse a position that
    /// is known to be taken. Pull until [`Stats::own_ops_missing`] is 0 and
    /// try again; if it never gets there (the relay no longer has the
    /// missing op), call [`Replica::reset_identity`].
    OwnChainAhead,
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
    /// Well-formed, but not something a v0 replica handles: an unknown
    /// sealed format or AEAD, a batch (kind 2), a key-log entry other than a
    /// genesis or one this build cannot check, or an unverifiable copy of an
    /// op at a position that is already settled.
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
    /// The op's HLC is more than `max_clock_ahead_ms` ahead of the local
    /// clock: the author's clock (or this device's) is wrong. See
    /// [`AuthorStatus::clock_lead_ms`].
    ClockTooFarAhead,
    /// The genesis of one author more than `max_authors`.
    TooManyAuthors,
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
    /// The op's HLC is more than `max_drift_ms` (and at most
    /// `max_clock_ahead_ms`) ahead of the local clock. It is applied by a
    /// later call once local time has caught up.
    ClockAhead,
    /// The op uses a format, hash or signature algorithm this build does not
    /// know, or is signed by a key the author's log does not hold. It is
    /// kept (WIRE-V0 section 6) and checked again after a restore, so a
    /// newer build can apply it.
    Unverifiable,
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
    /// The op would have to wait, but pending storage (the author's share or
    /// all of it) is full, so it was dropped. The pull cursor moves on all
    /// the same; [`Replica::needs_resync`] is now `true`. Keep ingesting.
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
    /// Local commits made (ops re-issued by `reset_identity` included).
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
    /// Ops dropped because pending storage was full (the incoming one, or an
    /// older one evicted for it).
    pub refused: u64,
    /// Ops rejected as [`Reject::ClockTooFarAhead`].
    pub clock_rejected: u64,
    /// Key logs rejected as [`Reject::TooManyAuthors`].
    pub authors_refused: u64,
    /// Times the relay was seen to have lost its log
    /// ([`Replica::observe_relay_head`]).
    pub relay_resets: u64,
    /// Authors whose key log is known, this device included.
    pub authors: usize,
    /// Sealed items waiting in the outbox.
    pub outbox: usize,
    /// Acknowledged items not yet seen echoed back by the relay.
    pub unechoed: usize,
    /// [`Replica::needs_resync`].
    pub needs_resync: bool,
    /// [`Replica::forked`].
    pub forked: bool,
    /// How many ops of this device's own author are known to exist beyond
    /// the ones applied (after a rollback, while catching up). While it is
    /// not 0, `local_commit` fails with [`Error::OwnChainAhead`].
    pub own_ops_missing: u64,
}

/// What a replica knows about one author (one device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorStatus {
    /// The author id.
    pub author: Multihash,
    /// `true` for this device's current identity.
    pub own: bool,
    /// `seq` of the author's latest applied op (0: none yet).
    pub applied_seq: u64,
    /// Ops of this author currently pending.
    pub pending: usize,
    /// An op of this author was dropped because pending storage was full:
    /// later ops of the author cannot apply until a resync fetches it again.
    pub gap: bool,
    /// By how many milliseconds the HLC of the author's most recently
    /// evaluated op led this device's clock, if that was more than
    /// `max_drift_ms` (the op was held or rejected); `0` once an op of the
    /// author applies. Non-zero for long, or beyond `max_clock_ahead_ms`,
    /// means that device's clock (or this one's) is wrong.
    pub clock_lead_ms: u64,
    /// The author signed two different ops at one `seq`. Replicas may hold
    /// different halves, and then disagree about this author's later ops.
    pub equivocated: bool,
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
    clock_rejected: u64,
    authors_refused: u64,
    relay_resets: u64,
}

struct Author {
    log: KeyLog,
    /// Applied op ids; index `i` is `seq = i + 1`.
    ops: Vec<OpKey>,
    /// HLC and signed bytes of the op at `ops.last()`.
    head_hlc: Hlc,
    head_bytes: Vec<u8>,
    gap: bool,
    clock_lead_ms: u64,
    equivocated: bool,
}

impl Author {
    fn new(log: KeyLog) -> Author {
        Author {
            log,
            ops: Vec::new(),
            head_hlc: Hlc::default(),
            head_bytes: Vec::new(),
            gap: false,
            clock_lead_ms: 0,
            equivocated: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Blocker {
    /// The key log of this author.
    Author(OpKey),
    /// This author's chain reaching `seq - 1` (or passing `seq`).
    Seq(OpKey, u64),
    /// Nothing that can happen while this build runs.
    Opaque,
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
    /// The author the op claims (`None` if it cannot be read), for the
    /// per-author bound.
    bucket: Option<OpKey>,
    /// The `seq` the op claims (`u64::MAX` if it cannot be read).
    seq: u64,
}

struct Ready {
    id: OpKey,
    author: OpKey,
    seq: u64,
    hlc: Hlc,
    changes: Vec<Change>,
}

enum Eval {
    Apply(Ready),
    Wait(Blocker, PendingReason),
    /// Held for the clock; `lead` is how far ahead it is.
    Later {
        wall_ms: u64,
        lead: u64,
    },
    Duplicate,
    Equivocation {
        author: OpKey,
        seq: u64,
    },
    /// A validly signed op of this device's own identity that conflicts with
    /// the chain this replica recorded.
    SelfFork,
    ClockReject {
        author: OpKey,
        lead: u64,
    },
    Drop(Reject),
}

struct Outcome {
    eval: Eval,
    bucket: Option<OpKey>,
    seq: u64,
    /// A validly signed op of this device's own identity beyond its head.
    own_ahead: bool,
    /// A validly signed op of this device's own identity that should be the
    /// next one and does not continue the chain.
    own_conflict: bool,
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
    forked: bool,
    /// Highest `seq` of a validly signed op of this device's own identity
    /// seen so far (0: none beyond what it wrote itself).
    own_seen: u64,
    /// An op was dropped for lack of pending space and its author is not one
    /// with a key log (which carry their own flag).
    gap_other: bool,
    authors: BTreeMap<OpKey, Author>,
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
    /// Acknowledged items the relay has not echoed back yet, with the BLAKE3
    /// of each.
    unechoed: VecDeque<([u8; 32], Vec<u8>)>,
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

/// A device identity: the signing key, its genesis key-log entry and the
/// author id that entry defines.
struct Identity {
    signer: SigningKey,
    log: KeyLog,
    key: OpKey,
}

fn identity(fragment_id: &[u8], seed: &[u8; 32]) -> Result<Identity, Error> {
    let signer = SigningKey::ed25519(seed);
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
    let key = OpKey::from_multihash(log.author()).ok_or(Error::State("genesis"))?;
    Ok(Identity { signer, log, key })
}

/// A signed and sealed op, not yet part of any state.
struct Built {
    id: OpKey,
    hlc: Hlc,
    signed: Vec<u8>,
    sealed: Vec<u8>,
    /// The changes exactly as every other replica will decode them.
    changes: Vec<Change>,
}

impl Replica {
    /// A replica with this device's identity and nothing else.
    fn base(root: [u8; 32], device_seed: [u8; 32], config: Config) -> Result<Replica, Error> {
        let pairing = Pairing::from_root(root);
        let seed = Zeroizing::new(device_seed);
        let fragment_id = pairing.fragment_id();
        let me = identity(&fragment_id, &seed)?;
        let mut authors = BTreeMap::new();
        authors.insert(me.key, Author::new(me.log));
        Ok(Replica {
            config,
            key: pairing.fragment_key(),
            pairing,
            seed,
            fragment_id,
            signer: me.signer,
            me: me.key,
            clock: Hlc::default(),
            cursor: 0,
            forked: false,
            own_seen: 0,
            gap_other: false,
            authors,
            merge: Merge::default(),
            pending: BTreeMap::new(),
            pending_hashes: BTreeSet::new(),
            pending_bytes: 0,
            next_order: 0,
            waiting: BTreeMap::new(),
            timed: BTreeSet::new(),
            recheck: BTreeSet::new(),
            outbox: VecDeque::new(),
            unechoed: VecDeque::new(),
            counters: Counters::default(),
            equivocations: Vec::new(),
        })
    }

    fn sealed_genesis(&self, author: &OpKey, nonce: [u8; 24]) -> Result<Vec<u8>, Error> {
        let genesis = self
            .authors
            .get(author)
            .and_then(|a| a.log.entries().first())
            .ok_or(Error::State("genesis"))?
            .clone();
        Ok(
            SealedOp::seal(&self.key, &self.fragment_id, nonce, &Plain::KeyLog(genesis))?
                .to_bytes()?,
        )
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
        let sealed = r.sealed_genesis(&r.me, genesis_nonce)?;
        r.outbox.push_back(sealed);
        Ok(r)
    }

    // ------------------------------------------------------------ identity

    /// Public routing id of the fragment.
    pub fn fragment_id(&self) -> &[u8; FRAGMENT_ID_LEN] {
        &self.fragment_id
    }

    /// Bearer token for the relay at `relay_origin` (`scheme://host[:port]`,
    /// see [`canonical_origin`](crate::canonical_origin)). Each relay gets a
    /// different token.
    pub fn relay_token(&self, relay_origin: &str) -> Result<Zeroizing<[u8; 32]>, OriginError> {
        self.pairing.relay_token(relay_origin)
    }

    /// The pairing secret, to show to another device.
    pub fn pairing(&self) -> &Pairing {
        &self.pairing
    }

    /// This device's author id (content id of its genesis key-log entry).
    pub fn author(&self) -> Multihash {
        self.me.to_multihash()
    }

    /// `true` once the replica has seen proof that this device's author
    /// chain exists in a version that **conflicts** with the one it holds: a
    /// validly signed op of its own identity at a position where it recorded
    /// a different op, or one that claims to be the next op and does not
    /// continue from its head.
    ///
    /// The cause is a state rollback (a restore from a backup, or state
    /// saved separately from the push) followed by a local commit, or a
    /// second device running with a copy of this one's seed. Signing more
    /// ops as this author would equivocate again, and peers would reject
    /// them without anyone being told. So
    /// [`local_commit`](Replica::local_commit) fails with [`Error::Forked`]
    /// until [`reset_identity`](Replica::reset_identity) gives the device a
    /// fresh author. Ingest keeps working while forked: the replica follows
    /// the version of its old chain that the relay has (the one peers hold)
    /// and keeps the ops it wrote on its own branch for `reset_identity` to
    /// re-issue.
    ///
    /// # Rollback without a conflict: fast-forward
    ///
    /// A rolled-back replica that has **not** written anything simply sees
    /// its own later ops come back from the relay, each continuing from its
    /// head. Those are applied like anyone's ops (with effects), its own
    /// head, next `seq` and HLC move forward with them, and it is not forked:
    /// once it has caught up it writes as before, as the same author.
    ///
    /// The replica cannot know how many of its own ops the relay holds. Two
    /// things keep the window small, and one of them is the application's:
    ///
    /// - once an op of its own beyond its head has been *seen* (even one
    ///   that cannot apply yet because an earlier one is missing),
    ///   `local_commit` fails with [`Error::OwnChainAhead`] until the chain
    ///   up to it is applied ([`Stats::own_ops_missing`]);
    /// - **after restoring state that may be old, pull to the relay's head
    ///   before the first local commit.** A commit made before that reuses a
    ///   position; it is detected as a conflict when the earlier op arrives,
    ///   and then the device is forked.
    pub fn forked(&self) -> bool {
        self.forked
    }

    /// Give this device a new author identity ("rejoin as a new device"),
    /// keeping the pairing, the merge state and everything known about other
    /// authors.
    ///
    /// `new_device_seed` is 32 fresh random bytes; the old seed is forgotten.
    /// `nonce` is 24 fresh random bytes; the nonces of the items this call
    /// seals are derived from it (BLAKE3 `derive_key` with the item's
    /// index), so it must never be used for anything else.
    ///
    /// Queued to the outbox: the new genesis key-log entry, then one new op
    /// for every op of the old identity that this replica wrote, that peers
    /// will not have accepted (it sits on the losing branch of the fork), and
    /// whose sealed bytes are still at hand (in the outbox, or acknowledged
    /// but not yet echoed back). Those ops carry the same changes under new
    /// stamps, so what the device wrote between the rollback and its
    /// detection reaches the other replicas after all.
    ///
    /// Returns effects for the engine, as [`ingest`](Replica::ingest) does:
    /// re-issued changes are newer writes now, and can win where the
    /// originals had lost. Clears [`forked`](Replica::forked).
    ///
    /// May be called on a replica that is not forked. On error nothing has
    /// changed.
    pub fn reset_identity(
        &mut self,
        new_device_seed: [u8; 32],
        nonce: [u8; 24],
    ) -> Result<Vec<Change>, Error> {
        let seed = Zeroizing::new(new_device_seed);
        let new = identity(&self.fragment_id, &seed)?;
        if self.authors.contains_key(&new.key) {
            return Err(Error::State("device seed already in use"));
        }
        let nonce = Zeroizing::new(nonce);
        // Item `i` is sealed under the first 24 bytes of
        // derive_key(context, caller's nonce ‖ i).
        let nonce_at = |i: u64| -> [u8; 24] {
            let mut material: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32));
            material.extend_from_slice(&*nonce);
            material.extend_from_slice(&i.to_le_bytes());
            let full = Zeroizing::new(blake3::derive_key(CTX_RESET_NONCE, &material));
            core::array::from_fn(|k| full[k])
        };

        // Ops of the old identity that are not on the chain peers follow.
        let old = self.authors.get(&self.me).ok_or(Error::State("author"))?;
        let mut orphans: Vec<([u8; 32], Vec<Change>)> = Vec::new();
        let retained = self
            .unechoed
            .iter()
            .map(|(h, b)| (*h, b))
            .chain(self.outbox.iter().map(|b| (*blake3::hash(b).as_bytes(), b)));
        for (hash, sealed) in retained {
            let Some(op) = self.open_own_op(sealed) else {
                continue;
            };
            let on_chain = usize::try_from(op.body().seq)
                .ok()
                .and_then(|s| s.checked_sub(1))
                .and_then(|i| old.ops.get(i))
                .is_some_and(|k| Some(*k) == OpKey::from_multihash(op.id()));
            if on_chain {
                continue;
            }
            if let Ok(changes) = decode_payload(&op.body().payload) {
                orphans.push((hash, changes));
            }
        }

        // Build everything before touching the state.
        let genesis = new.log.entries().first().ok_or(Error::State("genesis"))?;
        let sealed_genesis = SealedOp::seal(
            &self.key,
            &self.fragment_id,
            nonce_at(0),
            &Plain::KeyLog(genesis.clone()),
        )?
        .to_bytes()?;
        let mut built: Vec<Built> = Vec::new();
        let mut hlc = self.clock;
        let deps = self.dep_heads(&new.key);
        for (i, (_, changes)) in orphans.iter().enumerate() {
            // No wall clock here: the next HLC after everything seen.
            hlc = hlc.tick(0);
            let op = self.build_op(
                &new.signer,
                new.key,
                i as u64 + 1,
                built.last().map(|b| b.id),
                hlc,
                &deps,
                encode_payload(changes)?,
                nonce_at(i as u64 + 1),
            )?;
            built.push(op);
        }

        // Nothing below can fail.
        let reissued: BTreeSet<[u8; 32]> = orphans.iter().map(|(h, _)| *h).collect();
        self.unechoed.retain(|(h, _)| !reissued.contains(h));
        self.outbox
            .retain(|b| !reissued.contains(blake3::hash(b).as_bytes()));
        self.seed = seed;
        self.signer = new.signer;
        self.me = new.key;
        self.forked = false;
        self.own_seen = 0;
        self.authors.insert(new.key, Author::new(new.log));
        self.outbox.push_back(sealed_genesis);
        let mut effects = Vec::new();
        for op in built {
            effects.extend(self.merge.apply(
                &op.changes,
                Stamp {
                    hlc: op.hlc,
                    id: op.id,
                },
                false,
            ));
            self.record_own(op);
        }
        Ok(effects)
    }

    /// Open one of this replica's sealed items; `Some` if it is an op of the
    /// current identity.
    fn open_own_op(&self, sealed: &[u8]) -> Option<Op> {
        let item = SealedOp::from_bytes(sealed).ok()?;
        let Plain::Op(signed) = item.open(&self.key, &self.fragment_id).ok()? else {
            return None;
        };
        let op = Op::from_bytes(&signed).ok()?;
        (OpKey::from_multihash(&op.body().author) == Some(self.me)).then_some(op)
    }

    // ------------------------------------------------------------ local writes

    /// Heads of every author but `me`; if there are too many, the most
    /// recent.
    fn dep_heads(&self, me: &OpKey) -> Vec<Multihash> {
        let mut heads: Vec<(Hlc, OpKey)> = self
            .authors
            .iter()
            .filter(|(k, _)| *k != me)
            .filter_map(|(_, a)| a.ops.last().map(|id| (a.head_hlc, *id)))
            .collect();
        heads.sort_unstable_by(|a, b| b.cmp(a));
        heads.truncate(MAX_DEPS);
        heads.iter().map(|(_, id)| id.to_multihash()).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_op(
        &self,
        signer: &SigningKey,
        author: OpKey,
        seq: u64,
        prev: Option<OpKey>,
        hlc: Hlc,
        deps: &[Multihash],
        payload: Value,
        nonce: [u8; 24],
    ) -> Result<Built, Error> {
        let body = OpBody {
            hash_alg: HashAlg::Blake3_256.id(),
            fragment_id: self.fragment_id.to_vec(),
            author: author.to_multihash(),
            seq,
            prev: prev.map(OpKey::to_multihash),
            hlc,
            deps: deps.to_vec(),
            payload,
        };
        let op = Op::sign(&body, &[signer])?;
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
        Ok(Built {
            id: OpKey::from_multihash(op.id()).ok_or(Error::State("op id"))?,
            hlc,
            changes: decode_payload(&op.body().payload)?,
            signed,
            sealed,
        })
    }

    /// Book an op of this device that the merge state already holds.
    fn record_own(&mut self, op: Built) {
        self.clock = op.hlc;
        if let Some(me) = self.authors.get_mut(&self.me) {
            me.ops.push(op.id);
            me.head_hlc = op.hlc;
            me.head_bytes = op.signed;
        }
        self.outbox.push_back(op.sealed);
        self.counters.local += 1;
    }

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
    ///   idempotent);
    /// - a `NodePut` that creates the last missing endpoint of an edge the
    ///   replica holds but could not show yet: an `EdgePut` for that edge.
    ///
    /// "Already applied" means the plain reading of each change: a put
    /// creates the entity if needed and writes what it carries, a delete
    /// removes the entity and nothing else.
    ///
    /// # Errors
    ///
    /// [`Error::Forked`] if the device's author chain has forked (see
    /// [`forked`](Replica::forked)); the payload errors of SYNC-V0 section 4.
    /// On error nothing has changed and nothing was queued.
    ///
    /// `now_ms` is taken as given. A wrong local clock cannot be told from a
    /// long time offline by anything the replica knows, so it is not checked
    /// here; an op stamped far in the future is held or rejected by the
    /// *other* replicas, which report it in [`AuthorStatus::clock_lead_ms`].
    pub fn local_commit(
        &mut self,
        changes: &[Change],
        now_ms: u64,
        nonce: [u8; 24],
    ) -> Result<Vec<Change>, Error> {
        if self.forked {
            return Err(Error::Forked);
        }
        let me = self.authors.get(&self.me).ok_or(Error::State("author"))?;
        if self.own_seen > me.ops.len() as u64 {
            return Err(Error::OwnChainAhead);
        }
        let payload = encode_payload(changes)?;
        let hlc = self.clock.tick(now_ms);
        let op = self.build_op(
            &self.signer,
            self.me,
            me.ops.len() as u64 + 1,
            me.ops.last().copied(),
            hlc,
            &self.dep_heads(&self.me),
            payload,
            nonce,
        )?;
        // Nothing below can fail.
        let effects = self.merge.apply(
            &op.changes,
            Stamp {
                hlc: op.hlc,
                id: op.id,
            },
            true,
        );
        self.record_own(op);
        Ok(effects)
    }

    // ------------------------------------------------------------ ingest

    /// Take one sealed item received from a relay or a peer.
    ///
    /// `relay_seq` is the position the relay gave the item (`0` if it did not
    /// come from the relay this replica's cursor belongs to). The pull cursor
    /// moves up to it whatever happens to the item: a replica never asks for
    /// the same item again because it could not use it. `now_ms` is the
    /// local clock in Unix milliseconds.
    ///
    /// Never fails and never panics, whatever the bytes are: the outcome says
    /// what happened and carries the effects for the engine.
    pub fn ingest(&mut self, sealed: &[u8], relay_seq: u64, now_ms: u64) -> IngestOutcome {
        let mut effects = Vec::new();
        let mut applied = self.drain_due(now_ms, &mut effects);
        let status = self.ingest_item(sealed, now_ms, &mut effects, &mut applied);
        self.cursor = self.cursor.max(relay_seq);
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
            Reject::ClockTooFarAhead => self.counters.clock_rejected += 1,
            Reject::TooManyAuthors => self.counters.authors_refused += 1,
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
        // One of our own items coming back: the relay has it.
        if !self.unechoed.is_empty() {
            let hash = *blake3::hash(sealed).as_bytes();
            if let Some(i) = self.unechoed.iter().position(|(h, _)| *h == hash) {
                // While forked they are kept: `reset_identity` needs them.
                if !self.forked {
                    self.unechoed.remove(i);
                }
                return self.duplicate();
            }
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
        if self.authors.len() >= self.config.max_authors {
            return self.reject(Reject::TooManyAuthors);
        }
        self.authors.insert(author, Author::new(log));
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
                bucket: None,
                seq: u64::MAX,
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
                if self.make_room(order) {
                    IngestStatus::Pending(why)
                } else {
                    IngestStatus::PendingFull
                }
            }
        }
    }

    /// Enforce the pending bounds after `order` was added. Returns whether
    /// `order` is still held.
    ///
    /// An author over its share loses its op with the highest `seq` (the one
    /// furthest from being applicable), which may be the new one. When the
    /// store as a whole is full the new op goes. Either way the author is
    /// marked as having a gap.
    fn make_room(&mut self, order: u64) -> bool {
        let Some((bucket, seq)) = self.pending.get(&order).map(|p| (p.bucket, p.seq)) else {
            return false;
        };
        let (mut items, mut size) = (0usize, 0usize);
        let mut last = (seq, order);
        for (o, p) in &self.pending {
            if p.bucket == bucket {
                items += 1;
                size += p.bytes.len();
                last = last.max((p.seq, *o));
            }
        }
        let mut kept = true;
        if items > self.config.max_pending_items_per_author
            || size > self.config.max_pending_bytes_per_author
        {
            self.evict(last.1, bucket);
            kept = last.1 != order;
        }
        if kept
            && (self.pending.len() > self.config.max_pending_items
                || self.pending_bytes > self.config.max_pending_bytes)
        {
            self.evict(order, bucket);
            kept = false;
        }
        kept
    }

    fn evict(&mut self, order: u64, bucket: Option<OpKey>) {
        self.unregister(order);
        self.forget(order);
        self.counters.refused += 1;
        match bucket.and_then(|k| self.authors.get_mut(&k)) {
            Some(a) => a.gap = true,
            None => self.gap_other = true,
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
        let mut out = self.evaluate(&item.bytes, &mut verified, now_ms, false);
        if out.own_conflict || matches!(out.eval, Eval::SelfFork) {
            self.forked = true;
        }
        if out.own_ahead {
            // Our own chain is known to reach this far: no signing below it.
            self.own_seen = self.own_seen.max(out.seq);
        }
        if let Eval::SelfFork = out.eval {
            // Follow the version of our old chain that the relay has, if
            // this op continues the part both versions share. What we wrote
            // on our own branch stays merged; `reset_identity` re-issues it.
            let adopt = self.evaluate(&item.bytes, &mut verified, now_ms, true);
            out.eval = match adopt.eval {
                Eval::Apply(ready) => {
                    if let Some(me) = self.authors.get_mut(&ready.author) {
                        me.ops
                            .truncate(usize::try_from(ready.seq - 1).unwrap_or(usize::MAX));
                    }
                    Eval::Apply(ready)
                }
                _ => Eval::Drop(Reject::Equivocation),
            };
        }
        if let Some(item) = self.pending.get_mut(&order) {
            item.verified = verified;
            item.bucket = out.bucket;
            item.seq = out.seq;
        }
        match out.eval {
            Eval::Wait(blocker, why) => {
                self.waiting.entry(blocker).or_default().push(order);
                Step::Waiting(why)
            }
            Eval::Later { wall_ms, lead } => {
                self.timed.insert((wall_ms, order));
                if let Some(a) = out.bucket.and_then(|k| self.authors.get_mut(&k)) {
                    a.clock_lead_ms = lead;
                }
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
            Eval::ClockReject { author, lead } => {
                self.forget(order);
                if let Some(a) = self.authors.get_mut(&author) {
                    a.clock_lead_ms = lead;
                }
                self.reject(Reject::ClockTooFarAhead);
                Step::Dropped(Reject::ClockTooFarAhead)
            }
            Eval::Equivocation { author, seq } => {
                if let Some(item) = self.forget(order) {
                    self.record_equivocation(author, seq, item.bytes);
                }
                self.reject(Reject::Equivocation);
                Step::Dropped(Reject::Equivocation)
            }
            // Resolved above.
            Eval::SelfFork => Step::Duplicate,
            Eval::Apply(ready) => {
                let Some(item) = self.forget(order) else {
                    return Step::Duplicate;
                };
                // `evaluate` checked the drift bound, so this is `Some`,
                // except for an op of our own (taken whatever its stamp):
                // there the clock must at least not fall behind our chain.
                self.clock = self
                    .clock
                    .observe(ready.hlc, now_ms, self.config.max_drift_ms)
                    .unwrap_or_else(|| self.clock.max(ready.hlc));
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
                    a.clock_lead_ms = 0;
                }
                self.counters.applied += 1;
                // The next op of the author, and any other copies or rivals
                // held for this position.
                for seq in [ready.seq, ready.seq.saturating_add(1)] {
                    if let Some(woken) = self.waiting.remove(&Blocker::Seq(ready.author, seq)) {
                        work.extend(woken);
                    }
                }
                Step::Applied
            }
        }
    }

    /// Decide what to do with a signed op. Pure: no state changes.
    ///
    /// An op is applicable when its author's key log is known and the
    /// author's previous op is applied. `deps` are not consulted: merge is a
    /// function of the set of ops, so nothing an op of *another* author does
    /// or fails to do can be a reason to withhold this one.
    ///
    /// With `adopt_own`, an op of this device's identity at or below its
    /// head is judged as if the head were just before it (see `step`).
    fn evaluate(
        &self,
        signed: &[u8],
        verified: &mut bool,
        now_ms: u64,
        adopt_own: bool,
    ) -> Outcome {
        let mut out = Outcome {
            eval: Eval::Duplicate,
            bucket: None,
            seq: u64::MAX,
            own_ahead: false,
            own_conflict: false,
        };
        let unverifiable = Eval::Wait(Blocker::Opaque, PendingReason::Unverifiable);
        let op = match Op::from_bytes(signed) {
            Ok(op) => op,
            // A newer format or hash: keep the bytes for a newer build.
            Err(DecodeError::UnsupportedFormat(_) | DecodeError::UnsupportedKind(_)) => {
                out.eval = unverifiable;
                return out;
            }
            Err(e) => {
                out.eval = Eval::Drop(Reject::Op(InvalidReason::Malformed(e)));
                return out;
            }
        };
        let body = op.body();
        out.eval = (|| {
            if body.fragment_id != self.fragment_id {
                return Eval::Drop(Reject::WrongFragment);
            }
            let (Some(id), Some(author_key)) = (
                OpKey::from_multihash(op.id()),
                OpKey::from_multihash(&body.author),
            ) else {
                return unverifiable;
            };
            out.bucket = Some(author_key);
            out.seq = body.seq;
            let seq = body.seq;
            let Some(author) = self.authors.get(&author_key) else {
                return Eval::Wait(Blocker::Author(author_key), PendingReason::UnknownAuthor);
            };
            let recorded = usize::try_from(seq)
                .ok()
                .and_then(|s| s.checked_sub(1))
                .and_then(|i| author.ops.get(i));
            if recorded == Some(&id) {
                return Eval::Duplicate;
            }
            let own = author_key == self.me;
            let head = if adopt_own && own && recorded.is_some() {
                seq - 1
            } else {
                author.ops.len() as u64
            };
            if !*verified {
                // The drift check is done below, where it can hold the op.
                match verify(signed, &VerifyCtx::new(&self.fragment_id, &author.log)) {
                    Verdict::Valid(_) => *verified = true,
                    // A position that is already settled needs no further
                    // copies; anything else is kept for a newer build.
                    Verdict::Unverifiable { .. } if seq <= head => {
                        return Eval::Drop(Reject::Unsupported);
                    }
                    Verdict::Unverifiable { .. } => {
                        return Eval::Wait(
                            Blocker::Seq(author_key, seq),
                            PendingReason::Unverifiable,
                        );
                    }
                    Verdict::Invalid { reason } => return Eval::Drop(Reject::Op(reason)),
                }
            }
            if seq <= head {
                // Every position up to `head` holds an applied op, and this
                // is not it: two validly signed ops at one `(author, seq)`.
                return if own {
                    Eval::SelfFork
                } else {
                    Eval::Equivocation {
                        author: author_key,
                        seq,
                    }
                };
            }
            out.own_ahead = own;
            let changes = match decode_payload(&body.payload) {
                Ok(c) => c,
                Err(e) => return Eval::Drop(Reject::Payload(e)),
            };
            if seq != head + 1 {
                return Eval::Wait(Blocker::Seq(author_key, seq), PendingReason::MissingPrev);
            }
            let before = usize::try_from(head)
                .ok()
                .and_then(|h| h.checked_sub(1))
                .and_then(|i| author.ops.get(i));
            let prev = body.prev.as_ref().map(OpKey::from_multihash);
            let linked = match (prev, before) {
                (None, None) => true,
                (Some(Some(p)), Some(last)) => p == *last,
                _ => false,
            };
            if !linked {
                out.own_conflict = own;
                return Eval::Drop(Reject::ChainFork);
            }
            // (When adopting, the HLC of the op before is no longer at hand;
            // the replicas that took this branch first checked it.)
            if head > 0 && head == author.ops.len() as u64 && body.hlc <= author.head_hlc {
                out.own_conflict = own;
                return Eval::Drop(Reject::HlcNotMonotonic);
            }
            // An op of our own was stamped by this device's clock and is
            // part of a chain we must rejoin before writing again: it is
            // taken as it is, even if the clock has since been set back.
            let lead = if own {
                0
            } else {
                body.hlc.wall_ms.saturating_sub(now_ms)
            };
            if lead > self.config.max_clock_ahead_ms.max(self.config.max_drift_ms) {
                return Eval::ClockReject {
                    author: author_key,
                    lead,
                };
            }
            if lead > self.config.max_drift_ms {
                return Eval::Later {
                    wall_ms: body.hlc.wall_ms,
                    lead,
                };
            }
            Eval::Apply(Ready {
                id,
                author: author_key,
                seq,
                hlc: body.hlc,
                changes,
            })
        })();
        out
    }

    fn record_equivocation(&mut self, author: OpKey, seq: u64, rejected: Vec<u8>) {
        let Some(a) = self.authors.get_mut(&author) else {
            return;
        };
        a.equivocated = true;
        if self.equivocations.iter().any(|e| e.rejected == rejected)
            || self.equivocations.len() >= MAX_EQUIVOCATIONS
        {
            return;
        }
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

    /// Take the first `count` items out of the outbox after the relay
    /// acknowledged them. Returns how many were taken.
    ///
    /// They are not forgotten yet: each is kept until the relay hands it
    /// back in a pull (an echo, which [`ingest`](Replica::ingest) recognises
    /// by its bytes), so that a relay that acknowledges and then loses its
    /// log can be given them again (see
    /// [`observe_relay_head`](Replica::observe_relay_head)). At most
    /// `max_unechoed_items` are kept; beyond that the oldest go.
    pub fn outbox_ack(&mut self, count: usize) -> usize {
        let n = count.min(self.outbox.len());
        for item in self.outbox.drain(..n) {
            self.unechoed
                .push_back((*blake3::hash(&item).as_bytes(), item));
        }
        while self.unechoed.len() > self.config.max_unechoed_items {
            self.unechoed.pop_front();
        }
        n
    }

    /// The pull cursor: ask the relay for items after this position.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Set the pull cursor.
    pub fn set_cursor(&mut self, cursor: u64) {
        self.cursor = cursor;
    }

    /// Tell the replica what the relay answered as `Batch.next` (the position
    /// of the last item the relay holds at or after the cursor it was asked
    /// about). Call it for every `Batch`, before or after ingesting its
    /// items.
    ///
    /// A relay never has fewer items than it has handed out, unless it lost
    /// its log and started numbering from 1 again. If `next` is below the
    /// replica's cursor, that is what happened: the cursor goes back to 0 (so
    /// that what other devices push to the new log is not skipped), every
    /// acknowledged item that was never seen echoed is put back at the front
    /// of the outbox, [`Stats::relay_resets`] is incremented and `true` is
    /// returned.
    ///
    /// This recovers what was in flight. It does not recover history: what
    /// only the relay held is gone (SYNC-V0 section 8).
    pub fn observe_relay_head(&mut self, next: u64) -> bool {
        if next >= self.cursor {
            return false;
        }
        self.cursor = 0;
        self.counters.relay_resets += 1;
        while let Some((_, item)) = self.unechoed.pop_back() {
            self.outbox.push_front(item);
        }
        true
    }

    /// `true` if an op was dropped because pending storage was full. The
    /// dropped op, and with it every later op of its author, can only be had
    /// by pulling again; replay is idempotent. The transport should call
    /// [`start_resync`](Replica::start_resync) and pull from the start, not
    /// at once but with a growing delay: if the reason the ops cannot apply
    /// has not gone (see [`authors`](Replica::authors)), the flag comes back.
    pub fn needs_resync(&self) -> bool {
        self.gap_other || self.authors.values().any(|a| a.gap)
    }

    /// Begin a resync: the pull cursor goes to 0 and
    /// [`needs_resync`](Replica::needs_resync) is cleared.
    pub fn start_resync(&mut self) {
        self.cursor = 0;
        self.gap_other = false;
        for a in self.authors.values_mut() {
            a.gap = false;
        }
    }

    /// Discard every pending op and return how many there were.
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
            clock_rejected: c.clock_rejected,
            authors_refused: c.authors_refused,
            relay_resets: c.relay_resets,
            authors: self.authors.len(),
            outbox: self.outbox.len(),
            unechoed: self.unechoed.len(),
            needs_resync: self.needs_resync(),
            forked: self.forked,
            own_ops_missing: self.own_seen.saturating_sub(
                self.authors.get(&self.me).map_or(0, |a| a.ops.len() as u64),
            ),
        }
    }

    /// Every author whose key log is known, ordered by author id: how far
    /// its chain has been applied and whether something is wrong with it.
    pub fn authors(&self) -> Vec<AuthorStatus> {
        self.authors
            .iter()
            .map(|(k, a)| AuthorStatus {
                author: k.to_multihash(),
                own: *k == self.me,
                applied_seq: a.ops.len() as u64,
                pending: self
                    .pending
                    .values()
                    .filter(|p| p.bucket == Some(*k))
                    .count(),
                gap: a.gap,
                clock_lead_ms: a.clock_lead_ms,
                equivocated: a.equivocated,
            })
            .collect()
    }

    /// Equivocation records, oldest first (at most [`MAX_EQUIVOCATIONS`]).
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    // ------------------------------------------------------------ state

    /// The whole replica state as deterministic CBOR (SYNC-V0 section 7).
    ///
    /// **The bytes contain the root secret and the device seed**, and
    /// [`from_bytes`](Replica::from_bytes) trusts them: store them under
    /// *authenticated* encryption, and in the same atomic write as the
    /// engine's data. The returned buffer is zeroized on drop.
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
                    Value::Bool(a.gap),
                    uint(a.clock_lead_ms),
                    Value::Bool(a.equivocated),
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
            Value::Array(vec![
                Value::Bool(self.forked),
                Value::Bool(self.gap_other),
                uint(self.own_seen),
            ]),
            Value::Array(authors),
            self.merge.to_value()?,
            Value::Array(self.pending.values().map(|p| bytes(&p.bytes)).collect()),
            Value::Array(self.outbox.iter().map(|o| bytes(o)).collect()),
            Value::Array(self.unechoed.iter().map(|(_, o)| bytes(o)).collect()),
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
                    c.clock_rejected,
                    c.authors_refused,
                    c.relay_resets,
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
    /// Strict about *form*: the bytes must be exactly what `to_bytes`
    /// produces for the state they describe (the restored replica is
    /// re-encoded and compared), every key log must verify, and the device's
    /// own identity must be among them.
    ///
    /// **Not a check of integrity.** Bytes that were changed into another
    /// well-formed state are accepted: a different cursor, a missing op in
    /// an author's list, an altered pending or outbox item, other merge
    /// stamps. Whoever can write the stored state can make the replica
    /// believe anything, so the state must be kept under authenticated
    /// encryption (an AEAD), not merely encrypted.
    ///
    /// Every pending op, including those held as
    /// [`PendingReason::Unverifiable`], is evaluated afresh by the next call
    /// that carries a clock, so a newer build gets to apply what an older
    /// one could only keep.
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
        if f.remaining() != 12 {
            return Err(BAD);
        }
        let root: Zeroizing<[u8; 32]> = Zeroizing::new(f.fixed().ok_or(BAD)?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(f.fixed().ok_or(BAD)?);
        let mut r = Replica::base(*root, *seed, config)?;
        r.clock = f.value().and_then(hlc_from).ok_or(BAD)?;
        r.cursor = f.u64().ok_or(BAD)?;
        let mut flags = Fields::exact(f.value().ok_or(BAD)?, 3).ok_or(BAD)?;
        r.forked = flags.bool().ok_or(BAD)?;
        r.gap_other = flags.bool().ok_or(BAD)?;
        r.own_seen = flags.u64().ok_or(BAD)?;

        let mut authors = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for a in f.array().ok_or(BAD)? {
            let mut a = Fields::exact(a, 7).ok_or(BAD)?;
            let log =
                KeyLog::genesis(a.bytes().ok_or(BAD)?).map_err(|_| Error::State("key log"))?;
            if log.fragment_id() != r.fragment_id {
                return Err(Error::State("key log of another fragment"));
            }
            let key = OpKey::from_multihash(log.author()).ok_or(Error::State("key log"))?;
            let mut ops = Vec::new();
            for id in a.array().ok_or(BAD)? {
                let id = OpKey::from_value(id).ok_or(BAD)?;
                if !seen.insert(id) {
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
                    gap: a.bool().ok_or(BAD)?,
                    clock_lead_ms: a.u64().ok_or(BAD)?,
                    equivocated: a.bool().ok_or(BAD)?,
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
                    bucket: None,
                    seq: u64::MAX,
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
        for o in f.array().ok_or(BAD)? {
            let Value::Bytes(b) = o else {
                return Err(BAD);
            };
            r.unechoed
                .push_back((*blake3::hash(b).as_bytes(), b.clone()));
        }
        let mut c = Fields::exact(f.value().ok_or(BAD)?, 11).ok_or(BAD)?;
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
            clock_rejected: next()?,
            authors_refused: next()?,
            relay_resets: next()?,
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
        // The secrets are top-level byte strings; the merge state below them
        // is not secret from whoever holds the fragment key.
        if let Value::Array(items) = &mut self.0 {
            for item in items.iter_mut() {
                if let Value::Bytes(b) = item {
                    b.zeroize();
                }
            }
        }
    }
}
