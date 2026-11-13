//! # gsp-sync
//!
//! The GSP sync v0 replica (`docs/SYNC-V0.md`): pairing secrets, the op
//! payload, the merge rules, pending ops, the outbox and the pull cursor.
//!
//! This crate is a **sans-IO state machine**. It opens no sockets, reads no
//! clock and calls no random number generator: the caller passes `now_ms` and
//! the random bytes (root secret, device seed, one 24-byte nonce per sealed
//! item). It knows nothing about any database engine and builds for
//! `wasm32-unknown-unknown`.
//!
//! ## Who calls what
//!
//! An **engine adapter** owns the graph engine:
//!
//! - for every commit the engine makes, it calls
//!   [`Replica::local_commit`] with the commit's [`Change`]s and applies the
//!   (normally empty) list of corrections that comes back;
//! - it applies the `effects` of every [`Replica::ingest`] and
//!   [`Replica::poll`] to the engine, in order;
//! - it stores [`Replica::to_bytes`] in the same atomic write as the engine's
//!   data.
//!
//! A **transport** talks to the relay. One round:
//!
//! 1. push [`Replica::outbox_peek`], and on the relay's `Ack` call
//!    [`Replica::outbox_ack`];
//! 2. pull after [`Replica::cursor`]; hand `Batch.next` to
//!    [`Replica::observe_relay_head`] and every item, with its position, to
//!    [`Replica::ingest`]. Never stop at an item because of its status: the
//!    cursor moves past everything;
//! 3. if [`Replica::needs_resync`], schedule (with a growing delay) a
//!    [`Replica::start_resync`] followed by a pull from the start;
//! 4. if [`Replica::forked`], tell the application: the device has to
//!    [`Replica::reset_identity`] before it can write again.
//!
//! The relay token is per relay: [`Replica::relay_token`] takes the relay's
//! origin.
//!
//! ## Effects
//!
//! Effects are [`Change`]s read as instructions to an engine:
//!
//! - `NodePut` / `EdgePut`: create the entity if it is absent, add and remove
//!   the labels, set and unset the properties listed. Only what changed is
//!   listed; the first put of an entity carries everything it has.
//! - `NodeDel` / `EdgeDel`: remove the entity. Removing what is not there is
//!   not an error. An edge that is removed because an endpoint went away can
//!   come back with a later `EdgePut` (when its endpoints were re-fixed by an
//!   earlier put that arrived late); a removed node never comes back.
//!
//! Within one list the order is: node puts, edge deletes, edge puts, node
//! deletes. So an edge is never put before its endpoints exist and a node is
//! never deleted while the list still has to delete one of its edges. An
//! `EdgePut` for an edge the engine already holds always names the endpoints
//! and type the engine already has; when those change, the list holds an
//! `EdgeDel` followed by a full `EdgePut`.
//!
//! Property values come out of a replica in canonical form: map entries in
//! the order of the deterministic encoding, every NaN as the one canonical
//! NaN. `==` on [`Change`], [`NodeView`] and [`EdgeView`] is the derived one,
//! so it is sensitive to the in-memory order of map entries and treats NaN as
//! unequal to itself; the replica itself compares values by their encoding
//! when it decides whether something changed.
//!
//! ## How a replica stays live
//!
//! - **An op applies when its author's key log is known and the author's
//!   previous op is applied.** Nothing else gates it. `deps` are written
//!   (the heads of the other authors) as causal metadata and are not
//!   consulted, so one author's stuck or forked chain never holds back
//!   another author's ops.
//! - **The cursor always advances.** Whatever an item turns out to be, the
//!   replica does not ask for it again because of it.
//! - **Pending ops are bounded** per author and in total ([`Config`]). When a
//!   bound is hit an op is dropped ([`IngestStatus::PendingFull`]; for an
//!   author over its share, the op furthest from being applicable), the
//!   author is marked ([`AuthorStatus::gap`]) and [`Replica::needs_resync`]
//!   turns on. A resync replays the relay log from the start; replay is
//!   idempotent.
//! - **Clocks.** An op whose HLC leads `now_ms` by more than `max_drift_ms`
//!   is held ([`PendingReason::ClockAhead`]) and applied once local time has
//!   caught up; its timestamp is not merged into the local clock before
//!   that. One that leads by more than `max_clock_ahead_ms` (24 hours) is
//!   rejected ([`Reject::ClockTooFarAhead`]). Both show in
//!   [`AuthorStatus::clock_lead_ms`], so an application can say whose clock
//!   is wrong.
//! - **Unverifiable ops are kept** ([`PendingReason::Unverifiable`]), within
//!   the same bounds, and evaluated again after a restore.
//! - **Rollback is detected.** See [`Replica::forked`].
//!
//! ## Other decisions where SYNC-V0 leaves room
//!
//! - **Not handled in v0**, dropped and counted in [`Stats::unsupported`]:
//!   batches (kind 2) and key-log entries other than a genesis. v0 has no
//!   key rotation or revocation, so a key log is its genesis entry.
//! - **Node and edge gids are separate namespaces.** A node tombstone does
//!   not tombstone an edge with the same gid.
//! - **Stamp order** is `(hlc.wall_ms, hlc.counter, hash algorithm id, digest
//!   bytes)`; changes within one op are ordered by position (see the `merge`
//!   module source).
//!
//! ## Not audited
//!
//! Like the wire crate under it, this is new, unreviewed code.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod change;
mod cv;
mod merge;
mod pairing;
mod replica;

pub use change::{
    Change, Gid, MAX_CHANGES, MAX_NAME_BYTES, MAX_PAYLOAD_BYTES, PayloadError, decode_payload,
    encode_payload,
};
pub use merge::{EdgeView, NodeView};
pub use pairing::{
    CTX_FRAGMENT_ID, CTX_FRAGMENT_KEY, CTX_RELAY_TOKEN, FRAGMENT_ID_LEN, OriginError,
    PAIRING_PREFIX, Pairing, PairingError, base64url, canonical_origin,
};
pub use replica::{
    AuthorStatus, Config, Equivocation, Error, IngestOutcome, IngestStatus, MAX_EQUIVOCATIONS,
    MAX_SEALED_BYTES, PendingReason, Reject, Replica, Stats,
};
