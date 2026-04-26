// siafudb-sync/src/protocol/changelog.rs
//
// NOTE: this is the protocol-layer change log (cursors, mutation
// metadata) that pairs with siafudb-core's engine-level ChangeLog.
// The Mutation import below is staged for the M4 translation layer
// that turns engine ChangeLogEntry into a transport-ready Mutation.
// Remove the allow once M4 lands and the import becomes load-bearing.

#![allow(dead_code, unused_imports)]

// THE CHANGE LOG
//
// The change log is an append-only sequence of mutations produced by
// this SiafuDB instance. Every write to the graph appends a mutation
// to the log. The sync protocol reads from the log to determine what
// needs to be sent to other instances.
//
// The change log is the bridge between the database engine and the
// sync protocol. The engine writes to it; the protocol reads from it.
// This separation means the engine doesn't need to know about sync,
// and the sync doesn't need to know about the engine's internals.
//
// Each entry in the log has a monotonically increasing sequence number
// that the sync protocol uses as a cursor. When syncing with another
// instance, the protocol says "give me everything after sequence N"
// and the log returns the mutations in order. This is the same pattern
// that Kafka uses for consumer offsets, and it's efficient because
// it avoids scanning the entire log on every sync cycle.

use super::mutation::{Mutation, MutationBatch, VectorClock};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// The change log for a SiafuDB instance.
///
/// Append-only. Mutations go in, sync protocol reads them out.
/// The log is the source of truth for "what changed since last sync."
#[derive(Debug)]
pub struct ChangeLog {
    /// The instance this log belongs to.
    instance_id: Uuid,

    /// The current vector clock for this instance.
    /// Incremented with every mutation.
    clock: Arc<RwLock<VectorClock>>,

    /// The log entries, in order.
    /// In production, this would be backed by persistent storage
    /// (a dedicated section of the SiafuDB file). For now, in-memory.
    entries: Arc<RwLock<Vec<ChangeLogEntry>>>,

    /// The current sequence number (monotonically increasing).
    sequence: Arc<RwLock<u64>>,
}

/// A single entry in the change log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeLogEntry {
    /// Monotonically increasing sequence number.
    /// Sync protocol uses this as a cursor.
    pub sequence: u64,

    /// The mutation batch at this position.
    pub batch: MutationBatch,

    /// The vector clock at the time of this entry.
    pub clock_snapshot: VectorClock,
}

/// A cursor into the change log, used by the sync protocol
/// to track how far it has read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCursor {
    /// The instance this cursor is reading from.
    pub source_instance: Uuid,

    /// The last sequence number that was successfully synced.
    pub last_sequence: u64,
}

impl ChangeLog {
    /// Create a new change log for the given instance.
    pub fn new(instance_id: Uuid) -> Self {
        Self {
            instance_id,
            clock: Arc::new(RwLock::new(VectorClock::new())),
            entries: Arc::new(RwLock::new(Vec::new())),
            sequence: Arc::new(RwLock::new(0)),
        }
    }

    /// Append a mutation batch to the log.
    ///
    /// This is called by the database engine after every write.
    /// The sync protocol will pick up the entry on its next read.
    pub fn append(&self, batch: MutationBatch) -> u64 {
        let mut seq = self.sequence.write().unwrap();
        *seq += 1;
        let current_seq = *seq;

        let mut clock = self.clock.write().unwrap();
        clock.increment(self.instance_id);
        let clock_snapshot = clock.clone();

        let entry = ChangeLogEntry {
            sequence: current_seq,
            batch,
            clock_snapshot,
        };

        let mut entries = self.entries.write().unwrap();
        entries.push(entry);

        current_seq
    }

    /// Read all entries after the given sequence number.
    ///
    /// This is how the sync protocol catches up — "give me everything
    /// that happened after sequence N." Returns entries in order.
    pub fn read_after(&self, after_sequence: u64) -> Vec<ChangeLogEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.sequence > after_sequence)
            .cloned()
            .collect()
    }

    /// Get the current sequence number.
    pub fn current_sequence(&self) -> u64 {
        *self.sequence.read().unwrap()
    }

    /// Get the current vector clock.
    pub fn current_clock(&self) -> VectorClock {
        self.clock.read().unwrap().clone()
    }

    /// Compact the log by removing entries before the given sequence.
    ///
    /// Called after all sync peers have confirmed they've received
    /// entries up to this point. Keeps the log from growing unbounded.
    pub fn compact_before(&self, before_sequence: u64) {
        let mut entries = self.entries.write().unwrap();
        entries.retain(|e| e.sequence >= before_sequence);
    }
}
