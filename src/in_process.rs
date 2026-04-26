// Copyright (C) 2026 The Bundu Foundation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// siafudb-sync/src/in_process.rs
//
// In-process replicator — milestone 3.
//
// Drains entries from a source SiafuDB's change log and applies them to
// a destination SiafuDB in the same process, using an `mpsc` channel as
// the transport between producer and consumer halves. The channel is
// what makes this honest "channel transport" rather than a direct pull,
// even when the test runs on a single thread.
//
// Mutation translation, conflict resolution, and richer transports
// (HTTP, WebSocket, NTL signals) are later milestones — this exists to
// prove the engine + change log are sufficient to keep two instances
// in lockstep through a transport boundary.

use siafudb_core::{ChangeLogEntry, SiafuDB, SiafuError};
use std::sync::mpsc;

/// Tracks how far the destination has caught up to the source.
///
/// The replicator is intentionally stateless about the wire — every
/// `replicate()` call opens a fresh channel, drains, and closes. State
/// that survives across calls is just the cursor.
pub struct InProcessReplicator {
    cursor: u64,
}

impl Default for InProcessReplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl InProcessReplicator {
    pub fn new() -> Self {
        Self { cursor: 0 }
    }

    /// The last source-sequence the destination has caught up to.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Drain new entries from `source` since the last cursor, send them
    /// through an in-memory channel, and apply them on `destination`.
    /// Returns how many entries were applied.
    pub fn replicate(
        &mut self,
        source: &SiafuDB,
        destination: &SiafuDB,
    ) -> Result<usize, SiafuError> {
        let pending = {
            let log_handle = source.change_log();
            let log = log_handle
                .lock()
                .map_err(|e| SiafuError::SyncError(format!("source change log poisoned: {e}")))?;
            log.since(self.cursor)
        };

        if pending.is_empty() {
            return Ok(0);
        }

        let (tx, rx) = mpsc::channel::<ChangeLogEntry>();

        for entry in pending {
            tx.send(entry)
                .map_err(|e| SiafuError::SyncError(format!("channel send failed: {e}")))?;
        }
        drop(tx);

        let mut applied = 0usize;
        while let Ok(entry) = rx.recv() {
            destination.execute(&entry.query)?;
            self.cursor = entry.sequence;
            applied += 1;
        }

        Ok(applied)
    }
}
