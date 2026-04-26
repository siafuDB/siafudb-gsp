// siafudb-sync/src/adapters/gspi.rs
//
// GSPI — Graph Sync Protocol Internal
//
// The third adapter, alongside GSPA (API) and GSPN (NTL).
//
// GSPI handles sync between SiafuDB instances running in the same
// process. This is the most common sync scenario in the architecture:
//
// - Phone: personal instance + Honeycomb network instance (same app)
// - Server: platform instance + analytics instance (same container)
// - Edge: regional instance + cache instance (same Durable Object)
//
// GSPI is the simplest adapter because there's no transport layer.
// Two instances are connected by a Rust channel. Mutations flow as
// native Rust types — no serialisation, no network, no authentication
// (same process = same trust boundary).
//
// The transformation layer still applies, because the two instances
// typically have different authority scopes. The personal instance
// holds sovereign data; the network instance holds public fragments.
// When a mutation flows from personal to network, PII must still be
// stripped. But the transformation happens on in-memory Rust structs,
// not on serialised JSON payloads, so it's dramatically faster than
// doing the same work in GSPA.
//
// Performance characteristics:
//   Latency: microseconds (channel send/receive)
//   Serialisation: none (native Rust types)
//   Memory: minimal (channel buffer + mutation struct)
//   CPU: transformation only (no encode/decode/encrypt/compress)
//   Battery: negligible (no radio, no network stack)
//
// This is the baseline that GSPA and GSPN are compared against.
// GSPI represents the theoretical minimum cost of sync — the cost
// of the protocol logic itself with zero transport overhead.

use crate::protocol::{MutationBatch, VectorClock};
use crate::protocol::transform::{
    ProjectedMutation, SyncRelationship, TransformEngine, TransformRule,
};
use siafudb_core::error::SiafuError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Configuration for a GSPI sync connection between two local instances.
#[derive(Debug, Clone)]
pub struct GspiConfig {
    /// Human-readable name for this internal connection.
    /// Examples: "personal→network", "platform→analytics"
    pub name: String,

    /// The instance ID of the source (the one producing mutations).
    pub source_instance: Uuid,

    /// The instance ID of the destination (the one receiving mutations).
    pub destination_instance: Uuid,

    /// The transformation rules to apply when mutations cross
    /// from source to destination. Even though both instances are
    /// in the same process, they typically have different authority
    /// scopes, so transformation is still necessary.
    ///
    /// Example: personal→network needs PII stripping.
    /// Example: platform→analytics needs anonymisation.
    /// Example: two personal instances (phone→tablet backup) needs
    ///          no transformation — full data passes through.
    pub transform_rules: Vec<TransformRule>,

    /// Channel buffer size. How many mutation batches can be queued
    /// before the sender blocks. Default: 1024.
    /// On constrained devices, reduce this to limit memory usage.
    /// On servers, increase for burst tolerance.
    pub channel_buffer: usize,

    /// Whether this connection is bidirectional.
    /// Most internal connections are unidirectional (personal→network)
    /// but some might be bidirectional (two personal instances syncing).
    pub bidirectional: bool,
}

/// A handle for sending mutations into an internal sync channel.
///
/// The source SiafuDB instance holds this handle and calls `send()`
/// whenever it produces a mutation that the destination should receive.
/// This is typically wired into the change log's mutation callback.
pub struct GspiSender {
    /// The configuration for this connection.
    config: GspiConfig,

    /// The sync relationship used for transformation.
    relationship: SyncRelationship,

    /// The actual channel sender.
    tx: mpsc::Sender<ProjectedMutation>,
}

/// A handle for receiving mutations from an internal sync channel.
///
/// The destination SiafuDB instance holds this handle and calls
/// `receive()` to get mutations that the source has produced.
/// This is typically wired into the sync engine's apply loop.
pub struct GspiReceiver {
    /// The actual channel receiver.
    rx: mpsc::Receiver<ProjectedMutation>,

    /// The source instance ID (for logging and diagnostics).
    source_instance: Uuid,
}

/// Create a GSPI connection between two SiafuDB instances.
///
/// Returns a sender (for the source instance) and a receiver
/// (for the destination instance). The caller is responsible for
/// wiring the sender into the source's change log callback and
/// the receiver into the destination's sync apply loop.
///
/// # Example
///
/// ```rust
/// // In the Mukoko app startup:
/// let personal_db = SiafuDB::open("personal.siafu")?;
/// let network_db = SiafuDB::open("network.siafu")?;
///
/// // Create internal sync: personal → network (with PII stripping)
/// let config = GspiConfig {
///     name: "personal→network".to_string(),
///     source_instance: personal_db.instance_id(),
///     destination_instance: network_db.instance_id(),
///     transform_rules: vec![
///         TransformRule::FilterByLabel {
///             include_labels: vec!["Review".into(), "Post".into()],
///             exclude_labels: vec!["Message".into(), "Preference".into()],
///         },
///         TransformRule::StripPII {
///             pii_properties: vec!["email".into(), "phone".into()],
///             hash_salt: "personal-to-network-salt".into(),
///         },
///     ],
///     channel_buffer: 1024,
///     bidirectional: false,
/// };
///
/// let (sender, receiver) = gspi_connect(config);
///
/// // Wire sender into personal_db's change log
/// // Wire receiver into network_db's sync apply loop
/// ```
pub fn gspi_connect(config: GspiConfig) -> (GspiSender, GspiReceiver) {
    let (tx, rx) = mpsc::channel(config.channel_buffer);

    // Build the sync relationship from the config's transform rules.
    let relationship = SyncRelationship {
        id: Uuid::new_v4(),
        name: config.name.clone(),
        peer_id: config.destination_instance,
        adapter_name: "gspi".to_string(),
        transform_rules: config.transform_rules.clone(),
        direction: if config.bidirectional {
            crate::protocol::transform::SyncDirection::Bidirectional
        } else {
            crate::protocol::transform::SyncDirection::Push
        },
        active: true,
    };

    let sender = GspiSender {
        config: config.clone(),
        relationship,
        tx,
    };

    let receiver = GspiReceiver {
        rx,
        source_instance: config.source_instance,
    };

    (sender, receiver)
}

impl GspiSender {
    /// Send a mutation batch through the internal channel.
    ///
    /// The batch is transformed according to the connection's rules
    /// before being sent. If the channel is full (destination is
    /// processing slowly), this will wait until space is available.
    ///
    /// This is the hot path for internal sync. It needs to be fast
    /// because it's called on every mutation from the source instance.
    /// The only work done here is transformation (which operates on
    /// in-memory Rust structs) and a channel send (which is a pointer
    /// copy into the channel buffer).
    pub async fn send(&self, batch: &MutationBatch) -> Result<(), SiafuError> {
        // Apply transformation rules.
        let projected = TransformEngine::project(batch, &self.relationship);

        let Some(mutations) = projected else {
            // All mutations filtered out — nothing relevant for the
            // destination. This is the common case: most personal
            // mutations (messages, preferences) aren't relevant to
            // the network instance. Only public content crosses.
            return Ok(());
        };

        // Send each projected mutation through the channel.
        for mutation in mutations {
            self.tx
                .send(mutation)
                .await
                .map_err(|e| SiafuError::SyncError(format!(
                    "GSPI channel closed for '{}': {}",
                    self.config.name, e
                )))?;
        }

        Ok(())
    }

    /// Try to send without waiting. Returns an error if the channel is full.
    ///
    /// Useful when you don't want the source instance's write path to
    /// block waiting for the destination. The mutation can be queued
    /// for retry or dropped depending on the application's preference.
    pub fn try_send(&self, batch: &MutationBatch) -> Result<(), SiafuError> {
        let projected = TransformEngine::project(batch, &self.relationship);

        let Some(mutations) = projected else {
            return Ok(());
        };

        for mutation in mutations {
            self.tx
                .try_send(mutation)
                .map_err(|e| SiafuError::SyncError(format!(
                    "GSPI channel full for '{}': {}",
                    self.config.name, e
                )))?;
        }

        Ok(())
    }

    /// The adapter name, for diagnostics.
    pub fn name(&self) -> &str {
        "gspi"
    }
}

impl GspiReceiver {
    /// Receive the next projected mutation from the channel.
    ///
    /// Blocks until a mutation is available or the channel is closed
    /// (source instance was dropped). The received mutation has already
    /// been transformed by the sender, so the receiver can apply it
    /// directly to its local graph without additional processing.
    pub async fn receive(&mut self) -> Option<ProjectedMutation> {
        self.rx.recv().await
    }

    /// Try to receive without waiting. Returns None if no mutation
    /// is available right now.
    pub fn try_receive(&mut self) -> Option<ProjectedMutation> {
        self.rx.try_recv().ok()
    }

    /// Drain all currently available mutations without waiting.
    ///
    /// Useful for batch processing — grab everything that's queued
    /// and apply it all at once, rather than processing one at a time.
    pub fn drain(&mut self) -> Vec<ProjectedMutation> {
        let mut mutations = Vec::new();
        while let Ok(m) = self.rx.try_recv() {
            mutations.push(m);
        }
        mutations
    }

    /// The source instance ID, for diagnostics.
    pub fn source_instance(&self) -> Uuid {
        self.source_instance
    }
}

impl Default for GspiConfig {
    fn default() -> Self {
        Self {
            name: "internal".to_string(),
            source_instance: Uuid::new_v4(),
            destination_instance: Uuid::new_v4(),
            transform_rules: vec![],
            channel_buffer: 1024,
            bidirectional: false,
        }
    }
}

// ============================================================
// THE THREE ADAPTERS — COMPLETE PICTURE
// ============================================================
//
// GSPI — Internal (same process)
//   Transport: Rust channel (mpsc)
//   Serialisation: None (native Rust types)
//   Discovery: Not needed (app creates both instances)
//   Authentication: Not needed (same trust boundary)
//   Transformation: In-memory struct manipulation
//   Latency: Microseconds
//   Use case: Personal ↔ Network on same phone
//             Platform ↔ Analytics on same server
//
// GSPA — API (network, traditional transport)
//   Transport: HTTP, gRPC, WebSocket, Kafka, Local TCP
//   Serialisation: JSON or protobuf
//   Discovery: mDNS for LAN, configured endpoints for WAN
//   Authentication: Mutual TLS with ed25519 keys
//   Transformation: Inside SiafuDB (TransformEngine)
//   Latency: Milliseconds (LAN) to seconds (WAN)
//   Use case: Device → Pod over internet
//             Platform → Doris over internal network
//             Device ↔ Device on same WiFi
//
// GSPN — NTL (network, signal-native transport)
//   Transport: NTL signal propagation
//   Serialisation: Zero-copy where possible
//   Discovery: NTL synapse topology
//   Authentication: NTL identity layer
//   Transformation: At NTL synapse level (not in SiafuDB)
//   Latency: Sub-millisecond local, milliseconds remote
//   Use case: Everything that GSPA does, but faster and simpler
//             The evolution target for all network sync
//
// A single SiafuDB instance can use all three simultaneously:
//   GSPI for internal sync with co-located instances
//   GSPA for sync with legacy systems and during NTL migration
//   GSPN for sync through the NTL network
//
// The sync protocol is identical across all three. Only the
// transport changes. Mutations look the same, conflict resolution
// works the same, vector clocks tick the same. The three adapters
// are three ways to carry the same protocol.
