// siafudb-sync/src/adapters/gspn.rs
//
// NOTE: Mutation import is staged for M5 (signal emission/reception
// through NTL). Remove the allow once that body populates.

#![allow(dead_code, unused_imports)]

// GSPN — Graph Sync Protocol with NTL
//
// The signal-native adapter. SiafuDB becomes a neuron in the NTL network.
//
// In GSPN mode, the interaction model is fundamentally different from GSPA:
//
// GSPA: push mutations to endpoint, pull mutations from endpoint.
//       Transformations happen inside SiafuDB before transmission.
//       Request-response. Connection-oriented. Endpoint-addressed.
//
// GSPN: emit signals into the NTL network, receive signals from it.
//       Transformations happen at NTL synapses, not inside SiafuDB.
//       Fire-and-forget. Connectionless. Topology-routed.
//
// What this gives you:
//
// - No serialisation overhead: NTL signals share Rust memory layout
//   with SiafuDB mutations. Zero-copy where possible.
//
// - No connection management: no HTTP connections to maintain, no
//   TLS session caches, no keepalive traffic. Synapses are logical,
//   not physical connections.
//
// - No endpoint configuration: SiafuDB doesn't need to know where
//   its peers are. It emits signals, and NTL's synapse topology
//   routes them. If a peer moves or goes offline, the network
//   adapts without SiafuDB knowing.
//
// - No transformation logic in SiafuDB: the database emits full
//   signals, and NTL synapses handle PII stripping, anonymisation,
//   and filtering based on synapse properties. If privacy rules
//   change, you update synapse config in NTL, not SiafuDB instances
//   on millions of devices.
//
// - Fire-and-forget writes: SiafuDB emits a signal and immediately
//   returns. No round-trip wait. The write path is never blocked
//   by network latency. For AI agents rapidly updating context,
//   this is the difference between fluid and stuttering.
//
// GSPN ships after GSPA. Individual sync relationships migrate
// from GSPA to GSPN as NTL matures. Both coexist indefinitely.

use crate::protocol::{Mutation, MutationBatch};
use siafudb_core::error::SiafuError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Configuration for a GSPN sync connection.
///
/// Much simpler than GspaConfig because the complexity lives in
/// NTL's synapse configuration, not in SiafuDB. SiafuDB just needs
/// to know how to connect to the local NTL node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspnConfig {
    /// The local NTL node endpoint.
    /// This is the NTL runtime running on the same device or in the
    /// same process. SiafuDB talks to its local NTL node, and NTL
    /// handles all network routing from there.
    pub ntl_endpoint: String,

    /// The signal type prefix for graph sync signals.
    /// Signals emitted by SiafuDB are typed so that NTL can route
    /// them to the right synapses. Default: "graph.sync"
    pub signal_type_prefix: String,

    /// This instance's identity in the NTL network.
    /// Used to register as a signal emitter/receiver with the local
    /// NTL node.
    pub instance_id: Uuid,

    /// Whether to include the full mutation payload in signals.
    /// When true (default), signals carry the complete mutation data.
    /// When false, signals carry only a reference, and receivers
    /// fetch the full data through a separate mechanism. Useful for
    /// very large mutations (e.g., bulk imports) where signal size
    /// matters.
    pub include_payload: bool,
}

/// A signal that SiafuDB emits into the NTL network.
///
/// This is the unit of communication in GSPN mode. Unlike GSPA's
/// projected mutations (which are destination-specific), a GSPN
/// signal is emitted once and the network handles routing and
/// transformation. SiafuDB doesn't know or care how many
/// destinations receive it or what transformations are applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSyncSignal {
    /// The signal type (e.g., "graph.sync.vertex.created").
    /// NTL uses this for routing — synapses subscribe to signal
    /// types they care about.
    pub signal_type: String,

    /// The mutation batch that triggered this signal.
    /// This is the FULL mutation, untransformed. NTL synapses
    /// handle any needed transformation (PII strip, anonymise)
    /// based on their configuration.
    pub batch: MutationBatch,

    /// The weight of this signal.
    /// Higher weight signals propagate more aggressively through
    /// the network. Real-time user actions (messages, posts) get
    /// high weight. Background analytics get low weight.
    /// NTL uses weight for prioritisation and flow control.
    pub weight: f32,

    /// The source fragment ID.
    /// Lets NTL route based on fragment topology — signals from
    /// personal fragments route differently than signals from
    /// platform fragments.
    pub source_fragment: Uuid,
}

/// The GSPN adapter instance.
///
/// Manages SiafuDB's connection to the local NTL node.
/// Unlike GSPA (which has one adapter per peer), GSPN has ONE
/// adapter that connects to the NTL network. The network handles
/// peer relationships through synapses.
pub struct GspnAdapter {
    /// Configuration for the NTL connection.
    config: GspnConfig,

    /// Whether we're connected to the local NTL node.
    connected: bool,
    // In a full implementation, this would hold:
    // - The NTL client connection
    // - A signal receiver channel for incoming signals
    // - Metrics (signals emitted, signals received, latency)
}

impl GspnAdapter {
    /// Create a new GSPN adapter.
    pub fn new(config: GspnConfig) -> Self {
        Self {
            config,
            connected: false,
        }
    }

    /// The adapter's name, used in logs and diagnostics.
    pub fn name(&self) -> &str {
        "gspn"
    }

    /// Connect to the local NTL node.
    ///
    /// This registers SiafuDB as a signal emitter and receiver
    /// with the NTL runtime. After connecting, SiafuDB can emit
    /// signals and will receive signals routed to it by the network.
    pub async fn connect(&mut self) -> Result<(), SiafuError> {
        // TODO: Connect to NTL runtime at config.ntl_endpoint.
        // Register signal types we emit: graph.sync.*
        // Register signal types we receive: graph.sync.*
        // The NTL runtime handles all network-level concerns
        // (peer discovery, synapse management, routing) from here.
        tracing::info!(
            "GSPN: connecting to NTL node at {}",
            self.config.ntl_endpoint
        );
        self.connected = true;
        Ok(())
    }

    /// Emit a graph mutation as an NTL signal.
    ///
    /// This is the core GSPN operation. The mutation is wrapped in
    /// a signal and emitted into the NTL network. SiafuDB does NOT:
    /// - Choose a destination (NTL routes based on synapse topology)
    /// - Transform the data (NTL synapses handle transformation)
    /// - Wait for acknowledgment (fire-and-forget with delivery guarantees)
    /// - Manage connections (NTL handles network-level concerns)
    ///
    /// SiafuDB just says "this happened" and the network takes it from there.
    /// This is what makes GSPN fundamentally different from GSPA.
    pub async fn emit(&self, batch: MutationBatch, weight: f32) -> Result<(), SiafuError> {
        if !self.connected {
            return Err(SiafuError::SyncError(
                "GSPN: not connected to NTL node".to_string(),
            ));
        }

        let signal_type = self.classify_signal(&batch);

        let signal = GraphSyncSignal {
            signal_type,
            batch,
            weight,
            source_fragment: self.config.instance_id,
        };

        // TODO: Emit signal to NTL runtime.
        // The NTL client library would provide something like:
        //   ntl_client.emit(signal).await
        //
        // This returns immediately. NTL handles delivery asynchronously.
        // If the network is unavailable, NTL queues the signal locally
        // and delivers it when connectivity returns.
        tracing::info!(
            "GSPN: emitting signal type={} weight={:.2}",
            signal.signal_type,
            signal.weight,
        );

        Ok(())
    }

    /// Receive incoming signals from the NTL network.
    ///
    /// In a full implementation, this would be a stream/channel that
    /// the sync engine reads from continuously. Signals arrive as
    /// other SiafuDB instances (or other graph databases with NTL
    /// adapters) emit mutations that are routed to this instance
    /// by the NTL synapse topology.
    ///
    /// The signals arriving here have ALREADY been transformed by
    /// NTL synapses. If a synapse is configured to strip PII, the
    /// signal arrives here already stripped. SiafuDB doesn't need
    /// to know about the transformation — it just applies what arrives.
    pub async fn receive(&self) -> Result<Option<GraphSyncSignal>, SiafuError> {
        if !self.connected {
            return Err(SiafuError::SyncError(
                "GSPN: not connected to NTL node".to_string(),
            ));
        }

        // TODO: Read from NTL signal receiver channel.
        // The NTL client library would provide something like:
        //   ntl_client.receive().await -> Option<Signal>
        //
        // This blocks until a signal arrives or a timeout occurs.
        // In production, this would be a tokio channel or similar.
        Ok(None)
    }

    /// Classify a mutation batch into an NTL signal type.
    ///
    /// Signal types are hierarchical strings that NTL uses for routing.
    /// Synapses subscribe to signal type patterns (e.g., "graph.sync.vertex.*")
    /// so that they only receive relevant signals.
    fn classify_signal(&self, batch: &MutationBatch) -> String {
        use crate::protocol::MutationType;

        // Classify based on the first mutation in the batch.
        // In practice, batches are usually homogeneous (all vertex creates,
        // or all edge creates) because they represent a single user action.
        let prefix = &self.config.signal_type_prefix;

        match batch.mutations.first().map(|m| &m.operation) {
            Some(MutationType::VertexCreated { labels, .. }) => {
                let label = labels.first().map(|l| l.as_str()).unwrap_or("unknown");
                format!("{}.vertex.created.{}", prefix, label.to_lowercase())
            }
            Some(MutationType::VertexUpdated { .. }) => {
                format!("{}.vertex.updated", prefix)
            }
            Some(MutationType::VertexDeleted { .. }) => {
                format!("{}.vertex.deleted", prefix)
            }
            Some(MutationType::EdgeCreated { edge_type, .. }) => {
                format!("{}.edge.created.{}", prefix, edge_type.to_lowercase())
            }
            Some(MutationType::EdgeUpdated { .. }) => {
                format!("{}.edge.updated", prefix)
            }
            Some(MutationType::EdgeDeleted { .. }) => {
                format!("{}.edge.deleted", prefix)
            }
            None => format!("{}.empty", prefix),
        }
    }

    /// Check whether the NTL network is available.
    pub async fn is_available(&self) -> bool {
        self.connected
    }
}

impl Default for GspnConfig {
    fn default() -> Self {
        Self {
            ntl_endpoint: String::from("ntl://localhost:4222"),
            signal_type_prefix: String::from("graph.sync"),
            instance_id: Uuid::new_v4(),
            include_payload: true,
        }
    }
}

// ============================================================
// SIDE-BY-SIDE COMPARISON: GSPA vs GSPN
// ============================================================
//
// The same scenario — Tatenda likes Amara's review — handled by each:
//
// GSPA:
//   1. Mutation written to Tatenda's SiafuDB change log
//   2. Sync engine reads mutation from change log
//   3. For EACH sync relationship:
//      a. TransformEngine applies rules (strip PII, anonymise, filter)
//      b. Projected mutation serialised to JSON
//      c. HTTP POST to peer endpoint
//      d. Wait for 200 OK acknowledgment
//      e. Update cursor on success, queue for retry on failure
//   4. Three sync relationships = three HTTP requests, three waits,
//      three serialisations, three sets of transformation rules
//      maintained inside SiafuDB
//
// GSPN:
//   1. Mutation written to Tatenda's SiafuDB change log
//   2. Sync engine reads mutation from change log
//   3. ONE signal emitted into NTL network (full mutation, untransformed)
//   4. NTL network routes signal through synapses:
//      - Synapse to pod: full signal passes through unchanged
//      - Synapse to analytics: signal transformed (PII stripped) at synapse
//      - Synapse to content owner: signal transformed (anonymised) at synapse
//   5. SiafuDB is done. No waiting. No per-destination logic.
//      NTL handles everything from step 3 onward.
//
// The difference:
//   GSPA: 3 serialisations, 3 HTTP round trips, 3 transform evaluations,
//         3 connection states, 3 retry queues, SiafuDB knows about all peers.
//   GSPN: 1 signal emission, 0 round trips, 0 transform evaluations in DB,
//         0 connection states, NTL handles delivery, SiafuDB knows nothing
//         about peers.
//
// That's not a marginal improvement. That's a categorical difference
// in complexity, latency, memory, and battery impact.
