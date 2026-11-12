// siafudb-sync/src/protocol/channel.rs
//
// NOTE: the InProcessChannel struct fields (name, relationship, tx, rx)
// and the VectorClock / ProjectedMutation / SyncCursor imports are used
// by the channel send/recv implementation that arrives with the M4
// mutation-translation work and the M3 follow-on bidirectional sync.
// Remove the allow once those code paths are live.

#![allow(dead_code, unused_imports)]

// THE GRAPH SYNC CHANNEL
//
// This is the universal primitive that the entire Graph Sync Protocol
// is built on. A channel connects two endpoints — a producer that emits
// mutations and a consumer that receives them. The protocol doesn't know
// or care how the channel moves data between the two ends. It just sends
// and receives.
//
// The channel abstraction unifies what were previously three separate
// adapters (GSPI, GSPA, GSPN) into one protocol with pluggable transport:
//
//   Channel<InProcess>  — Rust mpsc channel. Same process. Zero overhead.
//                         This is what two SiafuDB instances on the same
//                         phone use to sync personal ↔ network data.
//
//   Channel<Api>        — HTTP, gRPC, WebSocket, Kafka, local TCP.
//                         Traditional request-response transport. Works
//                         with every existing system.
//
//   Channel<Ntl>        — NTL signal propagation. The channel IS the
//                         synapse. Transformation happens at the channel
//                         level (in the synapse), not in the protocol.
//                         The neural-native transport.
//
// From the protocol's perspective, all three are the same thing:
//
//   channel.send(mutation).await
//   let mutation = channel.receive().await
//
// The protocol configures transformation rules on the channel, and the
// channel applies them in whatever way is appropriate for its transport.
// An InProcess channel transforms in-memory Rust structs. An Api channel
// transforms before serialisation. An Ntl channel delegates transformation
// to the NTL synapse layer.
//
// This is also the foundation for NTL itself. NTL's internal runtime
// is built from these same channel primitives — the in-process channel
// is NTL's innermost transport layer, and each successive layer (local,
// network, fabric) wraps the channel abstraction with additional
// capabilities. Building NTL on this foundation means NTL and SiafuDB
// share the same primitive, which eliminates impedance mismatch between
// the database and the transfer layer.

use super::changelog::SyncCursor;
use super::mutation::{MutationBatch, VectorClock};
use super::transform::{
    ProjectedMutation, SyncDirection, SyncRelationship, TransformEngine, TransformRule,
};
use serde::{Deserialize, Serialize};
use siafudb_core::error::SiafuError;
use std::fmt;
use uuid::Uuid;

// ============================================================
// THE CHANNEL TRAIT — THE UNIVERSAL SYNC INTERFACE
// ============================================================

/// The universal interface for the Graph Sync Protocol.
///
/// Every sync connection — whether internal, over API, or through NTL —
/// implements this trait. The protocol operates entirely through this
/// interface and never needs to know what transport is underneath.
///
/// A SyncChannel is one half of a connection. The producing side gets
/// a SyncChannel that it calls `send()` on. The consuming side gets a
/// SyncChannel that it calls `receive()` on. Some channel implementations
/// are bidirectional (both sides can send and receive); others are
/// unidirectional.
///
/// Transformation rules are configured on the channel itself. When a
/// mutation is sent, the channel applies the rules before delivering
/// to the other end. This means:
/// - InProcess channels transform in-memory (fastest possible)
/// - API channels transform before serialisation (no double work)
/// - NTL channels delegate to synapse-level transformation
///
/// The channel is also the primitive that NTL is built from. NTL's
/// runtime uses channels internally at every layer of its transport
/// hierarchy, which means NTL and SiafuDB share the same foundational
/// abstraction.
#[async_trait::async_trait]
pub trait SyncChannel: Send + Sync {
    /// Send a mutation batch through the channel.
    ///
    /// The channel handles transformation, serialisation (if needed),
    /// and transport. The caller just provides the raw mutation batch
    /// and the channel does the rest.
    ///
    /// Returns Ok(()) when the mutation has been accepted by the channel.
    /// For InProcess channels, this means it's in the receiver's buffer.
    /// For API channels, this means the peer acknowledged receipt.
    /// For NTL channels, this means the signal was emitted (fire-and-forget).
    async fn send(&self, batch: MutationBatch) -> Result<(), SiafuError>;

    /// Receive the next mutation batch from the channel.
    ///
    /// Blocks until a mutation is available, the channel is closed,
    /// or a timeout occurs. The received mutation has already been
    /// transformed by the channel — the receiver applies it directly
    /// to its local graph without additional processing.
    ///
    /// Returns None if the channel is closed (the other end disconnected).
    async fn receive(&self) -> Result<Option<MutationBatch>, SiafuError>;

    /// Check whether the channel is currently connected and usable.
    ///
    /// For InProcess: always true while both ends exist.
    /// For API: true if the peer is reachable.
    /// For NTL: true if the local NTL node is running.
    fn is_connected(&self) -> bool;

    /// The transport type of this channel (for diagnostics and logging).
    fn transport(&self) -> ChannelTransport;

    /// The name of this channel (for diagnostics and logging).
    fn name(&self) -> &str;
}

/// The transport type underlying a sync channel.
///
/// Used for diagnostics, logging, and metrics. The protocol doesn't
/// branch on this — it treats all channels identically through the
/// SyncChannel trait. But operators need to know what transport is
/// in use for troubleshooting and capacity planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelTransport {
    /// Rust mpsc channel. Same process. Zero overhead.
    InProcess,

    /// HTTP/HTTPS with JSON or binary payloads.
    Http,

    /// gRPC with protobuf payloads.
    Grpc,

    /// WebSocket for bidirectional real-time sync.
    WebSocket,

    /// Kafka producer/consumer.
    Kafka,

    /// Direct TCP on local network (binary format, mutual TLS).
    LocalTcp,

    /// NTL signal propagation through the neural transfer layer.
    Ntl,
}

impl fmt::Display for ChannelTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProcess => write!(f, "in-process"),
            Self::Http => write!(f, "http"),
            Self::Grpc => write!(f, "grpc"),
            Self::WebSocket => write!(f, "websocket"),
            Self::Kafka => write!(f, "kafka"),
            Self::LocalTcp => write!(f, "local-tcp"),
            Self::Ntl => write!(f, "ntl"),
        }
    }
}

// ============================================================
// CHANNEL CONFIGURATION
// ============================================================

/// Configuration for creating a sync channel.
///
/// This is the unified configuration that replaces GspiConfig, GspaConfig,
/// and GspnConfig. The transport field determines which channel
/// implementation is created; the rest of the config is shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Human-readable name for this channel.
    /// Examples: "personal→network", "device→pod", "platform→doris"
    pub name: String,

    /// The transport to use.
    pub transport: ChannelTransport,

    /// Transport-specific configuration.
    /// Only the fields relevant to the chosen transport need to be set.
    pub transport_config: TransportConfig,

    /// The transformation rules applied to mutations as they flow
    /// through this channel. The rules determine what the receiving
    /// end sees — full data, PII-stripped, anonymised, filtered, etc.
    ///
    /// For InProcess and API channels, SiafuDB applies these rules
    /// before sending. For NTL channels, these rules are exported as
    /// synapse properties and NTL applies them at the network level.
    pub transform_rules: Vec<TransformRule>,

    /// The direction of data flow through this channel.
    pub direction: SyncDirection,

    /// The buffer size for the channel.
    /// For InProcess: the mpsc channel capacity.
    /// For API: the outbound mutation queue size.
    /// For NTL: the signal emission queue size.
    pub buffer_size: usize,
}

/// Transport-specific configuration.
///
/// Each transport has its own requirements (API needs an endpoint URL,
/// NTL needs a node address, InProcess needs nothing). This struct
/// carries whatever the transport needs, and irrelevant fields are
/// ignored for transports that don't use them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransportConfig {
    /// The remote endpoint URL (for HTTP, gRPC, WebSocket).
    /// Ignored for InProcess and NTL.
    pub endpoint: Option<String>,

    /// Kafka brokers and topic (for Kafka transport).
    pub kafka_brokers: Option<String>,
    pub kafka_topic: Option<String>,

    /// The local NTL node address (for NTL transport).
    /// Ignored for all non-NTL transports.
    pub ntl_endpoint: Option<String>,

    /// Whether to compress payloads (for network transports).
    /// Ignored for InProcess.
    pub compress: bool,

    /// Authentication token (for API transports).
    /// Ignored for InProcess and NTL (which have their own auth).
    pub auth_token: Option<String>,

    /// Sync interval in seconds (for polling-based transports).
    /// None means sync immediately or on explicit trigger.
    /// Ignored for InProcess (which is immediate by nature).
    pub sync_interval_seconds: Option<u64>,

    /// NTL signal weight (for NTL transport).
    /// Higher weight signals propagate more aggressively.
    /// Ignored for non-NTL transports.
    pub ntl_signal_weight: Option<f32>,
}

// ============================================================
// IN-PROCESS CHANNEL IMPLEMENTATION
// ============================================================

/// An in-process sync channel using a Rust mpsc channel.
///
/// This is the fastest possible sync — mutations move as native Rust
/// types through a tokio channel with no serialisation, no network,
/// and no overhead beyond the channel's own synchronisation.
///
/// This is also the innermost layer of NTL's transport hierarchy.
/// When NTL's runtime manages in-process communication, it uses
/// this same channel underneath. Building NTL on this foundation
/// means there's zero impedance mismatch between SiafuDB and NTL
/// at the in-process level.
pub struct InProcessChannel {
    /// Channel name for diagnostics.
    name: String,

    /// The sync relationship (carries transformation rules).
    relationship: SyncRelationship,

    /// Sender half of the mpsc channel.
    tx: tokio::sync::mpsc::Sender<MutationBatch>,

    /// Receiver half of the mpsc channel (wrapped in a mutex for
    /// shared access — in practice, only one consumer reads).
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<MutationBatch>>,
}

/// Create a pair of in-process channels for bidirectional sync
/// between two SiafuDB instances in the same process.
///
/// Returns (channel_a, channel_b) where:
/// - channel_a.send() delivers to channel_b.receive()
/// - channel_b.send() delivers to channel_a.receive()
///
/// Each direction has its own transformation rules, because the
/// data flowing from personal→network needs different treatment
/// than data flowing from network→personal.
pub fn create_in_process_pair(
    name_a_to_b: &str,
    name_b_to_a: &str,
    rules_a_to_b: Vec<TransformRule>,
    rules_b_to_a: Vec<TransformRule>,
    buffer_size: usize,
) -> (InProcessChannel, InProcessChannel) {
    let (tx_a, rx_a) = tokio::sync::mpsc::channel(buffer_size);
    let (tx_b, rx_b) = tokio::sync::mpsc::channel(buffer_size);

    let channel_a = InProcessChannel {
        name: name_a_to_b.to_string(),
        relationship: build_relationship(name_a_to_b, &rules_a_to_b),
        tx: tx_b,                          // A sends to B's receiver
        rx: tokio::sync::Mutex::new(rx_a), // A receives from B's sender
    };

    let channel_b = InProcessChannel {
        name: name_b_to_a.to_string(),
        relationship: build_relationship(name_b_to_a, &rules_b_to_a),
        tx: tx_a,                          // B sends to A's receiver
        rx: tokio::sync::Mutex::new(rx_b), // B receives from A's sender
    };

    (channel_a, channel_b)
}

/// Create a unidirectional in-process channel (source → destination).
///
/// The source calls send(), the destination calls receive().
/// Used when data only flows one direction (e.g., platform → analytics).
pub fn create_in_process_channel(
    name: &str,
    transform_rules: Vec<TransformRule>,
    buffer_size: usize,
) -> (InProcessSender, InProcessReceiver) {
    let (tx, rx) = tokio::sync::mpsc::channel(buffer_size);
    let relationship = build_relationship(name, &transform_rules);

    let sender = InProcessSender {
        name: name.to_string(),
        relationship,
        tx,
    };

    let receiver = InProcessReceiver {
        name: name.to_string(),
        rx,
    };

    (sender, receiver)
}

/// The sending half of a unidirectional in-process channel.
pub struct InProcessSender {
    name: String,
    relationship: SyncRelationship,
    tx: tokio::sync::mpsc::Sender<MutationBatch>,
}

/// The receiving half of a unidirectional in-process channel.
pub struct InProcessReceiver {
    name: String,
    rx: tokio::sync::mpsc::Receiver<MutationBatch>,
}

impl InProcessSender {
    /// Send a mutation batch, applying transformation rules first.
    ///
    /// This is the hot path. The only work done here is:
    /// 1. Transform the batch (in-memory struct manipulation)
    /// 2. Send through the mpsc channel (pointer copy into buffer)
    ///
    /// If transformation filters out all mutations (e.g., a personal
    /// preference update isn't relevant to the network instance),
    /// the send is a no-op.
    pub async fn send(&self, batch: &MutationBatch) -> Result<(), SiafuError> {
        // Apply transformation rules.
        let projected = TransformEngine::project(batch, &self.relationship);

        let Some(mutations) = projected else {
            // All mutations filtered out — nothing relevant for the receiver.
            return Ok(());
        };

        // Reconstruct a MutationBatch from the projected mutations.
        // In the in-process case, we could optimise this further by
        // passing ProjectedMutation directly, but using MutationBatch
        // keeps the channel interface uniform across all transports.
        let projected_batch = MutationBatch {
            id: batch.id,
            mutations: mutations.into_iter().map(|pm| pm.mutation).collect(),
            atomic: batch.atomic,
        };

        self.tx
            .send(projected_batch)
            .await
            .map_err(|e| SiafuError::SyncError(format!("Channel '{}' closed: {}", self.name, e)))?;

        Ok(())
    }

    /// Try to send without waiting. Returns error if channel is full.
    pub fn try_send(&self, batch: &MutationBatch) -> Result<(), SiafuError> {
        let projected = TransformEngine::project(batch, &self.relationship);

        let Some(mutations) = projected else {
            return Ok(());
        };

        let projected_batch = MutationBatch {
            id: batch.id,
            mutations: mutations.into_iter().map(|pm| pm.mutation).collect(),
            atomic: batch.atomic,
        };

        self.tx
            .try_send(projected_batch)
            .map_err(|e| SiafuError::SyncError(format!("Channel '{}' full: {}", self.name, e)))?;

        Ok(())
    }
}

impl InProcessReceiver {
    /// Receive the next mutation batch. Blocks until available.
    pub async fn receive(&mut self) -> Option<MutationBatch> {
        self.rx.recv().await
    }

    /// Try to receive without blocking.
    pub fn try_receive(&mut self) -> Option<MutationBatch> {
        self.rx.try_recv().ok()
    }

    /// Drain all currently queued batches.
    pub fn drain(&mut self) -> Vec<MutationBatch> {
        let mut batches = Vec::new();
        while let Ok(batch) = self.rx.try_recv() {
            batches.push(batch);
        }
        batches
    }
}

// ============================================================
// HELPER
// ============================================================

fn build_relationship(name: &str, rules: &[TransformRule]) -> SyncRelationship {
    SyncRelationship {
        id: Uuid::new_v4(),
        name: name.to_string(),
        peer_id: Uuid::nil(),
        adapter_name: "channel".to_string(),
        transform_rules: rules.to_vec(),
        direction: SyncDirection::Push,
        active: true,
    }
}

// ============================================================
// THE UNIFIED PICTURE
// ============================================================
//
// The Graph Sync Protocol is one protocol. The channel is its
// universal interface. Transport is pluggable.
//
// ┌─────────────────────────────────────────────────┐
// │           Graph Sync Protocol                    │
// │  (mutations, vector clocks, conflict resolution) │
// └──────────────────────┬──────────────────────────┘
//                        │
//              ┌─────────▼──────────┐
//              │   SyncChannel      │
//              │   send() / receive()│
//              └─────────┬──────────┘
//                        │
//          ┌─────────────┼──────────────┐
//          │             │              │
//   ┌──────▼──────┐ ┌───▼────┐ ┌───────▼──────┐
//   │  InProcess  │ │  API   │ │     NTL      │
//   │  (channel)  │ │ (HTTP) │ │  (signal)    │
//   │             │ │ (gRPC) │ │              │
//   │  Same       │ │ (WS)  │ │  Synapse     │
//   │  process    │ │ (Kafka)│ │  topology    │
//   │             │ │ (TCP)  │ │  routing     │
//   │  Zero       │ │        │ │              │
//   │  overhead   │ │ Legacy │ │  Neural      │
//   │             │ │ compat │ │  native      │
//   └─────────────┘ └────────┘ └──────────────┘
//
// NTL's own runtime is built from these same channel primitives:
//
//   NTL InProcess layer  = InProcessChannel (this code)
//   NTL Local layer      = Unix socket / shared memory channel
//   NTL Network layer    = TCP/QUIC channel with discovery
//   NTL Fabric layer     = Full synapse routing with learning
//
// Each NTL layer wraps the one below it. The innermost layer is
// literally this code. Building NTL on this foundation means the
// database and the transfer layer share the same primitive, which
// is why Rust channels are the right foundation for everything.
