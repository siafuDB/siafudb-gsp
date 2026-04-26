// siafudb-sync/src/adapters/gspa.rs
//
// NOTE: the GspaAdapter.cursor field is consumed by the pull_http /
// pull_websocket / pull_grpc / pull_kafka bodies that arrive in M4.
// Remove the allow once those transport methods are implemented.

#![allow(dead_code, unused_imports, rustdoc::bare_urls)]

// GSPA — Graph Sync Protocol with API
//
// The traditional adapter. Request-response transport over HTTP/gRPC/WebSocket.
// Ships first because it works with existing infrastructure and every
// developer understands it.
//
// In GSPA mode:
// - SiafuDB maintains connections to known endpoints
// - Mutations are serialised (JSON/protobuf) for transmission
// - Transformations (PII strip, anonymise) happen INSIDE SiafuDB
//   before data leaves the instance, because SiafuDB is the last
//   code to touch the data before it hits the wire
// - Push/pull semantics: SiafuDB pushes mutations to peers and
//   pulls mutations from peers on a configurable schedule
// - Batching: small mutations are batched to amortise HTTP overhead
// - Retry: failed transmissions are queued and retried with backoff
//
// GSPA is not the end state — it's the bridge. As GSPN matures,
// sync relationships migrate from GSPA to GSPN one at a time.
// But GSPA never goes away, because there will always be systems
// that speak HTTP and never adopt NTL.

use crate::protocol::changelog::SyncCursor;
use crate::protocol::transform::{ProjectedMutation, SyncRelationship, TransformEngine};
use crate::protocol::{MutationBatch, VectorClock};
use serde::{Deserialize, Serialize};
use siafudb_core::error::SiafuError;
use uuid::Uuid;

/// Configuration for a GSPA sync relationship.
///
/// Each GSPA relationship connects this SiafuDB instance to one
/// remote peer over a traditional API transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspaConfig {
    /// The URL of the remote peer's sync endpoint.
    /// Examples:
    ///   "https://pod.amara.nyuchi.com/sync"     (personal pod)
    ///   "https://api.mukoko.com/graph/sync"      (platform)
    ///   "https://doris.internal/ingest"           (analytics)
    ///   "ws://192.168.1.100:7474/sync"           (local network peer)
    pub endpoint: String,

    /// The transport protocol to use.
    pub transport: GspaTransport,

    /// How often to attempt sync (in seconds).
    /// For real-time sync (e.g., messaging), this might be 1-5 seconds.
    /// For background sync (e.g., analytics), this might be 300+ seconds.
    /// None means sync only when explicitly triggered.
    pub sync_interval_seconds: Option<u64>,

    /// Maximum number of mutations to include in a single batch.
    /// Larger batches are more efficient over HTTP but use more memory.
    pub max_batch_size: usize,

    /// Whether to compress payloads before transmission.
    /// Reduces bandwidth at the cost of CPU. Recommended for
    /// mobile devices on cellular connections.
    pub compress: bool,

    /// Authentication token for the remote endpoint.
    /// In production, this would be a cryptographic bearer token
    /// derived from the instance's identity.
    pub auth_token: Option<String>,

    /// The sync relationship that defines transformation rules.
    /// This is where PII stripping, anonymisation, and filtering
    /// are configured for this specific peer.
    pub relationship: SyncRelationship,
}

/// The API transport protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GspaTransport {
    /// Standard HTTP/HTTPS with JSON payloads.
    /// Most compatible. Works through any proxy or firewall.
    Http,

    /// gRPC with protobuf payloads.
    /// More efficient than HTTP/JSON. Better for high-throughput
    /// server-to-server sync (e.g., platform to Doris).
    Grpc,

    /// WebSocket for bidirectional real-time sync.
    /// Lower latency than HTTP polling. Good for device-to-pod
    /// sync where mutations should propagate within seconds.
    WebSocket,

    /// Direct local network transport (TCP + mutual TLS, binary format).
    /// Optimised for LAN conditions where bandwidth is abundant and
    /// latency is minimal. Uses SiafuDB's native binary mutation format
    /// instead of JSON — no serialisation overhead. Mutual TLS with
    /// ed25519 keys from the identity module for authentication.
    ///
    /// This is the fastest possible sync between two SiafuDB instances,
    /// because both ends speak the same format and there's no translation.
    /// Used automatically when local network discovery finds a peer.
    Local,

    /// Kafka producer/consumer.
    /// For environments where Kafka is the existing event bus.
    /// Mutations become Kafka messages on a topic.
    Kafka {
        /// Kafka bootstrap servers.
        brokers: String,
        /// Topic name for outgoing mutations.
        topic: String,
    },
}

/// The GSPA adapter instance.
///
/// Manages one sync relationship over API transport.
/// A SiafuDB instance might have several GspaAdapter instances,
/// one per sync relationship that uses API transport.
pub struct GspaAdapter {
    /// Configuration for this adapter.
    config: GspaConfig,

    /// The last sync cursor — where we left off with this peer.
    cursor: SyncCursor,

    /// Outbound queue — mutations waiting to be sent.
    /// Populated when mutations are produced faster than they can
    /// be transmitted, or when the peer is temporarily unreachable.
    outbound_queue: Vec<ProjectedMutation>,
}

impl GspaAdapter {
    /// Create a new GSPA adapter with the given configuration.
    pub fn new(config: GspaConfig, instance_id: Uuid) -> Self {
        Self {
            cursor: SyncCursor {
                source_instance: instance_id,
                last_sequence: 0,
            },
            config,
            outbound_queue: Vec::new(),
        }
    }

    /// The adapter's name, used in logs and diagnostics.
    pub fn name(&self) -> &str {
        "gspa"
    }

    /// Process a mutation batch for this sync relationship.
    ///
    /// This is the core GSPA flow:
    /// 1. Read the mutation batch from the change log
    /// 2. Apply transformation rules (PII strip, anonymise, filter)
    /// 3. Serialise the projected mutations for the wire
    /// 4. Transmit to the peer endpoint
    /// 5. Handle acknowledgment or queue for retry
    ///
    /// In GSPA, transformations happen HERE because SiafuDB is the
    /// last code to touch data before it hits the API wire. This is
    /// the key difference from GSPN, where transformations happen
    /// at the NTL synapse level.
    pub async fn process_batch(&mut self, batch: &MutationBatch) -> Result<(), SiafuError> {
        // Step 1: Apply transformation rules for this relationship
        let projected = TransformEngine::project(batch, &self.config.relationship);

        let Some(mutations) = projected else {
            // All mutations were filtered out — nothing to send to this peer.
            // This is normal: a mutation to the personal graph might be
            // filtered out for the analytics pipeline because it doesn't
            // match the include labels.
            return Ok(());
        };

        // Step 2: Add to outbound queue
        self.outbound_queue.extend(mutations);

        // Step 3: If queue has reached batch size, flush
        if self.outbound_queue.len() >= self.config.max_batch_size {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flush the outbound queue — transmit all queued mutations to the peer.
    pub async fn flush(&mut self) -> Result<(), SiafuError> {
        if self.outbound_queue.is_empty() {
            return Ok(());
        }

        let payload = std::mem::take(&mut self.outbound_queue);

        match &self.config.transport {
            GspaTransport::Http => self.send_http(&payload).await,
            GspaTransport::WebSocket => self.send_websocket(&payload).await,
            GspaTransport::Grpc => self.send_grpc(&payload).await,
            GspaTransport::Kafka { .. } => self.send_kafka(&payload).await,
            GspaTransport::Local => Err(SiafuError::SyncError(
                "GSPA local transport not yet implemented".into(),
            )),
        }
    }

    /// Pull mutations from the remote peer.
    ///
    /// This is the inbound GSPA flow: query the peer for mutations
    /// that happened after our last cursor position, receive them,
    /// and return them for the sync engine to apply locally.
    pub async fn pull(&mut self) -> Result<Vec<MutationBatch>, SiafuError> {
        match &self.config.transport {
            GspaTransport::Http => self.pull_http().await,
            GspaTransport::WebSocket => self.pull_websocket().await,
            GspaTransport::Grpc => self.pull_grpc().await,
            GspaTransport::Kafka { .. } => self.pull_kafka().await,
            GspaTransport::Local => Err(SiafuError::SyncError(
                "GSPA local transport not yet implemented".into(),
            )),
        }
    }

    /// Check whether the remote peer is reachable.
    pub async fn is_available(&self) -> bool {
        // TODO: Implement health check per transport type.
        // For HTTP: HEAD request to the endpoint.
        // For WebSocket: check connection state.
        // For Kafka: check broker connectivity.
        true
    }

    // === Transport-specific implementations ===
    // Each transport serialises and transmits differently,
    // but the protocol semantics are identical.

    async fn send_http(&self, payload: &[ProjectedMutation]) -> Result<(), SiafuError> {
        // TODO: Implement HTTP POST to endpoint with JSON payload.
        // Headers: Content-Type: application/json
        //          Authorization: Bearer {auth_token}
        //          X-SiafuDB-Instance: {instance_id}
        //          X-SiafuDB-Protocol: GSPA/1.0
        //
        // The payload is serialised as JSON. In production, this would
        // use reqwest or hyper. For now, placeholder.
        tracing::info!(
            "GSPA/HTTP: would send {} projected mutations to {}",
            payload.len(),
            self.config.endpoint
        );
        Ok(())
    }

    async fn send_websocket(&self, payload: &[ProjectedMutation]) -> Result<(), SiafuError> {
        // TODO: Implement WebSocket message send.
        // WebSocket is preferred for device-to-pod sync because it
        // maintains a persistent connection and pushes in real time.
        tracing::info!(
            "GSPA/WS: would send {} projected mutations to {}",
            payload.len(),
            self.config.endpoint
        );
        Ok(())
    }

    async fn send_grpc(&self, payload: &[ProjectedMutation]) -> Result<(), SiafuError> {
        // TODO: Implement gRPC streaming call.
        // gRPC is preferred for server-to-server sync because it's
        // more efficient than HTTP/JSON for high-throughput flows.
        tracing::info!(
            "GSPA/gRPC: would send {} projected mutations to {}",
            payload.len(),
            self.config.endpoint
        );
        Ok(())
    }

    async fn send_kafka(&self, payload: &[ProjectedMutation]) -> Result<(), SiafuError> {
        // TODO: Implement Kafka producer.
        // Each projected mutation becomes a Kafka message on the configured topic.
        tracing::info!(
            "GSPA/Kafka: would send {} projected mutations",
            payload.len(),
        );
        Ok(())
    }

    async fn pull_http(&mut self) -> Result<Vec<MutationBatch>, SiafuError> {
        // TODO: GET {endpoint}?after={cursor.last_sequence}
        tracing::info!("GSPA/HTTP: would pull from {}", self.config.endpoint);
        Ok(vec![])
    }

    async fn pull_websocket(&mut self) -> Result<Vec<MutationBatch>, SiafuError> {
        // TODO: Read from WebSocket connection
        tracing::info!("GSPA/WS: would pull from {}", self.config.endpoint);
        Ok(vec![])
    }

    async fn pull_grpc(&mut self) -> Result<Vec<MutationBatch>, SiafuError> {
        // TODO: gRPC streaming pull
        tracing::info!("GSPA/gRPC: would pull from {}", self.config.endpoint);
        Ok(vec![])
    }

    async fn pull_kafka(&mut self) -> Result<Vec<MutationBatch>, SiafuError> {
        // TODO: Kafka consumer poll
        tracing::info!("GSPA/Kafka: would pull");
        Ok(vec![])
    }
}

impl Default for GspaConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            transport: GspaTransport::Http,
            sync_interval_seconds: Some(30),
            max_batch_size: 100,
            compress: false,
            auth_token: None,
            relationship: SyncRelationship {
                id: Uuid::new_v4(),
                name: String::from("default"),
                peer_id: Uuid::nil(),
                adapter_name: String::from("gspa"),
                transform_rules: vec![],
                direction: crate::protocol::transform::SyncDirection::Bidirectional,
                active: true,
            },
        }
    }
}
