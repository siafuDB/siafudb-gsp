// siafudb-sync/src/protocol/mutation.rs
//
// The Mutation is the fundamental unit of the Graph Sync Protocol.
//
// When a SiafuDB instance modifies its graph — creating a node, adding
// an edge, updating a property, deleting anything — that change is
// captured as a Mutation. The mutation carries three things:
//
// 1. WHAT CHANGED — the operation (create, update, delete) and the
//    data involved (node type, properties, edge endpoints).
//
// 2. WHEN IT HAPPENED — a vector clock entry that establishes causal
//    ordering relative to other mutations across all instances.
//
// 3. WHO DID IT — the identity of the instance that produced the
//    mutation, with an optional cryptographic signature.
//
// Mutations are the protocol's lingua franca. They're what flows between
// SiafuDB instances regardless of transport (NTL, HTTP, Kafka). They're
// what adapters translate to and from when syncing with non-SiafuDB
// graph databases (JanusGraph, Neo4j). They're what the conflict
// resolution layer examines when concurrent changes collide.

use serde::{Deserialize, Serialize};
use siafudb_core::identity::NodeIdentity;
use uuid::Uuid;

/// A single graph mutation — one atomic change to the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    /// Unique identifier for this mutation.
    pub id: Uuid,

    /// The instance that produced this mutation.
    pub source_instance: Uuid,

    /// The fragment that this mutation belongs to.
    pub source_fragment: Uuid,

    /// What kind of change this mutation represents.
    pub operation: MutationType,

    /// Vector clock entry for causal ordering.
    ///
    /// Each instance maintains a logical clock that increments with
    /// every mutation. The vector clock is the set of all known clocks
    /// across all instances this one has synced with. This lets the
    /// conflict resolution layer determine whether two mutations are
    /// causally ordered (one happened before the other) or concurrent
    /// (they happened independently and might conflict).
    pub vector_clock: VectorClock,

    /// Unix timestamp (milliseconds) when this mutation was created.
    /// Used for display and debugging; the vector clock is the
    /// authoritative ordering mechanism, not wall-clock time.
    pub timestamp_ms: u64,

    /// Optional cryptographic signature from the source instance.
    /// When present, receivers can verify that this mutation genuinely
    /// came from the claimed source. Required for authenticated sync;
    /// optional for local-only or trusted-network deployments.
    pub signature: Option<Vec<u8>>,
}

/// The type of graph mutation.
///
/// These map to the fundamental operations on a property graph.
/// The mutation model is designed to be expressible in any graph
/// database's native operations, so that adapters can translate
/// without losing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationType {
    /// Create a new vertex (node) in the graph.
    VertexCreated {
        /// The globally unique identity of the new node.
        node_id: NodeIdentity,
        /// The label(s) for the node (e.g., "Person", "Place").
        labels: Vec<String>,
        /// The properties of the node as key-value pairs.
        properties: serde_json::Map<String, serde_json::Value>,
    },

    /// Update properties on an existing vertex.
    VertexUpdated {
        /// Which node is being updated.
        node_id: NodeIdentity,
        /// Properties that changed (only the changed ones, not the full set).
        properties: serde_json::Map<String, serde_json::Value>,
        /// Properties that were removed.
        removed_properties: Vec<String>,
    },

    /// Delete a vertex and all its edges.
    VertexDeleted {
        /// Which node is being deleted.
        node_id: NodeIdentity,
    },

    /// Create a new edge (relationship) between two vertices.
    EdgeCreated {
        /// Unique identity for this edge.
        edge_id: Uuid,
        /// The source vertex.
        from_node: NodeIdentity,
        /// The target vertex.
        to_node: NodeIdentity,
        /// The relationship type (e.g., "KNOWS", "VISITED").
        edge_type: String,
        /// Properties on the edge.
        properties: serde_json::Map<String, serde_json::Value>,
    },

    /// Update properties on an existing edge.
    EdgeUpdated {
        /// Which edge is being updated.
        edge_id: Uuid,
        /// Properties that changed.
        properties: serde_json::Map<String, serde_json::Value>,
        /// Properties that were removed.
        removed_properties: Vec<String>,
    },

    /// Delete an edge.
    EdgeDeleted {
        /// Which edge is being deleted.
        edge_id: Uuid,
    },
}

/// A batch of mutations that should be applied atomically.
///
/// When a single user action produces multiple graph changes (e.g.,
/// creating a Place node and adding a VISITED edge in one operation),
/// those changes are grouped into a batch. The sync protocol guarantees
/// that batches are applied atomically — receivers never see a partial
/// batch. This prevents inconsistent states where a node exists but
/// its required edges don't, or vice versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationBatch {
    /// Unique identifier for this batch.
    pub id: Uuid,

    /// The mutations in this batch, in order.
    pub mutations: Vec<Mutation>,

    /// Whether this batch must be applied atomically.
    /// Default: true. Can be set to false for advisory batching
    /// where partial application is acceptable.
    pub atomic: bool,
}

/// A vector clock for causal ordering of mutations.
///
/// Each entry maps an instance ID to the highest sequence number
/// seen from that instance. When comparing two vector clocks:
/// - If every entry in A >= the corresponding entry in B, then A >= B (A happened after B)
/// - If neither A >= B nor B >= A, then A and B are concurrent (potential conflict)
///
/// This is the mechanism that lets the sync protocol detect conflicts
/// without requiring synchronized wall clocks across devices.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VectorClock {
    /// Map from instance UUID to the highest sequence number
    /// seen from that instance.
    pub entries: std::collections::HashMap<Uuid, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the clock for the given instance.
    pub fn increment(&mut self, instance_id: Uuid) -> u64 {
        let counter = self.entries.entry(instance_id).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Merge another vector clock into this one (take the max of each entry).
    pub fn merge(&mut self, other: &VectorClock) {
        for (id, &seq) in &other.entries {
            let entry = self.entries.entry(*id).or_insert(0);
            *entry = (*entry).max(seq);
        }
    }

    /// Determine the causal relationship between this clock and another.
    pub fn compare(&self, other: &VectorClock) -> CausalOrder {
        let mut self_gte_other = true;
        let mut other_gte_self = true;

        // Check all keys from both clocks
        let all_keys: std::collections::HashSet<_> = self
            .entries
            .keys()
            .chain(other.entries.keys())
            .collect();

        for key in all_keys {
            let self_val = self.entries.get(key).copied().unwrap_or(0);
            let other_val = other.entries.get(key).copied().unwrap_or(0);

            if self_val < other_val {
                self_gte_other = false;
            }
            if other_val < self_val {
                other_gte_self = false;
            }
        }

        match (self_gte_other, other_gte_self) {
            (true, true) => CausalOrder::Equal,
            (true, false) => CausalOrder::After,
            (false, true) => CausalOrder::Before,
            (false, false) => CausalOrder::Concurrent,
        }
    }
}

/// The causal relationship between two events.
#[derive(Debug, Clone, PartialEq)]
pub enum CausalOrder {
    /// This event happened before the other.
    Before,
    /// This event happened after the other.
    After,
    /// The events are causally equal (same clock).
    Equal,
    /// The events are concurrent (happened independently, may conflict).
    Concurrent,
}

impl MutationBatch {
    /// Create a new batch with a single mutation.
    pub fn single(mutation: Mutation) -> Self {
        Self {
            id: Uuid::new_v4(),
            mutations: vec![mutation],
            atomic: true,
        }
    }

    /// Create a new batch with multiple mutations.
    pub fn new(mutations: Vec<Mutation>) -> Self {
        Self {
            id: Uuid::new_v4(),
            mutations,
            atomic: true,
        }
    }
}
