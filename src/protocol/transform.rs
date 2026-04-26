// siafudb-sync/src/protocol/transform.rs
//
// NOTE: VectorClock and NodeIdentity imports are staged for M4 (when
// outbound mutations are signed and ordered) and M5 (NTL signal-level
// identity). Remove the allow once those bodies populate.

#![allow(dead_code, unused_imports)]

// THE TRANSFORMATION LAYER
//
// This is the layer that makes the Graph Sync Protocol more than just
// replication. When a mutation needs to flow from this instance to
// another, the transformation layer determines WHAT the destination
// should receive — which might be very different from what was written
// locally.
//
// Example: Tatenda likes Amara's review.
//
// The raw mutation: VertexCreated { type: Engagement, user: "tatenda",
//   content: "amara-review-123", action: "like", timestamp: ... }
//
// Destination: Tatenda's pod
//   → Full mutation, unchanged. The pod holds everything.
//
// Destination: Analytics pipeline (Doris)
//   → PII stripped. user becomes anonymous hash. Content ref preserved.
//     { type: Engagement, user: "anon_hash_7f3a", content: "amara-review-123",
//       action: "like", timestamp: ... }
//
// Destination: Content owner (Amara) notification
//   → Anonymised engagement signal. No user identity at all.
//     { type: EngagementSignal, content: "amara-review-123",
//       action: "like", count_delta: 1 }
//
// The sync protocol applies these transformations automatically based on
// the rules configured for each sync relationship. The developer doesn't
// manually build three different payloads — they write the engagement once,
// and the protocol handles the projections.
//
// NTL doesn't know about any of this. NTL just carries the resulting
// signals. The intelligence is here, in the sync protocol.

use super::mutation::{Mutation, MutationBatch, MutationType, VectorClock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siafudb_core::identity::NodeIdentity;
use uuid::Uuid;

/// A sync relationship between this instance and a remote peer.
///
/// Each relationship defines: who the peer is, how to reach them
/// (which adapter), and what transformations to apply to mutations
/// before sending them.
///
/// A single SiafuDB instance might have many relationships:
/// - Phone → Pod (full personal sync)
/// - Phone → Platform (public content, PII stripped)
/// - Platform → Doris (analytics, anonymised)
/// - Platform → Content owners (engagement signals, anonymised)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRelationship {
    /// Unique identifier for this relationship.
    pub id: Uuid,

    /// Human-readable name (e.g., "device-to-pod", "platform-to-analytics").
    pub name: String,

    /// The remote peer's identity.
    pub peer_id: Uuid,

    /// Which adapter to use for transport (e.g., "ntl", "http", "kafka").
    pub adapter_name: String,

    /// The transformation rules to apply before sending mutations.
    pub transform_rules: Vec<TransformRule>,

    /// The direction of this sync relationship.
    pub direction: SyncDirection,

    /// Whether this relationship is currently active.
    pub active: bool,
}

/// The direction of a sync relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncDirection {
    /// This instance pushes mutations to the peer.
    Push,
    /// This instance pulls mutations from the peer.
    Pull,
    /// Bidirectional — both push and pull.
    Bidirectional,
}

/// A rule that transforms mutations before they're sent to a peer.
///
/// Rules are evaluated in order. Each rule can modify, filter, or
/// transform the mutation. If any rule filters out the mutation
/// (returns None), the mutation is not sent to this peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformRule {
    /// Only send mutations that match these node labels.
    /// Example: Only send "Review" and "Place" nodes to the platform.
    FilterByLabel {
        /// Labels to include. If empty, all labels pass.
        include_labels: Vec<String>,
        /// Labels to exclude. Takes precedence over include.
        exclude_labels: Vec<String>,
    },

    /// Strip personally identifiable information from mutations.
    /// Replaces identity fields with anonymised hashes.
    /// The hash is deterministic (same input → same hash) so that
    /// the analytics pipeline can correlate anonymised events
    /// without knowing who produced them.
    StripPII {
        /// Property names that contain PII and should be hashed.
        pii_properties: Vec<String>,
        /// A salt for the hash (different per relationship, so the
        /// same user gets different anonymous IDs in different contexts).
        hash_salt: String,
    },

    /// Fully anonymise the mutation — remove all identity information.
    /// Used for signals like "someone engaged with your content"
    /// where the recipient shouldn't know who.
    Anonymise,

    /// Aggregate mutations instead of sending individually.
    /// Example: Instead of sending each individual "like" event,
    /// batch them into "content X received 5 likes in the last hour."
    Aggregate {
        /// How many seconds to batch before sending.
        window_seconds: u64,
        /// The aggregation type.
        aggregation: AggregationType,
    },

    /// Transform the mutation into a different schema for the destination.
    /// Used when syncing with non-SiafuDB databases that expect
    /// different property names or structures.
    Remap {
        /// Map from source property name to destination property name.
        property_mapping: std::collections::HashMap<String, String>,
        /// Properties to add to every mutation (e.g., adding a "source"
        /// field that identifies which SiafuDB instance produced it).
        inject_properties: std::collections::HashMap<String, serde_json::Value>,
    },

    /// Only send mutations that match a predicate on properties.
    /// Example: Only send engagements where action = "purchase"
    /// to the commerce analytics pipeline.
    FilterByProperty {
        property: String,
        /// The comparison operator.
        operator: FilterOperator,
        /// The value to compare against.
        value: serde_json::Value,
    },
}

/// How to aggregate mutations in a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationType {
    /// Count the number of mutations in the window.
    Count,
    /// Sum a numeric property across mutations.
    Sum { property: String },
    /// Take only the latest mutation in the window.
    Latest,
}

/// Comparison operators for property-based filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    StartsWith,
}

/// A mutation that has been transformed for a specific destination.
///
/// This is what actually gets handed to the adapter for transport.
/// It might be identical to the original mutation (for pod sync),
/// or it might be significantly different (stripped, anonymised,
/// aggregated, remapped).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectedMutation {
    /// The original mutation ID (for tracking and deduplication).
    pub source_mutation_id: Uuid,

    /// The relationship this projection was created for.
    pub relationship_id: Uuid,

    /// The transformed mutation data.
    pub mutation: Mutation,

    /// Whether any PII was stripped in this projection.
    pub pii_stripped: bool,

    /// Whether the source identity was anonymised.
    pub anonymised: bool,
}

/// The transformation engine that applies rules to mutations.
pub struct TransformEngine;

impl TransformEngine {
    /// Apply a set of transformation rules to a mutation batch,
    /// producing a projected batch for a specific destination.
    ///
    /// Returns None if the entire batch was filtered out.
    pub fn project(
        batch: &MutationBatch,
        relationship: &SyncRelationship,
    ) -> Option<Vec<ProjectedMutation>> {
        let mut projected = Vec::new();

        for mutation in &batch.mutations {
            if let Some(pm) = Self::project_single(mutation, relationship) {
                projected.push(pm);
            }
        }

        if projected.is_empty() {
            None
        } else {
            Some(projected)
        }
    }

    /// Apply transformation rules to a single mutation.
    fn project_single(
        mutation: &Mutation,
        relationship: &SyncRelationship,
    ) -> Option<ProjectedMutation> {
        let mut working = mutation.clone();
        let mut pii_stripped = false;
        let mut anonymised = false;

        for rule in &relationship.transform_rules {
            match rule {
                TransformRule::FilterByLabel {
                    include_labels,
                    exclude_labels,
                } => {
                    let labels = Self::extract_labels(&working);
                    // If exclude list matches, filter out
                    if labels.iter().any(|l| exclude_labels.contains(l)) {
                        return None;
                    }
                    // If include list is specified and doesn't match, filter out
                    if !include_labels.is_empty()
                        && !labels.iter().any(|l| include_labels.contains(l))
                    {
                        return None;
                    }
                }

                TransformRule::StripPII {
                    pii_properties,
                    hash_salt,
                } => {
                    Self::apply_pii_strip(&mut working, pii_properties, hash_salt);
                    pii_stripped = true;
                }

                TransformRule::Anonymise => {
                    Self::apply_anonymise(&mut working);
                    anonymised = true;
                }

                TransformRule::FilterByProperty {
                    property,
                    operator,
                    value,
                } => {
                    if !Self::check_property_filter(&working, property, operator, value) {
                        return None;
                    }
                }

                TransformRule::Remap {
                    property_mapping,
                    inject_properties,
                } => {
                    Self::apply_remap(&mut working, property_mapping, inject_properties);
                }

                // Aggregation is handled at a higher level (the sync scheduler)
                // because it requires buffering mutations across time windows.
                TransformRule::Aggregate { .. } => {}
            }
        }

        Some(ProjectedMutation {
            source_mutation_id: mutation.id,
            relationship_id: relationship.id,
            mutation: working,
            pii_stripped,
            anonymised,
        })
    }

    /// Extract labels from a mutation (for filtering).
    fn extract_labels(mutation: &Mutation) -> Vec<String> {
        match &mutation.operation {
            MutationType::VertexCreated { labels, .. } => labels.clone(),
            MutationType::VertexUpdated { .. } => vec![], // TODO: look up labels from local state
            MutationType::VertexDeleted { .. } => vec![],
            MutationType::EdgeCreated { edge_type, .. } => vec![edge_type.clone()],
            MutationType::EdgeUpdated { .. } => vec![],
            MutationType::EdgeDeleted { .. } => vec![],
        }
    }

    /// Replace PII properties with deterministic anonymous hashes.
    fn apply_pii_strip(mutation: &mut Mutation, pii_properties: &[String], salt: &str) {
        let hash_property = |value: &serde_json::Value, salt: &str| -> serde_json::Value {
            let mut hasher = Sha256::new();
            hasher.update(salt.as_bytes());
            hasher.update(value.to_string().as_bytes());
            let hash = hasher.finalize();
            serde_json::Value::String(format!("anon_{}", hex::encode(&hash[..8])))
        };

        match &mut mutation.operation {
            MutationType::VertexCreated { properties, .. }
            | MutationType::VertexUpdated { properties, .. } => {
                for prop_name in pii_properties {
                    if let Some(value) = properties.get(prop_name) {
                        let hashed = hash_property(value, salt);
                        properties.insert(prop_name.clone(), hashed);
                    }
                }
            }
            MutationType::EdgeCreated { properties, .. }
            | MutationType::EdgeUpdated { properties, .. } => {
                for prop_name in pii_properties {
                    if let Some(value) = properties.get(prop_name) {
                        let hashed = hash_property(value, salt);
                        properties.insert(prop_name.clone(), hashed);
                    }
                }
            }
            _ => {}
        }
    }

    /// Remove all identity information from a mutation.
    fn apply_anonymise(mutation: &mut Mutation) {
        // Replace the source instance with a zero UUID
        mutation.source_instance = Uuid::nil();
        // Clear the signature (can't verify an anonymised mutation)
        mutation.signature = None;
    }

    /// Check if a mutation passes a property filter.
    fn check_property_filter(
        mutation: &Mutation,
        property: &str,
        operator: &FilterOperator,
        expected: &serde_json::Value,
    ) -> bool {
        let properties = match &mutation.operation {
            MutationType::VertexCreated { properties, .. } => Some(properties),
            MutationType::VertexUpdated { properties, .. } => Some(properties),
            MutationType::EdgeCreated { properties, .. } => Some(properties),
            MutationType::EdgeUpdated { properties, .. } => Some(properties),
            _ => None,
        };

        let Some(props) = properties else {
            return true; // Non-property mutations pass through
        };

        let Some(actual) = props.get(property) else {
            return false; // Property not present, doesn't match
        };

        match operator {
            FilterOperator::Equals => actual == expected,
            FilterOperator::NotEquals => actual != expected,
            _ => true, // TODO: implement remaining operators
        }
    }

    /// Remap property names and inject additional properties.
    fn apply_remap(
        mutation: &mut Mutation,
        mapping: &std::collections::HashMap<String, String>,
        inject: &std::collections::HashMap<String, serde_json::Value>,
    ) {
        let remap_props = |properties: &mut serde_json::Map<String, serde_json::Value>| {
            // Remap existing properties
            let remapped: Vec<(String, serde_json::Value)> = properties
                .iter()
                .map(|(k, v)| {
                    let new_key = mapping.get(k).cloned().unwrap_or_else(|| k.clone());
                    (new_key, v.clone())
                })
                .collect();

            properties.clear();
            for (k, v) in remapped {
                properties.insert(k, v);
            }

            // Inject additional properties
            for (k, v) in inject {
                properties.insert(k.clone(), v.clone());
            }
        };

        match &mut mutation.operation {
            MutationType::VertexCreated { properties, .. }
            | MutationType::VertexUpdated { properties, .. } => remap_props(properties),
            MutationType::EdgeCreated { properties, .. }
            | MutationType::EdgeUpdated { properties, .. } => remap_props(properties),
            _ => {}
        }
    }
}
