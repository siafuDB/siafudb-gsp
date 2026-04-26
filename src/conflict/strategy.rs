// siafudb-sync/src/conflict/strategy.rs

use crate::protocol::mutation::{CausalOrder, Mutation, VectorClock};
use serde::{Deserialize, Serialize};

/// How to resolve conflicts between concurrent mutations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Last Writer Wins — the mutation with the higher vector clock wins.
    /// Simple, predictable, and sufficient for most use cases.
    /// This is the default for personal data sync between a user's devices.
    LastWriterWins,

    /// Merge properties — combine both mutations' property changes.
    /// Non-overlapping properties are kept from both sides.
    /// Overlapping properties use LWW for the individual property.
    MergeProperties,

    /// Reject the incoming mutation and keep local state.
    /// Used when this instance is authoritative and doesn't accept
    /// external modifications (e.g., the platform graph for platform data).
    RejectIncoming,

    /// Accept the incoming mutation and overwrite local state.
    /// Used when this instance is a cache that defers to the
    /// authoritative source (e.g., a device caching platform data).
    AcceptIncoming,
}

impl ConflictStrategy {
    /// Determine the default strategy based on fragment authority.
    pub fn default_for_authoritative() -> Self {
        Self::RejectIncoming
    }

    pub fn default_for_referenced() -> Self {
        Self::AcceptIncoming
    }

    pub fn default_for_personal() -> Self {
        Self::LastWriterWins
    }
}
