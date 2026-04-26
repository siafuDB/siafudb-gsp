// siafudb-sync/src/protocol/mod.rs
//
// THE GRAPH SYNC PROTOCOL
//
// This is the protocol that makes SiafuDB more than just another embedded
// graph database. It's the mechanism by which graph fragments stay in sync
// across devices, pods, edge nodes, and platform servers.
//
// The protocol has a layered design:
//
// 1. MUTATION MODEL (this module)
//    Defines what a graph change looks like as a data structure.
//    This is transport-agnostic — the same mutation representation
//    travels over NTL, HTTP, Kafka, or any other transport.
//
// 2. CONFLICT RESOLUTION (../conflict/)
//    Defines how concurrent mutations to the same data are resolved.
//    Uses vector clocks for causal ordering and configurable strategies
//    (last-writer-wins, merge, application-defined) for conflicts.
//
// 3. ADAPTERS (../adapters/)
//    Defines how the protocol speaks to different transports and
//    different graph databases. The NTL adapter is the native transport.
//    The HTTP adapter is for legacy/API compatibility. The JanusGraph
//    adapter enables sync with the server-side platform graph.

pub mod mutation;
pub mod changelog;
pub mod transform;
pub mod channel;

pub use mutation::{Mutation, MutationType, MutationBatch, VectorClock, CausalOrder};
pub use changelog::{ChangeLog, ChangeLogEntry, SyncCursor};
pub use transform::{
    SyncRelationship, SyncDirection, TransformRule, TransformEngine,
    ProjectedMutation, AggregationType, FilterOperator,
};
pub use channel::{
    SyncChannel, ChannelTransport, ChannelConfig, TransportConfig,
    InProcessChannel, InProcessSender, InProcessReceiver,
    create_in_process_pair, create_in_process_channel,
};
