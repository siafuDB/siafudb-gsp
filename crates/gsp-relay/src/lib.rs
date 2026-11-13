//! # gsp-relay
//!
//! GSP v0 reference relay (`docs/SYNC-V0.md` section 6): an HTTP server that
//! stores sealed items per fragment in arrival order and hands them back.
//!
//! The relay holds no keys and never opens a sealed item. What it has for
//! each item is what `gsp_wire::SealedOp` exposes without the fragment key:
//! fragment id, AEAD id, nonce, and ciphertext. It is not trusted for
//! ordering, completeness or freshness; `relay_seq` is only a resume cursor.
//!
//! - [`Relay`]: token registration, numbering, dedupe, quotas, long-poll.
//!   [`Relay::handle`] answers one HTTP request; [`serve`] runs a listener.
//! - [`Store`]: where items live. [`MemStore`] is volatile; [`DirStore`]
//!   keeps one append-only log per fragment and survives restarts.
//! - [`Config`]: every limit and the CORS origin.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod dirstore;
pub mod http;
pub mod log;
pub mod relay;
pub mod store;

pub use config::{Config, Fsync};
pub use dirstore::DirStore;
pub use http::serve;
pub use relay::{Reject, Relay};
pub use store::{LoadedFragment, MemStore, Store, TokenHash};
