//! # gsp-wire
//!
//! Wire format v0 of the Graph Sync Protocol (GSP): canonical CBOR ops with
//! hybrid Ed25519 + ML-DSA-65 signatures, an authenticated per-author key
//! log, sealed (encrypted) ops for relays, and the v0 frame types.
//!
//! This crate is **engine-independent**: it knows nothing about graphs or any
//! storage engine. An op's `payload` is an opaque CBOR value. It is `no_std`
//! (with `alloc`), does no I/O, and never calls an RNG: seeds and nonces come
//! from the caller.
//!
//! The normative description, with test vectors, is `docs/WIRE-V0.md`.
//!
//! ## The rules this crate enforces
//!
//! - **One encoding.** Deterministic CBOR (RFC 8949 section 4.2.1). Decoders
//!   reject anything that is not byte-for-byte canonical.
//! - **Ids are content hashes of received bytes.** The signed body travels as
//!   an opaque byte string; a receiver hashes those bytes and never
//!   re-encodes. The hash algorithm is inside the id ([`Multihash`]).
//! - **Signatures are bound to their audience.** The signed message is a CBOR
//!   array of domain tag, fragment id, op id, algorithm and key id
//!   ([`sig_input`]): length-prefixed, domain-separated, no raw concatenation.
//! - **Policy comes from the key log, not the op.** Which algorithms an author
//!   must sign with is read from the author's [`KeyLog`] at the op's `seq`. A
//!   hybrid author's op without its ML-DSA signature is `Invalid`.
//! - **Unknown never means valid.** Unknown format, hash or signature
//!   algorithm, author or key: [`Verdict::Unverifiable`]. Retain, never apply.
//! - **Per-author chains.** Every op has `seq` and `prev`; two valid ops at
//!   one `seq` are an [`EquivocationProof`].
//! - **Sign-then-encrypt.** A relay sees a [`SealedOp`]: fragment id, nonce,
//!   ciphertext.
//!
//! ## Cargo features
//!
//! - **`ml-dsa`** (on by default): ML-DSA-65 signing and verification, and
//!   with it the `ml-dsa` dependency. A build without it (for example a
//!   browser bundle for fragments whose devices all sign with Ed25519) has
//!   no [`SigningKey::ml_dsa_65`] and treats ML-DSA-65 as what it then is: a
//!   registered algorithm this build does not implement
//!   ([`SigAlg::implemented`]). An op carrying such a signature is
//!   [`Verdict::Unverifiable`], never valid and never invalid; a key log
//!   that needs the algorithm is [`KeyLogError::Unsupported`]. Parsing, ids
//!   and everything about Ed25519 are the same in both builds.
//!
//! ## Cryptography: maturity, stated plainly
//!
//! - `ml-dsa` is a **0.1.x** RustCrypto release. Its own README says it has
//!   **never been independently audited**. Nobody on this project has reviewed
//!   its constant-time behaviour or measured it on a phone. Treat ML-DSA-65
//!   here as the post-quantum half of a hybrid, never as the sole signature.
//! - ML-DSA signing here is the **deterministic** variant (no RNG in this
//!   crate). FIPS 204 prefers the hedged variant, which resists some fault
//!   attacks; revisit before signing on hardware an attacker can glitch.
//! - `ed25519-dalek` 3 and `chacha20poly1305` 0.11 are current major releases
//!   of widely used crates; this crate adds no audit of its own.
//! - This crate itself is new, unaudited code.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod batch;
pub mod cbor;
pub mod chain;
pub mod keylog;
pub mod message;
pub mod op;
pub mod registry;
pub mod sealed;
pub mod types;
pub mod verdict;

pub use batch::{Batch, BatchBody, VerifiedBatch, verify_batch};
pub use cbor::{DecodeError, EncodeError, Value};
pub use chain::{AuthorChain, ChainOutcome, EquivocationProof};
pub use keylog::{KeyLog, KeyLogAction, KeyLogEntry, KeyLogError, KeyLogs, KeyState};
pub use message::Message;
pub use op::{Hlc, Op, OpBody, VerifiedOp, VerifyCtx, verify};
pub use registry::{AeadAlg, HashAlg, KemAlg, SigAlg};
pub use sealed::{FragmentKey, Plain, SealError, SealedOp};
pub use types::{
    Domain, FORMAT_V0, Multihash, PublicKey, Signature, Signed, SigningKey, sig_input,
};
pub use verdict::{InvalidReason, UnverifiableReason, Verdict};
