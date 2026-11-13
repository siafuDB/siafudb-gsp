//! The op payload: a list of graph changes (SYNC-V0 section 4).
//!
//! [`Change`] is used in three places with one meaning each:
//!
//! - as the **payload** of an op (what [`encode_payload`] / [`decode_payload`]
//!   handle), where a delete is a permanent tombstone;
//! - as a **local commit** handed to
//!   [`Replica::local_commit`](crate::Replica::local_commit);
//! - as an **effect** emitted by a replica: an instruction to make the engine's
//!   visible graph equal to the replica's (see the crate documentation).

use crate::cv::{Fields, bytes, uint};
use gsp_wire::{EncodeError, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Global id of a node or an edge: 16 random bytes chosen by the device that
/// creates the entity.
pub type Gid = [u8; 16];

/// Most changes one op may carry.
pub const MAX_CHANGES: usize = 1024;
/// Largest encoded payload, in bytes (64 KiB).
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Longest property key, label or edge type, in UTF-8 bytes.
pub const MAX_NAME_BYTES: usize = 256;

/// One graph change.
///
/// The sets and maps are ordered collections, so "sorted, no duplicates" holds
/// by construction for values built in Rust; [`decode_payload`] enforces it
/// for bytes from the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    /// Create a node if it does not exist, then change labels and properties.
    /// Wire: `[1, gid, labels_add, labels_remove, set, unset]`.
    NodePut {
        /// The node.
        gid: Gid,
        /// Labels to make present.
        labels_add: BTreeSet<String>,
        /// Labels to make absent.
        labels_remove: BTreeSet<String>,
        /// Properties to write.
        set: BTreeMap<String, Value>,
        /// Properties to make absent.
        unset: BTreeSet<String>,
    },
    /// Delete a node. Wire: `[2, gid]`.
    NodeDel {
        /// The node.
        gid: Gid,
    },
    /// Create an edge if it does not exist, then change properties.
    /// Wire: `[3, gid, src, dst, type, set, unset]`.
    EdgePut {
        /// The edge.
        gid: Gid,
        /// Source node.
        src: Gid,
        /// Destination node.
        dst: Gid,
        /// Edge type (relationship name).
        ty: String,
        /// Properties to write.
        set: BTreeMap<String, Value>,
        /// Properties to make absent.
        unset: BTreeSet<String>,
    },
    /// Delete an edge. Wire: `[4, gid]`.
    EdgeDel {
        /// The edge.
        gid: Gid,
    },
}

impl Change {
    /// A `NodePut` that only creates the node.
    pub fn node(gid: Gid) -> Change {
        Change::NodePut {
            gid,
            labels_add: BTreeSet::new(),
            labels_remove: BTreeSet::new(),
            set: BTreeMap::new(),
            unset: BTreeSet::new(),
        }
    }

    /// An `EdgePut` that only creates the edge.
    pub fn edge(gid: Gid, src: Gid, dst: Gid, ty: &str) -> Change {
        Change::EdgePut {
            gid,
            src,
            dst,
            ty: ty.into(),
            set: BTreeMap::new(),
            unset: BTreeSet::new(),
        }
    }

    /// The gid of the node or edge this change is about.
    pub fn gid(&self) -> &Gid {
        match self {
            Change::NodePut { gid, .. }
            | Change::NodeDel { gid }
            | Change::EdgePut { gid, .. }
            | Change::EdgeDel { gid } => gid,
        }
    }
}

/// Why a list of changes is not a valid payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// The payload is not an array, or a field has the wrong type or count
    /// (named).
    Shape(&'static str),
    /// No changes at all.
    Empty,
    /// More than [`MAX_CHANGES`] changes.
    TooManyChanges,
    /// The encoded payload is larger than [`MAX_PAYLOAD_BYTES`].
    TooLarge,
    /// A change kind other than 1 to 4.
    UnknownKind(u64),
    /// A gid that is not exactly 16 bytes.
    Gid,
    /// A label, key or `unset` array that is not strictly ascending bytewise
    /// (unsorted or with a duplicate; named).
    NotSorted(&'static str),
    /// A property key, label or edge type longer than [`MAX_NAME_BYTES`].
    NameTooLong,
    /// The same key in `set` and `unset`, or the same label in both label
    /// lists (named).
    Conflict(&'static str),
    /// A property value that cannot be encoded (integer outside the CBOR
    /// range, nesting too deep).
    Encode(EncodeError),
}

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp payload error: {self:?}")
    }
}
impl core::error::Error for PayloadError {}

fn name_ok(s: &str) -> Result<(), PayloadError> {
    if s.len() > MAX_NAME_BYTES {
        Err(PayloadError::NameTooLong)
    } else {
        Ok(())
    }
}

fn names_to_value(names: &BTreeSet<String>) -> Value {
    Value::Array(names.iter().map(|n| Value::Text(n.clone())).collect())
}

fn set_to_value(set: &BTreeMap<String, Value>) -> Value {
    Value::Map(set.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

/// Rules that hold for one change regardless of how it was built.
fn check(c: &Change) -> Result<(), PayloadError> {
    let props = |set: &BTreeMap<String, Value>, unset: &BTreeSet<String>| {
        for k in set.keys().chain(unset) {
            name_ok(k)?;
        }
        if unset.iter().any(|k| set.contains_key(k)) {
            return Err(PayloadError::Conflict("set/unset"));
        }
        Ok(())
    };
    match c {
        Change::NodePut {
            labels_add,
            labels_remove,
            set,
            unset,
            ..
        } => {
            for l in labels_add.iter().chain(labels_remove) {
                name_ok(l)?;
            }
            if labels_add.intersection(labels_remove).next().is_some() {
                return Err(PayloadError::Conflict("labels"));
            }
            props(set, unset)
        }
        Change::EdgePut { ty, set, unset, .. } => {
            name_ok(ty)?;
            props(set, unset)
        }
        Change::NodeDel { .. } | Change::EdgeDel { .. } => Ok(()),
    }
}

/// Validate `changes` and build the payload value
/// `[+ change]`. Every rule of SYNC-V0 section 4 is checked, including the
/// 64 KiB bound on the encoding.
pub fn encode_payload(changes: &[Change]) -> Result<Value, PayloadError> {
    if changes.is_empty() {
        return Err(PayloadError::Empty);
    }
    if changes.len() > MAX_CHANGES {
        return Err(PayloadError::TooManyChanges);
    }
    let mut out = Vec::with_capacity(changes.len());
    for c in changes {
        check(c)?;
        out.push(Value::Array(match c {
            Change::NodePut {
                gid,
                labels_add,
                labels_remove,
                set,
                unset,
            } => vec![
                uint(1),
                bytes(gid),
                names_to_value(labels_add),
                names_to_value(labels_remove),
                set_to_value(set),
                names_to_value(unset),
            ],
            Change::NodeDel { gid } => vec![uint(2), bytes(gid)],
            Change::EdgePut {
                gid,
                src,
                dst,
                ty,
                set,
                unset,
            } => vec![
                uint(3),
                bytes(gid),
                bytes(src),
                bytes(dst),
                Value::Text(ty.clone()),
                set_to_value(set),
                names_to_value(unset),
            ],
            Change::EdgeDel { gid } => vec![uint(4), bytes(gid)],
        }));
    }
    let payload = Value::Array(out);
    let len = payload.encode().map_err(PayloadError::Encode)?.len();
    if len > MAX_PAYLOAD_BYTES {
        return Err(PayloadError::TooLarge);
    }
    Ok(payload)
}

fn gid(f: &mut Fields<'_>) -> Result<Gid, PayloadError> {
    f.value()
        .and_then(|v| match v {
            Value::Bytes(b) => Some(b),
            _ => None,
        })
        .ok_or(PayloadError::Shape("gid"))?
        .as_slice()
        .try_into()
        .map_err(|_| PayloadError::Gid)
}

fn names(f: &mut Fields<'_>, what: &'static str) -> Result<BTreeSet<String>, PayloadError> {
    let raw = f.array().ok_or(PayloadError::Shape(what))?;
    let mut out = BTreeSet::new();
    let mut last: Option<&str> = None;
    for v in raw {
        let Value::Text(s) = v else {
            return Err(PayloadError::Shape(what));
        };
        if last.is_some_and(|l| l.as_bytes() >= s.as_bytes()) {
            return Err(PayloadError::NotSorted(what));
        }
        last = Some(s);
        out.insert(s.clone());
    }
    Ok(out)
}

fn set(f: &mut Fields<'_>) -> Result<BTreeMap<String, Value>, PayloadError> {
    match f.value() {
        // The CBOR layer already guarantees text keys without duplicates.
        Some(Value::Map(entries)) => {
            let mut out = BTreeMap::new();
            for (k, v) in entries {
                if out.insert(k.clone(), v.clone()).is_some() {
                    return Err(PayloadError::NotSorted("set"));
                }
            }
            Ok(out)
        }
        _ => Err(PayloadError::Shape("set")),
    }
}

/// Strictly decode a payload value into changes, applying every rule of
/// SYNC-V0 section 4. An op whose payload fails here is `Invalid`.
pub fn decode_payload(payload: &Value) -> Result<Vec<Change>, PayloadError> {
    let Value::Array(items) = payload else {
        return Err(PayloadError::Shape("payload"));
    };
    if items.is_empty() {
        return Err(PayloadError::Empty);
    }
    if items.len() > MAX_CHANGES {
        return Err(PayloadError::TooManyChanges);
    }
    let len = payload.encode().map_err(PayloadError::Encode)?.len();
    if len > MAX_PAYLOAD_BYTES {
        return Err(PayloadError::TooLarge);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        const W: &str = "change";
        let mut f = Fields::open(item).ok_or(PayloadError::Shape(W))?;
        let kind = f.u64().ok_or(PayloadError::Shape(W))?;
        let arity = match kind {
            1 => 5,
            2 | 4 => 1,
            3 => 6,
            k => return Err(PayloadError::UnknownKind(k)),
        };
        if f.remaining() != arity {
            return Err(PayloadError::Shape(W));
        }
        let change = match kind {
            1 => Change::NodePut {
                gid: gid(&mut f)?,
                labels_add: names(&mut f, "labels_add")?,
                labels_remove: names(&mut f, "labels_remove")?,
                set: set(&mut f)?,
                unset: names(&mut f, "unset")?,
            },
            2 => Change::NodeDel { gid: gid(&mut f)? },
            3 => Change::EdgePut {
                gid: gid(&mut f)?,
                src: gid(&mut f)?,
                dst: gid(&mut f)?,
                ty: f.text().ok_or(PayloadError::Shape("type"))?.into(),
                set: set(&mut f)?,
                unset: names(&mut f, "unset")?,
            },
            _ => Change::EdgeDel { gid: gid(&mut f)? },
        };
        check(&change)?;
        out.push(change);
    }
    Ok(out)
}
