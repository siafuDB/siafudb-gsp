//! Merge state and rules (SYNC-V0 section 5), and the computation of effects.
//!
//! Every rule is a function of the *set* of ops applied:
//!
//! - a tombstone is permanent and makes every put for its gid, earlier or
//!   later, irrelevant, so the per-gid state is dropped when it is set;
//! - properties and labels are last-writer-wins registers ordered by
//!   [`Stamp`]; an `unset` or a label removal is a register holding "absent";
//! - an edge's endpoints and type are those of the put with the lowest stamp;
//! - visibility is derived, never stored.
//!
//! Two changes of one op share a stamp. Between them the later one in the
//! payload wins a register, the earlier one fixes an edge's endpoints, and a
//! delete beats a put wherever it stands. That is still a function of the set
//! of ops, because an op is applied whole.

use crate::change::{Change, Gid};
use crate::cv::{Fields, bytes, uint, value_eq};
use gsp_wire::{EncodeError, Hlc, Multihash, Value};
use std::collections::{BTreeMap, BTreeSet};

/// An op id (or author id) with a hash this build implements: always 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpKey {
    pub(crate) alg: u16,
    pub(crate) digest: [u8; 32],
}

impl OpKey {
    pub(crate) fn from_multihash(m: &Multihash) -> Option<OpKey> {
        Some(OpKey {
            alg: m.alg,
            digest: m.digest.as_slice().try_into().ok()?,
        })
    }
    pub(crate) fn to_multihash(self) -> Multihash {
        Multihash {
            alg: self.alg,
            digest: self.digest.to_vec(),
        }
    }
    pub(crate) fn to_value(self) -> Value {
        Value::Array(vec![uint(u64::from(self.alg)), bytes(&self.digest)])
    }
    pub(crate) fn from_value(v: &Value) -> Option<OpKey> {
        let mut f = Fields::exact(v, 2)?;
        Some(OpKey {
            alg: f.u16()?,
            digest: f.fixed()?,
        })
    }
}

/// The stamp of a write: the HLC of its op, then the op id. The derived order
/// is `(wall_ms, counter, hash alg, digest)`, which for the 32-byte digests
/// used here is the bytewise order of the encoded op id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stamp {
    pub(crate) hlc: Hlc,
    pub(crate) id: OpKey,
}

type Props = BTreeMap<String, (Stamp, Option<Value>)>;

#[derive(Debug, Clone, Default)]
struct NodeState {
    labels: BTreeMap<String, (Stamp, bool)>,
    props: Props,
}

#[derive(Debug, Clone)]
struct EdgeState {
    /// Lowest stamp of any put: the one that fixed `src`, `dst` and `ty`.
    stamp: Stamp,
    src: Gid,
    dst: Gid,
    ty: String,
    props: Props,
}

/// A visible node as an engine should hold it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeView {
    /// The node.
    pub gid: Gid,
    /// Labels present.
    pub labels: BTreeSet<String>,
    /// Properties present.
    pub props: BTreeMap<String, Value>,
}

/// A visible edge as an engine should hold it.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeView {
    /// The edge.
    pub gid: Gid,
    /// Source node (visible).
    pub src: Gid,
    /// Destination node (visible).
    pub dst: Gid,
    /// Edge type.
    pub ty: String,
    /// Properties present.
    pub props: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Merge {
    /// Nodes with at least one put and no tombstone: exactly the visible ones.
    nodes: BTreeMap<Gid, NodeState>,
    /// Edges with at least one put and no tombstone, visible or not.
    edges: BTreeMap<Gid, EdgeState>,
    node_tombs: BTreeSet<Gid>,
    edge_tombs: BTreeSet<Gid>,
    /// Derived: node gid to the edges in `edges` that name it as an endpoint.
    incident: BTreeMap<Gid, BTreeSet<Gid>>,
}

fn lww<T>(map: &mut BTreeMap<String, (Stamp, T)>, key: &str, stamp: Stamp, val: T) {
    match map.get_mut(key) {
        Some(reg) if reg.0 > stamp => {}
        Some(reg) => *reg = (stamp, val),
        None => {
            map.insert(key.into(), (stamp, val));
        }
    }
}

fn write_props(
    props: &mut Props,
    set: &BTreeMap<String, Value>,
    unset: &BTreeSet<String>,
    stamp: Stamp,
) {
    for (k, v) in set {
        lww(props, k, stamp, Some(v.clone()));
    }
    for k in unset {
        lww(props, k, stamp, None);
    }
}

fn present(props: &Props) -> BTreeMap<String, Value> {
    props
        .iter()
        .filter_map(|(k, (_, v))| v.as_ref().map(|v| (k.clone(), v.clone())))
        .collect()
}

fn naive_props(
    props: &mut BTreeMap<String, Value>,
    set: &BTreeMap<String, Value>,
    unset: &BTreeSet<String>,
) {
    for (k, v) in set {
        props.insert(k.clone(), v.clone());
    }
    for k in unset {
        props.remove(k);
    }
}

/// `(set, unset)` that turn `from` into `to`.
fn props_delta(
    from: &BTreeMap<String, Value>,
    to: &BTreeMap<String, Value>,
) -> (BTreeMap<String, Value>, BTreeSet<String>) {
    let set = to
        .iter()
        .filter(|(k, v)| !from.get(*k).is_some_and(|old| value_eq(old, v)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let unset = from
        .keys()
        .filter(|k| !to.contains_key(*k))
        .cloned()
        .collect();
    (set, unset)
}

impl NodeView {
    fn to_put(&self) -> Change {
        Change::NodePut {
            gid: self.gid,
            labels_add: self.labels.clone(),
            labels_remove: BTreeSet::new(),
            set: self.props.clone(),
            unset: BTreeSet::new(),
        }
    }
}

impl EdgeView {
    fn to_put(&self) -> Change {
        Change::EdgePut {
            gid: self.gid,
            src: self.src,
            dst: self.dst,
            ty: self.ty.clone(),
            set: self.props.clone(),
            unset: BTreeSet::new(),
        }
    }
}

impl Merge {
    pub(crate) fn node(&self, gid: &Gid) -> Option<NodeView> {
        self.nodes.get(gid).map(|n| NodeView {
            gid: *gid,
            labels: n
                .labels
                .iter()
                .filter(|(_, (_, on))| *on)
                .map(|(l, _)| l.clone())
                .collect(),
            props: present(&n.props),
        })
    }

    /// The edge as it would look if both endpoints were visible.
    fn edge_raw(&self, gid: &Gid) -> Option<EdgeView> {
        self.edges.get(gid).map(|e| EdgeView {
            gid: *gid,
            src: e.src,
            dst: e.dst,
            ty: e.ty.clone(),
            props: present(&e.props),
        })
    }

    fn edge_visible(&self, e: &EdgeState) -> bool {
        self.nodes.contains_key(&e.src) && self.nodes.contains_key(&e.dst)
    }

    pub(crate) fn edge(&self, gid: &Gid) -> Option<EdgeView> {
        let e = self.edges.get(gid)?;
        if self.edge_visible(e) {
            self.edge_raw(gid)
        } else {
            None
        }
    }

    pub(crate) fn nodes(&self) -> Vec<NodeView> {
        self.nodes.keys().filter_map(|g| self.node(g)).collect()
    }

    pub(crate) fn edges(&self) -> Vec<EdgeView> {
        self.edges.keys().filter_map(|g| self.edge(g)).collect()
    }

    pub(crate) fn node_tombstoned(&self, gid: &Gid) -> bool {
        self.node_tombs.contains(gid)
    }

    pub(crate) fn edge_tombstoned(&self, gid: &Gid) -> bool {
        self.edge_tombs.contains(gid)
    }

    fn link(&mut self, edge: Gid, src: Gid, dst: Gid) {
        self.incident.entry(src).or_default().insert(edge);
        self.incident.entry(dst).or_default().insert(edge);
    }

    fn unlink(&mut self, edge: &Gid, src: &Gid, dst: &Gid) {
        for n in [src, dst] {
            if let Some(set) = self.incident.get_mut(n) {
                set.remove(edge);
                if set.is_empty() {
                    self.incident.remove(n);
                }
            }
        }
    }

    fn write(&mut self, change: &Change, stamp: Stamp) {
        match change {
            Change::NodePut {
                gid,
                labels_add,
                labels_remove,
                set,
                unset,
            } => {
                if self.node_tombs.contains(gid) {
                    return;
                }
                let n = self.nodes.entry(*gid).or_default();
                for l in labels_add {
                    lww(&mut n.labels, l, stamp, true);
                }
                for l in labels_remove {
                    lww(&mut n.labels, l, stamp, false);
                }
                write_props(&mut n.props, set, unset, stamp);
            }
            Change::NodeDel { gid } => {
                self.node_tombs.insert(*gid);
                self.nodes.remove(gid);
            }
            Change::EdgePut {
                gid,
                src,
                dst,
                ty,
                set,
                unset,
            } => {
                if self.edge_tombs.contains(gid) {
                    return;
                }
                let mut relink = None;
                match self.edges.get_mut(gid) {
                    None => {
                        let mut props = Props::new();
                        write_props(&mut props, set, unset, stamp);
                        self.edges.insert(
                            *gid,
                            EdgeState {
                                stamp,
                                src: *src,
                                dst: *dst,
                                ty: ty.clone(),
                                props,
                            },
                        );
                        self.link(*gid, *src, *dst);
                    }
                    Some(e) => {
                        if stamp < e.stamp {
                            relink = Some((e.src, e.dst));
                            e.stamp = stamp;
                            e.src = *src;
                            e.dst = *dst;
                            e.ty = ty.clone();
                        }
                        write_props(&mut e.props, set, unset, stamp);
                    }
                }
                if let Some((old_src, old_dst)) = relink {
                    self.unlink(gid, &old_src, &old_dst);
                    self.link(*gid, *src, *dst);
                }
            }
            Change::EdgeDel { gid } => {
                self.edge_tombs.insert(*gid);
                if let Some(e) = self.edges.remove(gid) {
                    self.unlink(gid, &e.src, &e.dst);
                }
            }
        }
    }

    /// Apply the changes of one op and return the effects.
    ///
    /// For a remote op (`local == false`) the effects turn the visible state
    /// before the op into the visible state after it. For a local commit the
    /// engine has already applied `changes` itself, so the starting point is
    /// the visible state before the op with `changes` applied *naively*
    /// (puts upsert, deletes remove, nothing else): the effects are then only
    /// the corrections, usually none.
    pub(crate) fn apply(&mut self, changes: &[Change], stamp: Stamp, local: bool) -> Vec<Change> {
        // What the engine holds for every entity this op names.
        let mut exp_nodes: BTreeMap<Gid, Option<NodeView>> = BTreeMap::new();
        let mut exp_edges: BTreeMap<Gid, Option<EdgeView>> = BTreeMap::new();
        for c in changes {
            match c {
                Change::NodePut { gid, .. } | Change::NodeDel { gid } => {
                    exp_nodes.entry(*gid).or_insert_with(|| self.node(gid));
                }
                Change::EdgePut { gid, .. } | Change::EdgeDel { gid } => {
                    exp_edges.entry(*gid).or_insert_with(|| self.edge(gid));
                }
            }
        }
        let was_visible: BTreeMap<Gid, bool> =
            exp_nodes.iter().map(|(g, v)| (*g, v.is_some())).collect();
        if local {
            for c in changes {
                naive(&mut exp_nodes, &mut exp_edges, c);
            }
        }

        for c in changes {
            self.write(c, stamp);
        }

        // Edges not named by the op change only when an endpoint appears or
        // disappears; their own state is untouched.
        for (node, before) in &was_visible {
            if *before == self.nodes.contains_key(node) {
                continue;
            }
            let Some(incident) = self.incident.get(node) else {
                continue;
            };
            for e in incident {
                if exp_edges.contains_key(e) {
                    continue;
                }
                let Some(st) = self.edges.get(e) else {
                    continue;
                };
                let before_vis = |n: &Gid| {
                    was_visible
                        .get(n)
                        .copied()
                        .unwrap_or_else(|| self.nodes.contains_key(n))
                };
                let view = if before_vis(&st.src) && before_vis(&st.dst) {
                    self.edge_raw(e)
                } else {
                    None
                };
                exp_edges.insert(*e, view);
            }
        }

        // Order matters to an engine with referential integrity: nodes appear
        // before the edges that need them, edges go before their nodes.
        let mut node_puts = Vec::new();
        let mut node_dels = Vec::new();
        let mut edge_dels = Vec::new();
        let mut edge_puts = Vec::new();
        for (gid, exp) in &exp_nodes {
            match (exp, self.node(gid)) {
                (None, None) => {}
                (None, Some(now)) => node_puts.push(now.to_put()),
                (Some(_), None) => node_dels.push(Change::NodeDel { gid: *gid }),
                (Some(old), Some(now)) => {
                    let (set, unset) = props_delta(&old.props, &now.props);
                    let labels_add: BTreeSet<String> =
                        now.labels.difference(&old.labels).cloned().collect();
                    let labels_remove: BTreeSet<String> =
                        old.labels.difference(&now.labels).cloned().collect();
                    if !(set.is_empty()
                        && unset.is_empty()
                        && labels_add.is_empty()
                        && labels_remove.is_empty())
                    {
                        node_puts.push(Change::NodePut {
                            gid: *gid,
                            labels_add,
                            labels_remove,
                            set,
                            unset,
                        });
                    }
                }
            }
        }
        for (gid, exp) in &exp_edges {
            match (exp, self.edge(gid)) {
                (None, None) => {}
                (None, Some(now)) => edge_puts.push(now.to_put()),
                (Some(_), None) => edge_dels.push(Change::EdgeDel { gid: *gid }),
                (Some(old), Some(now)) => {
                    if old.src != now.src || old.dst != now.dst || old.ty != now.ty {
                        // An engine cannot re-point an edge: replace it.
                        edge_dels.push(Change::EdgeDel { gid: *gid });
                        edge_puts.push(now.to_put());
                        continue;
                    }
                    let (set, unset) = props_delta(&old.props, &now.props);
                    if !(set.is_empty() && unset.is_empty()) {
                        edge_puts.push(Change::EdgePut {
                            gid: *gid,
                            src: now.src,
                            dst: now.dst,
                            ty: now.ty,
                            set,
                            unset,
                        });
                    }
                }
            }
        }
        let mut out = node_puts;
        out.append(&mut edge_dels);
        out.append(&mut edge_puts);
        out.append(&mut node_dels);
        out
    }

    /// The whole visible graph as puts: nodes first, then edges.
    pub(crate) fn snapshot(&self) -> Vec<Change> {
        let mut out: Vec<Change> = self.nodes().iter().map(NodeView::to_put).collect();
        out.extend(self.edges().iter().map(EdgeView::to_put));
        out
    }

    // ------------------------------------------------------------ state

    fn stamps(&self) -> BTreeMap<Stamp, u64> {
        let mut set = BTreeSet::new();
        let mut props = |p: &Props| {
            for (s, _) in p.values() {
                set.insert(*s);
            }
        };
        for n in self.nodes.values() {
            props(&n.props);
        }
        for e in self.edges.values() {
            props(&e.props);
        }
        for n in self.nodes.values() {
            for (s, _) in n.labels.values() {
                set.insert(*s);
            }
        }
        for e in self.edges.values() {
            set.insert(e.stamp);
        }
        set.into_iter().zip(0u64..).collect()
    }

    /// `[stamps, nodes, edges, node_tombs, edge_tombs]`. Stamps are stored
    /// once, sorted, and referred to by index.
    pub(crate) fn to_value(&self) -> Result<Value, EncodeError> {
        let table = self.stamps();
        let idx = |s: &Stamp| uint(table.get(s).copied().unwrap_or(u64::MAX));
        // A property value is stored as the bytes of its own encoding: values
        // may nest as deep as an op allows, which is deeper than fits under
        // the state's own levels.
        let props = |p: &Props| -> Result<Value, EncodeError> {
            let mut out = Vec::with_capacity(p.len());
            for (k, (s, v)) in p {
                let mut item = vec![Value::Text(k.clone()), idx(s)];
                if let Some(v) = v {
                    item.push(Value::Bytes(v.encode()?));
                }
                out.push(Value::Array(item));
            }
            Ok(Value::Array(out))
        };
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for (g, n) in &self.nodes {
            nodes.push(Value::Array(vec![
                bytes(g),
                Value::Array(
                    n.labels
                        .iter()
                        .map(|(l, (s, on))| {
                            Value::Array(vec![Value::Text(l.clone()), idx(s), Value::Bool(*on)])
                        })
                        .collect(),
                ),
                props(&n.props)?,
            ]));
        }
        let mut edges = Vec::with_capacity(self.edges.len());
        for (g, e) in &self.edges {
            edges.push(Value::Array(vec![
                bytes(g),
                idx(&e.stamp),
                bytes(&e.src),
                bytes(&e.dst),
                Value::Text(e.ty.clone()),
                props(&e.props)?,
            ]));
        }
        let gids = |s: &BTreeSet<Gid>| Value::Array(s.iter().map(|g| bytes(g)).collect());
        Ok(Value::Array(vec![
            Value::Array(
                table
                    .keys()
                    .map(|s| {
                        Value::Array(vec![
                            uint(s.hlc.wall_ms),
                            uint(u64::from(s.hlc.counter)),
                            uint(u64::from(s.id.alg)),
                            bytes(&s.id.digest),
                        ])
                    })
                    .collect(),
            ),
            Value::Array(nodes),
            Value::Array(edges),
            gids(&self.node_tombs),
            gids(&self.edge_tombs),
        ]))
    }

    /// Inverse of [`Merge::to_value`]. Shape only: the caller re-encodes the
    /// whole state and compares, which rejects anything unsorted, duplicated
    /// or otherwise not the one canonical form.
    pub(crate) fn from_value(v: &Value) -> Option<Merge> {
        let mut f = Fields::exact(v, 5)?;
        let mut table = Vec::new();
        for s in f.array()? {
            let mut s = Fields::exact(s, 4)?;
            table.push(Stamp {
                hlc: Hlc {
                    wall_ms: s.u64()?,
                    counter: s.u32()?,
                },
                id: OpKey {
                    alg: s.u16()?,
                    digest: s.fixed()?,
                },
            });
        }
        let stamp = |f: &mut Fields<'_>| -> Option<Stamp> {
            table.get(usize::try_from(f.u64()?).ok()?).copied()
        };
        let props = |f: &mut Fields<'_>| -> Option<Props> {
            let mut out = Props::new();
            for p in f.array()? {
                let mut p = Fields::open(p)?;
                let key = p.text()?;
                let s = stamp(&mut p)?;
                let val = match p.remaining() {
                    0 => None,
                    1 => Some(Value::decode(p.bytes()?).ok()?),
                    _ => return None,
                };
                out.insert(key.into(), (s, val));
            }
            Some(out)
        };
        let mut m = Merge::default();
        for n in f.array()? {
            let mut n = Fields::exact(n, 3)?;
            let gid: Gid = n.fixed()?;
            let mut labels = BTreeMap::new();
            for l in n.array()? {
                let mut l = Fields::exact(l, 3)?;
                let name = l.text()?;
                labels.insert(name.into(), (stamp(&mut l)?, l.bool()?));
            }
            let props = props(&mut n)?;
            m.nodes.insert(gid, NodeState { labels, props });
        }
        for e in f.array()? {
            let mut e = Fields::exact(e, 6)?;
            let gid: Gid = e.fixed()?;
            let st = EdgeState {
                stamp: stamp(&mut e)?,
                src: e.fixed()?,
                dst: e.fixed()?,
                ty: e.text()?.into(),
                props: props(&mut e)?,
            };
            m.link(gid, st.src, st.dst);
            m.edges.insert(gid, st);
        }
        for g in f.array()? {
            m.node_tombs.insert(Fields::fixed_of(g)?);
        }
        for g in f.array()? {
            m.edge_tombs.insert(Fields::fixed_of(g)?);
        }
        // A tombstoned gid holds no state.
        if m.nodes.keys().any(|g| m.node_tombs.contains(g))
            || m.edges.keys().any(|g| m.edge_tombs.contains(g))
        {
            return None;
        }
        Some(m)
    }
}

/// Apply one change the way an engine does: puts upsert, deletes remove.
fn naive(
    nodes: &mut BTreeMap<Gid, Option<NodeView>>,
    edges: &mut BTreeMap<Gid, Option<EdgeView>>,
    change: &Change,
) {
    match change {
        Change::NodePut {
            gid,
            labels_add,
            labels_remove,
            set,
            unset,
        } => {
            let n = nodes.entry(*gid).or_default().get_or_insert(NodeView {
                gid: *gid,
                labels: BTreeSet::new(),
                props: BTreeMap::new(),
            });
            n.labels.extend(labels_add.iter().cloned());
            for l in labels_remove {
                n.labels.remove(l);
            }
            naive_props(&mut n.props, set, unset);
        }
        Change::NodeDel { gid } => {
            nodes.insert(*gid, None);
        }
        Change::EdgePut {
            gid,
            src,
            dst,
            ty,
            set,
            unset,
        } => {
            let e = edges.entry(*gid).or_default().get_or_insert(EdgeView {
                gid: *gid,
                src: *src,
                dst: *dst,
                ty: ty.clone(),
                props: BTreeMap::new(),
            });
            e.src = *src;
            e.dst = *dst;
            e.ty = ty.clone();
            naive_props(&mut e.props, set, unset);
        }
        Change::EdgeDel { gid } => {
            edges.insert(*gid, None);
        }
    }
}
