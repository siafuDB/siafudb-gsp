//! Convergence property tests.
//!
//! Random local commits on two or three replicas of one fragment, sealed
//! items delivered in random order with duplicates, replicas saved and
//! restored at random points. At the end, after everything has reached
//! everyone:
//!
//! 1. every replica holds the same visible graph, and nothing is pending;
//! 2. on every replica, a naive model graph that was fed only that replica's
//!    own local commits, the corrections `local_commit` returned and the
//!    effects `ingest` emitted equals the replica's visible graph. `Dev`
//!    asserts this after *every* call, not only at the end, and applies
//!    effects in strict mode (edge puts find their endpoints, deletes find
//!    their targets, nodes go after their edges).
//!
//! The second property is the one an engine adapter depends on.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::Value;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const LABELS: [&str; 3] = ["A", "B", "C"];
const KEYS: [&str; 3] = ["k1", "k2", "k3"];
const TYPES: [&str; 2] = ["T", "U"];
const NODES: u8 = 5;
const EDGES: u8 = 4;

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        (0i64..4).prop_map(int),
        Just(Value::Null),
        Just(Value::Bool(true)),
        Just(text("x")),
        Just(Value::Float(0.5)),
        Just(Value::Array(vec![
            int(1),
            Value::Map(vec![("m".into(), int(2))])
        ])),
    ]
}

/// For each of three names: leave alone, set/add, or unset/remove. Disjoint
/// by construction, as the payload rules require.
fn prop_writes() -> impl Strategy<Value = (BTreeMap<String, Value>, BTreeSet<String>)> {
    proptest::collection::vec((0u8..4, value()), 3).prop_map(|choices| {
        let mut set = BTreeMap::new();
        let mut unset = BTreeSet::new();
        for (key, (what, v)) in KEYS.iter().zip(choices) {
            match what {
                0 | 1 => {}
                2 => {
                    set.insert(key.to_string(), v);
                }
                _ => {
                    unset.insert(key.to_string());
                }
            }
        }
        (set, unset)
    })
}

fn change() -> impl Strategy<Value = Change> {
    let node_put = (
        0..NODES,
        proptest::collection::vec(0u8..4, 3),
        prop_writes(),
    )
        .prop_map(|(g, labels, (set, unset))| {
            let mut labels_add = BTreeSet::new();
            let mut labels_remove = BTreeSet::new();
            for (l, what) in LABELS.iter().zip(labels) {
                match what {
                    0 | 1 => {}
                    2 => {
                        labels_add.insert(l.to_string());
                    }
                    _ => {
                        labels_remove.insert(l.to_string());
                    }
                }
            }
            Change::NodePut {
                gid: gid(g),
                labels_add,
                labels_remove,
                set,
                unset,
            }
        });
    let edge_put = (0..EDGES, 0..NODES, 0..NODES, 0usize..2, prop_writes()).prop_map(
        |(g, src, dst, ty, (set, unset))| Change::EdgePut {
            gid: gid(100 + g),
            src: gid(src),
            dst: gid(dst),
            ty: TYPES[ty].into(),
            set,
            unset,
        },
    );
    prop_oneof![
        6 => node_put,
        5 => edge_put,
        1 => (0..NODES).prop_map(|g| Change::NodeDel { gid: gid(g) }),
        1 => (0..EDGES).prop_map(|g| Change::EdgeDel { gid: gid(100 + g) }),
    ]
}

#[derive(Debug, Clone)]
enum Step {
    /// A local commit on one device.
    Commit(usize, Vec<Change>),
    /// A device pushes its outbox to the relay log.
    Push(usize),
    /// A device receives one item of the log, any item, possibly again.
    Deliver(usize, usize),
    /// A device receives a run of the log in relay order.
    Pull(usize, usize),
    /// A device is saved to bytes and restored.
    Restore(usize),
}

fn step(devs: usize) -> impl Strategy<Value = Step> {
    prop_oneof![
        5 => (0..devs, proptest::collection::vec(change(), 1..4))
            .prop_map(|(d, c)| Step::Commit(d, c)),
        3 => (0..devs).prop_map(Step::Push),
        6 => (0..devs, any::<usize>()).prop_map(|(d, i)| Step::Deliver(d, i)),
        2 => (0..devs, 1usize..6).prop_map(|(d, n)| Step::Pull(d, n)),
        1 => (0..devs).prop_map(Step::Restore),
    ]
}

fn scenario() -> impl Strategy<Value = (usize, Vec<Step>, u64)> {
    (2usize..4).prop_flat_map(|devs| {
        (
            Just(devs),
            proptest::collection::vec(step(devs), 1..48),
            any::<u64>(),
        )
    })
}

struct World {
    devs: Vec<Dev>,
    /// What the relay holds, in arrival order.
    log: Vec<Vec<u8>>,
    /// Per device: how far it has pulled in relay order.
    pulled: Vec<usize>,
    now: u64,
    /// Per-device wall clock offsets, all inside the drift bound.
    skew: Vec<u64>,
}

impl World {
    fn new(n: usize) -> World {
        World {
            devs: (0..n).map(|i| Dev::new(i as u8 + 1)).collect(),
            log: Vec::new(),
            pulled: vec![0; n],
            now: T0,
            skew: [0, 40, 7_000].into_iter().take(n).collect(),
        }
    }

    fn clock(&self, d: usize) -> u64 {
        self.now + self.skew[d]
    }

    fn push(&mut self, d: usize) {
        let items = self.devs[d].drain();
        self.log.extend(items);
    }

    fn run(&mut self, s: &Step) {
        // Time passes, but not always: equal readings exercise the HLC counter.
        self.now += match s {
            Step::Commit(d, _) => (*d as u64) % 2,
            _ => 1,
        };
        match s {
            Step::Commit(d, changes) => {
                let now = self.clock(*d);
                self.devs[*d].commit(changes, now);
            }
            Step::Push(d) => self.push(*d),
            Step::Deliver(d, i) => {
                if !self.log.is_empty() {
                    let item = self.log[i % self.log.len()].clone();
                    let now = self.clock(*d);
                    self.devs[*d].ingest(&item, 0, now);
                }
            }
            Step::Pull(d, n) => {
                let from = self.pulled[*d];
                let to = (from + n).min(self.log.len());
                for i in from..to {
                    let item = self.log[i].clone();
                    let now = self.clock(*d);
                    self.devs[*d].ingest(&item, i as u64 + 1, now);
                    assert_eq!(self.devs[*d].r.cursor(), i as u64 + 1);
                }
                self.pulled[*d] = to;
            }
            Step::Restore(d) => self.devs[*d].restore(),
        }
    }

    /// Everything reaches everyone, in a different random order per device.
    fn settle(&mut self, seed: u64) {
        for d in 0..self.devs.len() {
            self.push(d);
        }
        let mut rng = Rng(seed | 1);
        self.now += 1;
        for d in 0..self.devs.len() {
            let mut order: Vec<usize> = (0..self.log.len()).collect();
            rng.shuffle(&mut order);
            let now = self.clock(d);
            for i in order {
                let item = self.log[i].clone();
                self.devs[d].ingest(&item, 0, now);
            }
        }
    }

    fn assert_converged(&self) {
        let first = &self.devs[0];
        let ops: u64 = self.devs.iter().map(|d| d.r.stats().local).sum();
        for d in &self.devs {
            let st = d.r.stats();
            assert_eq!(st.pending, 0, "nothing may stay pending");
            assert_eq!(st.pending_bytes, 0);
            assert_eq!(st.outbox, 0);
            assert_eq!(st.authors, self.devs.len());
            assert_eq!((st.invalid, st.equivocations, st.unsupported), (0, 0, 0));
            assert_eq!(st.applied + st.local, ops, "every op applied exactly once");
            assert_eq!(d.r.nodes(), first.r.nodes(), "replicas disagree on nodes");
            assert_eq!(d.r.edges(), first.r.edges(), "replicas disagree on edges");
            // The model was fed only local commits, corrections and effects.
            d.check();
            assert_eq!(d.model, first.model);
            // No visible edge without visible endpoints.
            for e in d.r.edges() {
                assert!(d.r.node(&e.src).is_some() && d.r.node(&e.dst).is_some());
            }
            // And a fresh engine can be built from the snapshot.
            let mut fresh = Model::default();
            fresh.apply_all(&d.r.snapshot(), true);
            assert_eq!(fresh, d.model);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 2000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn replicas_converge_and_effects_are_sufficient((n, steps, seed) in scenario()) {
        let mut w = World::new(n);
        for s in &steps {
            w.run(s);
        }
        w.settle(seed);
        w.assert_converged();
    }

    /// Relay order, the realistic transport: every device pushes, then pulls
    /// after its cursor. The cursor ends at the end of the log.
    #[test]
    fn in_order_pull_converges(
        n in 2usize..4,
        rounds in proptest::collection::vec(
            proptest::collection::vec((0usize..3, proptest::collection::vec(change(), 1..4)), 0..5),
            1..8,
        ),
    ) {
        let mut w = World::new(n);
        for round in &rounds {
            for (d, changes) in round {
                w.run(&Step::Commit(d % n, changes.clone()));
            }
            for d in 0..n {
                w.push(d);
            }
            for d in 0..n {
                let behind = w.log.len() - w.pulled[d];
                w.run(&Step::Pull(d, behind));
                prop_assert_eq!(w.devs[d].r.cursor(), w.log.len() as u64);
                prop_assert_eq!(w.devs[d].r.stats().pending, 0);
            }
            // After a full round everyone agrees already.
            for d in 1..n {
                prop_assert_eq!(w.devs[d].r.nodes(), w.devs[0].r.nodes());
                prop_assert_eq!(w.devs[d].r.edges(), w.devs[0].r.edges());
            }
        }
        w.settle(1);
        w.assert_converged();
    }
}

proptest! {
    // Restoring every device after every step is slow in a debug build
    // (each restore re-verifies the key logs), hence fewer cases.
    #![proptest_config(ProptestConfig {
        cases: 24,
        max_shrink_iters: 500,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// The same script with and without save/restore after every step ends
    /// in byte-identical replica states.
    #[test]
    fn restoring_mid_stream_changes_nothing((n, steps, seed) in scenario()) {
        let mut plain = World::new(n);
        let mut restored = World::new(n);
        for s in &steps {
            if !matches!(s, Step::Restore(_)) {
                plain.run(s);
            } else {
                plain.now += 1;
            }
            restored.run(s);
            for d in restored.devs.iter_mut() {
                d.restore();
            }
        }
        plain.settle(seed);
        restored.settle(seed);
        restored.assert_converged();
        for d in 0..n {
            prop_assert_eq!(
                &*plain.devs[d].r.to_bytes().unwrap(),
                &*restored.devs[d].r.to_bytes().unwrap()
            );
            prop_assert_eq!(&plain.devs[d].model, &restored.devs[d].model);
        }
    }
}
