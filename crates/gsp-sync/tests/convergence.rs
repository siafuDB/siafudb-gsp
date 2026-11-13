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
//!
//! A further test (`honest_ops_converge_despite_faults`) adds what the
//! security review asked about: items that never reach a replica, an author
//! whose clock runs ahead, an author who equivocates, and pending bounds
//! small enough to be hit. There the claim is narrower and is the one that
//! matters: every op of every honest author ends up applied on every honest
//! replica, and they agree on everything but what the equivocator wrote.
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
        World::with(n, Config::default())
    }

    fn with(n: usize, config: Config) -> World {
        World {
            devs: (0..n)
                .map(|i| Dev::with(ROOT, i as u8 + 1, config))
                .collect(),
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

// ---------------------------------------------------------------- faults

/// Gids only the equivocating author writes to.
const MALLORY_NODES: u8 = 60;
const HOUR: u64 = 3_600_000;

#[derive(Debug, Clone)]
enum Fault {
    /// Something an honest device or its transport does.
    Honest(Step),
    /// An in-order pull in which the items picked by `mask` never arrive:
    /// the cursor moves past them all the same.
    LossyPull(usize, usize, u8),
    /// The equivocator writes its next op. With `twin`, it writes two
    /// different ops at that position, and continues its chain on one.
    Mallory {
        twin: bool,
        twin_first: bool,
        chain_on_twin: bool,
    },
    /// The author with the fast clock writes: two hours ahead (held by
    /// everyone until then), or with `far` more than a year ahead (rejected).
    Clocky { far: bool, key: usize },
}

fn fault(devs: usize) -> impl Strategy<Value = Fault> {
    prop_oneof![
        10 => step(devs).prop_map(Fault::Honest),
        3 => (0..devs, 1usize..8, any::<u8>()).prop_map(|(d, n, m)| Fault::LossyPull(d, n, m)),
        3 => (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
            |(twin, twin_first, chain_on_twin)| Fault::Mallory { twin, twin_first, chain_on_twin }
        ),
        3 => (proptest::bool::weighted(0.15), 0usize..3)
            .prop_map(|(far, key)| Fault::Clocky { far, key }),
    ]
}

/// An author driven by hand: the last op of its chain, and how many it made.
struct Chain {
    forge: Forge,
    last: Option<gsp_wire::Op>,
    wall: u64,
}

impl Chain {
    fn new(seed: u8) -> Chain {
        Chain {
            forge: Forge::new(ROOT, seed),
            last: None,
            wall: 0,
        }
    }
    fn seq(&self) -> u64 {
        self.last.as_ref().map_or(1, |o| o.body().seq + 1)
    }
    fn make(&mut self, wall: u64, changes: &[Change]) -> gsp_wire::Op {
        // Strictly increasing along the chain, as an honest author's HLC is.
        self.wall = wall.max(self.wall + 1);
        self.forge
            .op(self.seq(), self.last.as_ref(), self.wall, changes)
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 1000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn honest_ops_converge_despite_faults(
        n in 2usize..4,
        faults in proptest::collection::vec(fault(3), 1..60),
        seed in any::<u64>(),
    ) {
        // Bounds small enough that the stuck authors fill them.
        let config = Config {
            max_pending_items_per_author: 3,
            max_pending_items: 7,
            ..Config::default()
        };
        let mut w = World::with(n, config);
        let mut mallory = Chain::new(90);
        let mut clocky = Chain::new(91);
        w.log.push(mallory.forge.sealed_genesis());
        w.log.push(clocky.forge.sealed_genesis());
        let mut clocky_stuck_at: Option<u64> = None;

        for f in &faults {
            match f {
                Fault::Honest(s) => {
                    let s = match s {
                        Step::Commit(d, c) => Step::Commit(d % n, c.clone()),
                        Step::Push(d) => Step::Push(d % n),
                        Step::Deliver(d, i) => Step::Deliver(d % n, *i),
                        Step::Pull(d, k) => Step::Pull(d % n, *k),
                        Step::Restore(d) => Step::Restore(d % n),
                    };
                    w.run(&s);
                }
                Fault::LossyPull(d, k, mask) => {
                    let d = d % n;
                    w.now += 1;
                    let from = w.pulled[d];
                    let to = (from + k).min(w.log.len());
                    for i in from..to {
                        if mask >> (i % 8) & 1 == 1 {
                            continue;
                        }
                        let item = w.log[i].clone();
                        let now = w.clock(d);
                        w.devs[d].ingest(&item, i as u64 + 1, now);
                    }
                    // What the transport does with `Batch.next`.
                    w.devs[d].r.set_cursor(to as u64);
                    prop_assert!(!w.devs[d].r.observe_relay_head(to as u64));
                    w.pulled[d] = to;
                }
                Fault::Mallory { twin, twin_first, chain_on_twin } => {
                    let g = MALLORY_NODES + (mallory.seq() % 3) as u8;
                    let wall = w.now;
                    let op = mallory.make(wall, &[node(g, &[], &[("m", int(1))])]);
                    let mut items = vec![mallory.forge.sealed_op(&op)];
                    let mut keep = op;
                    if *twin {
                        let other = mallory
                            .forge
                            .op(keep.body().seq, mallory.last.as_ref(), mallory.wall,
                                &[node(g, &["twin"], &[("m", int(2))])]);
                        items.push(mallory.forge.sealed_op(&other));
                        if *twin_first {
                            items.swap(0, 1);
                        }
                        if *chain_on_twin {
                            keep = other;
                        }
                    }
                    mallory.last = Some(keep);
                    w.log.extend(items);
                }
                Fault::Clocky { far, key } => {
                    // It writes to the gids the honest devices use.
                    let lead = if *far { 400 * 24 * HOUR } else { 2 * HOUR };
                    let wall = w.now + lead;
                    let g = (clocky.seq() % u64::from(NODES)) as u8;
                    let op = clocky.make(wall, &[node(g, &["C"], &[(KEYS[*key], text("clocky"))])]);
                    if *far && clocky_stuck_at.is_none() {
                        clocky_stuck_at = Some(op.body().seq);
                    }
                    w.log.push(clocky.forge.sealed_op(&op));
                    clocky.last = Some(op);
                }
            }
            // No replica ever has its cursor held back by what it could not
            // use, and none is forked.
            for d in &w.devs {
                prop_assert!(!d.r.forked());
            }
        }

        // Settle. Everyone pushes; three hours pass (so what was held for
        // the clock can apply); every replica resyncs from the start of the
        // relay log, as its transport does when `needs_resync` says so.
        for d in 0..n {
            w.push(d);
        }
        w.now += 3 * HOUR;
        let mut rng = Rng(seed | 1);
        for d in 0..n {
            // First whatever random leftovers a flaky network delivers...
            for _ in 0..w.log.len() / 2 {
                let i = (rng.next() as usize) % w.log.len();
                let item = w.log[i].clone();
                let now = w.clock(d);
                w.devs[d].ingest(&item, 0, now);
            }
            // ...then the resync.
            w.devs[d].r.start_resync();
            for i in 0..w.log.len() {
                let item = w.log[i].clone();
                let now = w.clock(d);
                w.devs[d].ingest(&item, i as u64 + 1, now);
                prop_assert_eq!(w.devs[d].r.cursor(), i as u64 + 1);
            }
            // A second replay changes nothing: replay is idempotent.
            let before = (w.devs[d].r.nodes(), w.devs[d].r.edges());
            for i in 0..w.log.len() {
                let item = w.log[i].clone();
                let now = w.clock(d);
                let out = w.devs[d].ingest(&item, i as u64 + 1, now);
                prop_assert!(out.effects.is_empty() && out.applied == 0);
            }
            prop_assert_eq!(&before, &(w.devs[d].r.nodes(), w.devs[d].r.edges()));
        }

        let honest_view = |d: &Dev| {
            let nodes: Vec<NodeView> = d
                .r
                .nodes()
                .into_iter()
                .filter(|x| x.gid[0] < MALLORY_NODES)
                .collect();
            (nodes, d.r.edges())
        };
        let authors: Vec<(gsp_wire::Multihash, u64)> = w
            .devs
            .iter()
            .map(|d| (d.r.author(), d.r.stats().local))
            .collect();
        let first = honest_view(&w.devs[0]);
        for d in &w.devs {
            // Every op of every honest author is applied on every replica.
            let known = d.r.authors();
            for (author, ops) in &authors {
                let st = known.iter().find(|a| a.author == *author).expect("known");
                prop_assert_eq!(st.applied_seq, *ops);
                prop_assert_eq!(st.pending, 0);
                prop_assert!(!st.gap && !st.equivocated);
            }
            // They agree on everything the equivocator did not write. That
            // includes what the author with the fast clock wrote: its ops
            // apply (or are refused) on all of them alike.
            prop_assert_eq!(&honest_view(d), &first);
            let c = known
                .iter()
                .find(|a| a.author == clocky.forge.author())
                .expect("known");
            let want = clocky_stuck_at.map_or(clocky.seq() - 1, |s| s - 1);
            prop_assert_eq!(c.applied_seq, want);
            // The model saw only local commits, corrections and effects.
            d.check();
            for e in d.r.edges() {
                prop_assert!(d.r.node(&e.src).is_some() && d.r.node(&e.dst).is_some());
            }
            // Bounds held throughout; whatever is still pending belongs to
            // the two faulty authors.
            let st = d.r.stats();
            prop_assert!(st.pending <= config.max_pending_items);
            let faulty: usize = known
                .iter()
                .filter(|a| {
                    a.author == clocky.forge.author() || a.author == mallory.forge.author()
                })
                .map(|a| a.pending)
                .sum();
            prop_assert_eq!(st.pending, faulty);
            prop_assert!(!st.forked);
        }
    }
}
