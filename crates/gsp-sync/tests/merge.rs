//! The merge rules of SYNC-V0 section 5, one scenario per rule, with the
//! exact effects each replica emits. Every call goes through `Dev`, which
//! also checks that a naive engine fed only local commits and effects equals
//! the replica's visible state.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::{Multihash, Op, Plain, SealedOp};

/// Open a sealed outbox item the way a second device would.
fn open(sealed: &[u8]) -> Plain {
    let p = Pairing::from_root(ROOT);
    SealedOp::from_bytes(sealed)
        .unwrap()
        .open(&p.fragment_key(), &p.fragment_id())
        .unwrap()
}

fn op_of(sealed: &[u8]) -> Op {
    match open(sealed) {
        Plain::Op(b) => Op::from_bytes(&b).unwrap(),
        other => panic!("not an op: {other:?}"),
    }
}

/// Two devices that already know each other's key log.
fn pair() -> (Dev, Dev) {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    let (ga, gb) = (a.drain(), b.drain());
    assert_eq!(b.ingest(&ga[0], 0, T0).status, IngestStatus::KeyLog);
    assert_eq!(a.ingest(&gb[0], 0, T0).status, IngestStatus::KeyLog);
    (a, b)
}

/// Move everything in `from`'s outbox to `to`; returns all effects.
fn sync(from: &mut Dev, to: &mut Dev, now: u64) -> Vec<Change> {
    let mut effects = Vec::new();
    for item in from.drain() {
        effects.extend(to.ingest(&item, 0, now).effects);
    }
    effects
}

fn same(a: &Dev, b: &Dev) {
    assert_eq!(a.r.nodes(), b.r.nodes());
    assert_eq!(a.r.edges(), b.r.edges());
}

#[test]
fn first_push_is_the_genesis_key_log_then_ops() {
    let mut a = Dev::new(1);
    assert_eq!(a.r.outbox_len(), 1);
    a.commit(&[node(1, &["P"], &[("k", int(1))])], T0);
    let items = a.drain();
    assert!(matches!(open(&items[0]), Plain::KeyLog(_)));
    let op = op_of(&items[1]);
    assert_eq!(op.body().seq, 1);
    assert_eq!(op.body().author, a.r.author());
    assert_eq!(op.body().fragment_id, a.r.fragment_id().to_vec());
    assert_eq!(op.sigs().len(), 1, "policy [Ed25519]: one signature");
    assert_eq!(op.sigs()[0].alg, 1);
}

#[test]
fn a_remote_commit_arrives_as_the_same_changes() {
    let (mut a, mut b) = pair();
    let commit = [
        node(1, &["Person"], &[("name", text("Tendai"))]),
        node(2, &["Person"], &[]),
        edge(9, 1, 2, "KNOWS", &[("since", int(2020))]),
    ];
    assert_eq!(a.commit(&commit, T0 + 1), vec![], "nothing to correct");
    let effects = sync(&mut a, &mut b, T0 + 2);
    assert_eq!(effects, commit.to_vec());
    same(&a, &b);
    assert_eq!(
        b.r.node(&gid(1)).unwrap().props,
        props(&[("name", text("Tendai"))])
    );
    let e = b.r.edge(&gid(9)).unwrap();
    assert_eq!((e.src, e.dst, e.ty.as_str()), (gid(1), gid(2), "KNOWS"));
    assert_eq!(b.r.stats().applied, 1);
}

#[test]
fn deletes_win_over_earlier_and_later_puts() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &["P"], &[("k", int(1))])], T0 + 1);
    sync(&mut a, &mut b, T0 + 2);

    // B deletes; A, not knowing, writes with a *later* stamp.
    assert_eq!(b.commit(&[node_del(1)], T0 + 10), vec![]);
    assert_eq!(a.commit(&[node(1, &[], &[("k", int(2))])], T0 + 20), vec![]);
    assert_eq!(a.r.node(&gid(1)).unwrap().props, props(&[("k", int(2))]));

    // The delete reaches A: the node goes. The later put reaches B: nothing.
    assert_eq!(sync(&mut b, &mut a, T0 + 30), vec![node_del(1)]);
    assert_eq!(sync(&mut a, &mut b, T0 + 30), vec![]);
    same(&a, &b);
    assert!(a.r.node(&gid(1)).is_none());
    assert!(a.r.node_deleted(&gid(1)) && b.r.node_deleted(&gid(1)));

    // Permanent: a put long after the delete creates nothing, and the
    // replica tells the local engine to take its node back out.
    assert_eq!(
        a.commit(&[node(1, &["P"], &[("k", int(3))])], T0 + 1000),
        vec![node_del(1)]
    );
    assert_eq!(sync(&mut a, &mut b, T0 + 1001), vec![]);
    same(&a, &b);
    assert!(b.r.nodes().is_empty());

    // Same for edges.
    a.commit(
        &[
            node(2, &[], &[]),
            node(3, &[], &[]),
            edge(9, 2, 3, "T", &[]),
        ],
        T0 + 2000,
    );
    sync(&mut a, &mut b, T0 + 2001);
    b.commit(&[edge_del(9)], T0 + 2010);
    a.commit(&[edge(9, 2, 3, "T", &[("k", int(1))])], T0 + 2020);
    assert_eq!(sync(&mut b, &mut a, T0 + 2030), vec![edge_del(9)]);
    assert_eq!(sync(&mut a, &mut b, T0 + 2030), vec![]);
    assert_eq!(
        a.commit(&[edge(9, 2, 3, "T", &[])], T0 + 3000),
        vec![edge_del(9)]
    );
    sync(&mut a, &mut b, T0 + 3001);
    same(&a, &b);
    assert!(a.r.edges().is_empty() && a.r.edge_deleted(&gid(9)));
}

#[test]
fn a_delete_for_a_gid_never_seen_blocks_a_put_that_arrives_later() {
    let (mut a, mut b) = pair();
    // A creates and B never hears of it; C-like situation built with B
    // deleting blind.
    b.commit(&[node_del(1), edge_del(9)], T0 + 5);
    a.commit(
        &[
            node(1, &[], &[]),
            node(2, &[], &[]),
            edge(9, 2, 2, "T", &[]),
        ],
        T0 + 1,
    );
    assert_eq!(sync(&mut a, &mut b, T0 + 10), vec![node(2, &[], &[])]);
    assert_eq!(
        sync(&mut b, &mut a, T0 + 10),
        vec![edge_del(9), node_del(1)]
    );
    same(&a, &b);
}

#[test]
fn properties_are_last_writer_wins_per_key() {
    let (mut a, mut b) = pair();
    a.commit(
        &[node(1, &[], &[("x", int(0)), ("y", int(0)), ("z", int(0))])],
        T0 + 1,
    );
    sync(&mut a, &mut b, T0 + 2);

    // Concurrent: A writes x and y early, B writes y and z late.
    a.commit(&[node(1, &[], &[("x", int(1)), ("y", int(1))])], T0 + 10);
    b.commit(&[node(1, &[], &[("y", int(2)), ("z", int(2))])], T0 + 20);
    // B gets A's older op: only x is news. A gets B's newer op: y and z.
    assert_eq!(
        sync(&mut a, &mut b, T0 + 30),
        vec![node(1, &[], &[("x", int(1))])]
    );
    assert_eq!(
        sync(&mut b, &mut a, T0 + 30),
        vec![node(1, &[], &[("y", int(2)), ("z", int(2))])]
    );
    same(&a, &b);
    assert_eq!(
        a.r.node(&gid(1)).unwrap().props,
        props(&[("x", int(1)), ("y", int(2)), ("z", int(2))])
    );
}

#[test]
fn unset_is_a_write_of_absent_and_competes_like_any_other() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &[], &[("k", int(0)), ("j", int(0))])], T0 + 1);
    sync(&mut a, &mut b, T0 + 2);
    let unset = |keys: &[&str]| Change::NodePut {
        gid: gid(1),
        labels_add: Default::default(),
        labels_remove: Default::default(),
        set: Default::default(),
        unset: set_of(keys),
    };
    // k: unset is later than the set, so it wins. j: the set is later.
    a.commit(&[node(1, &[], &[("k", int(1))])], T0 + 10);
    b.commit(&[unset(&["k", "j"])], T0 + 20);
    a.commit(&[node(1, &[], &[("j", int(9))])], T0 + 30);
    assert_eq!(
        sync(&mut a, &mut b, T0 + 40),
        vec![node(1, &[], &[("j", int(9))])]
    );
    assert_eq!(sync(&mut b, &mut a, T0 + 40), vec![unset(&["k"])]);
    same(&a, &b);
    assert_eq!(a.r.node(&gid(1)).unwrap().props, props(&[("j", int(9))]));

    // An unset for a key that never existed still holds its stamp: an older
    // set arriving afterwards loses to it.
    b.commit(&[unset(&["ghost"])], T0 + 100);
    a.commit(&[node(1, &[], &[("ghost", int(1))])], T0 + 90);
    assert_eq!(sync(&mut a, &mut b, T0 + 110), vec![]);
    assert_eq!(sync(&mut b, &mut a, T0 + 110), vec![unset(&["ghost"])]);
    same(&a, &b);
}

#[test]
fn labels_are_last_writer_wins_between_present_and_absent() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &["L", "M"], &[])], T0 + 1);
    sync(&mut a, &mut b, T0 + 2);
    let labels = |add: &[&str], remove: &[&str]| Change::NodePut {
        gid: gid(1),
        labels_add: set_of(add),
        labels_remove: set_of(remove),
        set: Default::default(),
        unset: Default::default(),
    };
    // L: removed at 10, re-added at 20 -> present. M: re-added at 10 (no-op
    // then), removed at 20 -> absent. N: added at 10, removed at 20 -> absent.
    a.commit(&[labels(&["M", "N"], &["L"])], T0 + 10);
    b.commit(&[labels(&["L"], &["M", "N"])], T0 + 20);
    assert_eq!(sync(&mut a, &mut b, T0 + 30), vec![]);
    assert_eq!(
        sync(&mut b, &mut a, T0 + 30),
        vec![labels(&["L"], &["M", "N"])]
    );
    same(&a, &b);
    assert_eq!(a.r.node(&gid(1)).unwrap().labels, set_of(&["L"]));
}

#[test]
fn equal_hlc_is_broken_by_op_id_and_both_sides_agree() {
    let (mut a, mut b) = pair();
    // Fresh clocks, same `now`: both ops carry HLC (T0 + 5, 0).
    a.commit(&[node(1, &[], &[("k", text("from-a"))])], T0 + 5);
    b.commit(&[node(1, &[], &[("k", text("from-b"))])], T0 + 5);
    let (ia, ib) = (a.drain(), b.drain());
    let (oa, ob) = (op_of(&ia[0]), op_of(&ib[0]));
    assert_eq!(oa.body().hlc, ob.body().hlc);
    let winner = if oa.id().digest > ob.id().digest {
        "from-a"
    } else {
        "from-b"
    };
    a.ingest(&ib[0], 0, T0 + 6);
    b.ingest(&ia[0], 0, T0 + 6);
    same(&a, &b);
    assert_eq!(
        a.r.node(&gid(1)).unwrap().props,
        props(&[("k", text(winner))])
    );
}

#[test]
fn edge_endpoints_and_type_are_fixed_by_the_lowest_stamp() {
    let (mut a, mut b) = pair();
    a.commit(
        &[node(1, &[], &[]), node(2, &[], &[]), node(3, &[], &[])],
        T0 + 1,
    );
    sync(&mut a, &mut b, T0 + 2);

    // Both create edge 9, differently. A's put has the lower stamp.
    a.commit(
        &[edge(9, 1, 2, "A", &[("p", int(1)), ("only-a", int(1))])],
        T0 + 10,
    );
    b.commit(
        &[edge(9, 2, 3, "B", &[("p", int(2)), ("only-b", int(2))])],
        T0 + 20,
    );

    // A already has the winning endpoints; B's later put only adds properties.
    assert_eq!(
        sync(&mut b, &mut a, T0 + 30),
        vec![edge(9, 1, 2, "A", &[("p", int(2)), ("only-b", int(2))])]
    );
    // B had the losing endpoints: the edge is replaced, with everything.
    assert_eq!(
        sync(&mut a, &mut b, T0 + 30),
        vec![
            edge_del(9),
            edge(
                9,
                1,
                2,
                "A",
                &[("p", int(2)), ("only-a", int(1)), ("only-b", int(2))]
            )
        ]
    );
    same(&a, &b);

    // A later local put with other endpoints changes nothing but properties;
    // the replica has the engine put the real edge back.
    assert_eq!(
        b.commit(&[edge(9, 3, 3, "C", &[("q", int(1))])], T0 + 100),
        vec![
            edge_del(9),
            edge(
                9,
                1,
                2,
                "A",
                &[
                    ("p", int(2)),
                    ("only-a", int(1)),
                    ("only-b", int(2)),
                    ("q", int(1))
                ]
            )
        ]
    );
    assert_eq!(
        sync(&mut b, &mut a, T0 + 101),
        vec![edge(9, 1, 2, "A", &[("q", int(1))])]
    );
    same(&a, &b);
}

#[test]
fn an_edge_becomes_visible_when_its_endpoints_arrive() {
    let (mut a, mut b) = pair();
    // A's engine made an edge between nodes the replica has never seen put:
    // the replica says so.
    assert_eq!(
        a.commit(&[edge(9, 1, 2, "T", &[("w", int(1))])], T0 + 1),
        vec![edge_del(9)]
    );
    assert!(a.r.edge(&gid(9)).is_none());
    assert_eq!(sync(&mut a, &mut b, T0 + 2), vec![], "no visible change");

    // One endpoint is not enough.
    b.commit(&[node(1, &[], &[])], T0 + 10);
    assert_eq!(sync(&mut b, &mut a, T0 + 11), vec![node(1, &[], &[])]);
    assert!(a.r.edge(&gid(9)).is_none());

    // The second endpoint makes the edge appear, on the device that puts it
    // (as a correction, the engine does not know about the edge) and on the
    // other (as an effect, after the node).
    assert_eq!(
        b.commit(&[node(2, &[], &[])], T0 + 20),
        vec![edge(9, 1, 2, "T", &[("w", int(1))])]
    );
    assert_eq!(
        sync(&mut b, &mut a, T0 + 21),
        vec![node(2, &[], &[]), edge(9, 1, 2, "T", &[("w", int(1))])]
    );
    same(&a, &b);
    assert!(a.r.edge(&gid(9)).is_some());
}

#[test]
fn deleting_a_node_hides_its_edges_for_good() {
    let (mut a, mut b) = pair();
    a.commit(
        &[
            node(1, &[], &[]),
            node(2, &[], &[]),
            node(3, &[], &[]),
            edge(7, 1, 2, "T", &[]),
            edge(8, 2, 3, "T", &[]),
            edge(9, 1, 3, "T", &[]),
            edge(6, 2, 2, "LOOP", &[]),
        ],
        T0 + 1,
    );
    sync(&mut a, &mut b, T0 + 2);
    assert_eq!(b.r.edges().len(), 4);

    // The deleting device: its engine removed the node only, so the replica
    // lists the edges that went with it.
    assert_eq!(
        b.commit(&[node_del(2)], T0 + 10),
        vec![edge_del(6), edge_del(7), edge_del(8)]
    );
    // The other device: edges first, then the node.
    assert_eq!(
        sync(&mut b, &mut a, T0 + 11),
        vec![edge_del(6), edge_del(7), edge_del(8), node_del(2)]
    );
    same(&a, &b);
    assert_eq!(a.r.edges().len(), 1);
    // The hidden edges are not tombstoned, only hidden; but the node is, so
    // nothing brings them back: a new put of the edge stays invisible.
    assert!(!a.r.edge_deleted(&gid(7)));
    assert_eq!(
        a.commit(&[edge(7, 1, 2, "T", &[("k", int(1))])], T0 + 20),
        vec![edge_del(7)]
    );
    assert_eq!(sync(&mut a, &mut b, T0 + 21), vec![]);
    same(&a, &b);

    // A device that explicitly deletes the edges with the node gets nothing
    // back.
    assert_eq!(a.commit(&[edge_del(9), node_del(1)], T0 + 30), vec![]);
    assert_eq!(
        sync(&mut a, &mut b, T0 + 31),
        vec![edge_del(9), node_del(1)]
    );
    same(&a, &b);
}

#[test]
fn changes_of_one_op_share_a_stamp_and_are_ordered_by_position() {
    let (mut a, mut b) = pair();
    // Later change wins a register; a delete beats a put wherever it stands;
    // the first put fixes an edge.
    let fix = a.commit(
        &[
            node(1, &["X"], &[("k", int(1))]),
            node(1, &[], &[("k", int(2))]),
            node_del(2),
            node(2, &[], &[]),
            node(3, &[], &[]),
            edge(9, 1, 3, "FIRST", &[]),
            edge(9, 3, 1, "SECOND", &[("p", int(1))]),
        ],
        T0 + 1,
    );
    // The naive engine has node 2 and the re-pointed edge; both are corrected.
    assert_eq!(
        fix,
        vec![
            edge_del(9),
            edge(9, 1, 3, "FIRST", &[("p", int(1))]),
            node_del(2)
        ]
    );
    let effects = sync(&mut a, &mut b, T0 + 2);
    assert_eq!(
        effects,
        vec![
            node(1, &["X"], &[("k", int(2))]),
            node(3, &[], &[]),
            edge(9, 1, 3, "FIRST", &[("p", int(1))]),
        ]
    );
    same(&a, &b);
}

#[test]
fn effects_carry_only_what_changed() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &["L"], &[("k", int(1)), ("j", int(1))])], T0 + 1);
    sync(&mut a, &mut b, T0 + 2);
    // Re-writing the same values and labels with a newer stamp is not a
    // visible change.
    a.commit(&[node(1, &["L"], &[("k", int(1))])], T0 + 10);
    assert_eq!(sync(&mut a, &mut b, T0 + 11), vec![]);
    // 1 and 1.0 are different values.
    a.commit(
        &[node(1, &[], &[("k", gsp_wire::Value::Float(1.0))])],
        T0 + 20,
    );
    assert_eq!(
        sync(&mut a, &mut b, T0 + 21),
        vec![node(1, &[], &[("k", gsp_wire::Value::Float(1.0))])]
    );
    // A bare put of an existing node is not a change either.
    a.commit(&[Change::node(gid(1))], T0 + 30);
    assert_eq!(sync(&mut a, &mut b, T0 + 31), vec![]);
    // A node's first put is announced even when it carries nothing.
    a.commit(&[Change::node(gid(2))], T0 + 40);
    assert_eq!(sync(&mut a, &mut b, T0 + 41), vec![Change::node(gid(2))]);
    same(&a, &b);
}

#[test]
fn the_same_item_twice_emits_nothing_the_second_time() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &["L"], &[("k", int(1))])], T0 + 1);
    a.commit(&[node_del(1)], T0 + 2);
    let items = a.drain();
    for it in &items {
        assert_eq!(b.ingest(it, 0, T0 + 3).status, IngestStatus::Applied);
    }
    for _ in 0..3 {
        for it in &items {
            let out = b.ingest(it, 0, T0 + 4);
            assert_eq!(out.status, IngestStatus::Duplicate);
            assert_eq!((out.applied, out.effects.len()), (0, 0));
        }
    }
    assert_eq!(b.r.stats().applied, 2);
    assert_eq!(b.r.stats().duplicates, 6);
    // A's own items echoed back by a relay: same thing.
    for it in &items {
        let out = a.ingest(it, 0, T0 + 4);
        assert_eq!(out.status, IngestStatus::Duplicate);
        assert!(out.effects.is_empty());
    }
    assert_eq!(a.r.stats().applied, 0);
}

#[test]
fn deps_are_the_heads_of_the_other_authors_and_prev_is_the_own_head() {
    let (mut a, mut b) = pair();
    let mut c = Dev::new(3);
    let gc = c.drain();
    a.ingest(&gc[0], 0, T0);

    a.commit(&[node(1, &[], &[])], T0 + 1);
    let a1 = a.drain();
    assert!(
        op_of(&a1[0]).body().deps.is_empty(),
        "nobody else has written"
    );
    assert!(op_of(&a1[0]).body().prev.is_none());

    b.ingest(&a1[0], 0, T0 + 2);
    b.commit(&[node(2, &[], &[])], T0 + 3);
    b.commit(&[node(3, &[], &[])], T0 + 4);
    let bs = b.drain();
    let (b1, b2) = (op_of(&bs[0]), op_of(&bs[1]));
    assert_eq!(b1.body().deps, vec![op_of(&a1[0]).id().clone()]);
    assert_eq!(b2.body().prev.as_ref(), Some(b1.id()));
    assert_eq!(b2.body().seq, 2);

    c.commit(&[node(4, &[], &[])], T0 + 5);
    let cs = c.drain();
    for it in bs.iter().chain(&cs) {
        a.ingest(it, 0, T0 + 6);
    }
    a.commit(&[node(5, &[], &[])], T0 + 7);
    let a2 = op_of(&a.drain()[0]);
    let mut want: Vec<Multihash> = vec![b2.id().clone(), op_of(&cs[0]).id().clone()];
    want.sort();
    let mut got = a2.body().deps.clone();
    got.sort();
    assert_eq!(got, want, "latest op of B and of C, not B's older one");
    assert_eq!(a2.body().prev.as_ref(), Some(op_of(&a1[0]).id()));
    // HLC moves forward along the chain and past everything seen.
    assert!(a2.body().hlc > b2.body().hlc);
}

#[test]
fn a_local_write_made_after_seeing_a_remote_one_wins_even_with_a_slow_clock() {
    let (mut a, mut b) = pair();
    // B's wall clock is two minutes ahead of A's.
    b.commit(&[node(1, &[], &[("k", text("b"))])], T0 + 120_000);
    sync(&mut b, &mut a, T0);
    // A writes afterwards, by its own (earlier) wall clock: the HLC still
    // orders it after what it has seen.
    a.commit(&[node(1, &[], &[("k", text("a"))])], T0 + 1);
    assert_eq!(
        sync(&mut a, &mut b, T0 + 120_001),
        vec![node(1, &[], &[("k", text("a"))])]
    );
    same(&a, &b);
}

#[test]
fn node_and_edge_gids_are_separate_namespaces() {
    let (mut a, mut b) = pair();
    a.commit(&[node(1, &[], &[]), edge(1, 1, 1, "SELF", &[])], T0 + 1);
    a.commit(&[edge_del(1)], T0 + 2);
    sync(&mut a, &mut b, T0 + 3);
    assert!(b.r.node(&gid(1)).is_some());
    assert!(b.r.edge_deleted(&gid(1)) && !b.r.node_deleted(&gid(1)));
    same(&a, &b);
}

#[test]
fn snapshot_rebuilds_the_visible_graph_in_an_empty_engine() {
    let (mut a, mut b) = pair();
    a.commit(
        &[
            node(1, &["A"], &[("k", int(1))]),
            node(2, &[], &[]),
            node(3, &[], &[]),
            edge(7, 1, 2, "T", &[("w", int(1))]),
            edge(8, 2, 3, "T", &[]),
        ],
        T0 + 1,
    );
    a.commit(&[node_del(3)], T0 + 2);
    sync(&mut a, &mut b, T0 + 3);
    let mut fresh = Model::default();
    fresh.apply_all(&b.r.snapshot(), true);
    assert_eq!(fresh, b.model);
    assert_eq!(fresh.nodes.len(), 2);
    assert_eq!(fresh.edges.len(), 1);
}

#[test]
fn deps_are_capped_at_64_keeping_the_most_recent_heads() {
    let mut d = Dev::with(
        ROOT,
        1,
        Config {
            max_authors: 100,
            ..Config::default()
        },
    );
    d.drain();
    let mut heads = Vec::new();
    for i in 0..70u8 {
        let mut f = Forge::new(ROOT, 100 + i);
        d.ingest(&f.sealed_genesis(), 0, T0);
        let op = f.op(1, None, T0 + u64::from(i), &[node(i, &[], &[])]);
        assert_eq!(
            d.ingest(&f.sealed_op(&op), 0, T0 + 100).status,
            IngestStatus::Applied
        );
        heads.push(op.id().clone());
    }
    assert_eq!(d.r.stats().authors, 71);
    d.commit(&[node(200, &[], &[])], T0 + 200);
    let op = op_of(&d.drain()[0]);
    assert_eq!(op.body().deps.len(), 64);
    // The six oldest heads are the ones left out.
    for (i, h) in heads.iter().enumerate() {
        assert_eq!(op.body().deps.contains(h), i >= 6, "head {i}");
    }
    // Another replica that has all 70 applies it.
    assert!(op.body().hlc.wall_ms == T0 + 200);
}
