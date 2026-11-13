//! Regression tests for the findings of the security review. Each of the
//! reviewer's proofs of concept is here, turned around: the scenario is the
//! same, the assertion is the outcome a replica must now give.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::Multihash;

fn statuses(d: &mut Dev, items: &[Vec<u8>], now: u64) -> Vec<IngestStatus> {
    items.iter().map(|it| d.ingest(it, 0, now).status).collect()
}

fn status_of(d: &Dev, author: &Multihash) -> AuthorStatus {
    d.r.authors()
        .into_iter()
        .find(|a| a.author == *author)
        .expect("author known")
}

/// Finding 1 and 5. An insider signs two ops at one position and shows a
/// different one to each honest replica. That used to split the replicas for
/// good *and* strand every honest author, because honest ops named the
/// insider's head in `deps`. Now the disagreement is confined to what the
/// equivocating author itself wrote.
#[test]
fn equivocation_does_not_spread_to_honest_authors() {
    let mut m = Forge::new(ROOT, 99);
    let x = m.op(1, None, T0, &[node(1, &[], &[("k", text("x"))])]);
    let y = m.op(1, None, T0, &[node(1, &[], &[("k", text("y"))])]);
    let g = m.sealed_genesis();
    let (sx, sy) = (m.sealed_op(&x), m.sealed_op(&y));

    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    let (ga, gb) = (a.drain(), b.drain());
    statuses(&mut a, &gb, T0);
    statuses(&mut b, &ga, T0);
    statuses(&mut a, std::slice::from_ref(&g), T0);
    statuses(&mut b, std::slice::from_ref(&g), T0);
    // The relay (or M) shows x to A first and y to B first.
    assert_eq!(a.ingest(&sx, 0, T0).status, IngestStatus::Applied);
    assert_eq!(b.ingest(&sy, 0, T0).status, IngestStatus::Applied);
    // Both honest devices write after that; their deps name M's head, which
    // is a different op on each.
    a.commit(&[node(10, &[], &[("by", text("a"))])], T0 + 10);
    b.commit(&[node(20, &[], &[("by", text("b"))])], T0 + 10);
    let (a_items, b_items) = (a.drain(), b.drain());
    // Everything is delivered to everyone.
    assert_eq!(
        statuses(&mut a, std::slice::from_ref(&sy), T0 + 20),
        [IngestStatus::Rejected(Reject::Equivocation)]
    );
    assert_eq!(
        statuses(&mut b, std::slice::from_ref(&sx), T0 + 20),
        [IngestStatus::Rejected(Reject::Equivocation)]
    );
    assert_eq!(statuses(&mut a, &b_items, T0 + 20), [IngestStatus::Applied]);
    assert_eq!(statuses(&mut b, &a_items, T0 + 20), [IngestStatus::Applied]);
    // Further honest writes, chained on the earlier ones.
    for i in 0..5u8 {
        a.commit(&[node(30 + i, &[], &[])], T0 + 30 + u64::from(i));
        b.commit(&[node(40 + i, &[], &[])], T0 + 30 + u64::from(i));
    }
    let (a2, b2) = (a.drain(), b.drain());
    assert!(
        statuses(&mut a, &b2, T0 + 100)
            .iter()
            .all(|s| *s == IngestStatus::Applied)
    );
    assert!(
        statuses(&mut b, &a2, T0 + 100)
            .iter()
            .all(|s| *s == IngestStatus::Applied)
    );
    // M carries on along the branch A holds. A applies it; B, holding the
    // other branch, rejects it at once instead of waiting for ever. Nobody
    // else is held up by it.
    let x2 = m.op(2, Some(&x), T0 + 200, &[node(2, &[], &[])]);
    let sx2 = m.sealed_op(&x2);
    assert_eq!(a.ingest(&sx2, 0, T0 + 201).status, IngestStatus::Applied);
    assert_eq!(
        b.ingest(&sx2, 0, T0 + 201).status,
        IngestStatus::Rejected(Reject::ChainFork)
    );
    a.commit(&[node(50, &[], &[])], T0 + 300);
    assert_eq!(
        statuses(&mut b, &a.drain(), T0 + 301),
        [IngestStatus::Applied]
    );

    for d in [&a, &b] {
        let st = d.r.stats();
        assert_eq!(st.pending, 0, "nothing waits on the equivocator");
        assert!(!st.needs_resync);
        // Every honest op is there, on both.
        for g in [10u8, 20, 30, 31, 32, 33, 34, 40, 41, 42, 43, 44, 50] {
            assert!(d.r.node(&gid(g)).is_some(), "node {g}");
        }
        // The equivocation is recorded, with a proof, and flagged.
        assert_eq!(d.r.equivocations().len(), 1);
        assert!(d.r.equivocations()[0].proof.is_some());
        assert!(status_of(d, &m.author()).equivocated);
        assert!(!status_of(d, &a.r.author()).equivocated);
    }
    let honest =
        |d: &Dev| -> Vec<NodeView> { d.r.nodes().into_iter().filter(|n| n.gid[0] >= 10).collect() };
    assert_eq!(honest(&a), honest(&b), "honest authors' ops converge");
    assert_eq!(status_of(&a, &b.r.author()).applied_seq, 6);
    assert_eq!(status_of(&b, &a.r.author()).applied_seq, 7);
    // What remains, stated in SYNC-V0 section 8: first seen stays, so the
    // two replicas keep different ops of M.
    assert_eq!(a.r.node(&gid(1)).unwrap().props, props(&[("k", text("x"))]));
    assert_eq!(b.r.node(&gid(1)).unwrap().props, props(&[("k", text("y"))]));
    assert!(a.r.node(&gid(2)).is_some() && b.r.node(&gid(2)).is_none());
}

/// Finding 4. A device whose state is rolled back signs ops at positions it
/// has used before. Peers reject them, and the device used to find out
/// nothing. Now it detects the fork when its own earlier op comes back from
/// the relay, refuses to sign, and recovers with a fresh identity under
/// which the lost writes are issued again.
#[test]
fn state_rollback_is_detected_and_recovered_by_a_new_identity() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    let (ga, gb) = (a.drain(), b.drain());
    statuses(&mut b, &ga, T0);
    statuses(&mut a, &gb, T0);
    let saved = a.r.to_bytes().unwrap();
    a.commit(&[node(1, &[], &[("v", int(1))])], T0);
    let first = a.drain();
    assert_eq!(statuses(&mut b, &first, T0), [IngestStatus::Applied]);
    let old_author = a.r.author();

    // Roll A back to before that commit (a backup restore, or state that
    // was saved separately from the push).
    a.r = Replica::from_bytes(&saved, a.config).unwrap();
    a.model = Model::of(&a.r);
    assert!(!a.r.forked());
    a.commit(&[node(2, &[], &[("v", int(2))])], T0 + 5);
    a.commit(&[node(3, &[], &[("v", int(3))])], T0 + 6);
    let later = a.drain();
    // The peer cannot accept either: one conflicts with the op it holds at
    // that position, the other builds on the conflict.
    assert_eq!(
        statuses(&mut b, &later, T0 + 10),
        [
            IngestStatus::Rejected(Reject::Equivocation),
            IngestStatus::Rejected(Reject::ChainFork)
        ]
    );
    assert!(b.r.node(&gid(2)).is_none() && b.r.node(&gid(3)).is_none());

    // A pulls. The relay log holds its earlier op, then the two new ones.
    let out = a.ingest(&first[0], 0, T0 + 10);
    assert!(a.r.forked(), "own op at a used position, with another id");
    assert!(a.r.stats().forked);
    // A follows the version of its chain the peers hold: the op is applied.
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 1));
    assert_eq!(out.effects, vec![node(1, &[], &[("v", int(1))])]);
    assert_eq!(
        statuses(&mut a, &later, T0 + 10),
        [IngestStatus::Duplicate, IngestStatus::Duplicate]
    );
    // What A wrote on its own branch is still in its graph.
    assert!(a.r.node(&gid(2)).is_some() && a.r.node(&gid(3)).is_some());

    // It refuses to sign: one more op as this author is one more that peers
    // would silently drop.
    let outbox = a.r.outbox_len();
    assert_eq!(
        a.try_commit(&[node(4, &[], &[])], T0 + 11).unwrap_err(),
        Error::Forked
    );
    assert_eq!(a.r.outbox_len(), outbox);
    assert!(a.r.node(&gid(4)).is_none());
    // The fork is part of the state: a restart does not forget it.
    a.restore();
    assert!(a.r.forked());
    assert_eq!(
        a.try_commit(&[node(4, &[], &[])], T0 + 11).unwrap_err(),
        Error::Forked
    );
    // Ingest still works while forked.
    b.commit(&[node(20, &[], &[])], T0 + 12);
    assert_eq!(
        statuses(&mut a, &b.drain(), T0 + 13),
        [IngestStatus::Applied]
    );

    // "Rejoin as a new device".
    let effects = a.r.reset_identity([0x41; 32], [0x42; 24]).unwrap();
    a.model.apply_all(&effects, true);
    a.check();
    assert!(!a.r.forked());
    let new_author = a.r.author();
    assert_ne!(new_author, old_author);
    assert_eq!(a.r.fragment_id(), b.r.fragment_id(), "same fragment");
    assert!(status_of(&a, &new_author).own && !status_of(&a, &old_author).own);
    // Queued: the new genesis and the two lost writes, re-issued.
    assert_eq!(a.r.outbox_len(), 3);
    assert_eq!(status_of(&a, &new_author).applied_seq, 2);
    let rejoin = a.drain();
    assert_eq!(
        statuses(&mut b, &rejoin, T0 + 20),
        [
            IngestStatus::KeyLog,
            IngestStatus::Applied,
            IngestStatus::Applied
        ]
    );
    // Converged: B has what A wrote after the rollback, A has what it had
    // lost.
    assert_eq!(a.r.nodes(), b.r.nodes());
    assert_eq!(a.model, b.model);
    for g in [1u8, 2, 3, 20] {
        assert!(b.r.node(&gid(g)).is_some(), "node {g}");
    }
    // And the device writes again, as the new author, and is heard.
    a.commit(
        &[
            node(5, &[], &[("v", int(5))]),
            node(1, &[], &[("v", int(9))]),
        ],
        T0 + 30,
    );
    b.commit(&[node(6, &[], &[])], T0 + 31);
    let (ai, bi) = (a.drain(), b.drain());
    assert_eq!(statuses(&mut b, &ai, T0 + 40), [IngestStatus::Applied]);
    assert_eq!(statuses(&mut a, &bi, T0 + 40), [IngestStatus::Applied]);
    // The relay echoes everything A ever pushed; nothing of it disturbs the
    // new identity.
    for item in first.iter().chain(&later).chain(&rejoin).chain(&ai) {
        let out = a.ingest(item, 0, T0 + 50);
        assert!(out.effects.is_empty());
    }
    assert!(!a.r.forked());
    assert_eq!(a.r.nodes(), b.r.nodes());
    assert_eq!(a.r.node(&gid(1)).unwrap().props, props(&[("v", int(9))]));
    a.restore();
    assert_eq!(a.r.author(), new_author);
    assert_eq!(
        a.r.reset_identity([0x41; 32], [0x43; 24]).unwrap_err(),
        Error::State("device seed already in use")
    );
}

/// Rollback without a conflict. The state is rolled back and the device
/// has not written anything yet. Its own later ops come back from the relay
/// beyond its head and continue from it: the replica takes them (it gets its
/// data, its position and its clock back) and carries on as the same author.
#[test]
fn a_rolled_back_replica_that_pulls_first_fast_forwards() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    let ga = a.drain();
    statuses(&mut b, &ga, T0);
    let saved = a.r.to_bytes().unwrap();
    a.commit(&[node(1, &[], &[("v", int(1))])], T0);
    a.commit(&[node(2, &[], &[])], T0 + 1);
    // Its clock was briefly far ahead for the third.
    a.commit(&[node(3, &[], &[])], T0 + 90 * 24 * 3_600_000);
    let ops = a.drain();
    let author = a.r.author();
    let reference = a.r.nodes();

    a.r = Replica::from_bytes(&saved, a.config).unwrap();
    a.model = Model::of(&a.r);
    assert!(a.r.nodes().is_empty());
    // Out of order on purpose: the second op first. It cannot apply yet,
    // but it proves the chain goes further than this replica knows.
    assert_eq!(
        a.ingest(&ops[1], 0, T0 + 3).status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    assert!(!a.r.forked());
    assert_eq!(a.r.stats().own_ops_missing, 2);
    // Writing now would reuse position 1, which is known to be taken.
    assert_eq!(
        a.try_commit(&[node(9, &[], &[])], T0 + 4).unwrap_err(),
        Error::OwnChainAhead
    );
    assert!(a.r.node(&gid(9)).is_none());
    // That knowledge is part of the state.
    a.restore();
    assert_eq!(
        a.try_commit(&[node(9, &[], &[])], T0 + 4).unwrap_err(),
        Error::OwnChainAhead
    );

    // The first op arrives: both apply, with effects, like anyone's ops.
    let out = a.ingest(&ops[0], 0, T0 + 5);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 2));
    assert_eq!(
        out.effects,
        vec![node(1, &[], &[("v", int(1))]), node(2, &[], &[])]
    );
    // The third carries a stamp three months ahead of the clock now. From
    // anyone else it would be rejected; it is this device's own, and the
    // chain cannot be rejoined without it.
    let out = a.ingest(&ops[2], 0, T0 + 5);
    assert_eq!(out.status, IngestStatus::Applied);
    assert!(!a.r.forked());
    assert_eq!(a.r.stats().own_ops_missing, 0);
    assert_eq!(a.r.nodes(), reference);
    assert_eq!(a.r.author(), author, "the same author as before");
    let me = status_of(&a, &author);
    assert_eq!((me.applied_seq, me.own), (3, true));

    // It writes again: position 4, on top of op 3, with a later HLC even
    // though the wall clock is three months behind op 3's.
    a.commit(&[node(4, &[], &[])], T0 + 6);
    let next = a.drain();
    assert_eq!(a.r.stats().local, 1);
    let late = T0 + 91 * 24 * 3_600_000;
    assert_eq!(
        statuses(&mut b, &ops, late),
        [
            IngestStatus::Applied,
            IngestStatus::Applied,
            IngestStatus::Applied
        ]
    );
    assert_eq!(statuses(&mut b, &next, late), [IngestStatus::Applied]);
    assert_eq!(a.r.nodes(), b.r.nodes());
    assert_eq!(status_of(&b, &author).applied_seq, 4);
    assert!(!status_of(&b, &author).equivocated);
    assert!(b.r.equivocations().is_empty());
}

/// The same rollback, but the user writes before the first pull. That write
/// takes a position the device has used before; nothing the replica knows
/// can prevent it. It is a real conflict, found when the earlier op arrives,
/// and then the device is forked.
#[test]
fn a_rolled_back_replica_that_writes_first_forks() {
    let mut a = Dev::new(1);
    let saved = a.r.to_bytes().unwrap();
    a.commit(&[node(1, &[], &[])], T0);
    let before = a.drain();
    a.r = Replica::from_bytes(&saved, a.config).unwrap();
    a.model = Model::of(&a.r);
    // Nothing has been seen yet: the commit is accepted.
    a.commit(&[node(2, &[], &[])], T0 + 1);
    assert!(!a.r.forked());
    // First pull.
    let out = a.ingest(&before[1], 0, T0 + 2);
    assert_eq!(out.status, IngestStatus::Applied);
    assert!(a.r.forked());
    assert_eq!(
        a.try_commit(&[node(3, &[], &[])], T0 + 3).unwrap_err(),
        Error::Forked
    );
    // Both writes are in its graph; the reset re-issues the second.
    assert!(a.r.node(&gid(1)).is_some() && a.r.node(&gid(2)).is_some());
    a.r.reset_identity([0x61; 32], [0x62; 24]).unwrap();
    assert_eq!(status_of(&a, &a.r.author()).applied_seq, 1);
}

/// An op of the device's own author that claims the next position and does
/// not continue from its head is a conflict as well: two devices are running
/// with one seed.
#[test]
fn an_own_op_that_does_not_chain_from_the_head_forks() {
    // A forge with the device's seed is the device's identity.
    let mut clone = Forge::new(ROOT, 1);
    let mut a = Dev::new(1);
    assert_eq!(clone.author(), a.r.author());

    // The clone writes first; the device has written nothing. This is
    // indistinguishable from the device's own past: fast-forward.
    let c1 = clone.op(1, None, T0, &[node(1, &[], &[])]);
    assert_eq!(
        a.ingest(&clone.sealed_op(&c1), 0, T0 + 1).status,
        IngestStatus::Applied
    );
    assert!(!a.r.forked());
    // The device writes position 2. So does the clone, differently.
    a.commit(&[node(2, &[], &[])], T0 + 2);
    let c2 = clone.op(2, Some(&c1), T0 + 2, &[node(3, &[], &[])]);
    let c3 = clone.op(3, Some(&c2), T0 + 3, &[node(4, &[], &[])]);
    // Position 3 arrives first. It waits for position 3's turn; when
    // evaluated it does not continue from the device's op at 2.
    let mut d = Dev::new(1);
    d.ingest(&clone.sealed_op(&c1), 0, T0 + 1);
    d.commit(&[node(2, &[], &[])], T0 + 2);
    let out = d.ingest(&clone.sealed_op(&c3), 0, T0 + 4);
    assert_eq!(
        out.status,
        IngestStatus::Rejected(Reject::ChainFork),
        "claims to follow an op this replica does not hold at 2"
    );
    assert!(d.r.forked());
    // On the first device the conflict shows at position 2 itself.
    let out = a.ingest(&clone.sealed_op(&c2), 0, T0 + 4);
    assert_eq!(
        out.status,
        IngestStatus::Applied,
        "the relay's branch is followed"
    );
    assert!(a.r.forked());
    assert_eq!(
        a.try_commit(&[node(5, &[], &[])], T0 + 5).unwrap_err(),
        Error::Forked
    );
}

/// Finding 2 and 3. One device with a clock a year ahead (an honest phone
/// with a wrong RTC, or an insider) used to fill pending storage, after
/// which the cursor was pinned and the replica never saw anything newer.
#[test]
fn a_far_future_clock_does_not_pin_the_cursor() {
    let cfg = Config {
        max_pending_items: 8,
        ..Config::default()
    };
    let mut victim = Dev::with(ROOT, 1, cfg);
    let mut honest = Dev::new(2);
    let mut skew = Dev::new(3);
    let year = 365 * 24 * 3600 * 1000;
    // The relay log, in arrival order.
    let mut log: Vec<Vec<u8>> = Vec::new();
    log.extend(honest.drain());
    log.extend(skew.drain());
    for i in 0..20u8 {
        skew.commit(&[node(100 + i, &[], &[])], T0 + year + u64::from(i));
        log.extend(skew.drain());
    }
    for i in 0..600u16 {
        honest.commit(
            &[node((i % 200) as u8, &[], &[("i", int(i64::from(i)))])],
            T0 + 1000 + u64::from(i),
        );
        log.extend(honest.drain());
    }
    // The transport: pull 256 after the cursor, ingest, repeat.
    let mut rounds = 0;
    loop {
        let after = victim.r.cursor() as usize;
        let batch: Vec<(u64, Vec<u8>)> = log
            .iter()
            .enumerate()
            .skip(after)
            .take(256)
            .map(|(i, it)| (i as u64 + 1, it.clone()))
            .collect();
        if batch.is_empty() {
            break;
        }
        let next = batch.last().map_or(0, |b| b.0);
        for (seq, it) in batch {
            victim.ingest(&it, seq, T0 + 2000);
        }
        assert!(!victim.r.observe_relay_head(next));
        rounds += 1;
        assert!(rounds <= 3, "the cursor is not moving");
    }
    assert_eq!(rounds, 3);
    assert_eq!(victim.r.cursor() as usize, log.len());
    // Every honest op is applied.
    assert_eq!(status_of(&victim, &honest.r.author()).applied_seq, 600);
    assert_eq!(
        victim.r.node(&gid(199)).unwrap().props,
        props(&[("i", int(599))])
    );
    assert_eq!(victim.r.nodes(), honest.r.nodes());
    // The skewed device: its first op is rejected, the rest wait behind it
    // within the bound, and the application can see why.
    let st = victim.r.stats();
    assert_eq!(st.clock_rejected, 1);
    assert_eq!(st.pending, 8);
    assert_eq!(st.refused, 11);
    let s = status_of(&victim, &skew.r.author());
    assert_eq!((s.applied_seq, s.pending, s.gap), (0, 8, true));
    assert!(s.clock_lead_ms > year - 10_000);
    assert!(victim.r.needs_resync());
    // Local work is not affected either.
    victim.commit(&[node(250, &[], &[])], T0 + 3000);
}

/// Finding 1, the smallest form: a dep that never exists.
#[test]
fn an_unsatisfiable_dep_does_not_keep_an_op_pending() {
    let mut m = Forge::new(ROOT, 77);
    let mut d = Dev::new(1);
    d.ingest(&m.sealed_genesis(), 0, T0);
    let bogus = Multihash {
        alg: 1,
        digest: vec![0xEE; 32],
    };
    let body = m.body(
        1,
        None,
        T0,
        vec![bogus],
        encode_payload(&[node(1, &[], &[])]).unwrap(),
    );
    let out = d.ingest(&m.sealed_op(&m.sign(&body)), 0, T0);
    assert_eq!(out.status, IngestStatus::Applied);
    assert_eq!(d.r.stats().pending, 0);
    // A genesis that is never sent still leaves its ops pending: nothing
    // can be checked without it. They are bounded, per claimed author.
    let mut ghost = Forge::new(ROOT, 78);
    let cap = Config::default().max_pending_items_per_author as u64;
    let mut prev = None;
    for i in 0..cap + 10 {
        let op = ghost.op(i + 1, prev.as_ref(), T0 + i, &[node(2, &[], &[])]);
        d.ingest(&ghost.sealed_op(&op), i + 1, T0);
        prev = Some(op);
    }
    let st = d.r.stats();
    assert_eq!((st.pending as u64, st.refused), (cap, 10));
    assert_eq!(d.r.cursor(), cap + 10);
}

/// The reviewer's state fuzz: `from_bytes` on mutated and truncated state
/// never panics, and whatever it accepts is in canonical form.
#[test]
fn mutated_state_never_panics() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    statuses(&mut a, &b.drain(), T0);
    for i in 0..20u8 {
        a.commit(
            &[
                node(i, &["L"], &[("k", int(i64::from(i)))]),
                edge(i + 100, i, 0, "T", &[]),
            ],
            T0 + u64::from(i),
        );
        b.commit(&[node(i + 50, &[], &[])], T0 + u64::from(i));
    }
    // Leave some pending: deliver in reverse.
    for it in b.drain().iter().rev().take(5) {
        a.ingest(it, 0, T0);
    }
    assert_eq!(a.r.stats().pending, 5);
    let bytes = a.r.to_bytes().unwrap().to_vec();
    let mut rng = Rng(12345);
    let mut accepted = 0;
    for _ in 0..600 {
        let mut m = bytes.clone();
        for _ in 0..1 + rng.next() % 4 {
            let p = (rng.next() as usize) % m.len();
            m[p] = rng.next() as u8;
        }
        if let Ok(r) = Replica::from_bytes(&m, a.config) {
            accepted += 1;
            assert_eq!(*r.to_bytes().unwrap(), m);
        }
    }
    for cut in (0..bytes.len()).step_by(31) {
        assert!(Replica::from_bytes(&bytes[..cut], a.config).is_err());
    }
    // Form is checked, integrity is not (documented on `from_bytes`): some
    // mutants are other well-formed states.
    assert!(accepted > 0);
}

/// Finding 6. A relay that lost its log numbers from 1 again. A client whose
/// cursor is beyond the new head used to skip everything pushed to the new
/// log up to its old position.
#[test]
fn a_relay_reset_is_noticed_and_in_flight_items_are_pushed_again() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    // Round 1: both push, the relay acks, both pull everything.
    let mut log: Vec<Vec<u8>> = Vec::new();
    a.commit(&[node(1, &[], &[])], T0);
    b.commit(&[node(2, &[], &[])], T0);
    log.extend(a.drain());
    log.extend(b.drain());
    assert_eq!(a.r.stats().unechoed, 2, "acked, not yet seen in a pull");
    for (i, it) in log.iter().enumerate() {
        a.ingest(it, i as u64 + 1, T0 + 1);
        b.ingest(it, i as u64 + 1, T0 + 1);
    }
    assert!(!a.r.observe_relay_head(4));
    assert_eq!(a.r.cursor(), 4);
    assert_eq!(a.r.stats().unechoed, 0, "echoed back: the relay has them");
    assert_eq!(a.r.nodes(), b.r.nodes());

    // Round 2: A pushes two more ops and gets the ack. Then the relay loses
    // everything.
    a.commit(&[node(3, &[], &[])], T0 + 2);
    a.commit(&[node(4, &[], &[])], T0 + 3);
    let lost = a.drain();
    assert_eq!(a.r.stats().unechoed, 2);
    // The unechoed items are part of the state.
    a.restore();
    assert_eq!(a.r.stats().unechoed, 2);
    let mut log: Vec<Vec<u8>> = Vec::new();
    // B, not knowing, pushes to the empty relay: its op is item 1 again.
    b.commit(&[node(5, &[], &[])], T0 + 4);
    log.extend(b.drain());

    // B pulls after 4 as well; the relay holds 1 item and answers `next = 1`.
    assert!(b.r.observe_relay_head(1));
    assert_eq!(b.r.cursor(), 0);
    // B's op is in the new log, but B has not seen it echoed, so it is
    // queued again. The relay stores an item once, whatever is pushed.
    assert_eq!(b.r.outbox_len(), 1);
    for it in b.drain() {
        assert!(log.contains(&it));
    }
    // A pulls after 4 and gets the same answer.
    assert!(a.r.observe_relay_head(1));
    assert_eq!(a.r.cursor(), 0, "start again, or item 1 would be skipped");
    assert_eq!(a.r.stats().relay_resets, 1);
    // What was acknowledged but never seen again is back in the outbox,
    // first, in order.
    assert_eq!(a.r.stats().unechoed, 0);
    assert_eq!(
        a.r.outbox_peek(9),
        lost.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    // A second look at the same head is not a second reset.
    assert!(!a.r.observe_relay_head(1));
    assert_eq!(a.r.stats().relay_resets, 1);

    // Carry on against the new log.
    log.extend(a.drain());
    for (i, it) in log.iter().enumerate() {
        a.ingest(it, i as u64 + 1, T0 + 5);
        b.ingest(it, i as u64 + 1, T0 + 5);
    }
    assert!(!a.r.observe_relay_head(3) && !b.r.observe_relay_head(3));
    assert_eq!(a.r.cursor(), 3);
    assert_eq!(a.r.nodes(), b.r.nodes());
    assert_eq!(a.r.nodes().len(), 5);
    assert_eq!(b.r.stats().relay_resets, 1);
    // The flag survives a restore.
    a.restore();
    assert_eq!(a.r.stats().relay_resets, 1);
}

#[test]
fn unechoed_items_are_bounded() {
    let config = Config {
        max_unechoed_items: 3,
        ..Config::default()
    };
    let mut a = Dev::with(ROOT, 1, config);
    for i in 0..6u8 {
        a.commit(&[node(i, &[], &[])], T0 + u64::from(i));
    }
    let all = a.drain();
    assert_eq!(all.len(), 7);
    assert_eq!(a.r.stats().unechoed, 3);
    // The newest three are the ones kept.
    assert!(a.r.observe_relay_head(0) || a.r.cursor() == 0);
    a.r.set_cursor(5);
    assert!(a.r.observe_relay_head(0));
    assert_eq!(
        a.r.outbox_peek(9),
        all[4..].iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    // An echo is recognised by its bytes whatever position it comes at, and
    // only once.
    let mut c = Dev::new(2);
    c.commit(&[node(1, &[], &[])], T0);
    let items = c.drain();
    assert_eq!(c.ingest(&items[1], 0, T0).status, IngestStatus::Duplicate);
    assert_eq!(c.r.stats().unechoed, 1);
    assert_eq!(c.ingest(&items[1], 0, T0).status, IngestStatus::Duplicate);
    assert_eq!(c.ingest(&items[0], 0, T0).status, IngestStatus::Duplicate);
    assert_eq!(c.r.stats().unechoed, 0);
    assert_eq!(c.r.stats().applied, 0);
}
