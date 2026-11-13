//! Replica state (SYNC-V0 section 7): `to_bytes` / `from_bytes` round trip,
//! versioning, strict decoding, and continuing after a restore.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::{Op, Plain, SealedOp, Value};

/// A replica with something in every part of its state: three authors, merge
/// state with tombstones, hidden edges and unset registers, pending ops of
/// three kinds, an outbox, an equivocation record, non-zero counters.
fn busy() -> (Dev, Forge) {
    let drift = Config::default().max_drift_ms;
    let mut d = Dev::new(1);
    d.drain();
    let mut other = Dev::new(2);
    let mut f = Forge::new(ROOT, 9);
    for g in other.drain() {
        d.ingest(&g, 1, T0);
    }
    d.ingest(&f.sealed_genesis(), 2, T0);

    d.commit(
        &[
            node(1, &["L", "M"], &[("k", int(1)), ("gone", int(1))]),
            node(2, &[], &[("f", Value::Float(-0.0))]),
            node(3, &[], &[]),
            edge(7, 1, 2, "T", &[("w", int(1))]),
            edge(8, 2, 3, "T", &[]),
            edge(9, 1, 5, "DANGLING", &[]),
        ],
        T0 + 1,
    );
    d.commit(
        &[
            Change::NodePut {
                gid: gid(1),
                labels_add: Default::default(),
                labels_remove: set_of(&["M"]),
                set: Default::default(),
                unset: set_of(&["gone"]),
            },
            node_del(3),
            edge_del(7),
        ],
        T0 + 2,
    );
    other.commit(&[node(4, &["O"], &[("from", text("other"))])], T0 + 3);
    for it in other.drain() {
        d.ingest(&it, 3, T0 + 4);
    }
    // Forged author: an applied op, an equivocation, a chain gap, a missing
    // dep, an op from the future, an op of an unknown author, a rejection.
    let op1 = f.op(1, None, T0 + 5, &[node(6, &[], &[])]);
    d.ingest(&f.sealed_op(&op1), 4, T0 + 6);
    let twin = f.op(1, None, T0 + 5, &[node(6, &["twin"], &[])]);
    d.ingest(&f.sealed_op(&twin), 5, T0 + 6);
    let op2 = f.op(2, Some(&op1), T0 + 7, &[node(6, &[], &[("two", int(2))])]);
    let op3 = f.op(3, Some(&op2), T0 + 8, &[node(6, &[], &[("three", int(3))])]);
    d.ingest(&f.sealed_op(&op3), 6, T0 + 9);
    let mut g = Forge::new(ROOT, 10);
    d.ingest(&g.sealed_genesis(), 7, T0 + 9);
    let future = g.op(1, None, T0 + drift + 100_000, &[node(7, &[], &[])]);
    d.ingest(&g.sealed_op(&future), 8, T0 + 9);
    let mut unknown = Forge::new(ROOT, 11);
    let stray = unknown.op(1, None, T0, &[node(8, &[], &[])]);
    d.ingest(&unknown.sealed_op(&stray), 9, T0 + 9);
    d.ingest(b"junk", 10, T0 + 9);

    let st = d.r.stats();
    assert_eq!(st.pending, 3);
    assert_eq!(st.authors, 4);
    assert_eq!((st.applied, st.local), (2, 2));
    assert_eq!((st.equivocations, st.undecryptable), (1, 1));
    assert_eq!(st.outbox, 2);
    assert_eq!(d.r.cursor(), 10);
    assert!(d.r.edge(&gid(8)).is_none() && d.r.edge(&gid(9)).is_none());
    // Leave `op2` for the caller: it releases op3.
    let _ = op2;
    (d, f)
}

fn value_of(state: &[u8]) -> Vec<Value> {
    match Value::decode(state).unwrap() {
        Value::Array(items) => items,
        _ => panic!("state is an array"),
    }
}

fn restore(items: Vec<Value>) -> Result<Replica, Error> {
    Replica::from_bytes(&Value::Array(items).encode().unwrap(), Config::default())
}

#[test]
fn round_trip_preserves_everything() {
    let (d, _) = busy();
    let bytes = d.r.to_bytes().unwrap();
    let back = Replica::from_bytes(&bytes, Config::default()).unwrap();
    assert_eq!(
        *back.to_bytes().unwrap(),
        *bytes,
        "deterministic and stable"
    );
    assert_eq!(back.stats(), d.r.stats());
    assert_eq!(back.nodes(), d.r.nodes());
    assert_eq!(back.edges(), d.r.edges());
    assert_eq!(back.cursor(), d.r.cursor());
    assert_eq!(back.author(), d.r.author());
    assert_eq!(back.fragment_id(), d.r.fragment_id());
    assert_eq!(
        back.relay_token("https://relay.example"),
        d.r.relay_token("https://relay.example")
    );
    assert_eq!(back.equivocations(), d.r.equivocations());
    assert_eq!(back.outbox_peek(9), d.r.outbox_peek(9));
    assert!(back.node_deleted(&gid(3)) && back.edge_deleted(&gid(7)));
    // The same state encodes to the same bytes on a replica built separately.
    let (again, _) = busy();
    assert_eq!(*again.r.to_bytes().unwrap(), *bytes);
}

#[test]
fn state_layout_is_tagged_and_versioned() {
    let (d, _) = busy();
    let bytes = d.r.to_bytes().unwrap();
    let items = value_of(&bytes);
    assert_eq!(items.len(), 14);
    assert_eq!(items[0], text("gsp-sync-state"));
    assert_eq!(items[1], int(2));
    assert_eq!(
        items[2],
        Value::Bytes(ROOT.to_vec()),
        "the state holds the root secret"
    );
    assert_eq!(items[3], Value::Bytes(vec![1; 32]), "and the device seed");

    let mut v = items.clone();
    v[1] = int(3);
    assert_eq!(restore(v).unwrap_err(), Error::StateVersion(3));
    // The layouts of earlier versions of this crate are not read either.
    for old in [0, 1] {
        let mut v = items.clone();
        v[1] = int(old);
        assert_eq!(restore(v).unwrap_err(), Error::StateVersion(old as u64));
    }
    let mut v = items.clone();
    v[1] = Value::Int(i128::from(u64::MAX));
    assert_eq!(restore(v).unwrap_err(), Error::StateVersion(u64::MAX));
    let mut v = items.clone();
    v[0] = text("gsp-sync-statf");
    assert!(matches!(restore(v), Err(Error::State(_))));
    let mut v = items.clone();
    v.push(Value::Null);
    assert!(matches!(restore(v), Err(Error::State(_))));
    let mut v = items.clone();
    v.pop();
    assert!(matches!(restore(v), Err(Error::State(_))));
    assert!(restore(items).is_ok());
    for junk in [&b""[..], b"\x80", b"\xf6", b"gsp-sync-state"] {
        assert!(matches!(
            Replica::from_bytes(junk, Config::default()),
            Err(Error::State(_))
        ));
    }
}

#[test]
fn decoding_is_strict() {
    let (d, _) = busy();
    let bytes = d.r.to_bytes().unwrap();
    let items = value_of(&bytes);
    let arr = |v: &Value| match v {
        Value::Array(a) => a.clone(),
        other => panic!("array expected, got {other:?}"),
    };
    let bad = |what: &str, items: Vec<Value>| {
        assert!(
            matches!(restore(items), Err(Error::State(_))),
            "{what}: accepted"
        );
    };

    // Trailing bytes, truncation, non-canonical CBOR.
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(Replica::from_bytes(&longer, Config::default()).is_err());
    for cut in [1, bytes.len() / 3, bytes.len() - 1] {
        assert!(Replica::from_bytes(&bytes[..cut], Config::default()).is_err());
    }

    // Authors out of order, duplicated, or without this device.
    let authors = arr(&items[7]);
    assert_eq!(authors.len(), 4);
    let mut v = items.clone();
    let mut swapped = authors.clone();
    swapped.swap(0, 1);
    v[7] = Value::Array(swapped);
    bad("authors unsorted", v);
    let mut v = items.clone();
    let mut dup = authors.clone();
    dup.push(authors[0].clone());
    v[7] = Value::Array(dup);
    bad("author twice", v);
    for skip in 0..authors.len() {
        let mut v = items.clone();
        let mut fewer = authors.clone();
        fewer.remove(skip);
        v[7] = Value::Array(fewer);
        // Dropping any author breaks something: this device's own identity,
        // or nothing structural (a peer with no state is simply forgotten,
        // which is a different valid state only if it had no ops).
        let own_or_active = restore(v.clone()).is_err();
        let had_ops = !arr(&arr(&authors[skip])[1]).is_empty();
        let is_me = arr(&authors[skip])[0]
            == Value::Bytes({
                let me = Forge::new(ROOT, 1);
                me.genesis.clone()
            });
        assert_eq!(own_or_active, is_me, "author {skip} (had ops: {had_ops})");
    }
    // A different device seed: the identity it gives is not among the authors.
    let mut v = items.clone();
    v[3] = Value::Bytes(vec![0x77; 32]);
    assert_eq!(restore(v).unwrap_err(), Error::State("own author missing"));
    // A different root: every key log belongs to another fragment.
    let mut v = items.clone();
    v[2] = Value::Bytes(vec![0x77; 32]);
    bad("other root", v);
    // Secrets of the wrong length.
    let mut v = items.clone();
    v[2] = Value::Bytes(vec![0x77; 31]);
    bad("short root", v);

    // An author's head that does not match its op list.
    let mut v = items.clone();
    let mut a = authors.clone();
    let me = a
        .iter()
        .position(|x| arr(&arr(x)[1]).len() == 2)
        .expect("the device itself has two ops");
    let mut fields = arr(&a[me]);
    let mut ops = arr(&fields[1]);
    ops.swap(0, 1);
    fields[1] = Value::Array(ops);
    a[me] = Value::Array(fields);
    v[7] = Value::Array(a);
    bad("head does not match op list", v);
    // An op id listed under two authors.
    let mut v = items.clone();
    let mut a = authors.clone();
    let donor = arr(&arr(&a[me])[1])[0].clone();
    let other = (0..a.len())
        .find(|i| *i != me && arr(&arr(&a[*i])[1]).is_empty())
        .unwrap();
    let mut fields = arr(&a[other]);
    fields[1] = Value::Array(vec![donor]);
    a[other] = Value::Array(fields);
    v[7] = Value::Array(a);
    bad("op under two authors", v);
    // A key log with a broken signature.
    let mut v = items.clone();
    let mut a = authors.clone();
    let mut fields = arr(&a[0]);
    let Value::Bytes(mut g) = fields[0].clone() else {
        panic!()
    };
    let last = g.len() - 1;
    g[last] ^= 1;
    fields[0] = Value::Bytes(g);
    a[0] = Value::Array(fields);
    v[7] = Value::Array(a);
    bad("key log signature", v);

    // Merge state: an unused stamp, unsorted stamps, a stamp index out of
    // range, a node that is also tombstoned, nodes out of order.
    let merge = arr(&items[8]);
    let stamps = arr(&merge[0]);
    let nodes = arr(&merge[1]);
    assert!(stamps.len() >= 3 && nodes.len() >= 3);
    let with_merge = |m: Vec<Value>| {
        let mut v = items.clone();
        v[8] = Value::Array(m);
        v
    };
    let mut m = merge.clone();
    let mut s = stamps.clone();
    s.push(Value::Array(vec![
        Value::Int(i128::from(u64::MAX)),
        int(0),
        int(1),
        Value::Bytes(vec![0xff; 32]),
    ]));
    m[0] = Value::Array(s);
    bad("unused stamp", with_merge(m));
    let mut m = merge.clone();
    let mut s = stamps.clone();
    s.swap(0, 1);
    m[0] = Value::Array(s);
    bad("stamps unsorted", with_merge(m));
    let mut m = merge.clone();
    m[0] = Value::Array(stamps[..1].to_vec());
    bad("stamp index out of range", with_merge(m));
    let mut m = merge.clone();
    let mut n = nodes.clone();
    n.swap(0, 1);
    m[1] = Value::Array(n);
    bad("nodes unsorted", with_merge(m));
    let mut m = merge.clone();
    let mut tombs = arr(&merge[3]);
    tombs.insert(0, arr(&nodes[0])[0].clone());
    m[3] = Value::Array(tombs);
    bad("visible node that is tombstoned", with_merge(m));
    let mut m = merge.clone();
    m.push(Value::Array(vec![]));
    bad("extra merge field", with_merge(m));

    // Pending: the same op twice.
    let mut v = items.clone();
    let mut p = arr(&items[9]);
    assert_eq!(p.len(), 3);
    p.push(p[0].clone());
    v[9] = Value::Array(p);
    bad("pending twice", v);
    // Counters: wrong count, negative.
    let mut v = items.clone();
    let mut c = arr(&items[12]);
    c.push(int(0));
    v[12] = Value::Array(c);
    bad("extra counter", v);
    let mut v = items.clone();
    let mut c = arr(&items[12]);
    c[0] = int(-1);
    v[12] = Value::Array(c);
    bad("negative counter", v);
    // Wrong types at the top level.
    for i in 2..14 {
        let mut v = items.clone();
        v[i] = text("nope");
        bad("wrong type", v);
    }
}

#[test]
fn any_single_byte_change_is_refused_or_is_itself_canonical() {
    // A flipped byte can describe a different valid state (a counter, the
    // cursor, a property value). What must never happen: a panic, or an
    // accepted state that does not re-encode to the bytes it came from.
    let mut d = Dev::new(1);
    let mut f = Forge::new(ROOT, 9);
    d.ingest(&f.sealed_genesis(), 1, T0);
    d.commit(
        &[
            node(1, &["L"], &[("k", int(1))]),
            node(2, &[], &[]),
            edge(9, 1, 2, "T", &[]),
        ],
        T0,
    );
    let op = f.op(
        2,
        Some(&f.op(1, None, T0, &[node(3, &[], &[])])),
        T0 + 1,
        &[node(3, &[], &[])],
    );
    d.ingest(&f.sealed_op(&op), 2, T0);
    assert_eq!(d.r.stats().pending, 1);
    let bytes = d.r.to_bytes().unwrap().to_vec();
    // Array head, tag, version, root secret, device seed.
    let header = 1 + 15 + 1 + 34 + 34;
    let (mut ok, mut refused) = (0, 0);
    // Every byte of the header, every fourth byte after it (a restore
    // verifies key logs, which is slow in a debug build).
    for i in (0..header).chain((header..bytes.len()).step_by(4)) {
        let mut t = bytes.clone();
        t[i] ^= 0x01;
        match Replica::from_bytes(&t, Config::default()) {
            Ok(r) => {
                ok += 1;
                assert!(
                    i >= header,
                    "byte {i} of the header changed and was accepted"
                );
                assert_eq!(*r.to_bytes().unwrap(), t, "byte {i}");
            }
            Err(_) => refused += 1,
        }
    }
    // Accepted changes are those inside opaque parts (sealed outbox items,
    // pending ops, signatures) and plain numbers (clock, cursor, counters).
    assert!(ok > 0 && refused > header);
}

#[test]
fn a_restored_replica_carries_on_where_it_stopped() {
    let (mut d, mut f) = busy();
    let mut peer = Dev::new(3);
    d.restore();

    // Pending ops are still waiting, and are released by what they wait for.
    let op1 = f.op(1, None, T0 + 5, &[node(6, &[], &[])]);
    let op2 = f.op(2, Some(&op1), T0 + 7, &[node(6, &[], &[("two", int(2))])]);
    let out = d.ingest(&f.sealed_op(&op2), 11, T0 + 10);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 2));
    assert_eq!(
        d.r.node(&gid(6)).unwrap().props,
        props(&[("two", int(2)), ("three", int(3))])
    );
    assert_eq!(d.r.cursor(), 11);

    // The own chain continues: seq 3, prev = the op made before the restore,
    // HLC after everything seen. A peer accepts the whole history.
    d.commit(&[node(1, &[], &[("after", text("restore"))])], T0 + 11);
    d.restore();
    let items = d.drain();
    assert_eq!(items.len(), 3);
    let p = Pairing::from_root(ROOT);
    let ops: Vec<Op> = items
        .iter()
        .map(|i| {
            let Plain::Op(b) = SealedOp::from_bytes(i)
                .unwrap()
                .open(&p.fragment_key(), &p.fragment_id())
                .unwrap()
            else {
                panic!()
            };
            Op::from_bytes(&b).unwrap()
        })
        .collect();
    assert_eq!(ops[2].body().seq, 3);
    assert_eq!(ops[2].body().prev.as_ref(), Some(ops[1].id()));
    assert!(ops[2].body().hlc > ops[1].body().hlc);
    assert_eq!(
        ops[2].body().deps.len(),
        2,
        "heads of the two other writers"
    );

    let genesis = Forge::new(ROOT, 1).sealed_genesis();
    peer.ingest(&genesis, 0, T0 + 12);
    for it in &items {
        peer.ingest(it, 0, T0 + 12);
    }
    // The peer lacks the other authors that the last op names in `deps`.
    // That does not matter: all three apply.
    assert_eq!(peer.r.stats().applied, 3);
    assert_eq!(peer.r.stats().pending, 0);
}

#[test]
fn deeply_nested_values_survive_the_state() {
    // The deepest value an op can carry: 28 containers around a leaf.
    let mut deep = int(7);
    for _ in 0..28 {
        deep = Value::Array(vec![deep]);
    }
    let mut d = Dev::new(1);
    d.commit(&[node(1, &[], &[("deep", deep.clone())])], T0);
    assert!(
        d.try_commit(
            &[node(
                1,
                &[],
                &[("deeper", Value::Array(vec![deep.clone()]))]
            )],
            T0
        )
        .is_err()
    );
    d.restore();
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("deep", deep)]));
}

#[test]
fn create_is_deterministic_in_its_inputs() {
    let a = Replica::create(ROOT, [1; 32], [3; 24], Config::default()).unwrap();
    let b = Replica::create(ROOT, [1; 32], [3; 24], Config::default()).unwrap();
    assert_eq!(*a.to_bytes().unwrap(), *b.to_bytes().unwrap());
    assert_eq!(a.author(), b.author());
    // Another seed is another author in the same fragment; another root is
    // another fragment and, for the same seed, another author.
    let c = Replica::create(ROOT, [2; 32], [3; 24], Config::default()).unwrap();
    assert_ne!(a.author(), c.author());
    assert_eq!(a.fragment_id(), c.fragment_id());
    let d = Replica::create([9; 32], [1; 32], [3; 24], Config::default()).unwrap();
    assert_ne!(a.fragment_id(), d.fragment_id());
    assert_ne!(a.author(), d.author());
    assert_eq!(a.pairing().root(), &ROOT);
    assert_eq!(a.fragment_id(), &Pairing::from_root(ROOT).fragment_id());
    assert_eq!(
        a.relay_token("https://relay.example"),
        Pairing::from_root(ROOT).relay_token("https://relay.example")
    );
}

#[test]
fn outbox_peek_and_ack() {
    let mut d = Dev::new(1);
    for i in 0..4 {
        d.commit(&[node(i, &[], &[])], T0 + u64::from(i));
    }
    assert_eq!(d.r.outbox_len(), 5);
    assert!(d.r.outbox_peek(0).is_empty());
    let first_two: Vec<Vec<u8>> = d.r.outbox_peek(2).into_iter().map(<[u8]>::to_vec).collect();
    assert_eq!(first_two.len(), 2);
    // Peeking removes nothing; items come out in commit order.
    assert_eq!(
        d.r.outbox_peek(2),
        first_two.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert_eq!(d.r.outbox_peek(100).len(), 5);
    assert_eq!(d.r.outbox_ack(2), 2);
    assert_eq!(d.r.outbox_len(), 3);
    assert_ne!(d.r.outbox_peek(1)[0], first_two[0].as_slice());
    // The outbox survives a restore; acking more than there is is harmless.
    d.restore();
    assert_eq!(d.r.outbox_len(), 3);
    assert_eq!(d.r.outbox_ack(10), 3);
    assert_eq!(d.r.outbox_ack(1), 0);
    // Cursor handling.
    assert_eq!(d.r.cursor(), 0);
    d.ingest(b"x", 7, T0);
    assert_eq!(d.r.cursor(), 7, "even a rejected item is done with");
    d.ingest(b"x", 3, T0);
    assert_eq!(d.r.cursor(), 7, "the cursor never moves back by itself");
    d.ingest(b"x", 0, T0);
    assert_eq!(d.r.cursor(), 7, "0 means: not from the relay");
    d.r.set_cursor(0);
    assert_eq!(d.r.cursor(), 0);
}

#[test]
fn nan_and_negative_zero_are_values_like_any_other() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    for g in b.drain() {
        a.r.ingest(&g, 0, T0);
    }
    // `Dev` compares models with `==`, under which NaN differs from itself,
    // so this test talks to the replicas directly.
    let nan =
        |r: &Replica| matches!(r.node(&gid(1)).unwrap().props["f"], Value::Float(x) if x.is_nan());
    let put = |v: f64| [node(1, &[], &[("f", Value::Float(v))])];
    a.r.local_commit(&put(f64::NAN), T0 + 1, [1; 24]).unwrap();
    assert!(nan(&a.r));
    let mut effects = Vec::new();
    for it in a.drain() {
        effects.extend(b.r.ingest(&it, 0, T0 + 2).effects);
    }
    assert_eq!(effects.len(), 1);
    assert!(nan(&b.r));
    // NaN over NaN is not a change, whatever its payload bits.
    b.r.local_commit(&put(f64::from_bits(0x7ff8_0000_0000_0001)), T0 + 3, [2; 24])
        .unwrap();
    let again: Vec<Change> = b
        .drain()
        .iter()
        .flat_map(|it| a.r.ingest(it, 0, T0 + 4).effects)
        .collect();
    assert_eq!(again, vec![]);
    // 0.0 over -0.0 is a change.
    a.r.local_commit(&put(-0.0), T0 + 5, [3; 24]).unwrap();
    a.r.local_commit(&put(0.0), T0 + 6, [4; 24]).unwrap();
    let items = a.drain();
    assert_eq!(b.r.ingest(&items[0], 0, T0 + 7).effects.len(), 1);
    assert_eq!(b.r.ingest(&items[1], 0, T0 + 7).effects, put(0.0).to_vec());
    // And the state round-trips with a NaN inside.
    let bytes = a.r.to_bytes().unwrap();
    let back = Replica::from_bytes(&bytes, Config::default()).unwrap();
    assert_eq!(*back.to_bytes().unwrap(), *bytes);
}
