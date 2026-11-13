//! The op payload (SYNC-V0 section 4): exact wire shape, round trip, and one
//! test per rejection rule, on both the encoding and the decoding side.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::Value;
use std::collections::{BTreeMap, BTreeSet};

fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}
fn b(g: u8) -> Value {
    Value::Bytes(vec![g; 16])
}
fn texts(items: &[&str]) -> Value {
    arr(items.iter().map(|s| text(s)).collect())
}
fn map(items: &[(&str, Value)]) -> Value {
    Value::Map(
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    )
}
/// A well-formed `node_put` value with the given fields.
fn raw_node(labels_add: Value, labels_remove: Value, set: Value, unset: Value) -> Value {
    arr(vec![int(1), b(1), labels_add, labels_remove, set, unset])
}
fn raw_edge(ty: Value, set: Value, unset: Value) -> Value {
    arr(vec![int(3), b(9), b(1), b(2), ty, set, unset])
}
fn one(change: Value) -> Result<Vec<Change>, PayloadError> {
    decode_payload(&arr(vec![change]))
}

fn sample() -> Vec<Change> {
    vec![
        Change::NodePut {
            gid: gid(1),
            labels_add: set_of(&["Person", "Admin"]),
            labels_remove: set_of(&["Guest"]),
            set: props(&[
                ("name", text("Tendai")),
                ("age", int(41)),
                ("neg", int(-7)),
                ("score", Value::Float(1.5)),
                ("ok", Value::Bool(true)),
                ("nothing", Value::Null),
                ("blob", Value::Bytes(vec![0, 255, 7])),
                ("list", arr(vec![int(1), text("two"), arr(vec![])])),
                // In canonical key order, which is what decoding yields.
                (
                    "nested",
                    map(&[("a", map(&[("deep", Value::Null)])), ("z", int(1))]),
                ),
            ]),
            unset: set_of(&["old", "older"]),
        },
        Change::NodeDel { gid: gid(2) },
        Change::EdgePut {
            gid: gid(9),
            src: gid(1),
            dst: gid(3),
            ty: "KNOWS".into(),
            set: props(&[("since", int(2020))]),
            unset: set_of(&["until"]),
        },
        Change::EdgeDel { gid: gid(8) },
        Change::node(gid(4)),
        Change::edge(gid(7), gid(4), gid(4), ""),
    ]
}

#[test]
fn round_trip_through_value_and_bytes() {
    let changes = sample();
    let payload = encode_payload(&changes).unwrap();
    assert_eq!(decode_payload(&payload).unwrap(), changes);
    // And through the bytes an op carries.
    let bytes = payload.encode().unwrap();
    let back = Value::decode(&bytes).unwrap();
    assert_eq!(decode_payload(&back).unwrap(), changes);
    assert_eq!(encode_payload(&changes).unwrap().encode().unwrap(), bytes);
}

#[test]
fn a_map_value_written_in_any_order_decodes_in_canonical_order() {
    let c = vec![node(
        1,
        &[],
        &[("m", map(&[("zz", int(1)), ("b", int(2)), ("a", int(3))]))],
    )];
    let p = encode_payload(&c).unwrap();
    let back = decode_payload(&Value::decode(&p.encode().unwrap()).unwrap()).unwrap();
    assert_eq!(
        back,
        vec![node(
            1,
            &[],
            &[("m", map(&[("a", int(3)), ("b", int(2)), ("zz", int(1))]))]
        )]
    );
}

#[test]
fn wire_shape_is_the_one_in_the_spec() {
    let payload = encode_payload(&[
        Change::NodePut {
            gid: gid(1),
            labels_add: set_of(&["b", "a"]),
            labels_remove: set_of(&["c"]),
            set: props(&[("k", int(1))]),
            unset: set_of(&["z", "y"]),
        },
        Change::NodeDel { gid: gid(2) },
        Change::EdgePut {
            gid: gid(3),
            src: gid(1),
            dst: gid(2),
            ty: "T".into(),
            set: BTreeMap::new(),
            unset: BTreeSet::new(),
        },
        Change::EdgeDel { gid: gid(4) },
    ])
    .unwrap();
    let want = arr(vec![
        arr(vec![
            int(1),
            b(1),
            texts(&["a", "b"]),
            texts(&["c"]),
            map(&[("k", int(1))]),
            texts(&["y", "z"]),
        ]),
        arr(vec![int(2), b(2)]),
        arr(vec![
            int(3),
            b(3),
            b(1),
            b(2),
            text("T"),
            map(&[]),
            texts(&[]),
        ]),
        arr(vec![int(4), b(4)]),
    ]);
    assert_eq!(payload.encode().unwrap(), want.encode().unwrap());
}

#[test]
fn name_arrays_sort_bytewise_not_by_length() {
    // Bytewise: "B" < "a" < "aa" < "b" < "é" (0xc3..). CBOR map-key order
    // would put the shorter "b" before "aa"; these arrays do not use it.
    let labels = ["B", "a", "aa", "b", "é"];
    let payload = encode_payload(&[Change::NodePut {
        gid: gid(1),
        labels_add: set_of(&labels),
        labels_remove: BTreeSet::new(),
        set: BTreeMap::new(),
        unset: BTreeSet::new(),
    }])
    .unwrap();
    assert_eq!(
        payload.encode().unwrap(),
        arr(vec![raw_node(
            texts(&labels),
            texts(&[]),
            map(&[]),
            texts(&[])
        )])
        .encode()
        .unwrap()
    );
    assert!(
        one(raw_node(
            texts(&["aa", "b"]),
            texts(&[]),
            map(&[]),
            texts(&[])
        ))
        .is_ok()
    );
    assert_eq!(
        one(raw_node(
            texts(&["b", "aa"]),
            texts(&[]),
            map(&[]),
            texts(&[])
        )),
        Err(PayloadError::NotSorted("labels_add"))
    );
}

// ------------------------------------------------------------ rejections

#[test]
fn rejects_non_array_and_empty_payload() {
    for v in [
        Value::Null,
        int(1),
        text("x"),
        map(&[]),
        Value::Bytes(vec![]),
    ] {
        assert_eq!(decode_payload(&v), Err(PayloadError::Shape("payload")));
    }
    assert_eq!(decode_payload(&arr(vec![])), Err(PayloadError::Empty));
    assert_eq!(encode_payload(&[]), Err(PayloadError::Empty));
}

#[test]
fn rejects_more_than_1024_changes() {
    let mut many: Vec<Change> = (0..1024u32)
        .map(|i| {
            let mut g = [0u8; 16];
            g[..4].copy_from_slice(&i.to_be_bytes());
            Change::NodeDel { gid: g }
        })
        .collect();
    let ok = encode_payload(&many).unwrap();
    assert_eq!(decode_payload(&ok).unwrap().len(), 1024);
    many.push(Change::NodeDel { gid: gid(0xee) });
    assert_eq!(encode_payload(&many), Err(PayloadError::TooManyChanges));
    let Value::Array(mut raw) = ok else { panic!() };
    raw.push(arr(vec![int(2), b(0xee)]));
    assert_eq!(decode_payload(&arr(raw)), Err(PayloadError::TooManyChanges));
}

#[test]
fn rejects_payload_over_64_kib_and_accepts_exactly_64_kib() {
    // payload = 0x81, change = 0x86 0x01 0x50 gid(16) 0x80 0x80 map 0x80
    // map = 0xa1 0x61 'k' 0x59 len(2) bytes  => overhead 1+1+1+17+1+1+(1+2+3)+1 = 29
    let with_blob = |n: usize| {
        vec![Change::NodePut {
            gid: gid(1),
            labels_add: BTreeSet::new(),
            labels_remove: BTreeSet::new(),
            set: props(&[("k", Value::Bytes(vec![0x5a; n]))]),
            unset: BTreeSet::new(),
        }]
    };
    let fits = with_blob(MAX_PAYLOAD_BYTES - 29);
    let payload = encode_payload(&fits).unwrap();
    assert_eq!(payload.encode().unwrap().len(), MAX_PAYLOAD_BYTES);
    assert_eq!(decode_payload(&payload).unwrap(), fits);

    let over = with_blob(MAX_PAYLOAD_BYTES - 28);
    assert_eq!(encode_payload(&over), Err(PayloadError::TooLarge));
    let raw = arr(vec![raw_node(
        texts(&[]),
        texts(&[]),
        map(&[("k", Value::Bytes(vec![0x5a; MAX_PAYLOAD_BYTES - 28]))]),
        texts(&[]),
    )]);
    assert_eq!(raw.encode().unwrap().len(), MAX_PAYLOAD_BYTES + 1);
    assert_eq!(decode_payload(&raw), Err(PayloadError::TooLarge));
    assert_eq!(MAX_PAYLOAD_BYTES, 65536);
}

#[test]
fn rejects_unknown_kinds_and_wrong_arity() {
    for k in [0i64, 5, 6, 255] {
        assert_eq!(
            one(arr(vec![int(k), b(1)])),
            Err(PayloadError::UnknownKind(k as u64))
        );
    }
    // Kind must be an unsigned integer; a change must be an array.
    for bad in [
        arr(vec![]),
        arr(vec![text("1"), b(1)]),
        arr(vec![int(-1), b(1)]),
        arr(vec![Value::Float(1.0), b(1)]),
        map(&[]),
        int(2),
        Value::Null,
    ] {
        assert_eq!(one(bad), Err(PayloadError::Shape("change")));
    }
    // Too few and too many fields, for each kind.
    let e = || texts(&[]);
    let m = || map(&[]);
    for bad in [
        arr(vec![int(1), b(1), e(), e(), m()]),
        arr(vec![int(1), b(1), e(), e(), m(), e(), e()]),
        arr(vec![int(2)]),
        arr(vec![int(2), b(1), b(2)]),
        arr(vec![int(3), b(1), b(1), b(2), text("T"), m()]),
        arr(vec![int(3), b(1), b(1), b(2), text("T"), m(), e(), e()]),
        arr(vec![int(4)]),
        arr(vec![int(4), b(1), Value::Null]),
    ] {
        assert_eq!(one(bad), Err(PayloadError::Shape("change")));
    }
}

#[test]
fn rejects_gids_that_are_not_16_bytes() {
    for len in [0usize, 1, 15, 17, 32] {
        let g = Value::Bytes(vec![1; len]);
        assert_eq!(one(arr(vec![int(2), g.clone()])), Err(PayloadError::Gid));
        assert_eq!(one(arr(vec![int(4), g.clone()])), Err(PayloadError::Gid));
        let e = || texts(&[]);
        assert_eq!(
            one(arr(vec![int(1), g.clone(), e(), e(), map(&[]), e()])),
            Err(PayloadError::Gid)
        );
        // Edge: gid, src and dst each.
        for pos in 1..=3 {
            let mut fields = vec![int(3), b(1), b(2), b(3), text("T"), map(&[]), e()];
            fields[pos] = g.clone();
            assert_eq!(one(arr(fields)), Err(PayloadError::Gid), "field {pos}");
        }
    }
    // A gid must be a byte string.
    assert_eq!(
        one(arr(vec![int(2), text("0123456789abcdef")])),
        Err(PayloadError::Shape("gid"))
    );
}

#[test]
fn rejects_unsorted_and_duplicate_name_arrays() {
    let e = || texts(&[]);
    let m = || map(&[]);
    for (bad, what) in [
        (raw_node(texts(&["b", "a"]), e(), m(), e()), "labels_add"),
        (raw_node(texts(&["a", "a"]), e(), m(), e()), "labels_add"),
        (raw_node(e(), texts(&["b", "a"]), m(), e()), "labels_remove"),
        (raw_node(e(), texts(&["a", "a"]), m(), e()), "labels_remove"),
        (raw_node(e(), e(), m(), texts(&["k2", "k1"])), "unset"),
        (raw_node(e(), e(), m(), texts(&["k", "k"])), "unset"),
        (raw_edge(text("T"), m(), texts(&["k2", "k1"])), "unset"),
        (raw_edge(text("T"), m(), texts(&["k", "k"])), "unset"),
    ] {
        assert_eq!(one(bad), Err(PayloadError::NotSorted(what)));
    }
}

#[test]
fn rejects_wrongly_typed_fields() {
    let e = || texts(&[]);
    let m = || map(&[]);
    assert_eq!(
        one(raw_node(arr(vec![int(1)]), e(), m(), e())),
        Err(PayloadError::Shape("labels_add"))
    );
    assert_eq!(
        one(raw_node(Value::Null, e(), m(), e())),
        Err(PayloadError::Shape("labels_add"))
    );
    assert_eq!(
        one(raw_node(e(), map(&[]), m(), e())),
        Err(PayloadError::Shape("labels_remove"))
    );
    assert_eq!(
        one(raw_node(e(), e(), e(), e())),
        Err(PayloadError::Shape("set"))
    );
    assert_eq!(
        one(raw_node(e(), e(), m(), arr(vec![Value::Bytes(vec![1])]))),
        Err(PayloadError::Shape("unset"))
    );
    assert_eq!(
        one(raw_edge(Value::Bytes(b"T".to_vec()), m(), e())),
        Err(PayloadError::Shape("type"))
    );
    assert_eq!(
        one(raw_edge(text("T"), Value::Null, e())),
        Err(PayloadError::Shape("set"))
    );
    assert_eq!(
        one(raw_edge(text("T"), m(), m())),
        Err(PayloadError::Shape("unset"))
    );
}

#[test]
fn rejects_key_in_both_set_and_unset() {
    let e = || texts(&[]);
    assert_eq!(
        one(raw_node(e(), e(), map(&[("k", int(1))]), texts(&["k"]))),
        Err(PayloadError::Conflict("set/unset"))
    );
    assert_eq!(
        one(raw_edge(
            text("T"),
            map(&[("k", int(1))]),
            texts(&["a", "k"])
        )),
        Err(PayloadError::Conflict("set/unset"))
    );
    assert_eq!(
        encode_payload(&[Change::NodePut {
            gid: gid(1),
            labels_add: BTreeSet::new(),
            labels_remove: BTreeSet::new(),
            set: props(&[("k", int(1))]),
            unset: set_of(&["k"]),
        }]),
        Err(PayloadError::Conflict("set/unset"))
    );
    assert_eq!(
        encode_payload(&[Change::EdgePut {
            gid: gid(1),
            src: gid(2),
            dst: gid(3),
            ty: "T".into(),
            set: props(&[("k", int(1))]),
            unset: set_of(&["k"]),
        }]),
        Err(PayloadError::Conflict("set/unset"))
    );
}

#[test]
fn rejects_label_in_both_lists() {
    assert_eq!(
        one(raw_node(
            texts(&["A", "B"]),
            texts(&["B", "C"]),
            map(&[]),
            texts(&[])
        )),
        Err(PayloadError::Conflict("labels"))
    );
    assert_eq!(
        encode_payload(&[Change::NodePut {
            gid: gid(1),
            labels_add: set_of(&["A", "B"]),
            labels_remove: set_of(&["B"]),
            set: BTreeMap::new(),
            unset: BTreeSet::new(),
        }]),
        Err(PayloadError::Conflict("labels"))
    );
}

#[test]
fn rejects_names_over_256_bytes_and_accepts_256() {
    let ok = "x".repeat(MAX_NAME_BYTES);
    let long = "x".repeat(MAX_NAME_BYTES + 1);
    // 256 bytes counted in UTF-8, not characters: 128 two-byte characters fit,
    // 129 do not.
    let ok_utf8 = "é".repeat(128);
    let long_utf8 = "é".repeat(129);
    let e = || texts(&[]);
    let m = || map(&[]);
    for name in [&ok, &ok_utf8] {
        assert!(one(raw_node(texts(&[name]), e(), m(), e())).is_ok());
        assert!(one(raw_node(e(), texts(&[name]), m(), e())).is_ok());
        assert!(one(raw_node(e(), e(), map(&[(name, int(1))]), e())).is_ok());
        assert!(one(raw_node(e(), e(), m(), texts(&[name]))).is_ok());
        assert!(one(raw_edge(text(name), m(), e())).is_ok());
        assert!(one(raw_edge(text("T"), map(&[(name, int(1))]), e())).is_ok());
        assert!(one(raw_edge(text("T"), m(), texts(&[name]))).is_ok());
    }
    for name in [&long, &long_utf8] {
        for bad in [
            raw_node(texts(&[name]), e(), m(), e()),
            raw_node(e(), texts(&[name]), m(), e()),
            raw_node(e(), e(), map(&[(name, int(1))]), e()),
            raw_node(e(), e(), m(), texts(&[name])),
            raw_edge(text(name), m(), e()),
            raw_edge(text("T"), map(&[(name, int(1))]), e()),
            raw_edge(text("T"), m(), texts(&[name])),
        ] {
            assert_eq!(one(bad), Err(PayloadError::NameTooLong));
        }
        assert_eq!(
            encode_payload(&[node(1, &[name], &[])]),
            Err(PayloadError::NameTooLong)
        );
        assert_eq!(
            encode_payload(&[node(1, &[], &[(name, int(1))])]),
            Err(PayloadError::NameTooLong)
        );
        assert_eq!(
            encode_payload(&[edge(1, 2, 3, name, &[])]),
            Err(PayloadError::NameTooLong)
        );
    }
    assert_eq!(MAX_NAME_BYTES, 256);
}

#[test]
fn rejects_values_that_cannot_be_encoded() {
    // An integer outside the CBOR range.
    let too_big = Value::Int(i128::from(u64::MAX) + 1);
    assert!(matches!(
        encode_payload(&[node(1, &[], &[("k", too_big)])]),
        Err(PayloadError::Encode(_))
    ));
    // Nesting beyond what an op can carry.
    let mut deep = Value::Null;
    for _ in 0..40 {
        deep = arr(vec![deep]);
    }
    assert!(matches!(
        encode_payload(&[node(1, &[], &[("k", deep)])]),
        Err(PayloadError::Encode(_))
    ));
}

#[test]
fn one_bad_change_rejects_the_whole_payload() {
    let good = arr(vec![int(2), b(1)]);
    let bad = arr(vec![int(2), Value::Bytes(vec![1; 15])]);
    assert_eq!(
        decode_payload(&arr(vec![good.clone(), good.clone(), bad, good])),
        Err(PayloadError::Gid)
    );
}

#[test]
fn every_value_type_of_the_spec_is_accepted() {
    let values = [
        Value::Null,
        Value::Bool(false),
        int(0),
        int(-1),
        Value::Int(i128::from(u64::MAX)),
        Value::Int(-(1i128 << 64)),
        Value::Float(0.1),
        Value::Float(f64::INFINITY),
        text(""),
        text("héllo"),
        Value::Bytes(vec![]),
        arr(vec![]),
        arr(vec![Value::Null, arr(vec![int(1)])]),
        map(&[]),
        map(&[("a", map(&[("b", arr(vec![text("c")]))]))]),
    ];
    for v in values {
        let c = vec![node(1, &[], &[("k", v.clone())])];
        let p = encode_payload(&c).unwrap();
        let back = decode_payload(&Value::decode(&p.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(back, c, "{v:?}");
    }
}
