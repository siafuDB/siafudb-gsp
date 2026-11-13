mod common;
use common::*;
use gsp_wire::*;

fn invalid<T: std::fmt::Debug>(v: Verdict<T>) -> InvalidReason {
    match v {
        Verdict::Invalid { reason } => reason,
        other => panic!("expected Invalid, got {other:?}"),
    }
}
fn unverifiable<T: std::fmt::Debug>(v: Verdict<T>) -> UnverifiableReason {
    match v {
        Verdict::Unverifiable { reason } => reason,
        other => panic!("expected Unverifiable, got {other:?}"),
    }
}

// ---------------------------------------------------------------- round trip

#[test]
fn round_trip_op_ed25519_and_hybrid() {
    for hybrid in [false, true] {
        let a = author(FRAG, hybrid, 1);
        let op = Op::sign(&body(&a, FRAG, 3), &a.keys()).unwrap();
        assert_eq!(op.sigs().len(), if hybrid { 2 } else { 1 });
        let bytes = op.to_bytes().unwrap();
        let back = Op::from_bytes(&bytes).unwrap();
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back.id(), op.id());
        // deps come back sorted; everything else is as written.
        // (A decoded map is in canonical key order, so compare field by field.)
        let mut want = body(&a, FRAG, 3);
        want.deps.sort();
        assert_eq!(back.body().deps, want.deps);
        assert_eq!(
            (back.body().seq, &back.body().prev, back.body().hlc),
            (3, &want.prev, want.hlc)
        );
        assert_eq!(
            (&back.body().author, &back.body().fragment_id),
            (&want.author, &want.fragment_id)
        );
        assert_eq!(back.body().to_bytes().unwrap(), want.to_bytes().unwrap());
        assert_eq!(back.body().to_bytes().unwrap(), op.body_bytes());
        let v = verify(&bytes, &VerifyCtx::new(FRAG, &a.log))
            .valid()
            .expect("valid");
        assert_eq!(v.id(), op.id());
        assert_eq!(v.bytes(), &bytes[..]);
        // id is the hash of the body bytes exactly as carried.
        assert_eq!(
            Multihash::compute(H, op.body_bytes()).as_ref(),
            Some(op.id())
        );
    }
}

#[test]
fn round_trip_sha3_ids() {
    let ed = SigningKey::from_seed(SigAlg::Ed25519, &[9; 32]);
    let g = KeyLogEntry {
        hash_alg: HashAlg::Sha3_256.id(),
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![ed.public()],
            policy: vec![1],
        },
    }
    .sign(&[&ed])
    .unwrap();
    let log = KeyLog::genesis(&g).unwrap();
    assert_eq!(log.author().alg, 2);
    let b = OpBody {
        hash_alg: 2,
        fragment_id: FRAG.to_vec(),
        author: log.author().clone(),
        seq: 1,
        prev: None,
        hlc: Hlc {
            wall_ms: 5,
            counter: 1,
        },
        deps: vec![],
        payload: Value::Null,
    };
    let bytes = Op::sign(&b, &[&ed]).unwrap().to_bytes().unwrap();
    let v = verify(&bytes, &VerifyCtx::new(FRAG, &log)).valid().unwrap();
    assert_eq!(v.id().alg, 2);
}

#[test]
fn round_trip_messages() {
    let a = author(FRAG, false, 1);
    let key = FragmentKey::new([3; 32]);
    let sealed = SealedOp::seal(&key, FRAG, [4; 24], &Plain::Op(signed(&a, FRAG, 1))).unwrap();
    let sig = Op::from_bytes(&signed(&a, FRAG, 1)).unwrap().sigs()[0].clone();
    let msgs = vec![
        Message::Hello {
            versions: vec![0],
            sig_algs: vec![1, 2],
            hash_algs: vec![1, 2],
            kem_algs: vec![1, 2],
            aead_algs: vec![1],
            nonce: vec![9; 32],
        },
        Message::Auth {
            fragment_id: FRAG.to_vec(),
            author: a.id(),
            sender_seq: 4,
            sigs: vec![sig],
        },
        Message::Push {
            fragment_id: FRAG.to_vec(),
            sealed: vec![sealed.clone(), sealed.clone()],
        },
        Message::Pull {
            fragment_id: FRAG.to_vec(),
            after: 17,
            limit: 500,
        },
        Message::Batch {
            fragment_id: FRAG.to_vec(),
            next: 19,
            more: true,
            sealed: vec![sealed],
        },
        Message::Ack {
            fragment_id: FRAG.to_vec(),
            cursor: 19,
            count: 2,
        },
        Message::Head {
            fragment_id: FRAG.to_vec(),
            cursor: u64::MAX,
        },
        Message::Error {
            code: 3,
            message: "no such fragment".into(),
        },
    ];
    for m in msgs {
        let bytes = m.to_bytes().unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }
    // Unknown frame type is a typed error, not a panic and not a guess.
    let unknown = Value::Array(vec![Value::uint(99)]).encode().unwrap();
    assert_eq!(
        Message::from_bytes(&unknown),
        Err(DecodeError::UnsupportedKind(99))
    );
}

#[test]
fn round_trip_keylog_entries_and_rebuild() {
    let mut a = author(FRAG, true, 1);
    let k2 = SigningKey::from_seed(SigAlg::Ed25519, &[42; 32]);
    let add = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::AddKey {
            key: k2.public(),
            from_seq: 7,
        },
    };
    assert_eq!(
        KeyLogEntry::from_bytes(&add.to_bytes().unwrap()).unwrap(),
        add
    );
    let mut signers = a.keys();
    signers.push(&k2);
    let signed_add = add.sign(&signers).unwrap();
    a.log.append(&signed_add).unwrap();
    let rebuilt = KeyLog::from_entries(a.log.entries().iter().map(|e| e.as_slice())).unwrap();
    assert_eq!(rebuilt, a.log);
    assert_eq!(rebuilt.keys().len(), 3);
}

// --------------------------------------------------------------- determinism

fn big_map(rng: &mut Rng, depth: usize) -> Value {
    let mut entries: Vec<(String, Value)> = Vec::new();
    // Keys chosen to exercise length-then-bytes ordering and multi-byte UTF-8.
    for (i, k) in [
        "",
        "a",
        "b",
        "aa",
        "ab",
        "B",
        "z",
        "zz",
        "é",
        "名前",
        "key-with-a-long-name-000000000000",
        "10",
        "9",
    ]
    .iter()
    .enumerate()
    {
        let v = match i % 6 {
            0 => Value::uint(i as u64 * 1000),
            1 => Value::Int(-(i as i128) - 1),
            2 => Value::Text(format!("v{i}")),
            3 => Value::Bytes(vec![i as u8; i]),
            4 => Value::Float(i as f64 + 0.1),
            _ => Value::Array(vec![Value::Bool(true), Value::Null]),
        };
        entries.push((k.to_string(), v));
    }
    if depth > 0 {
        entries.push(("nested".into(), big_map(rng, depth - 1)));
        entries.push((
            "nested2".into(),
            Value::Array(vec![big_map(rng, depth - 1)]),
        ));
    }
    rng.shuffle(&mut entries);
    Value::Map(entries)
}

#[test]
fn determinism_1000_shuffled_map_orders() {
    let a = author(FRAG, false, 1);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut reference: Option<(Vec<u8>, Multihash, Vec<u8>)> = None;
    let mut distinct_orders = std::collections::HashSet::new();
    for _ in 0..1000 {
        let p = big_map(&mut rng, 2);
        if let Value::Map(e) = &p {
            distinct_orders.insert(e.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>());
        }
        let mut b = body(&a, FRAG, 2);
        b.payload = p;
        rng.shuffle(&mut b.deps);
        let bytes = b.to_bytes().unwrap();
        let op = Op::sign(&b, &a.keys()).unwrap();
        let signed = op.to_bytes().unwrap();
        match &reference {
            None => reference = Some((bytes, op.id().clone(), signed)),
            Some((rb, rid, rs)) => {
                assert_eq!(&bytes, rb, "body bytes differ across map orders");
                assert_eq!(op.id(), rid);
                assert_eq!(
                    &signed, rs,
                    "signed bytes differ (signatures are deterministic)"
                );
            }
        }
    }
    assert!(
        distinct_orders.len() > 990,
        "shuffle produced only {} orders",
        distinct_orders.len()
    );
}

#[test]
fn signature_order_is_normalised() {
    let a = author(FRAG, true, 1);
    let b = body(&a, FRAG, 1);
    let x = Op::sign(&b, &[&a.ed, a.pq.as_ref().unwrap()])
        .unwrap()
        .to_bytes()
        .unwrap();
    let y = Op::sign(&b, &[a.pq.as_ref().unwrap(), &a.ed])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(x, y);
}

#[test]
fn cbor_matches_rfc8949_examples() {
    let enc = |v: Value| hex::encode(v.encode().unwrap());
    // RFC 8949 appendix A.
    assert_eq!(enc(Value::uint(0)), "00");
    assert_eq!(enc(Value::uint(23)), "17");
    assert_eq!(enc(Value::uint(24)), "1818");
    assert_eq!(enc(Value::uint(100)), "1864");
    assert_eq!(enc(Value::uint(1000)), "1903e8");
    assert_eq!(enc(Value::uint(1_000_000)), "1a000f4240");
    assert_eq!(enc(Value::uint(1_000_000_000_000)), "1b000000e8d4a51000");
    assert_eq!(enc(Value::uint(u64::MAX)), "1bffffffffffffffff");
    assert_eq!(enc(Value::Int(-1)), "20");
    assert_eq!(enc(Value::Int(-100)), "3863");
    assert_eq!(enc(Value::Int(-1000)), "3903e7");
    assert_eq!(enc(Value::Int(-18446744073709551616)), "3bffffffffffffffff");
    assert_eq!(enc(Value::Float(0.0)), "f90000");
    assert_eq!(enc(Value::Float(-0.0)), "f98000");
    assert_eq!(enc(Value::Float(1.0)), "f93c00");
    assert_eq!(enc(Value::Float(1.1)), "fb3ff199999999999a");
    assert_eq!(enc(Value::Float(1.5)), "f93e00");
    assert_eq!(enc(Value::Float(65504.0)), "f97bff");
    assert_eq!(enc(Value::Float(100000.0)), "fa47c35000");
    assert_eq!(enc(Value::Float(3.4028234663852886e+38)), "fa7f7fffff");
    assert_eq!(enc(Value::Float(1.0e+300)), "fb7e37e43c8800759c");
    assert_eq!(enc(Value::Float(5.960464477539063e-8)), "f90001");
    assert_eq!(enc(Value::Float(-4.1)), "fbc010666666666666");
    assert_eq!(enc(Value::Float(f64::INFINITY)), "f97c00");
    assert_eq!(enc(Value::Float(f64::NEG_INFINITY)), "f9fc00");
    assert_eq!(enc(Value::Float(f64::NAN)), "f97e00");
    assert_eq!(enc(Value::Bytes(vec![1, 2, 3, 4])), "4401020304");
    assert_eq!(enc(Value::Text("\u{6c34}".into())), "63e6b0b4");
    assert_eq!(
        enc(Value::Array(vec![
            Value::uint(1),
            Value::uint(2),
            Value::uint(3)
        ])),
        "83010203"
    );
    assert_eq!(
        enc(Value::Map(vec![
            (
                "b".into(),
                Value::Array(vec![Value::uint(2), Value::uint(3)])
            ),
            ("a".into(), Value::uint(1)),
        ])),
        "a26161016162820203"
    );
    // Length-first key order: "z" (1 byte) sorts before "aa" (2 bytes).
    assert_eq!(
        enc(Value::Map(vec![
            ("aa".into(), Value::uint(1)),
            ("z".into(), Value::uint(2))
        ])),
        "a2617a02626161 01".replace(' ', "")
    );
    assert_eq!(Value::Int(1 << 64).encode(), Err(EncodeError::IntRange));
    assert_eq!(
        Value::Map(vec![("a".into(), Value::Null), ("a".into(), Value::Null)]).encode(),
        Err(EncodeError::DuplicateKey)
    );
}

#[test]
fn decoder_rejects_non_canonical() {
    let dec = |h: &str| Value::decode(&hex::decode(h).unwrap());
    assert_eq!(dec("1817"), Err(DecodeError::NonCanonical)); // 23 in two bytes
    assert_eq!(dec("190001"), Err(DecodeError::NonCanonical)); // 1 as uint16
    assert_eq!(dec("fa3fc00000"), Err(DecodeError::NonCanonical)); // 1.5 as f32
    assert_eq!(dec("fb3ff8000000000000"), Err(DecodeError::NonCanonical)); // 1.5 as f64
    assert_eq!(dec("f97e01"), Err(DecodeError::NonCanonical)); // NaN with payload
    assert_eq!(dec("a2616201616101"), Err(DecodeError::NonCanonical)); // keys b, a
    assert_eq!(dec("a2616101616102"), Err(DecodeError::DuplicateKey));
    assert_eq!(dec("0000"), Err(DecodeError::Trailing));
    assert_eq!(dec("9f0102ff"), Err(DecodeError::UnsupportedType)); // indefinite array
    assert_eq!(dec("bf616101ff"), Err(DecodeError::UnsupportedType)); // indefinite map
    assert_eq!(dec("5f4101ff"), Err(DecodeError::UnsupportedType)); // indefinite bytes
    assert_eq!(dec("c100"), Err(DecodeError::UnsupportedType)); // tag
    assert_eq!(dec("f7"), Err(DecodeError::UnsupportedType)); // undefined
    assert_eq!(dec("a10102"), Err(DecodeError::UnsupportedType)); // integer map key
    assert_eq!(dec("62c328"), Err(DecodeError::Cbor)); // invalid UTF-8
    assert_eq!(dec("1b"), Err(DecodeError::Cbor)); // truncated
    assert_eq!(dec(""), Err(DecodeError::Cbor));
    assert_eq!(dec(&"81".repeat(40)), Err(DecodeError::TooDeep));
    assert!(dec("a26161016162820203").is_ok());
}

// -------------------------------------------------------------------- tamper

#[test]
fn tamper_every_field() {
    let a = author(FRAG, true, 1);
    let other = author(FRAG, true, 2);
    let logs = vec![a.log.clone(), other.log.clone()];
    let ctx = VerifyCtx::new(FRAG, &logs);
    let good = body(&a, FRAG, 3);
    let op = Op::sign(&good, &a.keys()).unwrap();
    assert!(verify(&op.to_bytes().unwrap(), &ctx).is_valid());
    let with = |f: &dyn Fn(&mut OpBody)| {
        let mut b = good.clone();
        f(&mut b);
        assert_ne!(
            b.to_bytes().unwrap(),
            good.to_bytes().unwrap(),
            "mutation was a no-op"
        );
        verify(&rewrap(&b, op.sigs()), &ctx)
    };

    // Every signed field, altered while keeping the original signatures.
    assert_eq!(invalid(with(&|b| b.seq = 4)), InvalidReason::BadSignature);
    assert_eq!(
        invalid(with(&|b| b.prev = Some(fake_hash(77)))),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| b.hlc.wall_ms += 1)),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| b.hlc.counter += 1)),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| b.deps.push(fake_hash(1)))),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| b.deps.clear())),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| b.payload = Value::Text("evil".into()))),
        InvalidReason::BadSignature
    );
    assert_eq!(
        invalid(with(&|b| {
            let Value::Map(m) = &mut b.payload else {
                unreachable!()
            };
            m[3].1 = Value::Text("Tendai ".into());
        })),
        InvalidReason::BadSignature
    );
    // hash_alg: BLAKE3 -> SHA3 changes the id, so the signatures are for another id.
    assert_eq!(
        invalid(with(&|b| b.hash_alg = 2)),
        InvalidReason::BadSignature
    );
    // fragment_id: wrong audience.
    assert_eq!(
        invalid(with(&|b| b.fragment_id = FRAG_B.to_vec())),
        InvalidReason::WrongFragment
    );
    // seq 3 -> 1 needs prev = null to be well-formed; still a bad signature.
    assert_eq!(
        invalid(with(&|b| {
            b.seq = 1;
            b.prev = None;
        })),
        InvalidReason::BadSignature
    );
    // Structurally impossible combinations are rejected before any crypto.
    let mut raw = good.clone();
    raw.prev = None;
    assert!(raw.to_bytes().is_err());

    // author: re-attributing the op to another known author. That author's key
    // log does not contain the signing keys, so nothing can be checked: the op
    // is Unverifiable (retained, never applied), not Valid.
    let v = with(&|b| b.author = other.id());
    assert_eq!(unverifiable(v), UnverifiableReason::UnknownKey);
    // ...and to an author nobody has heard of.
    assert_eq!(
        unverifiable(with(&|b| b.author = fake_hash(5))),
        UnverifiableReason::UnknownAuthor
    );

    // Signature fields.
    let tamper_sig = |i: usize, f: &dyn Fn(&mut Signature)| {
        let mut o = op.clone();
        f(&mut o.signed_mut().sigs[i]);
        verify(&o.to_bytes().unwrap(), &ctx)
    };
    for i in 0..2 {
        assert_eq!(
            invalid(tamper_sig(i, &|s| s.bytes[10] ^= 1)),
            InvalidReason::BadSignature
        );
        assert_eq!(
            unverifiable(tamper_sig(i, &|s| s.key_id.digest[0] ^= 1)),
            UnverifiableReason::UnknownKey
        );
    }
    // Swap the two signatures' algorithm tags: key and signature disagree.
    assert_eq!(
        invalid(tamper_sig(0, &|s| s.alg = 2)),
        InvalidReason::AlgMismatch
    );
    // Swap signature bytes between the two entries.
    let mut o = op.clone();
    let (x, y) = (o.sigs()[0].bytes.clone(), o.sigs()[1].bytes.clone());
    o.signed_mut().sigs[0].bytes = y;
    o.signed_mut().sigs[1].bytes = x;
    assert_eq!(
        invalid(verify(&o.to_bytes().unwrap(), &ctx)),
        InvalidReason::BadSignature
    );
    // No signatures at all.
    let mut o = op.clone();
    o.signed_mut().sigs.clear();
    assert_eq!(
        invalid(verify(&o.to_bytes().unwrap(), &ctx)),
        InvalidReason::NoSignatures
    );
}

#[test]
fn every_single_bit_flip_is_not_valid() {
    // Ed25519-only op so the sweep over every bit stays fast.
    let a = author(FRAG, false, 1);
    let ctx = VerifyCtx::new(FRAG, &a.log);
    let bytes = signed(&a, FRAG, 2);
    assert!(verify(&bytes, &ctx).is_valid());
    let (mut inv, mut unv) = (0, 0);
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut t = bytes.clone();
            t[i] ^= 1 << bit;
            match verify(&t, &ctx) {
                Verdict::Valid(_) => panic!("bit {bit} of byte {i} flipped and still Valid"),
                Verdict::Invalid { .. } => inv += 1,
                Verdict::Unverifiable { .. } => unv += 1,
            }
        }
    }
    println!(
        "bit flips: {} total, {inv} Invalid, {unv} Unverifiable, 0 Valid",
        bytes.len() * 8
    );
}

// ------------------------------------------------------------ fragment replay

#[test]
fn cross_fragment_replay_is_invalid() {
    // The same keys are used for an identity in fragment A and one in fragment B.
    let a = author(FRAG, true, 1);
    let b = author(FRAG_B, true, 1);
    assert_ne!(a.id(), b.id(), "author ids are fragment-bound");
    let logs = vec![a.log.clone(), b.log.clone()];
    let op = Op::sign(&body(&a, FRAG, 2), &a.keys()).unwrap();
    let bytes = op.to_bytes().unwrap();
    assert!(verify(&bytes, &VerifyCtx::new(FRAG, &logs)).is_valid());

    // 1. Replayed verbatim into fragment B.
    assert_eq!(
        invalid(verify(&bytes, &VerifyCtx::new(FRAG_B, &logs))),
        InvalidReason::WrongFragment
    );

    // 2. Body rewritten to claim fragment B (and B's author id), signatures kept.
    let mut forged = body(&a, FRAG, 2);
    forged.fragment_id = FRAG_B.to_vec();
    forged.author = b.id();
    let v = verify(&rewrap(&forged, op.sigs()), &VerifyCtx::new(FRAG_B, &logs));
    assert_eq!(invalid(v), InvalidReason::BadSignature);

    // 3. Only fragment_id rewritten, author left as A's: A's log is bound to fragment A.
    let mut forged = body(&a, FRAG, 2);
    forged.fragment_id = FRAG_B.to_vec();
    let v = verify(&rewrap(&forged, op.sigs()), &VerifyCtx::new(FRAG_B, &logs));
    assert_eq!(invalid(v), InvalidReason::WrongFragment);

    // 4. The audience is in the signed bytes directly, not only via the id.
    let kid = &op.sigs()[0].key_id;
    assert_ne!(
        sig_input(Domain::Op, FRAG, op.id(), 1, kid),
        sig_input(Domain::Op, FRAG_B, op.id(), 1, kid)
    );
    // ...and an op signature is not a batch or key-log signature.
    assert_ne!(
        sig_input(Domain::Op, FRAG, op.id(), 1, kid),
        sig_input(Domain::Batch, FRAG, op.id(), 1, kid)
    );
}

// ----------------------------------------------------------------- downgrade

#[test]
fn stripping_a_hybrid_signature_is_a_downgrade() {
    let a = author(FRAG, true, 1);
    let ctx = VerifyCtx::new(FRAG, &a.log);
    let op = Op::sign(&body(&a, FRAG, 2), &a.keys()).unwrap();
    for strip in [SigAlg::MlDsa65, SigAlg::Ed25519] {
        let mut o = op.clone();
        o.signed_mut().sigs.retain(|s| s.alg != strip.id());
        assert_eq!(o.sigs().len(), 1);
        let v = verify(&o.to_bytes().unwrap(), &ctx);
        assert_eq!(
            invalid(v),
            InvalidReason::MissingRequiredSignature,
            "stripped {strip:?}"
        );
    }
    // Signing with only one key in the first place is the same thing.
    let ed_only = Op::sign(&body(&a, FRAG, 2), &[&a.ed])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        invalid(verify(&ed_only, &ctx)),
        InvalidReason::MissingRequiredSignature
    );
    // Two Ed25519 signatures do not add up to a hybrid.
    let mut a2 = author(FRAG, true, 1);
    let ed2 = SigningKey::from_seed(SigAlg::Ed25519, &[50; 32]);
    let add = KeyLogEntry {
        hash_alg: H,
        prev: Some(a2.log.head().clone()),
        action: KeyLogAction::AddKey {
            key: ed2.public(),
            from_seq: 1,
        },
    };
    let mut s = a2.keys();
    s.push(&ed2);
    let add = add.sign(&s).unwrap();
    a2.log.append(&add).unwrap();
    let two_ed = Op::sign(&body(&a2, FRAG, 2), &[&a2.ed, &ed2])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        invalid(verify(&two_ed, &VerifyCtx::new(FRAG, &a2.log))),
        InvalidReason::MissingRequiredSignature
    );
}

#[test]
fn policy_upgrade_takes_effect_at_seq() {
    let mut a = author(FRAG, false, 1);
    let pq = SigningKey::from_seed(SigAlg::MlDsa65, &[77; 32]);
    let add = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::AddKey {
            key: pq.public(),
            from_seq: 10,
        },
    }
    .sign(&[&a.ed, &pq])
    .unwrap();
    a.log.append(&add).unwrap();
    let set = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::SetPolicy {
            policy: vec![1, 2],
            from_seq: 10,
        },
    }
    .sign(&[&a.ed])
    .unwrap();
    a.log.append(&set).unwrap();
    let ctx = VerifyCtx::new(FRAG, &a.log);
    let ed_only = |seq| {
        Op::sign(&body(&a, FRAG, seq), &[&a.ed])
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    let hybrid = |seq| {
        Op::sign(&body(&a, FRAG, seq), &[&a.ed, &pq])
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    assert!(verify(&ed_only(9), &ctx).is_valid());
    assert_eq!(
        invalid(verify(&ed_only(10), &ctx)),
        InvalidReason::MissingRequiredSignature
    );
    assert!(verify(&hybrid(10), &ctx).is_valid());
    // The ML-DSA key is not valid before seq 10.
    assert_eq!(
        invalid(verify(&hybrid(9), &ctx)),
        InvalidReason::KeyNotValidAtSeq
    );
    // After the upgrade, the log itself needs hybrid signatures.
    let weak = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::SetPolicy {
            policy: vec![1],
            from_seq: 20,
        },
    };
    assert_eq!(
        a.log.clone().append(&weak.sign(&[&a.ed]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    assert!(a.log.append(&weak.sign(&[&a.ed, &pq]).unwrap()).is_ok());
}

// ------------------------------------------------------------------- unknown

#[test]
fn unknown_algorithms_are_unverifiable_never_valid() {
    let a = author(FRAG, false, 1);
    let ctx = VerifyCtx::new(FRAG, &a.log);
    let op = Op::sign(&body(&a, FRAG, 2), &a.keys()).unwrap();

    // Unknown signature algorithm id next to a good Ed25519 signature.
    let mut o = op.clone();
    o.signed_mut().sigs.push(Signature {
        alg: 999,
        key_id: fake_hash(1),
        bytes: vec![1; 64],
    });
    assert_eq!(
        unverifiable(verify(&o.to_bytes().unwrap(), &ctx)),
        UnverifiableReason::UnknownSigAlg
    );

    // Unknown signature algorithm id as the only signature.
    let mut o = op.clone();
    o.signed_mut().sigs[0].alg = 999;
    let v = verify(&o.to_bytes().unwrap(), &ctx);
    assert!(!v.is_valid(), "{v:?}");

    // A signature claiming a key id hashed with an unknown hash algorithm.
    let mut o = op.clone();
    o.signed_mut().sigs[0].key_id.alg = 77;
    assert!(matches!(
        verify(&o.to_bytes().unwrap(), &ctx),
        Verdict::Unverifiable { .. }
    ));

    // Unknown hash algorithm for the op id (including registered-but-unimplemented SHA-256).
    for alg in [3u16, 500] {
        let mut b = body(&a, FRAG, 2);
        b.hash_alg = alg;
        let v = verify(&rewrap(&b, op.sigs()), &ctx);
        assert_eq!(unverifiable(v), UnverifiableReason::UnknownHashAlg);
        assert!(Op::sign(&b, &a.keys()).is_err());
    }

    // Unknown structure version.
    let Value::Array(mut items) = Value::decode(op.body_bytes()).unwrap() else {
        unreachable!()
    };
    items[0] = Value::uint(1);
    let v1 = Signed {
        body: Value::Array(items).encode().unwrap(),
        sigs: op.sigs().to_vec(),
    };
    assert_eq!(
        unverifiable(verify(&v1.to_bytes().unwrap(), &ctx)),
        UnverifiableReason::UnknownFormat
    );

    // A key log whose policy needs an algorithm this build lacks cannot be loaded.
    let g = KeyLogEntry {
        hash_alg: H,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![a.ed.public()],
            policy: vec![1, 999],
        },
    }
    .sign(&[&a.ed])
    .unwrap();
    assert_eq!(KeyLog::genesis(&g), Err(KeyLogError::Unsupported));

    // Unknown author.
    let stranger = author(FRAG, false, 9);
    assert_eq!(
        unverifiable(verify(&signed(&stranger, FRAG, 1), &ctx)),
        UnverifiableReason::UnknownAuthor
    );
}

// -------------------------------------------------------------- equivocation

#[test]
fn equivocation_is_detected_and_provable() {
    let a = author(FRAG, true, 1);
    let ctx = VerifyCtx::new(FRAG, &a.log);
    let mk = |seq: u64, prev: Option<Multihash>, text: &str| {
        let mut b = body(&a, FRAG, seq);
        b.prev = prev;
        b.payload = Value::Text(text.into());
        verify(&Op::sign(&b, &a.keys()).unwrap().to_bytes().unwrap(), &ctx)
            .valid()
            .unwrap()
    };
    let op1 = mk(1, None, "one");
    let op2 = mk(2, Some(op1.id().clone()), "two");
    let op2x = mk(2, Some(op1.id().clone()), "two, but different");
    let op3 = mk(3, Some(op2.id().clone()), "three");

    let mut chain = AuthorChain::new(a.id(), FRAG.to_vec());
    assert_eq!(chain.observe(&op1), ChainOutcome::Accepted);
    assert_eq!(chain.observe(&op3), ChainOutcome::Accepted); // out of order is fine
    assert_eq!(chain.contiguous_head(), 1);
    assert_eq!(chain.observe(&op2), ChainOutcome::Accepted);
    assert_eq!(chain.contiguous_head(), 3);
    assert_eq!(chain.observe(&op2), ChainOutcome::Duplicate);

    let ChainOutcome::Equivocation(proof) = chain.observe(&op2x) else {
        panic!("not detected")
    };
    assert_eq!(
        chain.id_at(2),
        Some(op2.id()),
        "the first op stays recorded"
    );
    // A third party with only the key log can check the proof.
    assert!(proof.verify(&VerifyCtx::new(FRAG, &a.log)));
    let wire = proof.to_bytes().unwrap();
    assert!(EquivocationProof::from_bytes(&wire).unwrap().verify(&ctx));
    // Not proofs: the same op twice, two different seqs, a tampered op.
    assert!(
        !EquivocationProof {
            a: op2.bytes().to_vec(),
            b: op2.bytes().to_vec()
        }
        .verify(&ctx)
    );
    assert!(
        !EquivocationProof {
            a: op2.bytes().to_vec(),
            b: op3.bytes().to_vec()
        }
        .verify(&ctx)
    );
    let mut bad = op2x.bytes().to_vec();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(
        !EquivocationProof {
            a: op2.bytes().to_vec(),
            b: bad
        }
        .verify(&ctx)
    );

    // A fork that shows up as a prev mismatch rather than a same-seq pair.
    let op4_fork = mk(4, Some(fake_hash(9)), "four on another branch");
    assert_eq!(chain.observe(&op4_fork), ChainOutcome::PrevMismatch);
    // HLC must increase along the chain.
    let mut b = body(&a, FRAG, 4);
    b.prev = Some(op3.id().clone());
    b.hlc = op3.body().hlc;
    let stale = verify(&Op::sign(&b, &a.keys()).unwrap().to_bytes().unwrap(), &ctx)
        .valid()
        .unwrap();
    assert_eq!(chain.observe(&stale), ChainOutcome::HlcNotMonotonic);
    // Another author's op does not belong here.
    let other = author(FRAG, false, 3);
    let o = verify(&signed(&other, FRAG, 1), &VerifyCtx::new(FRAG, &other.log))
        .valid()
        .unwrap();
    assert_eq!(chain.observe(&o), ChainOutcome::WrongChain);
}

// ---------------------------------------------------------------- revocation

#[test]
fn revoked_key_is_rejected_after_seq_n_and_accepted_before() {
    const N: u64 = 5;
    let mut a = author(FRAG, false, 1);
    let k2 = SigningKey::from_seed(SigAlg::Ed25519, &[2; 32]);
    let k1_id = a.ed.public().key_id(H).unwrap();
    let before = signed(&a, FRAG, N + 1);
    assert!(
        verify(&before, &VerifyCtx::new(FRAG, &a.log)).is_valid(),
        "valid before revocation"
    );

    // Revoking the only key would kill the author: refused.
    let revoke = |log: &KeyLog, signer: &SigningKey| {
        KeyLogEntry {
            hash_alg: H,
            prev: Some(log.head().clone()),
            action: KeyLogAction::RevokeKey {
                key_id: k1_id.clone(),
                after_seq: N,
            },
        }
        .sign(&[signer])
        .unwrap()
    };
    assert_eq!(
        a.log.clone().append(&revoke(&a.log, &a.ed)),
        Err(KeyLogError::Inconsistent)
    );

    let add = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::AddKey {
            key: k2.public(),
            from_seq: 1,
        },
    }
    .sign(&[&a.ed, &k2])
    .unwrap();
    a.log.append(&add).unwrap();
    let r = revoke(&a.log, &k2);
    a.log.append(&r).unwrap();

    let ctx = VerifyCtx::new(FRAG, &a.log);
    let by = |k: &SigningKey, seq: u64| {
        Op::sign(&body(&a, FRAG, seq), &[k])
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    for seq in [1, 2, N - 1, N] {
        assert!(
            verify(&by(&a.ed, seq), &ctx).is_valid(),
            "seq {seq} <= N must stay valid"
        );
    }
    for seq in [N + 1, N + 2, 1000] {
        assert_eq!(
            invalid(verify(&by(&a.ed, seq), &ctx)),
            InvalidReason::KeyNotValidAtSeq,
            "seq {seq}"
        );
    }
    // The op that was valid before the revocation was learned is now rejected.
    assert_eq!(
        invalid(verify(&before, &ctx)),
        InvalidReason::KeyNotValidAtSeq
    );
    // The replacement key works on both sides of N.
    assert!(verify(&by(&k2, N), &ctx).is_valid());
    assert!(verify(&by(&k2, N + 1), &ctx).is_valid());
    // A revoked key next to a good one still poisons the op.
    let both = Op::sign(&body(&a, FRAG, N + 1), &[&a.ed, &k2])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        invalid(verify(&both, &ctx)),
        InvalidReason::KeyNotValidAtSeq
    );
    // The revoked key can no longer extend the key log.
    let k3 = SigningKey::from_seed(SigAlg::Ed25519, &[3; 32]);
    let sneak = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::AddKey {
            key: k3.public(),
            from_seq: 1,
        },
    };
    assert_eq!(
        a.log.clone().append(&sneak.sign(&[&a.ed, &k3]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    // A later revocation cannot loosen an earlier one.
    let loosen = KeyLogEntry {
        hash_alg: H,
        prev: Some(a.log.head().clone()),
        action: KeyLogAction::RevokeKey {
            key_id: k1_id.clone(),
            after_seq: 1000,
        },
    }
    .sign(&[&k2])
    .unwrap();
    a.log.append(&loosen).unwrap();
    assert_eq!(a.log.find_key(&k1_id).unwrap().revoked_after, Some(N));
}

#[test]
fn keylog_rejects_bad_entries() {
    let a = author(FRAG, true, 1);
    let stranger = SigningKey::from_seed(SigAlg::Ed25519, &[66; 32]);
    let new = SigningKey::from_seed(SigAlg::Ed25519, &[67; 32]);
    let add = |prev: Multihash| KeyLogEntry {
        hash_alg: H,
        prev: Some(prev),
        action: KeyLogAction::AddKey {
            key: new.public(),
            from_seq: 1,
        },
    };
    let pq = a.pq.as_ref().unwrap();
    let try_append = |bytes: Vec<u8>| a.log.clone().append(&bytes);
    // Correctly signed: accepted.
    assert!(try_append(add(a.log.head().clone()).sign(&[&a.ed, pq, &new]).unwrap()).is_ok());
    // Not chained to the head.
    assert_eq!(
        try_append(add(fake_hash(1)).sign(&[&a.ed, pq, &new]).unwrap()),
        Err(KeyLogError::NotHead)
    );
    // Hybrid log, Ed25519-only authorisation: downgrade of the log itself.
    assert_eq!(
        try_append(add(a.log.head().clone()).sign(&[&a.ed, &new]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    // Signed by a key the log has never seen.
    assert_eq!(
        try_append(add(a.log.head().clone()).sign(&[&stranger, &new]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    // New key did not co-sign (no proof of possession).
    assert_eq!(
        try_append(add(a.log.head().clone()).sign(&[&a.ed, pq]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    // A second genesis cannot be appended; a non-genesis cannot start a log.
    let g = a.log.entries()[0].clone();
    assert_eq!(try_append(g.clone()), Err(KeyLogError::Genesis));
    assert_eq!(
        KeyLog::genesis(&add(a.log.head().clone()).sign(&[&a.ed, pq, &new]).unwrap()),
        Err(KeyLogError::Genesis)
    );
    // Genesis missing a declared key's signature.
    let g2 = KeyLogEntry {
        hash_alg: H,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![a.ed.public(), pq.public()],
            policy: vec![1, 2],
        },
    };
    assert_eq!(
        KeyLog::genesis(&g2.sign(&[&a.ed]).unwrap()),
        Err(KeyLogError::Unauthorized)
    );
    // Genesis whose policy no declared key can meet.
    let g3 = KeyLogEntry {
        hash_alg: H,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![a.ed.public()],
            policy: vec![1, 2],
        },
    };
    assert!(KeyLog::genesis(&g3.sign(&[&a.ed]).unwrap()).is_err());
    // Any bit flip in the genesis is rejected (sampled).
    for i in (0..g.len()).step_by(7) {
        let mut t = g.clone();
        t[i] ^= 0x04;
        assert!(KeyLog::genesis(&t).is_err(), "genesis byte {i}");
    }
}

// -------------------------------------------------------------------- sealed

#[test]
fn sealed_op_round_trip_tamper_and_wrong_key() {
    let a = author(FRAG, false, 1);
    let op_bytes = signed(&a, FRAG, 1);
    let key = FragmentKey::new([0x11; 32]);
    let sealed = SealedOp::seal(&key, FRAG, [0x22; 24], &Plain::Op(op_bytes.clone())).unwrap();
    let wire = sealed.to_bytes().unwrap();
    let back = SealedOp::from_bytes(&wire).unwrap();
    assert_eq!(back, sealed);
    let Plain::Op(inner) = back.open(&key, FRAG).unwrap() else {
        panic!("kind")
    };
    assert_eq!(inner, op_bytes);
    assert!(verify(&inner, &VerifyCtx::new(FRAG, &a.log)).is_valid());
    // Batch kind survives too.
    let sb = SealedOp::seal(&key, FRAG, [0x23; 24], &Plain::Batch(vec![1, 2, 3])).unwrap();
    assert_eq!(sb.open(&key, FRAG).unwrap(), Plain::Batch(vec![1, 2, 3]));

    // The relay-visible bytes leak neither author, key ids, signatures nor payload.
    let op = Op::from_bytes(&op_bytes).unwrap();
    let contains = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
    assert!(contains(FRAG), "fragment id is the routing header");
    assert!(!contains(&a.id().digest));
    assert!(!contains(&op.sigs()[0].key_id.digest));
    assert!(!contains(&op.sigs()[0].bytes));
    assert!(!contains(b"Tendai"));
    // [1, bstr] wrapper (5 bytes here) + 16-byte tag: length is all a relay learns.
    assert_eq!(sealed.ciphertext.len(), op_bytes.len() + 5 + 16);

    // Wrong key.
    assert_eq!(
        sealed.open(&FragmentKey::new([0x12; 32]), FRAG),
        Err(SealError::Decrypt)
    );
    // Every ciphertext byte, every nonce byte.
    for i in 0..sealed.ciphertext.len() {
        let mut t = sealed.clone();
        t.ciphertext[i] ^= 0x80;
        assert_eq!(
            t.open(&key, FRAG),
            Err(SealError::Decrypt),
            "ciphertext byte {i}"
        );
    }
    for i in 0..24 {
        let mut t = sealed.clone();
        t.nonce[i] ^= 1;
        assert_eq!(
            t.open(&key, FRAG),
            Err(SealError::Decrypt),
            "nonce byte {i}"
        );
    }
    // Truncation.
    let mut t = sealed.clone();
    t.ciphertext.truncate(10);
    assert_eq!(t.open(&key, FRAG), Err(SealError::Decrypt));
    // Header rewritten to another fragment: caught whether or not the receiver
    // notices the mismatch itself, because the header is authenticated data.
    let mut t = sealed.clone();
    t.fragment_id = FRAG_B.to_vec();
    assert_eq!(t.open(&key, FRAG), Err(SealError::WrongFragment));
    assert_eq!(t.open(&key, FRAG_B), Err(SealError::Decrypt));
    // Unknown AEAD id.
    let mut t = sealed.clone();
    t.aead_alg = 2;
    assert_eq!(t.open(&key, FRAG), Err(SealError::UnsupportedAead));
}

// --------------------------------------------------------------------- batch

#[test]
fn batch_is_signed_as_a_unit() {
    let a = author(FRAG, true, 1);
    let b = author(FRAG, false, 2);
    let logs = vec![a.log.clone(), b.log.clone()];
    let ctx = VerifyCtx::new(FRAG, &logs);
    let ops = vec![
        signed(&a, FRAG, 1),
        signed(&b, FRAG, 1),
        signed(&a, FRAG, 2),
    ];
    let bb = BatchBody {
        hash_alg: H,
        fragment_id: FRAG.to_vec(),
        sender: a.id(),
        sender_seq: 2,
        ops: ops.clone(),
    };
    assert_eq!(BatchBody::from_bytes(&bb.to_bytes().unwrap()).unwrap(), bb);
    let wire = Batch::sign(&bb, &a.keys()).unwrap();
    let vb = verify_batch(&wire, &ctx).valid().expect("valid batch");
    assert_eq!(vb.sender, a.id());
    assert_eq!(vb.ops.len(), 3);
    assert!(vb.ops.iter().all(|o| o.is_valid()));

    let sigs = Signed::from_bytes(&wire).unwrap().sigs;
    let rewrap = |bb: &BatchBody| {
        Signed {
            body: bb.to_bytes().unwrap(),
            sigs: sigs.clone(),
        }
        .to_bytes()
        .unwrap()
    };
    // Reordered, dropped, or injected ops break the batch signature.
    let mut t = bb.clone();
    t.ops.swap(0, 2);
    assert_eq!(
        invalid(verify_batch(&rewrap(&t), &ctx)),
        InvalidReason::BadSignature
    );
    let mut t = bb.clone();
    t.ops.pop();
    assert_eq!(
        invalid(verify_batch(&rewrap(&t), &ctx)),
        InvalidReason::BadSignature
    );
    let mut t = bb.clone();
    t.sender_seq = 3;
    assert_eq!(
        invalid(verify_batch(&rewrap(&t), &ctx)),
        InvalidReason::BadSignature
    );
    // Wrong fragment, downgrade, and op-signature reuse as a batch signature.
    assert_eq!(
        invalid(verify_batch(&wire, &VerifyCtx::new(FRAG_B, &logs))),
        InvalidReason::WrongFragment
    );
    let ed_only = Batch::sign(&bb, &[&a.ed]).unwrap();
    assert_eq!(
        invalid(verify_batch(&ed_only, &ctx)),
        InvalidReason::MissingRequiredSignature
    );
    assert!(!verify(&wire, &ctx).is_valid(), "a batch is not an op");
    assert!(
        !verify_batch(&ops[0], &ctx).is_valid(),
        "an op is not a batch"
    );
    // A valid batch can carry an op that is not valid; it is reported per op.
    let mut bad_op = ops[1].clone();
    let n = bad_op.len();
    bad_op[n - 1] ^= 1;
    let mixed = BatchBody {
        ops: vec![ops[0].clone(), bad_op],
        ..bb.clone()
    };
    let vb = verify_batch(&Batch::sign(&mixed, &a.keys()).unwrap(), &ctx)
        .valid()
        .unwrap();
    assert!(vb.ops[0].is_valid());
    assert!(!vb.ops[1].is_valid());
}

// ----------------------------------------------------------------------- hlc

#[test]
fn hlc_bounded_drift() {
    let a = author(FRAG, false, 1);
    let bytes = signed(&a, FRAG, 1); // wall_ms = 1_800_000_000_001
    let t = 1_800_000_000_001u64;
    let drift = gsp_wire::op::DEFAULT_MAX_DRIFT_MS;
    let ctx = |now| VerifyCtx::new(FRAG, &a.log).at(now);
    assert!(verify(&bytes, &ctx(t)).is_valid());
    assert!(verify(&bytes, &ctx(t - drift)).is_valid());
    assert_eq!(
        unverifiable(verify(&bytes, &ctx(t - drift - 1))),
        UnverifiableReason::HlcTooFarAhead
    );
    assert!(
        verify(&bytes, &ctx(t + 10 * 365 * 86_400_000)).is_valid(),
        "old ops stay valid"
    );

    let h = Hlc {
        wall_ms: 100,
        counter: 4,
    };
    assert_eq!(
        h.tick(200),
        Hlc {
            wall_ms: 200,
            counter: 0
        }
    );
    assert_eq!(
        h.tick(100),
        Hlc {
            wall_ms: 100,
            counter: 5
        }
    );
    assert_eq!(
        h.tick(50),
        Hlc {
            wall_ms: 100,
            counter: 5
        },
        "never goes backwards"
    );
    assert_eq!(
        Hlc {
            wall_ms: 100,
            counter: u32::MAX
        }
        .tick(1),
        Hlc {
            wall_ms: 101,
            counter: 0
        }
    );
    let remote = Hlc {
        wall_ms: 150,
        counter: 9,
    };
    assert_eq!(
        h.observe(remote, 120, 60),
        Some(Hlc {
            wall_ms: 150,
            counter: 10
        })
    );
    assert_eq!(
        h.observe(remote, 500, 60),
        Some(Hlc {
            wall_ms: 500,
            counter: 0
        })
    );
    assert_eq!(
        h.observe(remote, 80, 60),
        None,
        "150 > 80 + 60: refuse to adopt"
    );
    assert!(h.observe(remote, 120, 60).unwrap() > remote.max(h));
}

#[test]
fn sealed_key_log_entry_is_kind_3() {
    let a = author(FRAG, false, 1);
    let genesis = a.log.entries()[0].clone();
    let key = FragmentKey::new([0x11; 32]);
    let sealed = SealedOp::seal(&key, FRAG, [0x24; 24], &Plain::KeyLog(genesis.clone())).unwrap();
    let wire = sealed.to_bytes().unwrap();
    let back = SealedOp::from_bytes(&wire).unwrap();
    let Plain::KeyLog(inner) = back.open(&key, FRAG).unwrap() else {
        panic!("kind")
    };
    assert_eq!(inner, genesis);
    assert_eq!(KeyLog::genesis(&inner).unwrap(), a.log);

    // The three kinds are distinct on the wire: same bytes, different kind,
    // different plaintext, and one never opens as another.
    let as_op = SealedOp::seal(&key, FRAG, [0x24; 24], &Plain::Op(genesis.clone())).unwrap();
    assert_ne!(as_op.ciphertext, sealed.ciphertext);
    assert_eq!(as_op.open(&key, FRAG).unwrap(), Plain::Op(genesis.clone()));

    // The relay-visible bytes do not contain the public key or the author id.
    let contains = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(&a.ed.public().bytes));
    assert!(!contains(&a.id().digest));

    // Wrong key, wrong fragment, tampering.
    assert_eq!(
        back.open(&FragmentKey::new([0x12; 32]), FRAG),
        Err(SealError::Decrypt)
    );
    assert_eq!(back.open(&key, FRAG_B), Err(SealError::WrongFragment));
    let mut t = back.clone();
    let last = t.ciphertext.len() - 1;
    t.ciphertext[last] ^= 1;
    assert_eq!(t.open(&key, FRAG), Err(SealError::Decrypt));
}

#[test]
fn sealed_plaintext_kinds_outside_1_to_3_are_rejected() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let key_bytes = [0x11u8; 32];
    let key = FragmentKey::new(key_bytes);
    let aad = Value::Array(vec![
        Value::Text("gsp/v0/sealed".into()),
        Value::uint(0),
        Value::uint(1),
        Value::Bytes(FRAG.to_vec()),
    ])
    .encode()
    .unwrap();
    for kind in [0u64, 4, 255] {
        let pt = Value::Array(vec![Value::uint(kind), Value::Bytes(vec![1, 2, 3])])
            .encode()
            .unwrap();
        let cipher = chacha20poly1305::XChaCha20Poly1305::new((&key_bytes).into());
        let ciphertext = cipher
            .encrypt(
                &chacha20poly1305::XNonce::from([9u8; 24]),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        let sealed = SealedOp {
            aead_alg: 1,
            fragment_id: FRAG.to_vec(),
            nonce: vec![9; 24],
            ciphertext,
        };
        assert_eq!(
            sealed.open(&key, FRAG),
            Err(SealError::Malformed(DecodeError::UnsupportedKind(kind)))
        );
    }
}

// ------------------------------------------------- decoder cost on hostile input

/// CBOR head for `major` with a 32-bit length.
fn head32(major: u8, n: u32) -> Vec<u8> {
    let mut v = vec![(major << 5) | 26];
    v.extend_from_slice(&n.to_be_bytes());
    v
}

#[test]
fn map_key_order_is_enforced_at_the_first_offending_key() {
    // 1 MiB that claims to be one big map. The first two keys are equal;
    // everything after them is not even CBOR. A decoder that builds the map
    // before checking keys would report `Cbor` (or run out of memory on a
    // well-formed tail); one that checks as it goes reports the key.
    const N: u32 = 300_000;
    let mut dup = head32(5, N);
    dup.extend_from_slice(&[0x61, b'a', 0x00, 0x61, b'a', 0x00]);
    dup.resize(1 << 20, 0xff);
    assert_eq!(Value::decode(&dup), Err(DecodeError::DuplicateKey));

    let mut unsorted = head32(5, N);
    unsorted.extend_from_slice(&[0x61, b'b', 0x00, 0x61, b'a', 0x00]);
    unsorted.resize(1 << 20, 0xff);
    assert_eq!(Value::decode(&unsorted), Err(DecodeError::NonCanonical));

    // Length-first order: "b" sorts before "aa".
    let mut by_len = head32(5, N);
    by_len.extend_from_slice(&[0x62, b'a', b'a', 0x00, 0x61, b'b', 0x00]);
    by_len.resize(1 << 20, 0xff);
    assert_eq!(Value::decode(&by_len), Err(DecodeError::NonCanonical));

    // The same inside a frame, nested, and a well-formed megabyte of
    // duplicate keys: all fail on the second key, in no time.
    let mut all_dup = head32(5, 349_524);
    while all_dup.len() + 3 <= 1 << 20 {
        all_dup.extend_from_slice(&[0x61, b'k', 0x00]);
    }
    let started = std::time::Instant::now();
    for _ in 0..200 {
        assert_eq!(Value::decode(&all_dup), Err(DecodeError::DuplicateKey));
        assert!(Message::from_bytes(&all_dup).is_err());
    }
    // 400 megabyte-sized hostile inputs. Building each map first costs
    // seconds and tens of MiB apiece; failing at the second key costs
    // microseconds. The bound is loose enough for any machine.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));

    // Sorted keys still decode, and shortest-first order is the accepted one.
    let ok = Value::Map(vec![
        ("b".into(), Value::uint(1)),
        ("aa".into(), Value::uint(2)),
        ("a".into(), Value::uint(3)),
    ])
    .encode()
    .unwrap();
    assert!(Value::decode(&ok).is_ok());
}

#[test]
fn item_limit_stops_a_frame_of_tiny_items_early() {
    // 1 MiB array of one-byte integers: valid CBOR, and as a `Value` about
    // thirty times its size. A frame may hold at most MAX_FRAME_ITEMS items,
    // so the decoder refuses on reading the array head, before allocating.
    let n = (1u32 << 20) - 5;
    let mut big = head32(4, n);
    big.resize(1 << 20, 0x00);
    assert_eq!(
        Value::decode_limited(&big, gsp_wire::message::MAX_FRAME_ITEMS),
        Err(DecodeError::Shape("too many items"))
    );
    assert_eq!(
        Message::from_bytes(&big),
        Err(DecodeError::Shape("too many items"))
    );
    // Nested arrays that each stay under the limit but add up beyond it:
    // refused when the budget runs out, and the garbage after that point is
    // never looked at.
    let mut nested = vec![0x82];
    for _ in 0..2 {
        nested.extend(head32(4, 40_000));
        nested.resize(nested.len() + 40_000, 0x00);
    }
    let cut = nested.len() - 10_000;
    nested.truncate(cut);
    nested.resize(1 << 20, 0xff);
    assert_eq!(
        Value::decode_limited(&nested, gsp_wire::message::MAX_FRAME_ITEMS),
        Err(DecodeError::Shape("too many items"))
    );
    // An array that claims more elements than there are bytes left is
    // refused before anything is reserved for it.
    let mut liar = head32(4, u32::MAX);
    liar.extend_from_slice(&[0; 16]);
    assert_eq!(Value::decode(&liar), Err(DecodeError::Cbor));
    let mut liar = vec![0x9b];
    liar.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(Value::decode(&liar), Err(DecodeError::Cbor));
    let mut liar = vec![0xbb];
    liar.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(Value::decode(&liar), Err(DecodeError::Cbor));

    // The limit counts every item and is exact.
    let v = Value::Array(vec![Value::uint(1), Value::Array(vec![Value::Null])]);
    let enc = v.encode().unwrap();
    assert_eq!(Value::decode_limited(&enc, 4), Ok(v));
    assert_eq!(
        Value::decode_limited(&enc, 3),
        Err(DecodeError::Shape("too many items"))
    );
    // Real frames are far below it: a full default batch.
    let sealed = SealedOp {
        aead_alg: 1,
        fragment_id: FRAG.to_vec(),
        nonce: vec![0; 24],
        ciphertext: vec![0; 64],
    };
    let batch = Message::Batch {
        fragment_id: FRAG.to_vec(),
        next: 256,
        more: false,
        sealed: vec![sealed; 256],
    };
    assert_eq!(Message::from_bytes(&batch.to_bytes().unwrap()), Ok(batch));
}
