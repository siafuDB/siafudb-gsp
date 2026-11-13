//! What a replica does with items it should not trust: tampering, wrong
//! keys, other fragments, forged signatures, equivocation, replays, oversized
//! payloads, ops ahead of their key log, dependencies that never arrive,
//! clocks far ahead, full pending storage, and plain garbage.
mod common;
use common::*;
use gsp_sync::*;
use gsp_wire::{
    Hlc, InvalidReason, KeyLogAction, KeyLogEntry, Multihash, Op, Plain, SealedOp, Signature,
    Signed, Value, VerifyCtx,
};
use proptest::prelude::*;

const OTHER_ROOT: [u8; 32] = [0x5A; 32];

/// A device that knows the forged author `f`.
fn dev_knowing(f: &mut Forge) -> Dev {
    let mut d = Dev::new(1);
    d.drain();
    assert_eq!(
        d.ingest(&f.sealed_genesis(), 0, T0).status,
        IngestStatus::KeyLog
    );
    d
}

fn rejected(out: &IngestOutcome) -> &Reject {
    match &out.status {
        IngestStatus::Rejected(r) => {
            assert!(out.effects.is_empty() && out.applied == 0);
            r
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn fake_id(n: u8) -> Multihash {
    Multihash {
        alg: 1,
        digest: vec![n; 32],
    }
}

// ------------------------------------------------------------ the sealed layer

#[test]
fn tampered_ciphertext_is_rejected_at_every_byte() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let op = f.op(1, None, T0, &[node(1, &["L"], &[("k", int(1))])]);
    let sealed = f.sealed_op(&op);
    let before = d.r.to_bytes().unwrap();
    for i in 0..sealed.len() {
        for bit in [0x01u8, 0x80] {
            let mut t = sealed.clone();
            t[i] ^= bit;
            let out = d.ingest(&t, 0, T0);
            assert!(
                matches!(
                    rejected(&out),
                    Reject::Decrypt
                        | Reject::Malformed(_)
                        | Reject::WrongFragment
                        | Reject::Unsupported
                ),
                "byte {i}: {:?}",
                out.status
            );
        }
    }
    assert!(d.r.nodes().is_empty());
    let st = d.r.stats();
    assert_eq!((st.applied, st.pending), (0, 0));
    assert_eq!(
        st.undecryptable + st.invalid + st.unsupported,
        2 * sealed.len() as u64
    );
    // Truncations and extensions too.
    for cut in [0, 1, sealed.len() / 2, sealed.len() - 1] {
        rejected(&d.ingest(&sealed[..cut], 0, T0));
    }
    let mut longer = sealed.clone();
    longer.push(0);
    rejected(&d.ingest(&longer, 0, T0));
    // The untouched item still works, and only it changed anything.
    assert_ne!(*d.r.to_bytes().unwrap(), *before);
    assert_eq!(d.ingest(&sealed, 0, T0).status, IngestStatus::Applied);
    assert_eq!(d.r.nodes().len(), 1);
}

#[test]
fn an_item_sealed_under_another_key_is_rejected() {
    // Right fragment id in the header, wrong key: someone who learned the
    // public fragment id but not the root secret.
    let pairing = Pairing::from_root(ROOT);
    let wrong_key = Pairing::from_root(OTHER_ROOT).fragment_key();
    let id = pairing.fragment_id().to_vec();
    let mut f = Forge::for_fragment(wrong_key, id.clone(), id, 9);
    let mut d = Dev::new(1);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_genesis(), 0, T0)),
        &Reject::Decrypt
    );
    let op = f.op(1, None, T0, &[node(1, &[], &[])]);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&op), 0, T0)),
        &Reject::Decrypt
    );
    assert_eq!(d.r.stats().undecryptable, 2);
    assert_eq!(d.r.stats().authors, 1);
    assert!(d.r.nodes().is_empty());
}

#[test]
fn items_for_another_fragment_are_rejected_at_every_layer() {
    let mut d = Dev::new(1);
    let ours = Pairing::from_root(ROOT);
    let theirs = Pairing::from_root(OTHER_ROOT);

    // 1. A perfectly valid item of another fragment.
    let mut other = Forge::new(OTHER_ROOT, 9);
    assert_eq!(
        rejected(&d.ingest(&other.sealed_genesis(), 0, T0)),
        &Reject::WrongFragment
    );
    let op = other.op(1, None, T0, &[node(1, &[], &[])]);
    assert_eq!(
        rejected(&d.ingest(&other.sealed_op(&op), 0, T0)),
        &Reject::WrongFragment
    );

    // 2. The other fragment's item with our fragment id pasted into the
    // header: the header is authenticated, so it does not decrypt.
    let mut relabelled = SealedOp::from_bytes(&other.sealed_op(&op)).unwrap();
    relabelled.fragment_id = ours.fragment_id().to_vec();
    assert_eq!(
        rejected(&d.ingest(&relabelled.to_bytes().unwrap(), 0, T0)),
        &Reject::Decrypt
    );

    // 3. Sealed correctly for us by a holder of our key, but the key log
    // inside is bound to the other fragment.
    let mut cross = Forge::for_fragment(
        ours.fragment_key(),
        ours.fragment_id().to_vec(),
        theirs.fragment_id().to_vec(),
        9,
    );
    assert_eq!(
        rejected(&d.ingest(&cross.sealed_genesis(), 0, T0)),
        &Reject::WrongFragment
    );
    assert_eq!(d.r.stats().authors, 1);

    // 4. Sealed for us, author known to us, but the op inside is signed for
    // the other fragment.
    let mut f = Forge::new(ROOT, 8);
    d.ingest(&f.sealed_genesis(), 0, T0);
    let mut body = f.body(
        1,
        None,
        T0,
        vec![],
        encode_payload(&[node(1, &[], &[])]).unwrap(),
    );
    body.fragment_id = theirs.fragment_id().to_vec();
    let foreign = f.sign(&body);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&foreign), 0, T0)),
        &Reject::WrongFragment
    );
    assert!(d.r.nodes().is_empty());
    assert_eq!(d.r.stats().applied, 0);
}

#[test]
fn unsupported_kinds_are_dropped_and_counted() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    // A batch (kind 2).
    let batch = f.seal(&Plain::Batch(vec![1, 2, 3]));
    assert_eq!(rejected(&d.ingest(&batch, 0, T0)), &Reject::Unsupported);
    // A key-log entry that is not a genesis (v0 has no rotation).
    let add = KeyLogEntry {
        hash_alg: 1,
        prev: Some(f.log.head().clone()),
        action: KeyLogAction::SetPolicy {
            policy: vec![1],
            from_seq: 1,
        },
    }
    .sign(&[&f.signer])
    .unwrap();
    assert_eq!(
        rejected(&d.ingest(&f.seal(&Plain::KeyLog(add)), 0, T0)),
        &Reject::Unsupported
    );
    // A key log that is not even CBOR.
    assert!(matches!(
        rejected(&d.ingest(&f.seal(&Plain::KeyLog(vec![0xff; 40])), 0, T0)),
        Reject::KeyLog(_)
    ));
    // An op that is not CBOR.
    assert!(matches!(
        rejected(&d.ingest(&f.seal(&Plain::Op(vec![0xff; 40])), 0, T0)),
        Reject::Op(InvalidReason::Malformed(_))
    ));
    let st = d.r.stats();
    assert_eq!((st.unsupported, st.invalid), (2, 2));
}

// ------------------------------------------------------------ signatures

#[test]
fn forged_signatures_are_rejected() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let good = f.op(1, None, T0, &[node(1, &[], &[("k", int(1))])]);

    // 1. A signature with one bit flipped.
    let mut bad = good.clone();
    bad.signed_mut().sigs[0].bytes[5] ^= 1;
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&bad), 0, T0)),
        &Reject::Op(InvalidReason::BadSignature)
    );

    // 2. The author's signature moved onto a different body.
    let other_body = f.body(
        1,
        None,
        T0,
        vec![],
        encode_payload(&[node(1, &[], &[("k", int(666))])]).unwrap(),
    );
    let moved = Signed {
        body: other_body.to_bytes().unwrap(),
        sigs: good.sigs().to_vec(),
    }
    .to_bytes()
    .unwrap();
    assert_eq!(
        rejected(&d.ingest(&f.seal(&Plain::Op(moved)), 0, T0)),
        &Reject::Op(InvalidReason::BadSignature)
    );

    // 3. No signature at all.
    let naked = Signed {
        body: good.body_bytes().to_vec(),
        sigs: vec![],
    }
    .to_bytes()
    .unwrap();
    assert_eq!(
        rejected(&d.ingest(&f.seal(&Plain::Op(naked)), 0, T0)),
        &Reject::Op(InvalidReason::NoSignatures)
    );

    // 4. Another device of the fragment signs an op in this author's name:
    // the key is not in the author's log. That is unverifiable, not invalid
    // (a newer key log could explain it), so the bytes are kept; it is never
    // applied.
    let mut imposter = Forge::new(ROOT, 77);
    let mut body = imposter.body(
        1,
        None,
        T0,
        vec![],
        encode_payload(&[node(1, &[], &[("k", int(666))])]).unwrap(),
    );
    body.author = f.author();
    let forged = imposter.sign(&body);
    let out = d.ingest(&imposter.sealed_op(&forged), 0, T0);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::Unverifiable)
    );
    assert!(out.effects.is_empty());

    // 5. A key-log genesis whose proof of possession is broken.
    let mut g = Signed::from_bytes(&imposter.genesis).unwrap();
    g.sigs[0].bytes[0] ^= 1;
    let out = d.ingest(&imposter.seal(&Plain::KeyLog(g.to_bytes().unwrap())), 0, T0);
    assert!(matches!(rejected(&out), Reject::KeyLog(_)));

    assert!(d.r.nodes().is_empty());
    assert_eq!(d.r.stats().applied, 0);
    assert_eq!(d.r.stats().pending, 1, "only the unverifiable copy is held");
    assert_eq!(d.r.stats().authors, 2);
    // The real op is unaffected by the attempts, and once the position is
    // settled the unverifiable rival is let go.
    assert_eq!(
        d.ingest(&f.sealed_op(&good), 0, T0).status,
        IngestStatus::Applied
    );
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(1))]));
    assert_eq!(d.r.stats().pending, 0);
    assert_eq!(d.r.stats().applied, 1);
}

#[test]
fn a_copy_with_a_junk_signature_does_not_shadow_the_real_op() {
    // Signatures are outside the op id. Before the key log is known nothing
    // can be checked, so a spoiled copy and the real one are both held.
    let mut f = Forge::new(ROOT, 9);
    let mut d = Dev::new(1);
    let good = f.op(1, None, T0, &[node(1, &[], &[("k", int(1))])]);
    let mut spoiled = good.clone();
    let mut junk: Signature = good.sigs()[0].clone();
    junk.key_id = fake_id(0xee);
    spoiled.signed_mut().sigs.push(junk);
    assert_eq!(spoiled.id(), good.id());

    let out = d.ingest(&f.sealed_op(&spoiled), 0, T0);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::UnknownAuthor)
    );
    let out = d.ingest(&f.sealed_op(&good), 0, T0);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::UnknownAuthor)
    );
    assert_eq!(d.r.stats().pending, 2);

    let out = d.ingest(&f.sealed_genesis(), 0, T0);
    assert_eq!(out.status, IngestStatus::KeyLog);
    assert_eq!(out.applied, 1);
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(1))]));
    assert_eq!(d.r.stats().pending, 0);
}

/// Compare with the stored fixture; `GSP_WRITE_FIXTURES=1` rewrites it.
#[cfg(feature = "ml-dsa")]
fn fixture(name: &str, bytes: &[u8]) {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("GSP_WRITE_FIXTURES").is_some() {
        std::fs::write(&path, bytes).expect("write fixture");
    }
    assert_eq!(
        std::fs::read(&path).expect("fixture"),
        bytes,
        "{name} is stale: run with GSP_WRITE_FIXTURES=1"
    );
}

#[cfg(feature = "ml-dsa")]
#[test]
fn a_hybrid_author_is_accepted_and_a_downgraded_op_is_not() {
    // Another device may choose Ed25519 + ML-DSA-65 at genesis. Its ops need
    // both signatures; stripping the post-quantum one must not get through.
    use gsp_wire::{KeyLog, SigningKey};
    let pairing = Pairing::from_root(ROOT);
    let frag = pairing.fragment_id().to_vec();
    let ed = SigningKey::ed25519(&[21; 32]);
    let pq = SigningKey::ml_dsa_65(&[22; 32]);
    let genesis = KeyLogEntry {
        hash_alg: 1,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: frag.clone(),
            keys: vec![ed.public(), pq.public()],
            policy: vec![1, 2],
        },
    }
    .sign(&[&ed, &pq])
    .unwrap();
    let log = KeyLog::genesis(&genesis).unwrap();
    // Kept as files for the test below, which also runs in builds that
    // cannot make them.
    fixture("hybrid_genesis.bin", &genesis);
    let mut sealer = Forge::new(ROOT, 9);
    let mut d = Dev::new(1);
    assert_eq!(
        d.ingest(&sealer.seal(&Plain::KeyLog(genesis)), 0, T0)
            .status,
        IngestStatus::KeyLog
    );
    let body = gsp_wire::OpBody {
        hash_alg: 1,
        fragment_id: frag,
        author: log.author().clone(),
        seq: 1,
        prev: None,
        hlc: Hlc {
            wall_ms: T0,
            counter: 0,
        },
        deps: vec![],
        payload: encode_payload(&[node(1, &[], &[("k", int(1))])]).unwrap(),
    };
    let full = Op::sign(&body, &[&ed, &pq]).unwrap();
    assert_eq!(full.sigs().len(), 2);
    fixture("hybrid_op.bin", &full.to_bytes().unwrap());
    let ed_only = Op::sign(&body, &[&ed]).unwrap();
    assert_eq!(ed_only.id(), full.id());
    assert_eq!(
        rejected(&d.ingest(&sealer.sealed_op(&ed_only), 0, T0)),
        &Reject::Op(InvalidReason::MissingRequiredSignature)
    );
    assert!(d.r.nodes().is_empty());
    assert_eq!(
        d.ingest(&sealer.sealed_op(&full), 0, T0).status,
        IngestStatus::Applied
    );
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(1))]));
    // The state with a hybrid key log in it round-trips.
    d.restore();
}

/// A hybrid author's key log and first op, as made by a build with ML-DSA.
/// With the `ml-dsa` feature the replica accepts both. Without it ML-DSA-65
/// is an algorithm the build does not implement: the key log cannot be
/// checked, so it is not accepted (and not called invalid), and the author's
/// ops are held like those of any author whose key log is missing. Nothing
/// else is affected.
#[test]
fn a_hybrid_author_with_and_without_the_ml_dsa_feature() {
    let genesis: &[u8] = include_bytes!("fixtures/hybrid_genesis.bin");
    let op: &[u8] = include_bytes!("fixtures/hybrid_op.bin");
    let mut sealer = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut sealer);
    let out_genesis = d.ingest(&sealer.seal(&Plain::KeyLog(genesis.to_vec())), 1, T0);
    let out_op = d.ingest(&sealer.seal(&Plain::Op(op.to_vec())), 2, T0);
    assert_eq!(d.r.cursor(), 2);
    if cfg!(feature = "ml-dsa") {
        assert_eq!(out_genesis.status, IngestStatus::KeyLog);
        assert_eq!(out_op.status, IngestStatus::Applied);
        assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(1))]));
    } else {
        assert_eq!(rejected(&out_genesis), &Reject::Unsupported);
        assert_eq!(
            out_op.status,
            IngestStatus::Pending(PendingReason::UnknownAuthor)
        );
        let st = d.r.stats();
        assert_eq!((st.unsupported, st.invalid, st.pending), (1, 0, 1));
        assert_eq!(st.authors, 2);
        assert!(d.r.nodes().is_empty());
        // Held across a restore, for a build that can read it.
        d.restore();
        assert!(d.poll(T0 + 1).is_empty());
        assert_eq!(d.r.stats().pending, 1);
    }
    // Ed25519 authors, local commits and state work either way.
    let mine = sealer.op(1, None, T0, &[node(2, &[], &[])]);
    assert_eq!(
        d.ingest(&sealer.sealed_op(&mine), 3, T0).status,
        IngestStatus::Applied
    );
    d.commit(&[node(3, &[], &[])], T0 + 1);
    d.restore();
    assert!(d.r.node(&gid(2)).is_some() && d.r.node(&gid(3)).is_some());
}

// ------------------------------------------------------------ chains

#[test]
fn equivocation_first_seen_stays_and_the_proof_is_kept() {
    let mut f = Forge::new(ROOT, 9);
    let op_a = f.op(1, None, T0, &[node(1, &[], &[("k", text("a"))])]);
    let op_b = f.op(1, None, T0 + 1, &[node(1, &[], &[("k", text("b"))])]);
    assert_ne!(op_a.id(), op_b.id());
    let (sa, sb) = (f.sealed_op(&op_a), f.sealed_op(&op_b));

    for (first, second, kept, lost, value) in
        [(&sa, &sb, &op_a, &op_b, "a"), (&sb, &sa, &op_b, &op_a, "b")]
    {
        let mut d = dev_knowing(&mut f);
        assert_eq!(d.ingest(first, 0, T0).status, IngestStatus::Applied);
        let out = d.ingest(second, 0, T0);
        assert_eq!(rejected(&out), &Reject::Equivocation);
        assert_eq!(
            d.r.node(&gid(1)).unwrap().props,
            props(&[("k", text(value))])
        );
        let st = d.r.stats();
        assert_eq!((st.applied, st.equivocations, st.pending), (1, 1, 0));

        let ev = &d.r.equivocations()[0];
        assert_eq!(ev.author, f.author());
        assert_eq!(ev.seq, 1);
        assert_eq!(&ev.kept, kept.id());
        assert_eq!(ev.rejected, lost.to_bytes().unwrap());
        // Self-contained and checkable by anyone with the author's key log.
        let proof = ev.proof.as_ref().expect("conflict at the author's head");
        let frag = d.r.fragment_id().to_vec();
        assert!(proof.verify(&VerifyCtx::new(&frag, &f.log)));
        assert!(proof.to_bytes().is_ok());

        // Seeing it again adds no second record; the record survives a
        // restore.
        rejected(&d.ingest(second, 0, T0));
        assert_eq!(d.r.equivocations().len(), 1);
        d.restore();
        assert_eq!(d.r.equivocations().len(), 1);
        assert!(d.r.equivocations()[0].proof.is_some());
    }
}

#[test]
fn equivocation_below_the_head_is_rejected_with_the_kept_id() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let op1 = f.op(1, None, T0, &[node(1, &[], &[("k", int(1))])]);
    let op2 = f.op(2, Some(&op1), T0 + 1, &[node(1, &[], &[("k", int(2))])]);
    let op3 = f.op(3, Some(&op2), T0 + 2, &[node(1, &[], &[("k", int(3))])]);
    for op in [&op1, &op2, &op3] {
        assert_eq!(
            d.ingest(&f.sealed_op(op), 0, T0).status,
            IngestStatus::Applied
        );
    }
    // A second op at seq 2, properly chained to op1 and properly signed.
    let fork = f.op(2, Some(&op1), T0 + 5, &[node_del(1)]);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&fork), 0, T0)),
        &Reject::Equivocation
    );
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(3))]));
    let ev = &d.r.equivocations()[0];
    assert_eq!((ev.seq, &ev.kept), (2, op2.id()));
    assert_eq!(ev.rejected, fork.to_bytes().unwrap());
    assert!(ev.proof.is_none(), "older op bytes are not retained");
    // And whatever builds on the fork never applies.
    let fork3 = f.op(3, Some(&fork), T0 + 6, &[node(2, &[], &[])]);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&fork3), 0, T0)),
        &Reject::Equivocation
    );
    let fork4 = f.op(4, Some(&fork3), T0 + 7, &[node(2, &[], &[])]);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&fork4), 0, T0)),
        &Reject::ChainFork
    );
    assert_eq!(d.r.stats().pending, 0);
    assert!(d.r.node(&gid(2)).is_none());
}

#[test]
fn two_pending_ops_at_one_seq_first_seen_is_applied() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = Dev::new(1);
    let op_a = f.op(1, None, T0, &[node(1, &[], &[("k", text("a"))])]);
    let op_b = f.op(1, None, T0, &[node(1, &[], &[("k", text("b"))])]);
    d.ingest(&f.sealed_op(&op_b), 0, T0);
    d.ingest(&f.sealed_op(&op_a), 0, T0);
    assert_eq!(d.r.stats().pending, 2);
    let out = d.ingest(&f.sealed_genesis(), 0, T0);
    assert_eq!(out.applied, 1);
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", text("b"))]));
    let st = d.r.stats();
    assert_eq!((st.pending, st.equivocations), (0, 1));
    assert!(d.r.equivocations()[0].proof.is_some());
}

#[test]
fn chain_rules_wrong_prev_and_clock_going_backwards() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let op1 = f.op(1, None, T0 + 10, &[node(1, &[], &[])]);
    d.ingest(&f.sealed_op(&op1), 0, T0);

    // seq 2 naming something else as prev: the author's seq 1 is applied and
    // this does not build on it.
    let mut body = f.body(
        2,
        Some(&op1),
        T0 + 11,
        vec![],
        encode_payload(&[node(2, &[], &[])]).unwrap(),
    );
    body.prev = Some(fake_id(3));
    let wrong_prev = f.sign(&body);
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&wrong_prev), 0, T0)),
        &Reject::ChainFork
    );
    // seq 4 with an unknown prev cannot be told from an op that is early.
    let mut body = f.body(
        4,
        Some(&op1),
        T0 + 13,
        vec![],
        encode_payload(&[node(2, &[], &[])]).unwrap(),
    );
    body.prev = Some(fake_id(4));
    assert_eq!(
        d.ingest(&f.sealed_op(&f.sign(&body)), 0, T0).status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    // seq 3 whose prev is not what will be the author's seq 2: it waits for
    // its position like any early op, and is found out when seq 2 applies.
    let mut body = f.body(
        3,
        Some(&op1),
        T0 + 12,
        vec![],
        encode_payload(&[node(2, &[], &[])]).unwrap(),
    );
    body.prev = Some(op1.id().clone());
    assert_eq!(
        d.ingest(&f.sealed_op(&f.sign(&body)), 0, T0).status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    // seq 2 with an HLC equal to, and lower than, seq 1's.
    for wall in [T0 + 10, T0 + 9] {
        let back = f.op(2, Some(&op1), wall, &[node(2, &[], &[])]);
        assert_eq!(
            rejected(&d.ingest(&f.sealed_op(&back), 0, T0)),
            &Reject::HlcNotMonotonic
        );
    }
    assert!(d.r.node(&gid(2)).is_none());
    // A correct seq 2 still applies. The op with the bogus prev was at
    // "seq 2" as well, but it never applied, so this is no equivocation.
    let invalid = d.r.stats().invalid;
    let op2 = f.op(2, Some(&op1), T0 + 11, &[node(2, &[], &[])]);
    let out = d.ingest(&f.sealed_op(&op2), 0, T0);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 1));
    let st = d.r.stats();
    assert_eq!(st.equivocations, 0);
    // The waiting "seq 3" turned out not to continue the chain and is gone;
    // the "seq 4" still waits for a seq 3.
    assert_eq!((st.invalid, st.pending), (invalid + 1, 1));
}

#[test]
fn an_authors_ops_in_reverse_order_wait_and_then_apply_in_order() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let mut ops: Vec<Op> = Vec::new();
    for i in 0..6u64 {
        let op = f.op(
            i + 1,
            ops.last(),
            T0 + i,
            &[node(1, &[], &[("k", int(i as i64))])],
        );
        ops.push(op);
    }
    for op in ops.iter().skip(1).rev() {
        let out = d.ingest(&f.sealed_op(op), 0, T0 + 10);
        assert_eq!(
            out.status,
            IngestStatus::Pending(PendingReason::MissingPrev)
        );
        assert!(out.effects.is_empty());
    }
    assert_eq!(d.r.stats().pending, 5);
    let out = d.ingest(&f.sealed_op(&ops[0]), 0, T0 + 10);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 6));
    assert_eq!(d.r.node(&gid(1)).unwrap().props, props(&[("k", int(5))]));
    assert_eq!(d.r.stats().pending, 0);
}

// ------------------------------------------------------------ replay

#[test]
fn replayed_items_change_nothing() {
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    a.commit(
        &[node(1, &["L"], &[("k", int(1))]), node(2, &[], &[])],
        T0 + 1,
    );
    a.commit(&[edge(9, 1, 2, "T", &[])], T0 + 2);
    a.commit(&[node_del(2)], T0 + 3);
    let items = a.drain();
    for it in &items {
        b.ingest(it, 0, T0 + 4);
    }
    let state = b.r.to_bytes().unwrap();
    let dups = b.r.stats().duplicates;
    let mut rng = Rng(7);
    let mut again: Vec<&Vec<u8>> = items.iter().chain(&items).chain(&items).collect();
    rng.shuffle(&mut again);
    for it in &again {
        let out = b.ingest(it, 0, T0 + 5);
        assert_eq!(out.status, IngestStatus::Duplicate);
        assert!(out.effects.is_empty());
    }
    assert_eq!(b.r.stats().duplicates, dups + again.len() as u64);
    // Apart from the duplicate counter the state is byte-identical.
    let mut fresh = Dev::new(2);
    for it in &items {
        fresh.ingest(it, 0, T0 + 4);
    }
    assert_eq!(*fresh.r.to_bytes().unwrap(), *state);
    assert_eq!(b.r.nodes(), fresh.r.nodes());
    assert_eq!(b.r.stats().applied, 3);
}

// ------------------------------------------------------------ payload

#[test]
fn oversized_and_invalid_payloads_are_rejected() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let big = |n: usize| {
        Value::Array(vec![Value::Array(vec![
            int(1),
            Value::Bytes(vec![1; 16]),
            Value::Array(vec![]),
            Value::Array(vec![]),
            Value::Map(vec![("k".into(), Value::Bytes(vec![7; n]))]),
            Value::Array(vec![]),
        ])])
    };
    // One byte over 64 KiB, validly signed and sealed.
    let over = f.sign(&f.body(1, None, T0, vec![], big(MAX_PAYLOAD_BYTES - 28)));
    assert_eq!(
        rejected(&d.ingest(&f.sealed_op(&over), 0, T0)),
        &Reject::Payload(PayloadError::TooLarge)
    );
    // Exactly 64 KiB is fine.
    let fits = f.sign(&f.body(1, None, T0, vec![], big(MAX_PAYLOAD_BYTES - 29)));
    assert_eq!(
        d.ingest(&f.sealed_op(&fits), 0, T0).status,
        IngestStatus::Applied
    );

    // A sealed item beyond the item limit is not even opened.
    let huge = f.sign(&f.body(2, Some(&fits), T0 + 1, vec![], big(MAX_SEALED_BYTES)));
    let sealed = f.sealed_op(&huge);
    assert!(sealed.len() > MAX_SEALED_BYTES);
    assert_eq!(rejected(&d.ingest(&sealed, 0, T0)), &Reject::TooLarge);

    // Other payload rules, each in a validly signed op.
    let bad_payloads = [
        Value::Null,
        Value::Array(vec![]),
        Value::Array(vec![Value::Array(vec![int(9), Value::Bytes(vec![1; 16])])]),
        Value::Array(vec![Value::Array(vec![int(2), Value::Bytes(vec![1; 15])])]),
        Value::Map(vec![("op".into(), text("set_property"))]),
    ];
    for (i, p) in bad_payloads.into_iter().enumerate() {
        let op = f.sign(&f.body(2, Some(&fits), T0 + 1 + i as u64, vec![], p));
        assert!(matches!(
            rejected(&d.ingest(&f.sealed_op(&op), 0, T0)),
            Reject::Payload(_)
        ));
    }
    assert_eq!(d.r.stats().applied, 1);
    assert_eq!(d.r.stats().invalid, 6);

    // Local commits obey the same rules and leave no trace when refused.
    let state = d.r.to_bytes().unwrap();
    let too_big = [node(
        5,
        &[],
        &[("k", Value::Bytes(vec![0; MAX_PAYLOAD_BYTES]))],
    )];
    assert_eq!(
        d.try_commit(&too_big, T0 + 50).unwrap_err(),
        Error::Payload(PayloadError::TooLarge)
    );
    assert_eq!(
        d.try_commit(&[], T0 + 50).unwrap_err(),
        Error::Payload(PayloadError::Empty)
    );
    assert_eq!(*d.r.to_bytes().unwrap(), *state);
    assert_eq!(d.r.outbox_len(), 0);
}

#[test]
fn an_invalid_op_ends_its_authors_chain_but_nobody_elses() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let op1 = f.sign(&f.body(1, None, T0, vec![], Value::Null));
    assert!(matches!(
        rejected(&d.ingest(&f.sealed_op(&op1), 0, T0)),
        Reject::Payload(_)
    ));
    let op2 = f.op(2, Some(&op1), T0 + 1, &[node(1, &[], &[])]);
    assert_eq!(
        d.ingest(&f.sealed_op(&op2), 0, T0).status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    let mut g = Forge::new(ROOT, 10);
    d.ingest(&g.sealed_genesis(), 0, T0);
    let ok = g.op(1, None, T0, &[node(2, &[], &[])]);
    assert_eq!(
        d.ingest(&g.sealed_op(&ok), 0, T0).status,
        IngestStatus::Applied
    );
    assert!(d.r.node(&gid(1)).is_none() && d.r.node(&gid(2)).is_some());
}

// ------------------------------------------------------------ pending

#[test]
fn an_op_before_its_key_log_waits_for_it() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = Dev::new(1);
    let op1 = f.op(1, None, T0, &[node(1, &["L"], &[])]);
    let op2 = f.op(
        2,
        Some(&op1),
        T0 + 1,
        &[node(2, &[], &[]), edge(9, 1, 2, "T", &[])],
    );
    // Reverse order, key log last.
    let out = d.ingest(&f.sealed_op(&op2), 3, T0 + 5);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::UnknownAuthor)
    );
    let out = d.ingest(&f.sealed_op(&op1), 4, T0 + 5);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::UnknownAuthor)
    );
    assert!(d.r.nodes().is_empty());
    assert_eq!(d.r.stats().pending, 2);
    assert_eq!(
        d.r.cursor(),
        4,
        "held items are kept, so the cursor moves on"
    );

    // Pending survives save and restore.
    d.restore();
    assert_eq!(d.r.stats().pending, 2);

    let out = d.ingest(&f.sealed_genesis(), 5, T0 + 5);
    assert_eq!((out.status, out.applied), (IngestStatus::KeyLog, 2));
    assert_eq!(
        out.effects,
        vec![
            node(1, &["L"], &[]),
            node(2, &[], &[]),
            edge(9, 1, 2, "T", &[])
        ]
    );
    assert_eq!(d.r.stats().pending, 0);
    assert_eq!(d.r.cursor(), 5);
}

#[test]
fn deps_are_advisory_and_never_hold_an_op_back() {
    // An op names a dep nobody will ever see. It applies all the same: merge
    // is a function of the set of ops, and what another author did or did
    // not do is no reason to withhold this one.
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let ghost = f.sign(&f.body(
        1,
        None,
        T0,
        vec![fake_id(0xdd), fake_id(0xde)],
        encode_payload(&[node(1, &[], &[])]).unwrap(),
    ));
    let out = d.ingest(&f.sealed_op(&ghost), 0, T0);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 1));
    assert!(d.r.node(&gid(1)).is_some());
    assert_eq!(d.r.stats().pending, 0);
    assert!(!d.r.needs_resync());
}

#[test]
fn an_op_applies_before_the_op_of_another_author_it_names() {
    // G's op was written after seeing F's op and names it in `deps`. A
    // replica that gets G's first applies it at once; when F's arrives the
    // stamps decide, and the result is the same as in the other order.
    let mut f = Forge::new(ROOT, 9);
    let mut g = Forge::new(ROOT, 10);
    let base = f.op(
        1,
        None,
        T0,
        &[node(1, &[], &[("k", int(1)), ("j", int(1))])],
    );
    let later = g.sign(&g.body(
        1,
        None,
        T0 + 1,
        vec![base.id().clone()],
        encode_payload(&[node(1, &[], &[("k", int(2))])]).unwrap(),
    ));
    let (sb, sl) = (f.sealed_op(&base), g.sealed_op(&later));
    let mut results = Vec::new();
    for order in [[&sl, &sb], [&sb, &sl]] {
        let mut d = dev_knowing(&mut f);
        d.ingest(&g.sealed_genesis(), 0, T0);
        for item in order {
            let out = d.ingest(item, 0, T0 + 2);
            assert_eq!((out.status, out.applied), (IngestStatus::Applied, 1));
        }
        assert_eq!(
            d.r.node(&gid(1)).unwrap().props,
            props(&[("k", int(2)), ("j", int(1))])
        );
        results.push(d.r.snapshot());
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn pending_is_bounded_per_author_and_never_holds_the_cursor() {
    let config = Config {
        max_pending_items_per_author: 3,
        ..Config::default()
    };
    let mut f = Forge::new(ROOT, 9);
    let mut g = Forge::new(ROOT, 10);
    let mut d = Dev::with(ROOT, 1, config);
    d.ingest(&f.sealed_genesis(), 1, T0);
    d.ingest(&g.sealed_genesis(), 2, T0);
    let chain = |f: &Forge, n: u64, base: u8| {
        let mut ops: Vec<Op> = Vec::new();
        for i in 0..n {
            let op = f.op(i + 1, ops.last(), T0 + i, &[node(base + i as u8, &[], &[])]);
            ops.push(op);
        }
        ops
    };
    let fo = chain(&f, 8, 10);
    let go = chain(&g, 8, 50);
    let fs: Vec<Vec<u8>> = fo.iter().map(|o| f.sealed_op(o)).collect();
    let gs: Vec<Vec<u8>> = go.iter().map(|o| g.sealed_op(o)).collect();

    // The relay lost F's first op (or delivers it last): F's ops 2..8 arrive
    // with nothing to stand on. Three are kept, the lowest three.
    let mut seq = 2;
    let mut statuses = Vec::new();
    for item in &fs[1..] {
        seq += 1;
        statuses.push(d.ingest(item, seq, T0 + 100).status);
        assert_eq!(d.r.cursor(), seq, "the cursor moves past every item");
    }
    assert_eq!(
        statuses[..3],
        [
            IngestStatus::Pending(PendingReason::MissingPrev),
            IngestStatus::Pending(PendingReason::MissingPrev),
            IngestStatus::Pending(PendingReason::MissingPrev)
        ]
    );
    assert!(
        statuses[3..]
            .iter()
            .all(|s| *s == IngestStatus::PendingFull)
    );
    let st = d.r.stats();
    assert_eq!((st.pending, st.refused), (3, 4));
    assert!(st.needs_resync && d.r.needs_resync());
    let status_of = |d: &Dev, who: &Forge| {
        d.r.authors()
            .into_iter()
            .find(|a| a.author == who.author())
            .unwrap()
    };
    let fa = status_of(&d, &f);
    assert_eq!(
        (fa.applied_seq, fa.pending, fa.gap, fa.own),
        (0, 3, true, false)
    );

    // G is not affected in any way: all eight of its ops apply, in relay
    // order, while F is stuck.
    for item in &gs {
        seq += 1;
        assert_eq!(d.ingest(item, seq, T0 + 100).status, IngestStatus::Applied);
    }
    let ga = status_of(&d, &g);
    assert_eq!((ga.applied_seq, ga.pending, ga.gap), (8, 0, false));
    assert_eq!(d.r.nodes().len(), 8);
    // So are local commits.
    d.commit(&[node(200, &[], &[])], T0 + 101);

    // An op nearer the head displaces the furthest one instead of being
    // dropped: with op 2..4 held, op 1 would apply, so take a fresh replica
    // holding 5, 6, 7 and offer 3.
    let mut e = Dev::with(ROOT, 2, config);
    e.ingest(&f.sealed_genesis(), 0, T0);
    for i in [4, 5, 6] {
        e.ingest(&fs[i], 0, T0 + 100);
    }
    assert_eq!(
        e.ingest(&fs[2], 0, T0 + 100).status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    assert_eq!(e.r.stats().pending, 3);
    assert_eq!(e.r.stats().refused, 1);
    for i in [0, 1] {
        e.ingest(&fs[i], 0, T0 + 100);
    }
    assert_eq!(status_of(&e, &f).applied_seq, 3, "1, 2 and the kept 3");
    assert_eq!(
        e.r.stats().pending,
        2,
        "5 and 6 wait for 4; 7 was displaced"
    );

    // Recovery: the relay does have F's first op after all (it arrived
    // late, at the end of the log). The replica applies what it kept, and a
    // resync from the start fetches what it dropped. Replay is idempotent.
    seq += 1;
    let out = d.ingest(&fs[0], seq, T0 + 102);
    assert_eq!((out.status, out.applied), (IngestStatus::Applied, 4));
    assert!(
        d.r.needs_resync(),
        "ops 5..8 were dropped and are still missing"
    );
    d.r.start_resync();
    assert_eq!(d.r.cursor(), 0);
    assert!(!d.r.needs_resync());
    let log: Vec<&Vec<u8>> = fs[1..].iter().chain(&gs).chain([&fs[0]]).collect();
    let mut effects = 0;
    for (i, item) in log.iter().enumerate() {
        effects += d.ingest(item, i as u64 + 3, T0 + 103).effects.len();
    }
    assert_eq!(effects, 4, "exactly the four nodes that were missing");
    assert_eq!(status_of(&d, &f).applied_seq, 8);
    assert!(!d.r.needs_resync());
    assert_eq!(d.r.stats().pending, 0);
    assert_eq!(d.r.cursor(), seq);
    assert_eq!(d.r.nodes().len(), 17);
}

#[test]
fn the_global_pending_bound_drops_the_incoming_op() {
    // Ops of authors without a key log count against the claimed author; an
    // insider inventing authors runs into the bound on the whole store.
    let config = Config {
        max_pending_items: 4,
        ..Config::default()
    };
    let mut d = Dev::with(ROOT, 1, config);
    let mut statuses = Vec::new();
    for i in 0..6u8 {
        let mut ghost = Forge::new(ROOT, 100 + i);
        let op = ghost.op(1, None, T0, &[node(i, &[], &[])]);
        statuses.push(d.ingest(&ghost.sealed_op(&op), u64::from(i) + 1, T0).status);
    }
    assert!(
        statuses[..4]
            .iter()
            .all(|s| *s == IngestStatus::Pending(PendingReason::UnknownAuthor))
    );
    assert_eq!(
        statuses[4..],
        [IngestStatus::PendingFull, IngestStatus::PendingFull]
    );
    assert_eq!(d.r.cursor(), 6);
    assert!(d.r.needs_resync());
    assert_eq!(d.r.stats().pending, 4);
    // The byte bounds work the same way.
    let mut f = Forge::new(ROOT, 9);
    let op1 = f.op(1, None, T0, &[node(1, &[], &[])]);
    let op2 = f.op(2, Some(&op1), T0 + 1, &[node(2, &[], &[])]);
    let op3 = f.op(3, Some(&op2), T0 + 2, &[node(3, &[], &[])]);
    let one = op2.to_bytes().unwrap().len();
    for config in [
        Config {
            max_pending_bytes: one + 10,
            ..Config::default()
        },
        Config {
            max_pending_bytes_per_author: one + 10,
            ..Config::default()
        },
    ] {
        let mut d = Dev::with(ROOT, 1, config);
        d.ingest(&f.sealed_genesis(), 0, T0);
        assert!(matches!(
            d.ingest(&f.sealed_op(&op2), 0, T0).status,
            IngestStatus::Pending(_)
        ));
        assert_eq!(
            d.ingest(&f.sealed_op(&op3), 0, T0).status,
            IngestStatus::PendingFull
        );
        assert!(d.r.stats().pending_bytes <= one + 10);
        assert!(d.r.needs_resync());
    }
}

#[test]
fn needs_resync_survives_a_restore_and_clear_pending_empties_the_store() {
    let config = Config {
        max_pending_items_per_author: 1,
        ..Config::default()
    };
    let mut f = Forge::new(ROOT, 9);
    let mut d = Dev::with(ROOT, 1, config);
    d.ingest(&f.sealed_genesis(), 0, T0);
    let op1 = f.op(1, None, T0, &[node(1, &[], &[])]);
    let op2 = f.op(2, Some(&op1), T0 + 1, &[node(2, &[], &[])]);
    let op3 = f.op(3, Some(&op2), T0 + 2, &[node(3, &[], &[])]);
    d.ingest(&f.sealed_op(&op2), 0, T0);
    d.ingest(&f.sealed_op(&op3), 0, T0);
    assert!(d.r.needs_resync());
    d.restore();
    assert!(d.r.needs_resync());
    assert_eq!(d.r.clear_pending(), 1);
    assert_eq!(d.r.stats().pending_bytes, 0);
}

#[test]
fn authors_are_capped() {
    let config = Config {
        max_authors: 3,
        ..Config::default()
    };
    let mut d = Dev::with(ROOT, 1, config);
    let mut forges: Vec<Forge> = (0..4).map(|i| Forge::new(ROOT, 50 + i)).collect();
    let g: Vec<Vec<u8>> = forges.iter_mut().map(Forge::sealed_genesis).collect();
    assert_eq!(d.ingest(&g[0], 0, T0).status, IngestStatus::KeyLog);
    assert_eq!(d.ingest(&g[1], 0, T0).status, IngestStatus::KeyLog);
    // This device counts: the third foreign genesis is one too many.
    assert_eq!(rejected(&d.ingest(&g[2], 0, T0)), &Reject::TooManyAuthors);
    assert_eq!(rejected(&d.ingest(&g[3], 0, T0)), &Reject::TooManyAuthors);
    let st = d.r.stats();
    assert_eq!((st.authors, st.authors_refused), (3, 2));
    assert_eq!(d.r.authors().len(), 3);
    // Known authors are not affected: a repeat is still a duplicate, and
    // their ops apply.
    assert_eq!(d.ingest(&g[0], 0, T0).status, IngestStatus::Duplicate);
    let op = forges[1].op(1, None, T0, &[node(1, &[], &[])]);
    assert_eq!(
        d.ingest(&forges[1].sealed_op(&op), 0, T0).status,
        IngestStatus::Applied
    );
    // Ops of a refused author wait like those of any unknown author.
    let op = forges[2].op(1, None, T0, &[node(2, &[], &[])]);
    assert_eq!(
        d.ingest(&forges[2].sealed_op(&op), 0, T0).status,
        IngestStatus::Pending(PendingReason::UnknownAuthor)
    );
    assert_eq!(Config::default().max_authors, 64);
}

#[test]
fn unverifiable_ops_are_kept_and_checked_again_after_a_restore() {
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    // An op in a format from the future, and one with an unknown hash.
    let good = f.op(1, None, T0, &[node(1, &[], &[])]);
    let mut items = match Value::decode(good.body_bytes()).unwrap() {
        Value::Array(a) => a,
        _ => panic!(),
    };
    items[0] = int(7);
    let future_format = Signed {
        body: Value::Array(items.clone()).encode().unwrap(),
        sigs: good.sigs().to_vec(),
    }
    .to_bytes()
    .unwrap();
    items[0] = int(0);
    items[1] = int(99);
    let future_hash = Signed {
        body: Value::Array(items).encode().unwrap(),
        sigs: good.sigs().to_vec(),
    }
    .to_bytes()
    .unwrap();
    for bytes in [future_format, future_hash] {
        let out = d.ingest(&f.seal(&Plain::Op(bytes)), 5, T0);
        assert_eq!(
            out.status,
            IngestStatus::Pending(PendingReason::Unverifiable)
        );
    }
    assert_eq!(d.r.cursor(), 5);
    let st = d.r.stats();
    assert_eq!((st.pending, st.unsupported, st.invalid), (2, 0, 0));
    // They hold nothing up.
    assert_eq!(
        d.ingest(&f.sealed_op(&good), 0, T0).status,
        IngestStatus::Applied
    );
    // They survive a restore, where they are looked at again (this build
    // still cannot read them, a newer one could).
    d.restore();
    assert!(d.poll(T0 + 1).is_empty());
    assert_eq!(d.r.stats().pending, 2);
    // And they are bounded like everything else that is held.
    let config = Config {
        max_pending_items_per_author: 2,
        ..Config::default()
    };
    let mut d = Dev::with(ROOT, 1, config);
    for i in 0..4u8 {
        let body = Value::Array(vec![int(9), int(i64::from(i))])
            .encode()
            .unwrap();
        let bytes = Signed {
            body,
            sigs: good.sigs().to_vec(),
        }
        .to_bytes()
        .unwrap();
        let out = d.ingest(&f.seal(&Plain::Op(bytes)), 0, T0);
        if i < 2 {
            assert_eq!(
                out.status,
                IngestStatus::Pending(PendingReason::Unverifiable)
            );
        } else {
            assert_eq!(out.status, IngestStatus::PendingFull);
        }
    }
    assert!(d.r.needs_resync());
}

// ------------------------------------------------------------ clocks

#[test]
fn an_op_from_the_future_is_held_until_the_clock_catches_up() {
    let drift = Config::default().max_drift_ms;
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let far = T0 + drift + 60_000;
    let op1 = f.op(1, None, far, &[node(1, &[], &[("k", text("future"))])]);
    let op2 = f.op(2, Some(&op1), far + 1, &[node(2, &[], &[])]);

    let out = d.ingest(&f.sealed_op(&op1), 1, T0);
    assert_eq!(out.status, IngestStatus::Pending(PendingReason::ClockAhead));
    assert_eq!(d.r.cursor(), 1);
    // What follows it in the chain waits behind it.
    let out = d.ingest(&f.sealed_op(&op2), 2, T0);
    assert_eq!(
        out.status,
        IngestStatus::Pending(PendingReason::MissingPrev)
    );
    assert!(d.r.nodes().is_empty());

    // The future timestamp has not leaked into the local clock: a local
    // write now is stamped with local time.
    d.commit(&[node(1, &[], &[("k", text("local"))])], T0 + 10);
    let p = Pairing::from_root(ROOT);
    let Plain::Op(bytes) = SealedOp::from_bytes(d.r.outbox_peek(1)[0])
        .unwrap()
        .open(&p.fragment_key(), &p.fragment_id())
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        Op::from_bytes(&bytes).unwrap().body().hlc,
        Hlc {
            wall_ms: T0 + 10,
            counter: 0
        }
    );

    // Not yet: one millisecond short of the bound. Held across a restore.
    assert!(d.poll(far - drift - 1).is_empty());
    d.restore();
    assert!(d.poll(far - drift - 1).is_empty());
    assert_eq!(d.r.stats().pending, 2);

    // Exactly at the bound the first applies and wins the property with its
    // later stamp; the second is one millisecond further out.
    assert_eq!(
        d.poll(far - drift),
        vec![node(1, &[], &[("k", text("future"))])]
    );
    assert_eq!(d.r.stats().pending, 1);
    assert_eq!(d.poll(far - drift + 1), vec![node(2, &[], &[])]);
    assert_eq!(d.r.stats().pending, 0);
    assert_eq!(d.r.stats().applied, 2);

    // An op exactly at the bound is not held at all.
    let mut g = Forge::new(ROOT, 10);
    d.ingest(&g.sealed_genesis(), 0, T0);
    let edge_case = g.op(1, None, T0 + drift, &[node(3, &[], &[])]);
    assert_eq!(
        d.ingest(&g.sealed_op(&edge_case), 0, T0).status,
        IngestStatus::Applied
    );
    // Old timestamps are never a problem.
    let mut h = Forge::new(ROOT, 11);
    d.ingest(&h.sealed_genesis(), 0, T0);
    let ancient = h.op(1, None, 1, &[node(4, &[], &[])]);
    assert_eq!(
        d.ingest(&h.sealed_op(&ancient), 0, T0).status,
        IngestStatus::Applied
    );
}

#[test]
fn a_held_op_is_released_by_any_later_ingest() {
    let drift = Config::default().max_drift_ms;
    let mut f = Forge::new(ROOT, 9);
    let mut d = dev_knowing(&mut f);
    let op = f.op(1, None, T0 + drift + 1000, &[node(1, &[], &[])]);
    d.ingest(&f.sealed_op(&op), 0, T0);
    // Some unrelated item, much later, even a useless one.
    let out = d.ingest(b"garbage", 0, T0 + 5000);
    assert!(matches!(out.status, IngestStatus::Rejected(_)));
    assert_eq!(out.applied, 1);
    assert_eq!(out.effects, vec![node(1, &[], &[])]);
}

#[test]
fn an_op_beyond_the_clock_horizon_is_rejected_and_reported() {
    let cfg = Config::default();
    assert_eq!(cfg.max_clock_ahead_ms, 24 * 60 * 60 * 1000);
    let mut f = Forge::new(ROOT, 9);
    let mut g = Forge::new(ROOT, 10);
    let mut d = dev_knowing(&mut f);
    d.ingest(&g.sealed_genesis(), 0, T0);
    let lead_of = |d: &Dev, who: &Forge| {
        d.r.authors()
            .into_iter()
            .find(|a| a.author == who.author())
            .unwrap()
            .clock_lead_ms
    };

    // Exactly at the horizon: held. One millisecond beyond: rejected.
    let at = f.op(1, None, T0 + cfg.max_clock_ahead_ms, &[node(1, &[], &[])]);
    assert_eq!(
        d.ingest(&f.sealed_op(&at), 1, T0).status,
        IngestStatus::Pending(PendingReason::ClockAhead)
    );
    assert_eq!(lead_of(&d, &f), cfg.max_clock_ahead_ms);
    let year = 365 * 24 * 3600 * 1000;
    let beyond = g.op(1, None, T0 + year, &[node(2, &[], &[])]);
    let out = d.ingest(&g.sealed_op(&beyond), 2, T0);
    assert_eq!(rejected(&out), &Reject::ClockTooFarAhead);
    assert_eq!(d.r.cursor(), 2);
    let st = d.r.stats();
    assert_eq!((st.clock_rejected, st.pending, st.invalid), (1, 1, 0));
    // The application can tell whose clock it is, and by how much.
    assert_eq!(lead_of(&d, &g), year);
    assert!(!d.r.needs_resync(), "nothing a resync could fix right now");

    // The author keeps writing with its wrong clock. Its ops queue behind
    // the missing one, up to the author's bound, without touching anyone
    // else: here the device itself and author F.
    let mut prev = beyond.clone();
    for i in 0..300u64 {
        let op = g.op(i + 2, Some(&prev), T0 + year + 1 + i, &[node(3, &[], &[])]);
        d.ingest(&g.sealed_op(&op), 3 + i, T0);
        prev = op;
    }
    let st = d.r.stats();
    assert_eq!(st.pending, 1 + cfg.max_pending_items_per_author);
    assert_eq!(st.refused, 300 - cfg.max_pending_items_per_author as u64);
    assert_eq!(d.r.cursor(), 302);
    assert!(d.r.needs_resync());
    d.commit(&[node(9, &[], &[])], T0 + 1);
    assert_eq!(
        d.poll(T0 + cfg.max_clock_ahead_ms - cfg.max_drift_ms),
        vec![node(1, &[], &[])]
    );
    assert_eq!(lead_of(&d, &f), 0, "applied: nothing wrong any more");

    // When the wall clock does get there, a resync brings the author in.
    d.r.start_resync();
    let late = T0 + year;
    assert_eq!(
        d.ingest(&g.sealed_op(&beyond), 2, late).status,
        IngestStatus::Applied
    );
    assert_eq!(lead_of(&d, &g), 0);
    // The local clock was never dragged forward by the rejected timestamp.
    assert!(d.r.node(&gid(2)).is_some());
}

// ------------------------------------------------------------ confidentiality

#[test]
fn nothing_handed_to_the_outbox_contains_plaintext() {
    const MARKER: &str = "PLAINTEXT-MARKER-7f3a9c";
    let mut a = Dev::new(1);
    let mut b = Dev::new(2);
    let marker_gid: Gid = *b"GID-MARKER-16byt";
    a.commit(
        &[
            node(1, &[MARKER], &[(MARKER, text(MARKER))]),
            Change::NodePut {
                gid: marker_gid,
                labels_add: Default::default(),
                labels_remove: Default::default(),
                set: props(&[("blob", Value::Bytes(MARKER.as_bytes().to_vec()))]),
                unset: set_of(&[MARKER]),
            },
            edge(
                9,
                1,
                1,
                MARKER,
                &[("nested", Value::Array(vec![text(MARKER)]))],
            ),
        ],
        T0 + 1,
    );
    // B answers, so that deps (op ids) travel too.
    let from_a: Vec<Vec<u8>> =
        a.r.outbox_peek(usize::MAX)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
    for it in &from_a {
        b.ingest(it, 0, T0 + 2);
    }
    b.commit(&[node(1, &[], &[("reply", text(MARKER))])], T0 + 3);

    let pairing = Pairing::from_root(ROOT);
    let needles: Vec<(&str, Vec<u8>)> = vec![
        (
            "property value / label / key / type",
            MARKER.as_bytes().to_vec(),
        ),
        ("gid", marker_gid.to_vec()),
        ("root secret", ROOT.to_vec()),
        ("fragment key", pairing.fragment_key_bytes().to_vec()),
        (
            "relay token",
            pairing
                .relay_token("https://relay.example")
                .unwrap()
                .to_vec(),
        ),
        ("author id of A", a.r.author().digest),
        ("author id of B", b.r.author().digest),
        ("device seed of A", vec![1u8; 32]),
        ("payload field name", b"labels".to_vec()),
        ("signature domain", b"gsp/v0/op".to_vec()),
    ];
    let mut items = 0;
    for dev in [&a, &b] {
        assert!(dev.r.outbox_len() >= 2);
        for item in dev.r.outbox_peek(usize::MAX) {
            items += 1;
            for (what, needle) in &needles {
                assert!(
                    !contains(item, needle),
                    "an outbox item contains a value that must stay private (see `needles`): {what}"
                );
            }
            // What a relay does see: the fragment id, as the routing header.
            assert!(contains(item, &pairing.fragment_id()));
            // And every item is a well-formed sealed op for this fragment.
            let sealed = SealedOp::from_bytes(item).unwrap();
            assert_eq!(sealed.fragment_id, pairing.fragment_id().to_vec());
            assert_eq!(sealed.nonce.len(), 24);
        }
    }
    assert_eq!(items, 4);
    // The search does find the marker where it is expected: in the state,
    // which is why the state must be stored encrypted.
    let state = a.r.to_bytes().unwrap();
    assert!(contains(&state, MARKER.as_bytes()));
    assert!(contains(&state, &ROOT));
    // Nonces are the caller's and are not reused across items.
    let nonces: std::collections::BTreeSet<Vec<u8>> = [&a, &b]
        .iter()
        .flat_map(|d| d.r.outbox_peek(usize::MAX))
        .map(|i| SealedOp::from_bytes(i).unwrap().nonce)
        .collect();
    assert_eq!(nonces.len(), 4);
    assert!(
        !format!("{:?}", a.r).contains("165, 165"),
        "Debug prints no root"
    );
}

// ------------------------------------------------------------ garbage

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes never panic `ingest` or `from_bytes`, and never change
    /// the visible graph.
    #[test]
    fn garbage_never_panics_or_applies(
        blobs in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 1..8),
        seq in any::<u64>(),
        now in any::<u64>(),
    ) {
        let mut d = Dev::new(1);
        d.commit(&[node(1, &[], &[("k", int(1))])], T0);
        let nodes = d.r.nodes();
        for b in &blobs {
            let out = d.ingest(b, seq, now);
            prop_assert!(matches!(out.status, IngestStatus::Rejected(_)));
            prop_assert!(out.effects.is_empty());
            prop_assert!(Replica::from_bytes(b, Config::default()).is_err());
        }
        prop_assert_eq!(d.r.nodes(), nodes);
        prop_assert_eq!(d.r.stats().pending, 0);
    }

    /// The same for garbage that does decrypt: random plaintext under the
    /// right key, as an op and as a key log, and mutated real ops.
    #[test]
    fn sealed_garbage_never_panics_or_applies(
        blob in proptest::collection::vec(any::<u8>(), 0..300),
        flips in proptest::collection::vec((any::<usize>(), 1u8..=255), 1..4),
    ) {
        let mut f = Forge::new(ROOT, 9);
        let mut d = dev_knowing(&mut f);
        for plain in [Plain::Op(blob.clone()), Plain::KeyLog(blob.clone()), Plain::Batch(blob)] {
            let out = d.ingest(&f.seal(&plain), 0, T0);
            prop_assert!(matches!(out.status, IngestStatus::Rejected(_)));
        }
        // A real op with a few bytes changed *inside* the encryption.
        let op = f.op(1, None, T0, &[node(1, &["L"], &[("k", int(1))])]);
        let mut bytes = op.to_bytes().unwrap();
        for (pos, x) in flips {
            let i = pos % bytes.len();
            bytes[i] ^= x;
        }
        let out = d.ingest(&f.seal(&Plain::Op(bytes.clone())), 0, T0);
        if bytes != op.to_bytes().unwrap() {
            prop_assert!(
                !matches!(out.status, IngestStatus::Applied),
                "a modified signed op was applied"
            );
            prop_assert!(d.r.nodes().is_empty());
        }
    }
}
