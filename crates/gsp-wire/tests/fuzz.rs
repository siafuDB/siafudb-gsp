//! Property tests: decoders never panic, and nothing but the original bytes
//! verifies as the original op.
mod common;
use common::*;
use gsp_wire::*;
use proptest::prelude::*;

fn poke_everything(bytes: &[u8], log: &KeyLog) {
    let ctx = VerifyCtx::new(FRAG, log).at(1_800_000_000_000);
    let _ = Value::decode(bytes);
    let _ = Signed::from_bytes(bytes);
    let _ = Op::from_bytes(bytes);
    let _ = OpBody::from_bytes(bytes);
    let _ = verify(bytes, &ctx);
    let _ = BatchBody::from_bytes(bytes);
    let _ = verify_batch(bytes, &ctx);
    let _ = KeyLogEntry::from_bytes(bytes);
    let _ = KeyLog::genesis(bytes);
    let _ = log.clone().append(bytes);
    let _ = Message::from_bytes(bytes);
    let _ = EquivocationProof::from_bytes(bytes);
    if let Ok(s) = SealedOp::from_bytes(bytes) {
        let _ = s.open(&FragmentKey::new([1; 32]), FRAG);
    }
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::uint),
        any::<i64>().prop_map(|n| Value::Int(n.into())),
        (-18446744073709551616i128..18446744073709551616i128).prop_map(Value::Int),
        any::<f64>().prop_map(Value::Float),
        any::<f32>().prop_map(|f| Value::Float(f.into())),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,12}".prop_map(Value::Text),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map(".{0,6}", inner, 0..6)
                .prop_map(|m| Value::Map(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let a = author(FRAG, false, 1);
        poke_everything(&bytes, &a.log);
    }

    /// Arbitrary bytes are almost never CBOR, so also fuzz *near* valid input.
    #[test]
    fn mutated_valid_input_never_panics_and_never_verifies(
        which in 0usize..6,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
        cut in proptest::option::of(any::<prop::sample::Index>()),
        extra in proptest::collection::vec(any::<u8>(), 0..4),
    ) {
        let a = author(FRAG, false, 1);
        let op = signed(&a, FRAG, 2);
        let key = FragmentKey::new([1; 32]);
        let sealed = SealedOp::seal(&key, FRAG, [2; 24], &Plain::Op(op.clone())).unwrap();
        let seeds: [Vec<u8>; 6] = [
            op.clone(),
            a.log.entries()[0].clone(),
            Batch::sign(
                &BatchBody { hash_alg: H, fragment_id: FRAG.to_vec(), sender: a.id(), sender_seq: 2, ops: vec![op.clone()] },
                &a.keys(),
            ).unwrap(),
            sealed.to_bytes().unwrap(),
            Message::Push { fragment_id: FRAG.to_vec(), sealed: vec![sealed] }.to_bytes().unwrap(),
            Op::from_bytes(&op).unwrap().body_bytes().to_vec(),
        ];
        let original = seeds[which].clone();
        let mut bytes = original.clone();
        for (idx, val) in edits {
            let i = idx.index(bytes.len());
            bytes[i] = val;
        }
        if let Some(c) = cut {
            bytes.truncate(c.index(bytes.len() + 1));
        }
        bytes.extend(extra);
        poke_everything(&bytes, &a.log);
        if bytes != original {
            let ctx = VerifyCtx::new(FRAG, &a.log);
            prop_assert!(!verify(&bytes, &ctx).is_valid());
            prop_assert!(!verify_batch(&bytes, &ctx).is_valid());
        }
    }

    #[test]
    fn value_round_trip_is_canonical(v in arb_value()) {
        let bytes = v.encode().unwrap();
        let back = Value::decode(&bytes).unwrap();
        prop_assert_eq!(back.encode().unwrap(), bytes);
    }

    /// Whatever decodes, re-encodes to exactly the input (decode is injective).
    #[test]
    fn anything_that_decodes_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(v) = Value::decode(&bytes) {
            prop_assert_eq!(v.encode().unwrap(), bytes);
        }
    }
}
