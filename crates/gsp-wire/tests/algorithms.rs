//! What a build does with a signature algorithm it does not implement.
//!
//! These tests run in both feature settings. With the `ml-dsa` feature off,
//! ML-DSA-65 is such an algorithm: registered, not implemented. The hybrid
//! objects they use were made by a build that has it (vector 4 of
//! `docs/WIRE-V0.md`; `tests/vectors.rs` keeps the files in step).
use gsp_wire::*;

const FRAG: &[u8] = b"fragment-A";
const HYBRID_GENESIS: &[u8] = include_bytes!("fixtures/v4_genesis_signed.bin");
const HYBRID_OP: &[u8] = include_bytes!("fixtures/v4_op_signed.bin");
const ML_DSA: bool = cfg!(feature = "ml-dsa");

fn ed_author() -> (SigningKey, KeyLog) {
    let ed = SigningKey::ed25519(&[0x01; 32]);
    let genesis = KeyLogEntry {
        hash_alg: 1,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![ed.public()],
            policy: vec![1],
        },
    }
    .sign(&[&ed])
    .unwrap();
    let log = KeyLog::genesis(&genesis).unwrap();
    (ed, log)
}

fn ed_op(ed: &SigningKey, log: &KeyLog) -> Op {
    Op::sign(
        &OpBody {
            hash_alg: 1,
            fragment_id: FRAG.to_vec(),
            author: log.author().clone(),
            seq: 1,
            prev: None,
            hlc: Hlc {
                wall_ms: 1_800_000_000_001,
                counter: 0,
            },
            deps: vec![],
            payload: Value::Null,
        },
        &[ed],
    )
    .unwrap()
}

#[test]
fn fixtures_are_vector_4() {
    // The digests published in WIRE-V0.md section 12.
    let b3 = |d: &[u8]| hex::encode(Multihash::compute(1, d).unwrap().digest);
    assert_eq!(HYBRID_GENESIS.len(), 5473);
    assert_eq!(
        b3(HYBRID_GENESIS),
        "21c752465a4431c0e28131c7cbe07ac67221617f5904e1ee26b9098a333f6ef9"
    );
    assert_eq!(HYBRID_OP.len(), 3585);
    assert_eq!(
        b3(HYBRID_OP),
        "fd5b222ee6dfc20172c5b3b421b665aa7795f074fa4081be77d6bbd980a5bb71"
    );
}

#[test]
fn registry_knows_the_id_whether_or_not_the_build_implements_it() {
    assert_eq!(SigAlg::from_id(2), Some(SigAlg::MlDsa65));
    assert_eq!(SigAlg::MlDsa65.implemented(), ML_DSA);
    assert_eq!(SigAlg::supported(2).is_some(), ML_DSA);
    assert!(SigAlg::Ed25519.implemented());
    assert_eq!(SigAlg::supported(1), Some(SigAlg::Ed25519));
    assert_eq!(SigAlg::supported(0), None);
    assert_eq!(SigAlg::supported(3), None);
}

#[test]
fn hybrid_objects_parse_in_every_build() {
    // Structure never depends on the algorithms: ids, bodies and signature
    // entries survive, so the bytes can be kept and passed on.
    let env = Signed::from_bytes(HYBRID_GENESIS).unwrap();
    assert_eq!(env.sigs.len(), 2);
    assert_eq!(env.to_bytes().unwrap(), HYBRID_GENESIS);
    let entry = KeyLogEntry::from_bytes(&env.body).unwrap();
    let KeyLogAction::Genesis { keys, policy, .. } = &entry.action else {
        panic!("genesis")
    };
    assert_eq!(policy, &vec![1, 2]);
    assert_eq!(keys.iter().map(|k| k.alg).collect::<Vec<_>>(), vec![1, 2]);
    let op = Op::from_bytes(HYBRID_OP).unwrap();
    assert_eq!(op.to_bytes().unwrap(), HYBRID_OP);
    assert_eq!(
        hex::encode(&op.id().digest),
        "6b3d54ebcec79c01d085eddf76649a5ccf053115a3ddf12636cd51cbc77198a0"
    );
}

#[test]
fn a_key_log_that_needs_an_unimplemented_algorithm_is_unsupported() {
    match KeyLog::genesis(HYBRID_GENESIS) {
        Ok(log) => {
            assert!(ML_DSA, "accepted without being able to check it");
            assert!(verify(HYBRID_OP, &VerifyCtx::new(FRAG, &log)).is_valid());
        }
        // Not `Unauthorized`, not `Malformed`: this build cannot tell.
        Err(e) => {
            assert!(!ML_DSA);
            assert_eq!(e, KeyLogError::Unsupported);
        }
    }
    // Without the key log the op's author is simply unknown.
    let (_, ed_log) = ed_author();
    assert_eq!(
        verify(HYBRID_OP, &VerifyCtx::new(FRAG, &ed_log)),
        Verdict::Unverifiable {
            reason: UnverifiableReason::UnknownAuthor
        }
    );
    // A policy change to an unimplemented algorithm stops the log there.
    let (ed, mut log) = ed_author();
    let upgrade = KeyLogEntry {
        hash_alg: 1,
        prev: Some(log.head().clone()),
        action: KeyLogAction::SetPolicy {
            policy: vec![1, 2],
            from_seq: 5,
        },
    }
    .sign(&[&ed])
    .unwrap();
    let head = log.head().clone();
    let res = log.append(&upgrade);
    if ML_DSA {
        // Implemented, and then refused for a real reason: no ML-DSA key.
        assert_eq!(res, Err(KeyLogError::Inconsistent));
    } else {
        assert_eq!(res, Err(KeyLogError::Unsupported));
    }
    assert_eq!(log.head(), &head);
}

#[test]
fn a_signature_of_an_unimplemented_algorithm_is_never_valid_and_never_invalid() {
    let (ed, log) = ed_author();
    let good = ed_op(&ed, &log);
    assert!(verify(&good.to_bytes().unwrap(), &VerifyCtx::new(FRAG, &log)).is_valid());

    // The same op with a real ML-DSA-65 signature entry added (taken from the
    // hybrid op: right shape, a key this author's log does not hold).
    let pq_sig = Op::from_bytes(HYBRID_OP)
        .unwrap()
        .sigs()
        .iter()
        .find(|s| s.alg == 2)
        .unwrap()
        .clone();
    let mut with_pq = good.clone();
    with_pq.signed_mut().sigs.push(pq_sig);
    let verdict = verify(&with_pq.to_bytes().unwrap(), &VerifyCtx::new(FRAG, &log));
    assert_eq!(
        verdict,
        Verdict::Unverifiable {
            reason: if ML_DSA {
                // Implemented: what is missing is the key.
                UnverifiableReason::UnknownKey
            } else {
                UnverifiableReason::UnknownSigAlg
            }
        }
    );
    // The same as for an id nobody has registered.
    let mut with_unknown = good.clone();
    let mut junk = good.sigs()[0].clone();
    junk.alg = 999;
    junk.key_id.digest = vec![9; 32];
    with_unknown.signed_mut().sigs.push(junk);
    assert_eq!(
        verify(
            &with_unknown.to_bytes().unwrap(),
            &VerifyCtx::new(FRAG, &log)
        ),
        Verdict::Unverifiable {
            reason: UnverifiableReason::UnknownSigAlg
        }
    );
    // An unimplemented algorithm does not excuse a bad signature of an
    // implemented one: that is still invalid.
    let mut bad = with_pq.clone();
    let ed_idx = bad.sigs().iter().position(|s| s.alg == 1).unwrap();
    bad.signed_mut().sigs[ed_idx].bytes[0] ^= 1;
    assert_eq!(
        verify(&bad.to_bytes().unwrap(), &VerifyCtx::new(FRAG, &log)),
        Verdict::Invalid {
            reason: InvalidReason::BadSignature
        }
    );
}

#[test]
fn ed25519_only_works_in_every_build() {
    let (ed, log) = ed_author();
    assert_eq!(ed.alg(), SigAlg::Ed25519);
    let op = ed_op(&ed, &log);
    let bytes = op.to_bytes().unwrap();
    let v = verify(&bytes, &VerifyCtx::new(FRAG, &log)).valid().unwrap();
    let mut chain = AuthorChain::new(log.author().clone(), FRAG.to_vec());
    assert_eq!(chain.observe(&v), ChainOutcome::Accepted);
    let key = FragmentKey::new([3; 32]);
    let sealed = SealedOp::seal(&key, FRAG, [4; 24], &Plain::Op(bytes.clone())).unwrap();
    assert_eq!(sealed.open(&key, FRAG).unwrap(), Plain::Op(bytes));
}
