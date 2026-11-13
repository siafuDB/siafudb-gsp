//! Generates the test vectors published in `docs/WIRE-V0.md` and fails if the
//! document does not contain exactly what this code produces.
//!
//! Print them: `cargo test -p gsp-wire --test vectors -- --nocapture`.
use gsp_wire::*;

const FRAG: &[u8] = b"fragment-A";

fn b3(data: &[u8]) -> String {
    hex::encode(Multihash::compute(1, data).unwrap().digest)
}

fn vectors() -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let mut put = |name: &'static str, bytes: &[u8]| out.push((name, hex::encode(bytes)));

    // ---- Vector 1: Ed25519-only author, genesis + first op.
    let ed = SigningKey::ed25519(&[0x01; 32]);
    put("v1.ed25519_public_key", &ed.public().bytes);
    put("v1.key_id", &ed.public().key_id(1).unwrap().digest);
    let genesis_entry = KeyLogEntry {
        hash_alg: 1,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: FRAG.to_vec(),
            keys: vec![ed.public()],
            policy: vec![1],
        },
    };
    put("v1.genesis_body", &genesis_entry.to_bytes().unwrap());
    let genesis = genesis_entry.sign(&[&ed]).unwrap();
    put("v1.genesis_signed", &genesis);
    let log = KeyLog::genesis(&genesis).unwrap();
    put("v1.author_id", &log.author().digest);
    let body = OpBody {
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
        payload: Value::Map(vec![
            ("op".into(), Value::Text("set_property".into())),
            ("vertex".into(), Value::Bytes(vec![7; 16])),
            ("key".into(), Value::Text("name".into())),
            ("value".into(), Value::Text("Tendai".into())),
        ]),
    };
    let op = Op::sign(&body, &[&ed]).unwrap();
    put("v1.op_body", op.body_bytes());
    put("v1.op_id", &op.id().digest);
    put(
        "v1.sig_input",
        &sig_input(Domain::Op, FRAG, op.id(), 1, &op.sigs()[0].key_id),
    );
    put("v1.signature", &op.sigs()[0].bytes);
    let op_bytes = op.to_bytes().unwrap();
    put("v1.op_signed", &op_bytes);
    assert!(verify(&op_bytes, &VerifyCtx::new(FRAG, &log)).is_valid());

    // ---- Vector 2: deterministic CBOR and both hash algorithms.
    let v = Value::Map(vec![
        ("z".into(), Value::uint(1)),
        (
            "aa".into(),
            Value::Array(vec![
                Value::Float(1.5),
                Value::Int(-1),
                Value::Bytes(vec![0x00, 0xff]),
            ]),
        ),
        ("a".into(), Value::Null),
        ("\u{e9}".into(), Value::Bool(true)),
        ("b".into(), Value::Float(1.1)),
        ("big".into(), Value::uint(u64::MAX)),
        ("f32".into(), Value::Float(100000.0)),
    ]);
    let enc = v.encode().unwrap();
    put("v2.value", &enc);
    put(
        "v2.blake3_256",
        &Multihash::compute(1, &enc).unwrap().digest,
    );
    put("v2.sha3_256", &Multihash::compute(2, &enc).unwrap().digest);

    // ---- Vector 3: sealing vector 1's signed op.
    let key = FragmentKey::new([0x11; 32]);
    let sealed = SealedOp::seal(&key, FRAG, [0x22; 24], &Plain::Op(op_bytes.clone())).unwrap();
    let aad = Value::Array(vec![
        Value::Text("gsp/v0/sealed".into()),
        Value::uint(0),
        Value::uint(1),
        Value::Bytes(FRAG.to_vec()),
    ])
    .encode()
    .unwrap();
    put("v3.aad", &aad);
    let sealed_bytes = sealed.to_bytes().unwrap();
    put("v3.sealed", &sealed_bytes);
    assert_eq!(
        sealed.open(&key, FRAG).unwrap(),
        Plain::Op(op_bytes.clone())
    );
    let pull = Message::Pull {
        fragment_id: FRAG.to_vec(),
        after: 17,
        limit: 500,
    };
    put("v3.message_pull", &pull.to_bytes().unwrap());

    // Needs ML-DSA signing; a build without the `ml-dsa` feature checks
    // vectors 1 to 3 only.
    #[cfg(feature = "ml-dsa")]
    {
        // ---- Vector 4: hybrid author. Too large to print: sizes and digests.
        let pq = SigningKey::ml_dsa_65(&[0x02; 32]);
        let g = KeyLogEntry {
            hash_alg: 1,
            prev: None,
            action: KeyLogAction::Genesis {
                fragment_id: FRAG.to_vec(),
                keys: vec![ed.public(), pq.public()],
                policy: vec![1, 2],
            },
        }
        .sign(&[&ed, &pq])
        .unwrap();
        let hlog = KeyLog::genesis(&g).unwrap();
        let hbody = OpBody {
            author: hlog.author().clone(),
            ..body.clone()
        };
        let hop = Op::sign(&hbody, &[&ed, &pq]).unwrap();
        let hbytes = hop.to_bytes().unwrap();
        assert!(verify(&hbytes, &VerifyCtx::new(FRAG, &hlog)).is_valid());
        out.push(("v4.mldsa65_public_key_blake3", b3(&pq.public().bytes)));
        out.push((
            "v4.mldsa65_key_id",
            hex::encode(pq.public().key_id(1).unwrap().digest),
        ));
        out.push(("v4.genesis_signed_len", g.len().to_string()));
        out.push(("v4.genesis_signed_blake3", b3(&g)));
        out.push(("v4.author_id", hex::encode(&hlog.author().digest)));
        out.push(("v4.op_id", hex::encode(&hop.id().digest)));
        let pq_sig = hop.sigs().iter().find(|s| s.alg == 2).unwrap();
        out.push(("v4.mldsa65_signature_len", pq_sig.bytes.len().to_string()));
        out.push(("v4.mldsa65_signature_blake3", b3(&pq_sig.bytes)));
        out.push(("v4.op_signed_len", hbytes.len().to_string()));
        out.push(("v4.op_signed_blake3", b3(&hbytes)));
        // The two signed objects are also kept as files, so that a build
        // without ML-DSA has real hybrid input to test against
        // (tests/algorithms.rs).
        fixture("v4_genesis_signed.bin", &g);
        fixture("v4_op_signed.bin", &hbytes);
    }

    out
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

#[test]
fn vectors_match_the_spec_document() {
    let vs = vectors();
    for (name, value) in &vs {
        println!("{name} = {value}");
    }
    assert_eq!(vs, vectors(), "vectors are not reproducible");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/WIRE-V0.md");
    let doc = std::fs::read_to_string(path).expect("docs/WIRE-V0.md");
    // The document wraps long hex; compare with all whitespace removed.
    let flat: String = doc.chars().filter(|c| !c.is_whitespace()).collect();
    for (name, value) in &vs {
        assert!(
            flat.contains(&format!("{name}={value}")),
            "docs/WIRE-V0.md is missing or stale for {name}"
        );
    }
}
