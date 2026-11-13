#![allow(dead_code)]
use gsp_wire::*;

pub const FRAG: &[u8] = b"fragment-A";
pub const FRAG_B: &[u8] = b"fragment-B";
pub const H: u16 = 1; // BLAKE3-256

pub struct Author {
    pub ed: SigningKey,
    pub pq: Option<SigningKey>,
    pub log: KeyLog,
}

impl Author {
    pub fn keys(&self) -> Vec<&SigningKey> {
        let mut v = vec![&self.ed];
        v.extend(self.pq.as_ref());
        v
    }
    pub fn id(&self) -> Multihash {
        self.log.author().clone()
    }
}

pub fn author(fragment: &[u8], hybrid: bool, seed: u8) -> Author {
    let ed = SigningKey::from_seed(SigAlg::Ed25519, &[seed; 32]);
    let pq = hybrid.then(|| SigningKey::from_seed(SigAlg::MlDsa65, &[seed ^ 0xff; 32]));
    let mut keys = vec![ed.public()];
    let mut policy = vec![SigAlg::Ed25519.id()];
    let mut signers = vec![&ed];
    if let Some(pq) = &pq {
        keys.push(pq.public());
        policy.push(SigAlg::MlDsa65.id());
        signers.push(pq);
    }
    let genesis = KeyLogEntry {
        hash_alg: H,
        prev: None,
        action: KeyLogAction::Genesis {
            fragment_id: fragment.to_vec(),
            keys,
            policy,
        },
    }
    .sign(&signers)
    .unwrap();
    let log = KeyLog::genesis(&genesis).unwrap();
    Author { ed, pq, log }
}

pub fn fake_hash(n: u8) -> Multihash {
    Multihash {
        alg: H,
        digest: vec![n; 32],
    }
}

pub fn payload() -> Value {
    Value::Map(vec![
        ("op".into(), Value::Text("set_property".into())),
        ("vertex".into(), Value::Bytes(vec![7; 16])),
        ("key".into(), Value::Text("name".into())),
        ("value".into(), Value::Text("Tendai".into())),
    ])
}

pub fn body(a: &Author, fragment: &[u8], seq: u64) -> OpBody {
    OpBody {
        hash_alg: H,
        fragment_id: fragment.to_vec(),
        author: a.id(),
        seq,
        prev: (seq > 1).then(|| fake_hash(seq as u8)),
        hlc: Hlc {
            wall_ms: 1_800_000_000_000 + seq,
            counter: 0,
        },
        deps: vec![fake_hash(200), fake_hash(100)],
        payload: payload(),
    }
}

pub fn signed(a: &Author, fragment: &[u8], seq: u64) -> Vec<u8> {
    Op::sign(&body(a, fragment, seq), &a.keys())
        .unwrap()
        .to_bytes()
        .unwrap()
}

/// Re-wrap a (possibly altered) body with existing signatures.
pub fn rewrap(body: &OpBody, sigs: &[Signature]) -> Vec<u8> {
    Signed {
        body: body.to_bytes().unwrap(),
        sigs: sigs.to_vec(),
    }
    .to_bytes()
    .unwrap()
}

/// Tiny deterministic PRNG for shuffles (xorshift64*).
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}
