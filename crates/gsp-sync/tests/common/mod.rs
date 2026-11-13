//! Shared test support: a naive model graph (what an engine adapter would
//! keep), a device wrapper that checks the model against the replica after
//! every call, and a forge that builds arbitrary sealed items.
#![allow(dead_code)]

use gsp_sync::*;
use gsp_wire::{
    FragmentKey, Hlc, KeyLog, KeyLogAction, KeyLogEntry, Multihash, Op, OpBody, Plain, SealedOp,
    SigAlg, SigningKey, Value,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const ROOT: [u8; 32] = [0xA5; 32];
pub const T0: u64 = 1_800_000_000_000;

pub fn gid(n: u8) -> Gid {
    [n; 16]
}

pub fn text(s: &str) -> Value {
    Value::Text(s.into())
}

pub fn int(n: i64) -> Value {
    Value::Int(i128::from(n))
}

pub fn set_of(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

pub fn props(items: &[(&str, Value)]) -> BTreeMap<String, Value> {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// `NodePut` with labels to add and properties to set.
pub fn node(g: u8, labels: &[&str], set: &[(&str, Value)]) -> Change {
    Change::NodePut {
        gid: gid(g),
        labels_add: set_of(labels),
        labels_remove: BTreeSet::new(),
        set: props(set),
        unset: BTreeSet::new(),
    }
}

/// `EdgePut` with properties to set.
pub fn edge(g: u8, src: u8, dst: u8, ty: &str, set: &[(&str, Value)]) -> Change {
    Change::EdgePut {
        gid: gid(g),
        src: gid(src),
        dst: gid(dst),
        ty: ty.into(),
        set: props(set),
        unset: BTreeSet::new(),
    }
}

pub fn node_del(g: u8) -> Change {
    Change::NodeDel { gid: gid(g) }
}

pub fn edge_del(g: u8) -> Change {
    Change::EdgeDel { gid: gid(g) }
}

/// Tiny deterministic PRNG (xorshift64*).
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
    pub fn nonce(&mut self) -> [u8; 24] {
        let mut n = [0u8; 24];
        for chunk in n.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        n
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

type ModelNode = (BTreeSet<String>, BTreeMap<String, Value>);
type ModelEdge = (Gid, Gid, String, BTreeMap<String, Value>);

/// The graph an engine would hold if it applied every `Change` it is given in
/// the plainest way: puts upsert, deletes remove, nothing cascades.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Model {
    pub nodes: HashMap<Gid, ModelNode>,
    pub edges: HashMap<Gid, ModelEdge>,
}

impl Model {
    /// Apply one change. With `strict`, additionally require what an engine
    /// with referential integrity needs from an *effects* list: an edge put
    /// finds its endpoints and never re-points an existing edge, a delete
    /// finds its target, and a node is deleted only after its edges.
    pub fn apply(&mut self, c: &Change, strict: bool) {
        match c {
            Change::NodePut {
                gid,
                labels_add,
                labels_remove,
                set,
                unset,
            } => {
                let n = self.nodes.entry(*gid).or_default();
                n.0.extend(labels_add.iter().cloned());
                for l in labels_remove {
                    n.0.remove(l);
                }
                for (k, v) in set {
                    n.1.insert(k.clone(), v.clone());
                }
                for k in unset {
                    n.1.remove(k);
                }
            }
            Change::NodeDel { gid } => {
                let had = self.nodes.remove(gid).is_some();
                if strict {
                    assert!(had, "effect deletes a node the engine does not have");
                    assert!(
                        !self.edges.values().any(|e| e.0 == *gid || e.1 == *gid),
                        "effect deletes a node before its edges"
                    );
                }
            }
            Change::EdgePut {
                gid,
                src,
                dst,
                ty,
                set,
                unset,
            } => {
                if strict {
                    assert!(
                        self.nodes.contains_key(src) && self.nodes.contains_key(dst),
                        "effect puts an edge before its endpoints"
                    );
                    if let Some(e) = self.edges.get(gid) {
                        assert!(
                            e.0 == *src && e.1 == *dst && e.2 == *ty,
                            "effect re-points an existing edge"
                        );
                    }
                }
                let e = self
                    .edges
                    .entry(*gid)
                    .or_insert_with(|| (*src, *dst, ty.clone(), BTreeMap::new()));
                e.0 = *src;
                e.1 = *dst;
                e.2 = ty.clone();
                for (k, v) in set {
                    e.3.insert(k.clone(), v.clone());
                }
                for k in unset {
                    e.3.remove(k);
                }
            }
            Change::EdgeDel { gid } => {
                let had = self.edges.remove(gid).is_some();
                if strict {
                    assert!(had, "effect deletes an edge the engine does not have");
                }
            }
        }
    }

    pub fn apply_all(&mut self, changes: &[Change], strict: bool) {
        for c in changes {
            self.apply(c, strict);
        }
    }

    /// The model a replica's visible state corresponds to.
    pub fn of(r: &Replica) -> Model {
        Model {
            nodes: r
                .nodes()
                .into_iter()
                .map(|n| (n.gid, (n.labels, n.props)))
                .collect(),
            edges: r
                .edges()
                .into_iter()
                .map(|e| (e.gid, (e.src, e.dst, e.ty, e.props)))
                .collect(),
        }
    }
}

/// A device: a replica plus the model its adapter would maintain. Every call
/// checks that the model, fed only what an adapter sees, equals the
/// replica's visible state.
pub struct Dev {
    pub r: Replica,
    pub model: Model,
    pub rng: Rng,
    pub config: Config,
}

impl Dev {
    pub fn new(seed: u8) -> Dev {
        Dev::with(ROOT, seed, Config::default())
    }

    pub fn with(root: [u8; 32], seed: u8, config: Config) -> Dev {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ u64::from(seed));
        let r = Replica::create(root, [seed; 32], rng.nonce(), config).unwrap();
        Dev {
            r,
            model: Model::default(),
            rng,
            config,
        }
    }

    pub fn check(&self) {
        assert_eq!(
            self.model,
            Model::of(&self.r),
            "the effects stream did not keep the engine equal to the replica"
        );
    }

    /// A local commit, as an adapter does it: the engine applies the changes,
    /// the replica is told, the engine applies what comes back.
    pub fn commit(&mut self, changes: &[Change], now: u64) -> Vec<Change> {
        self.try_commit(changes, now).expect("local commit")
    }

    pub fn try_commit(&mut self, changes: &[Change], now: u64) -> Result<Vec<Change>, Error> {
        let fix = self.r.local_commit(changes, now, self.rng.nonce())?;
        self.model.apply_all(changes, false);
        self.model.apply_all(&fix, true);
        self.check();
        Ok(fix)
    }

    pub fn ingest(&mut self, sealed: &[u8], relay_seq: u64, now: u64) -> IngestOutcome {
        let out = self.r.ingest(sealed, relay_seq, now);
        self.model.apply_all(&out.effects, true);
        self.check();
        out
    }

    pub fn poll(&mut self, now: u64) -> Vec<Change> {
        let effects = self.r.poll(now);
        self.model.apply_all(&effects, true);
        self.check();
        effects
    }

    /// Take everything out of the outbox, as a transport would after an ack.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let items: Vec<Vec<u8>> = self
            .r
            .outbox_peek(usize::MAX)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(self.r.outbox_ack(items.len()), items.len());
        items
    }

    /// Save and restore the replica in place; the bytes must round-trip.
    pub fn restore(&mut self) {
        let bytes = self.r.to_bytes().unwrap();
        self.r = Replica::from_bytes(&bytes, self.config).unwrap();
        assert_eq!(*self.r.to_bytes().unwrap(), *bytes);
        self.check();
    }
}

/// Hand every item to every device listed, in order.
pub fn deliver(items: &[Vec<u8>], to: &mut [&mut Dev], now: u64) {
    for d in to.iter_mut() {
        for it in items {
            d.ingest(it, 0, now);
        }
    }
}

/// Builds sealed items by hand, for an author that is not a `Replica`: valid
/// ones, and ones broken in a chosen way.
pub struct Forge {
    pub key: FragmentKey,
    pub fragment_id: Vec<u8>,
    pub signer: SigningKey,
    pub genesis: Vec<u8>,
    pub log: KeyLog,
    pub rng: Rng,
}

impl Forge {
    pub fn new(root: [u8; 32], seed: u8) -> Forge {
        let pairing = Pairing::from_root(root);
        Forge::for_fragment(
            pairing.fragment_key(),
            pairing.fragment_id().to_vec(),
            pairing.fragment_id().to_vec(),
            seed,
        )
    }

    /// `sealed_for` is the fragment id in the sealed header and in ops;
    /// `genesis_for` the one the author's key log is bound to.
    pub fn for_fragment(
        key: FragmentKey,
        sealed_for: Vec<u8>,
        genesis_for: Vec<u8>,
        seed: u8,
    ) -> Forge {
        let signer = SigningKey::from_seed(SigAlg::Ed25519, &[seed; 32]);
        let genesis = KeyLogEntry {
            hash_alg: 1,
            prev: None,
            action: KeyLogAction::Genesis {
                fragment_id: genesis_for,
                keys: vec![signer.public()],
                policy: vec![1],
            },
        }
        .sign(&[&signer])
        .unwrap();
        let log = KeyLog::genesis(&genesis).unwrap();
        Forge {
            key,
            fragment_id: sealed_for,
            signer,
            genesis,
            log,
            rng: Rng(0xF0F0_F0F0 ^ u64::from(seed)),
        }
    }

    pub fn author(&self) -> Multihash {
        self.log.author().clone()
    }

    pub fn seal(&mut self, plain: &Plain) -> Vec<u8> {
        SealedOp::seal(&self.key, &self.fragment_id, self.rng.nonce(), plain)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    pub fn sealed_genesis(&mut self) -> Vec<u8> {
        let g = self.genesis.clone();
        self.seal(&Plain::KeyLog(g))
    }

    pub fn body(
        &self,
        seq: u64,
        prev: Option<&Op>,
        wall_ms: u64,
        deps: Vec<Multihash>,
        payload: Value,
    ) -> OpBody {
        OpBody {
            hash_alg: 1,
            fragment_id: self.fragment_id.clone(),
            author: self.author(),
            seq,
            prev: prev.map(|p| p.id().clone()),
            hlc: Hlc {
                wall_ms,
                counter: 0,
            },
            deps,
            payload,
        }
    }

    pub fn sign(&self, body: &OpBody) -> Op {
        Op::sign(body, &[&self.signer]).unwrap()
    }

    /// A valid signed op carrying `changes`.
    pub fn op(&self, seq: u64, prev: Option<&Op>, wall_ms: u64, changes: &[Change]) -> Op {
        self.sign(&self.body(seq, prev, wall_ms, vec![], encode_payload(changes).unwrap()))
    }

    pub fn sealed_op(&mut self, op: &Op) -> Vec<u8> {
        let bytes = op.to_bytes().unwrap();
        self.seal(&Plain::Op(bytes))
    }
}
