//! Shared helpers for the integration tests.
#![allow(dead_code)]

use gsp_relay::{Config, MemStore, Relay};
use gsp_wire::{FragmentKey, Message, Plain, SealedOp};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Deterministic PRNG (splitmix64). Tests only; never for real nonces.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 8);
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

/// A paired fragment as SYNC-V0 section 2 derives it from a root secret.
pub struct Fragment {
    pub id: Vec<u8>,
    pub key: FragmentKey,
    pub token: [u8; 32],
    rng: std::sync::Mutex<Rng>,
}

impl Fragment {
    pub fn new(seed: u64) -> Fragment {
        Fragment::with_stream(seed, 0)
    }

    /// Same fragment as `new(seed)`, with its own stream of test nonces.
    pub fn with_stream(seed: u64, stream: u64) -> Fragment {
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&seed.to_le_bytes());
        Fragment {
            id: blake3::derive_key("gsp/v0/fragment-id", &root)[..16].to_vec(),
            key: FragmentKey::new(blake3::derive_key("gsp/v0/fragment-key", &root)),
            token: blake3::derive_key("gsp/v0/relay-token", &root),
            rng: std::sync::Mutex::new(Rng(seed ^ 0xA5A5_A5A5 ^ (stream << 32))),
        }
    }

    /// Seal `plaintext` as a signed-op payload with a fresh test nonce.
    pub fn seal(&self, plaintext: &[u8]) -> SealedOp {
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&self.rng.lock().unwrap().bytes(24));
        SealedOp::seal(&self.key, &self.id, nonce, &Plain::Op(plaintext.to_vec())).unwrap()
    }

    pub fn seal_n(&self, n: usize, size: usize) -> Vec<SealedOp> {
        (0..n)
            .map(|_| {
                let pt = self.rng.lock().unwrap().bytes(size);
                self.seal(&pt)
            })
            .collect()
    }

    pub fn bearer(&self) -> String {
        format!("Bearer {}", b64url(&self.token))
    }

    pub fn push_bytes(&self, sealed: Vec<SealedOp>) -> Vec<u8> {
        Message::Push {
            fragment_id: self.id.clone(),
            sealed,
        }
        .to_bytes()
        .unwrap()
    }

    pub fn pull_bytes(&self, after: u64, limit: u32) -> Vec<u8> {
        Message::Pull {
            fragment_id: self.id.clone(),
            after,
            limit,
        }
        .to_bytes()
        .unwrap()
    }
}

pub fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

pub fn mem_relay(cfg: Config) -> Relay {
    Relay::new(cfg, MemStore::new()).unwrap()
}

pub fn post(path: &str, auth: Option<&str>, body: Vec<u8>) -> Request<Full<Bytes>> {
    let mut b = Request::post(path).header("content-type", "application/cbor");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Full::new(Bytes::from(body))).unwrap()
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: hyper::HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn message(&self) -> Message {
        Message::from_bytes(&self.body).expect("reply body is a frame")
    }
    /// Assert an error reply: status, and an `Error` frame carrying it.
    pub fn assert_error(&self, status: u16) {
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.headers["content-type"], "application/cbor");
        match self.message() {
            Message::Error { code, .. } => assert_eq!(code, status),
            other => panic!("expected Error frame, got {other:?}"),
        }
    }
}

pub async fn collect(resp: Response<gsp_relay::http::ReplyBody>) -> Reply {
    let (parts, body) = resp.into_parts();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes().to_vec(),
    }
}

pub async fn call(relay: &Relay, req: Request<Full<Bytes>>) -> Reply {
    collect(relay.handle(req).await).await
}

/// Push and return `(cursor, count)` from the `Ack`.
pub async fn push(relay: &Relay, f: &Fragment, sealed: Vec<SealedOp>) -> (u64, u32) {
    let r = call(
        relay,
        post("/v0/push", Some(&f.bearer()), f.push_bytes(sealed)),
    )
    .await;
    assert_eq!(r.status, 200, "push failed: {:?}", r.message());
    match r.message() {
        Message::Ack {
            fragment_id,
            cursor,
            count,
        } => {
            assert_eq!(fragment_id, f.id);
            (cursor, count)
        }
        other => panic!("expected Ack, got {other:?}"),
    }
}

/// Pull and return `(next, more, sealed)` from the `Batch`.
pub async fn pull(
    relay: &Relay,
    f: &Fragment,
    after: u64,
    limit: u32,
    wait_ms: u64,
) -> (u64, bool, Vec<SealedOp>) {
    let path = format!("/v0/pull?wait_ms={wait_ms}");
    let r = call(
        relay,
        post(&path, Some(&f.bearer()), f.pull_bytes(after, limit)),
    )
    .await;
    assert_eq!(r.status, 200, "pull failed: {:?}", r.message());
    batch(r.message(), f)
}

pub fn batch(m: Message, f: &Fragment) -> (u64, bool, Vec<SealedOp>) {
    match m {
        Message::Batch {
            fragment_id,
            next,
            more,
            sealed,
        } => {
            assert_eq!(fragment_id, f.id);
            (next, more, sealed)
        }
        other => panic!("expected Batch, got {other:?}"),
    }
}

/// Fresh directory under the system temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gsp-relay-test-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    /// The only `.log` file in the store (tests that use one fragment).
    pub fn only_log(&self) -> PathBuf {
        let mut logs: Vec<PathBuf> = std::fs::read_dir(self.0.join("fragments"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "log"))
            .collect();
        assert_eq!(logs.len(), 1);
        logs.pop().unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
