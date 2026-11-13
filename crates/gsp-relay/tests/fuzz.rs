//! Fuzz-style tests: random, truncated and mutated bodies on both endpoints
//! must never panic and never produce a 5xx.

mod common;

use common::*;
use gsp_relay::{Config, DirStore, Fsync, Relay};

async fn status(relay: &Relay, path: &str, auth: Option<&str>, body: Vec<u8>) -> u16 {
    call(relay, post(path, auth, body)).await.status.as_u16()
}

#[tokio::test]
async fn random_bodies_get_4xx() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(1);
    let auth = f.bearer();
    let mut rng = Rng(0xF00D);
    for i in 0..3000 {
        let len = match i % 4 {
            0 => rng.below(8),
            1 => rng.below(64),
            2 => rng.below(600),
            _ => rng.below(3000),
        };
        let mut body = rng.bytes(len);
        if i % 3 == 0 && !body.is_empty() {
            // Start like a frame: array header, then a plausible type.
            body[0] = 0x80 | (rng.below(8) as u8);
            if body.len() > 1 {
                body[1] = rng.below(10) as u8;
            }
        }
        for path in ["/v0/push", "/v0/pull", "/v0/pull?wait_ms=1"] {
            let s = status(&relay, path, Some(&auth), body.clone()).await;
            assert!(
                (400..500).contains(&s),
                "{path}: status {s} for {body:02x?}"
            );
        }
    }
    assert_eq!(relay.fragment_count(), 0);
}

#[tokio::test]
async fn truncated_frames_get_4xx() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(2);
    let auth = f.bearer();
    let push_body = f.push_bytes(f.seal_n(3, 40));
    let pull_body = f.pull_bytes(7, 9);
    for (path, body) in [("/v0/push", &push_body), ("/v0/pull", &pull_body)] {
        for cut in 0..body.len() {
            let s = status(&relay, path, Some(&auth), body[..cut].to_vec()).await;
            assert_eq!(s, 400, "{path} cut at {cut}");
        }
        // Each frame sent to the other endpoint, whole and truncated.
        let other = if path == "/v0/push" {
            "/v0/pull"
        } else {
            "/v0/push"
        };
        for cut in 0..=body.len() {
            let s = status(&relay, other, Some(&auth), body[..cut].to_vec()).await;
            assert_eq!(s, 400, "{other} cut at {cut}");
        }
    }
    assert_eq!(relay.fragment_count(), 0);
}

#[tokio::test]
async fn mutated_frames_never_cause_a_server_error() {
    // Durable store, so mutated-but-valid pushes also exercise the log.
    let dir = TempDir::new();
    let relay = Relay::new(
        Config::default(),
        DirStore::open(dir.path(), Fsync::Never).unwrap(),
    )
    .unwrap();
    let f = Fragment::new(3);
    let auth = f.bearer();
    let push_body = f.push_bytes(f.seal_n(3, 40));
    let pull_body = f.pull_bytes(0, 9);
    let mut rng = Rng(0xBEEF);
    let mut ok = 0;
    for i in 0..4000 {
        let (path, base) = if i % 2 == 0 {
            ("/v0/push", &push_body)
        } else {
            ("/v0/pull", &pull_body)
        };
        let mut body = base.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(body.len());
            match rng.below(4) {
                0 => body[at] ^= 1 << rng.below(8),
                1 => body[at] = rng.next() as u8,
                2 => {
                    body.remove(at);
                }
                _ => body.insert(at, rng.next() as u8),
            }
            if body.is_empty() {
                body.push(0);
            }
        }
        let s = status(&relay, path, Some(&auth), body.clone()).await;
        assert!(
            s == 200 || (400..500).contains(&s),
            "{path}: status {s} for {body:02x?}"
        );
        ok += usize::from(s == 200);
    }
    // Some mutations (a flipped ciphertext bit, a changed cursor) are still
    // valid frames; the relay cannot and need not tell.
    assert!(ok > 0);

    // The log is still consistent: it reopens and pages to the end.
    drop(relay);
    let relay = Relay::new(
        Config::default(),
        DirStore::open(dir.path(), Fsync::Never).unwrap(),
    )
    .unwrap();
    let (mut after, mut total) = (0, 0);
    loop {
        let (next, more, got) = pull(&relay, &f, after, 0, 0).await;
        total += got.len();
        after = next;
        if !more {
            break;
        }
    }
    assert_eq!(total as u64, after);
}

#[tokio::test]
async fn random_headers_and_queries_get_4xx() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(4);
    let body = f.pull_bytes(0, 1);
    let mut rng = Rng(0xCAFE);
    for _ in 0..2000 {
        // Random printable authorization values and query strings.
        let auth: String = (0..rng.below(80))
            .map(|_| (0x20 + rng.below(0x5f) as u8) as char)
            .collect();
        let query: String = (0..rng.below(30))
            .map(|_| b"wait_ms=&0123456789-x%"[rng.below(22)] as char)
            .collect();
        let path = format!("/v0/pull?{query}");
        let s = status(&relay, &path, Some(auth.trim()), body.clone()).await;
        assert!(
            (400..500).contains(&s),
            "status {s} for auth {auth:?} query {query:?}"
        );
    }
}
