//! Regression tests for the resource-exhaustion findings of the security
//! review. Each asserts the outcome a hostile client must NOT be able to
//! change.

mod common;

use common::*;
use gsp_relay::{
    Config, DirStore, Fsync, LoadedFragment, MemStore, Relay, Secret, Store, TokenHash,
};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

fn dir_relay(dir: &TempDir, cfg: Config) -> Relay {
    Relay::new(cfg, DirStore::open(dir.path(), Fsync::Always).unwrap()).unwrap()
}

fn files_in(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.path().join("fragments"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Finding 1. Strangers long-polling fragment ids nobody registered used to
/// take every relay-wide long-poll slot, so the owner got 429.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strangers_cannot_occupy_long_poll_slots() {
    let cfg = Config {
        max_polls: 16,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let owner = Fragment::new(1);
    push(&relay, &owner, owner.seal_n(1, 10)).await;

    // 64 strangers, four times the global cap, each asking to be held 25 s.
    let started = Instant::now();
    for i in 0..64u64 {
        let stranger = Fragment::new(1000 + i);
        let r = call(
            &relay,
            post(
                "/v0/pull?wait_ms=25000",
                Some(&stranger.bearer()),
                stranger.pull_bytes(0, 0),
            ),
        )
        .await;
        // Answered at once with the empty Batch; not held, not registered.
        assert_eq!(r.status, 200);
        assert_eq!(batch(r.message(), &stranger), (0, false, vec![]));
        assert_eq!(relay.poll_count(), 0);
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(relay.fragment_count(), 1);

    // A stranger's long-poll on the owner's fragment is a 401, not a slot.
    let stranger = Fragment::new(2);
    call(
        &relay,
        post(
            "/v0/pull?wait_ms=25000",
            Some(&stranger.bearer()),
            owner.pull_bytes(1, 0),
        ),
    )
    .await
    .assert_error(401);
    assert_eq!(relay.poll_count(), 0);

    // The owner's long-poll is accepted and held, then woken by a push.
    let waiter = {
        let relay = relay.clone();
        let req = post(
            "/v0/pull?wait_ms=25000",
            Some(&owner.bearer()),
            owner.pull_bytes(1, 0),
        );
        tokio::spawn(async move { call(&relay, req).await })
    };
    while relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let item = owner.seal_n(1, 10);
    push(&relay, &owner, item.clone()).await;
    let reply = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch(reply.message(), &owner), (2, false, item));
}

/// Finding 2. A refused first push used to register the fragment anyway
/// (and create a file); 50 refused pushes left 50 fragments.
#[tokio::test]
async fn refused_first_pushes_leave_no_trace() {
    let cfg = Config {
        total_quota_bytes: 4 * 1024 * 1024,
        fragment_quota_bytes: 512 * 1024,
        max_fragments: 30,
        ..Config::default()
    };
    let dir = TempDir::new();
    let mem = Arc::new(MemStore::new());
    let relays = [
        Relay::new(cfg.clone(), mem.clone()).unwrap(),
        dir_relay(&dir, cfg.clone()),
    ];
    for relay in &relays {
        let owner = Fragment::new(1);
        push(relay, &owner, owner.seal_n(1, 10)).await;

        // Strangers fill the relay-wide quota (this is still possible on an
        // open relay; see the registration secret test for the remedy).
        let mut strangers = 0u64;
        loop {
            let s = Fragment::new(5000 + strangers);
            let body = s.push_bytes(s.seal_n(1, 200_000));
            let r = call(relay, post("/v0/push", Some(&s.bearer()), body)).await;
            if r.status != 200 {
                r.assert_error(507);
                break;
            }
            strangers += 1;
        }
        assert!(strangers > 0);
        let before = relay.fragment_count();
        assert_eq!(before as u64, strangers + 1);
        let held_before = mem.dump().len();
        let files_before = files_in(&dir);

        // 50 more first pushes, refused in three different ways.
        for j in 0..50u64 {
            let s = Fragment::new(90_000 + j);
            let (body, status) = match j % 3 {
                // Relay-wide quota.
                0 => (s.push_bytes(s.seal_n(1, 200_000)), 507),
                // Per-fragment quota: 3 x 200 KB is over 512 KiB.
                1 => (s.push_bytes(s.seal_n(3, 200_000)), 413),
                // An item addressed to another fragment.
                _ => {
                    let other = Fragment::new(1);
                    (s.push_bytes(other.seal_n(1, 10)), 400)
                }
            };
            let r = call(relay, post("/v0/push", Some(&s.bearer()), body)).await;
            assert_eq!(r.status.as_u16(), status, "case {j}");
            // Not registered: the same id still answers like an unknown one.
            assert_eq!(pull(relay, &s, 0, 0, 0).await, (0, false, vec![]));
        }
        assert_eq!(relay.fragment_count(), before);
        assert_eq!(mem.dump().len(), held_before);
        assert_eq!(files_in(&dir), files_before);

        // Refused pushes reserved no quota: a tiny first push still fits
        // only if there is room, and the owner's fragment still works.
        assert_eq!(push(relay, &owner, owner.seal_n(1, 10)).await, (2, 1));
    }

    // The fragment-count cap is checked before anything is created too.
    let dir2 = TempDir::new();
    let relay2 = dir_relay(
        &dir2,
        Config {
            max_fragments: 1,
            ..Config::default()
        },
    );
    let a = Fragment::new(1);
    push(&relay2, &a, a.seal_n(1, 10)).await;
    let files = files_in(&dir2);
    for j in 0..20u64 {
        let s = Fragment::new(200 + j);
        call(
            &relay2,
            post("/v0/push", Some(&s.bearer()), s.push_bytes(s.seal_n(1, 10))),
        )
        .await
        .assert_error(507);
    }
    assert_eq!(relay2.fragment_count(), 1);
    assert_eq!(files_in(&dir2), files);

    // And nothing comes back after a restart.
    drop(relays);
    let reopened = dir_relay(&dir, cfg);
    assert_eq!(reopened.fragment_count(), files_in(&dir).len());
}

/// A store whose `create` or `append` can be made to fail or to block.
#[derive(Default)]
struct Faulty {
    inner: MemStore,
    fail_append: Mutex<bool>,
    gate: Mutex<bool>,
    opened: Condvar,
    entered: Mutex<usize>,
}

impl Store for Faulty {
    fn load(&self) -> std::io::Result<Vec<LoadedFragment>> {
        self.inner.load()
    }
    fn create(&self, id: &[u8], token: &TokenHash) -> std::io::Result<()> {
        self.inner.create(id, token)
    }
    fn append(&self, id: &[u8], first: u64, items: &[Vec<u8>]) -> std::io::Result<()> {
        *self.entered.lock().unwrap() += 1;
        let mut closed = self.gate.lock().unwrap();
        while *closed {
            closed = self.opened.wait(closed).unwrap();
        }
        if *self.fail_append.lock().unwrap() {
            return Err(std::io::Error::other("disk on fire"));
        }
        self.inner.append(id, first, items)
    }
    fn remove(&self, id: &[u8]) -> std::io::Result<()> {
        self.inner.remove(id)
    }
    fn read(&self, id: &[u8], after: u64, n: usize, b: usize) -> std::io::Result<Vec<Vec<u8>>> {
        self.inner.read(id, after, n, b)
    }
}

/// Finding 2, storage-failure variant: a first push that fails in the store
/// is rolled back completely.
#[tokio::test]
async fn first_push_that_fails_in_the_store_is_rolled_back() {
    let store = Arc::new(Faulty::default());
    let relay = Relay::new(Config::default(), store.clone()).unwrap();
    let f = Fragment::new(1);
    let items = f.seal_n(2, 100);

    *store.fail_append.lock().unwrap() = true;
    call(
        &relay,
        post("/v0/push", Some(&f.bearer()), f.push_bytes(items.clone())),
    )
    .await
    .assert_error(500);
    assert_eq!(relay.fragment_count(), 0);
    assert!(store.inner.dump().is_empty());

    // Not registered: another token may still claim the id, and the quota
    // reserved for the failed push was given back.
    *store.fail_append.lock().unwrap() = false;
    assert_eq!(push(&relay, &f, items).await, (2, 2));
}

/// Finding 3. Bodies of the wrong shape are turned away by an
/// allocation-free scan, before authentication state is consulted and
/// before any full decode. These are the reviewer's two bodies.
#[tokio::test]
async fn adversarial_bodies_are_rejected_before_decoding() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(1);

    // [3, h'01', [ {"":null, "":null, ...} ]]: half a million duplicate keys.
    let n: usize = (1024 * 1024 - 32) / 2;
    let mut map_body = vec![0x83, 0x03, 0x41, 0x01, 0x81, 0xba];
    map_body.extend_from_slice(&(n as u32).to_be_bytes());
    for _ in 0..n {
        map_body.extend_from_slice(&[0x60, 0xf6]);
    }
    // [3, h'01', [null x ~1M]].
    let n: usize = 1024 * 1024 - 16;
    let mut array_body = vec![0x83, 0x03, 0x41, 0x01, 0x9a];
    array_body.extend_from_slice(&(n as u32).to_be_bytes());
    array_body.extend(std::iter::repeat_n(0xf6, n));
    // Deep nesting, and a bstr that claims more than the body holds.
    let nested = [vec![0x83, 0x03, 0x41, 0x01], vec![0x81; 100_000]].concat();
    let liar = vec![
        0x83, 0x03, 0x41, 0x01, 0x81, 0x85, 0x00, 0x01, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    for (name, body, status) in [
        ("map", map_body, 400),
        // More than 64 "items": refused on the count alone.
        ("array", array_body, 413),
        ("nested", nested, 400),
        ("liar", liar, 400),
    ] {
        assert!(body.len() <= 1024 * 1024, "{name} fits the request limit");
        let started = Instant::now();
        let r = call(&relay, post("/v0/push", Some(&f.bearer()), body)).await;
        assert_eq!(r.status.as_u16(), status, "{name}");
        // Generous bound; the scan itself reads a handful of bytes. The
        // unpatched path took ~200 ms per body in a debug build.
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "{name} took {:?}",
            started.elapsed()
        );
    }
    assert_eq!(relay.fragment_count(), 0);
}

/// Finding 3. A wrong relay token, or a missing registration secret, is
/// refused before the body is decoded: the reply is 401/403 even when the
/// body would fail a full decode.
#[tokio::test]
async fn authentication_comes_before_decoding() {
    let relay = mem_relay(Config {
        registration_token: Some(Secret::new("letmein")),
        ..Config::default()
    });
    let f = Fragment::new(1);
    let stranger = Fragment::new(2);
    let reg = |f: &Fragment, body: Vec<u8>| {
        let mut req = post("/v0/push", Some(&f.bearer()), body);
        req.headers_mut()
            .insert("x-gsp-registration", "letmein".parse().unwrap());
        req
    };
    assert_eq!(
        call(&relay, reg(&f, f.push_bytes(f.seal_n(1, 10))))
            .await
            .status,
        200
    );

    // Right outer shape, but not canonical CBOR inside (uint 0 encoded in
    // two bytes): the strict decoder would say 400.
    let mut bad = f.push_bytes(f.seal_n(1, 10));
    let at = bad.windows(2).position(|w| w == [0x85, 0x00]).unwrap();
    bad.splice(at + 1..at + 2, [0x18, 0x00]);
    assert_eq!(
        call(&relay, post("/v0/push", Some(&f.bearer()), bad.clone()))
            .await
            .status,
        400
    );
    // The stranger never gets that far.
    call(
        &relay,
        post("/v0/push", Some(&stranger.bearer()), bad.clone()),
    )
    .await
    .assert_error(401);
    // Nor does an unregistered fragment without the registration secret.
    let mut bad2 = stranger.push_bytes(stranger.seal_n(1, 10));
    let at = bad2.windows(2).position(|w| w == [0x85, 0x00]).unwrap();
    bad2.splice(at + 1..at + 2, [0x18, 0x00]);
    call(&relay, post("/v0/push", Some(&stranger.bearer()), bad2))
        .await
        .assert_error(403);
}

/// Finding 3. The bytes being decoded and processed at once are bounded;
/// past the budget the answer is 503 with `retry-after`, not a queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decode_budget_is_bounded() {
    let store = Arc::new(Faulty::default());
    let cfg = Config {
        max_request_bytes: 4096,
        max_decode_bytes: 4096,
        ..Config::default()
    };
    let relay = Relay::new(cfg, store.clone()).unwrap();
    let f = Fragment::new(1);
    push(&relay, &f, f.seal_n(1, 10)).await;

    // First push (about 3 KiB) is decoded, then parks inside the store.
    *store.gate.lock().unwrap() = true;
    let entered = *store.entered.lock().unwrap();
    let first = {
        let relay = relay.clone();
        let req = post(
            "/v0/push",
            Some(&f.bearer()),
            f.push_bytes(f.seal_n(1, 3000)),
        );
        tokio::spawn(async move { call(&relay, req).await })
    };
    while *store.entered.lock().unwrap() == entered {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // A second 3 KiB push does not fit in what is left of the 4 KiB budget.
    let second = f.push_bytes(f.seal_n(1, 3000));
    let r = call(&relay, post("/v0/push", Some(&f.bearer()), second.clone())).await;
    r.assert_error(503);
    assert_eq!(r.headers["retry-after"], "1");
    // Once the first one finishes, the budget is free again.
    *store.gate.lock().unwrap() = false;
    store.opened.notify_all();
    assert_eq!(first.await.unwrap().status, 200);
    let r = call(&relay, post("/v0/push", Some(&f.bearer()), second)).await;
    assert_eq!(r.status, 200);
}

/// Finding 4a. With a registration secret set, only its holders can create
/// fragments; strangers cannot fill the relay.
#[tokio::test]
async fn registration_secret_closes_registration() {
    let dir = TempDir::new();
    let cfg = Config {
        registration_token: Some(Secret::new("operator-secret-1")),
        total_quota_bytes: 4 * 1024 * 1024,
        ..Config::default()
    };
    let relay = dir_relay(&dir, cfg.clone());
    let with = |f: &Fragment, secret: Option<&str>, body: Vec<u8>| {
        let mut req = post("/v0/push", Some(&f.bearer()), body);
        if let Some(s) = secret {
            req.headers_mut()
                .insert("x-gsp-registration", s.parse().unwrap());
        }
        req
    };

    // Strangers: no secret, wrong secret, a prefix, the secret with a suffix.
    for (i, secret) in [
        None,
        Some("guess"),
        Some("operator-secret-"),
        Some("operator-secret-12"),
    ]
    .into_iter()
    .enumerate()
    {
        let s = Fragment::new(100 + i as u64);
        let r = call(&relay, with(&s, secret, s.push_bytes(s.seal_n(1, 200_000)))).await;
        r.assert_error(403);
        // Also for an empty push, which would register nothing anyway.
        call(&relay, with(&s, secret, s.push_bytes(vec![])))
            .await
            .assert_error(403);
    }
    assert_eq!(relay.fragment_count(), 0);
    assert!(files_in(&dir).is_empty());

    // The owner registers with the secret...
    let owner = Fragment::new(1);
    let items = owner.seal_n(2, 100);
    let r = call(
        &relay,
        with(
            &owner,
            Some("operator-secret-1"),
            owner.push_bytes(items.clone()),
        ),
    )
    .await;
    assert_eq!(r.status, 200);
    // ...and from then on needs only the relay token, as does every other
    // device of the fragment. Pulls never need the secret.
    assert_eq!(push(&relay, &owner, owner.seal_n(1, 100)).await, (3, 1));
    assert_eq!(pull(&relay, &owner, 0, 2, 0).await, (2, true, items));
    // The secret does not replace the relay token on an existing fragment.
    let stranger = Fragment::new(2);
    let mut req = post(
        "/v0/push",
        Some(&stranger.bearer()),
        owner.push_bytes(owner.seal_n(1, 10)),
    );
    req.headers_mut()
        .insert("x-gsp-registration", "operator-secret-1".parse().unwrap());
    call(&relay, req).await.assert_error(401);

    // Existing fragments keep working if the secret is changed or removed,
    // and after a restart.
    drop(relay);
    let relay = dir_relay(
        &dir,
        Config {
            registration_token: Some(Secret::new("rotated")),
            ..cfg
        },
    );
    assert_eq!(push(&relay, &owner, owner.seal_n(1, 100)).await, (4, 1));

    // The secret is nowhere on disk.
    for name in files_in(&dir) {
        let bytes = std::fs::read(dir.path().join("fragments").join(name)).unwrap();
        assert!(!contains(&bytes, b"operator-secret-1"));
    }
}

/// Finding 4b. A fragment with zero items cannot exist while the relay
/// runs (registration and the first item are one step), so the only way to
/// get one is a crash between the two. Such leftovers are removed at
/// startup instead of coming back as registrations.
#[tokio::test]
async fn empty_fragments_are_not_resurrected_by_a_restart() {
    let dir = TempDir::new();
    let ghost = Fragment::new(1);
    let torn = Fragment::new(2);
    let real = Fragment::new(3);
    let real_items = real.seal_n(2, 50);
    {
        // "Crash" right after the fragment file was created.
        let store = DirStore::open(dir.path(), Fsync::Always).unwrap();
        store.load().unwrap();
        store.create(&ghost.id, &[9u8; 32]).unwrap();
    }
    {
        let relay = dir_relay(&dir, Config::default());
        // The ghost was already purged by this start.
        assert_eq!(relay.fragment_count(), 0);
        push(&relay, &torn, torn.seal_n(1, 300)).await;
        push(&relay, &real, real_items.clone()).await;
    }
    assert_eq!(files_in(&dir).len(), 2);
    // "Crash" in the middle of `torn`'s first and only record.
    let hex: String = torn.id.iter().map(|b| format!("{b:02x}")).collect();
    let log = dir.path().join("fragments").join(format!("{hex}.log"));
    let len = std::fs::metadata(&log).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(len - 50)
        .unwrap();

    let relay = dir_relay(&dir, Config::default());
    assert_eq!(relay.fragment_count(), 1);
    assert_eq!(files_in(&dir).len(), 1);
    assert_eq!(pull(&relay, &real, 0, 0, 0).await, (2, false, real_items));
    // The ids are free again: no stale token hash blocks their owners.
    assert_eq!(pull(&relay, &ghost, 0, 0, 0).await, (0, false, vec![]));
    assert_eq!(push(&relay, &ghost, ghost.seal_n(1, 10)).await, (1, 1));
    assert_eq!(push(&relay, &torn, torn.seal_n(1, 10)).await, (1, 1));
    drop(relay);
    assert_eq!(dir_relay(&dir, Config::default()).fragment_count(), 3);
}

/// Finding 6. A relay that lost its data numbers items from 1 again while
/// clients hold higher cursors. The signal a client gets: a pull with
/// `after` beyond the head is answered at once, never held, with an empty
/// Batch whose `next` is the relay's head (so `next < after`).
#[tokio::test]
async fn a_cursor_beyond_the_head_is_answered_at_once_with_the_head() {
    let f = Fragment::new(1);
    let old = mem_relay(Config::default());
    assert_eq!(push(&old, &f, f.seal_n(5, 10)).await, (5, 5));
    assert_eq!(pull(&old, &f, 0, 0, 0).await.0, 5);

    // The relay is replaced by an empty one. The client still has cursor 5.
    let new = mem_relay(Config::default());
    let timed_pull = |relay: Relay, after: u64| {
        let f = Fragment::new(1);
        async move {
            let started = Instant::now();
            let got = pull(&relay, &f, after, 0, 25_000).await;
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "pull was held for {:?}",
                started.elapsed()
            );
            assert_eq!(relay.poll_count(), 0);
            got
        }
    };
    // Fragment unknown to the new relay: next = 0 < 5.
    assert_eq!(timed_pull(new.clone(), 5).await, (0, false, vec![]));

    // Another device re-registers and pushes two items: head is 2.
    let items = f.seal_n(2, 10);
    assert_eq!(push(&new, &f, items.clone()).await, (2, 2));
    // Still ahead of the relay: answered at once, next = 2 < 5, although
    // items the client has never seen exist at cursors 1 and 2.
    assert_eq!(timed_pull(new.clone(), 5).await, (2, false, vec![]));
    assert_eq!(timed_pull(new.clone(), 3).await, (2, false, vec![]));
    // The client reacts by pulling from 0 and gets them.
    assert_eq!(pull(&new, &f, 0, 0, 0).await, (2, false, items));

    // Exactly at the head is the normal case and is held.
    let started = Instant::now();
    assert_eq!(pull(&new, &f, 2, 0, 300).await, (2, false, vec![]));
    assert!(started.elapsed() >= Duration::from_millis(290));
}

/// Finding 7. Two relays cannot open one data directory.
#[tokio::test]
async fn data_directory_is_locked() {
    let dir = TempDir::new();
    let first = DirStore::open(dir.path(), Fsync::Always).unwrap();
    let err = DirStore::open(dir.path(), Fsync::Always).err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy);
    assert!(err.to_string().contains("in use"));
    assert!(dir.path().join("LOCK").exists());

    // Still locked while a relay built on it is alive, including clones.
    let relay = Relay::new(Config::default(), first).unwrap();
    let clone = relay.clone();
    drop(relay);
    assert!(DirStore::open(dir.path(), Fsync::Always).is_err());
    drop(clone);

    // Released with the last handle; a leftover LOCK file does not block.
    assert!(dir.path().join("LOCK").exists());
    let again = dir_relay(&dir, Config::default());
    let f = Fragment::new(1);
    assert_eq!(push(&again, &f, f.seal_n(1, 10)).await, (1, 1));
}
