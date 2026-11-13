//! In-process tests of the relay's HTTP behaviour (SYNC-V0 section 6),
//! driving `Relay::handle` directly with the in-memory store.

mod common;

use common::*;
use gsp_relay::{Config, DirStore, Fsync, MemStore, Relay};
use gsp_wire::{Message, Plain};
use http_body_util::Full;
use hyper::body::{Body, Bytes, Frame};
use hyper::{Method, Request};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

#[tokio::test]
async fn push_pull_round_trip_and_cursor_semantics() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(1);
    let items = f.seal_n(3, 100);

    assert_eq!(push(&relay, &f, items.clone()).await, (3, 3));

    // `after` is exclusive; items are numbered from 1.
    let (next, more, got) = pull(&relay, &f, 0, 100, 0).await;
    assert_eq!((next, more), (3, false));
    assert_eq!(got, items);

    let (next, more, got) = pull(&relay, &f, 1, 100, 0).await;
    assert_eq!((next, more), (3, false));
    assert_eq!(got, items[1..]);

    // Limit: one item, more to come, `next` is the cursor of the last item.
    let (next, more, got) = pull(&relay, &f, 0, 1, 0).await;
    assert_eq!((next, more), (1, true));
    assert_eq!(got, items[..1]);

    // Caught up, and past the end: empty, `next` is the head.
    assert_eq!(pull(&relay, &f, 3, 100, 0).await, (3, false, vec![]));
    assert_eq!(pull(&relay, &f, 99, 100, 0).await, (3, false, vec![]));

    // A second push continues the numbering.
    let more_items = f.seal_n(2, 10);
    assert_eq!(push(&relay, &f, more_items.clone()).await, (5, 2));
    let (next, _, got) = pull(&relay, &f, 3, 0, 0).await;
    assert_eq!(next, 5);
    assert_eq!(got, more_items);

    // An empty push is acknowledged with the current head.
    assert_eq!(push(&relay, &f, vec![]).await, (5, 0));
}

#[tokio::test]
async fn fragments_are_numbered_independently() {
    let relay = mem_relay(Config::default());
    let a = Fragment::new(1);
    let b = Fragment::new(2);
    assert_eq!(push(&relay, &a, a.seal_n(2, 10)).await, (2, 2));
    let b_items = b.seal_n(1, 10);
    assert_eq!(push(&relay, &b, b_items.clone()).await, (1, 1));
    assert_eq!(pull(&relay, &b, 0, 0, 0).await, (1, false, b_items));
}

#[tokio::test]
async fn more_flag_pages_by_item_count_and_by_bytes() {
    let cfg = Config {
        max_batch_items: 4,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let f = Fragment::new(3);
    let items = f.seal_n(10, 50);
    push(&relay, &f, items.clone()).await;

    let mut after = 0;
    let mut seen = Vec::new();
    let mut pages = Vec::new();
    loop {
        // Ask for more than the relay's Batch limit: it is clamped.
        let (next, more, got) = pull(&relay, &f, after, 1000, 0).await;
        assert_eq!(next, after + got.len() as u64);
        pages.push(got.len());
        seen.extend(got);
        after = next;
        if !more {
            break;
        }
    }
    assert_eq!(pages, [4, 4, 2]);
    assert_eq!(seen, items);

    // Byte cap: each item is about 600 bytes, the cap fits two.
    let cfg = Config {
        max_batch_bytes: 1300,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let items = f.seal_n(5, 550);
    push(&relay, &f, items.clone()).await;
    let (next, more, got) = pull(&relay, &f, 0, 0, 0).await;
    assert_eq!((next, more, got.len()), (2, true, 2));

    // An item larger than the byte cap is still delivered, alone.
    let cfg = Config {
        max_batch_bytes: 10,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    push(&relay, &f, items.clone()).await;
    let (next, more, got) = pull(&relay, &f, 0, 0, 0).await;
    assert_eq!((next, more, got.len()), (1, true, 1));
}

#[tokio::test]
async fn byte_identical_items_are_stored_once() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(4);
    let items = f.seal_n(3, 40);

    assert_eq!(push(&relay, &f, items.clone()).await, (3, 3));
    // Same bytes again: accepted (count 3), nothing stored (cursor still 3).
    assert_eq!(push(&relay, &f, items.clone()).await, (3, 3));
    // A mix: one old, one new, the new one twice in the same push.
    let new = f.seal_n(1, 40);
    let mixed = vec![items[0].clone(), new[0].clone(), new[0].clone()];
    assert_eq!(push(&relay, &f, mixed).await, (4, 3));

    let (next, more, got) = pull(&relay, &f, 0, 0, 0).await;
    assert_eq!((next, more), (4, false));
    assert_eq!(got, [items.clone(), new].concat());

    // Same plaintext sealed under a new nonce is a different item.
    let a = f.seal(b"same plaintext");
    let b = f.seal(b"same plaintext");
    assert_ne!(a, b);
    assert_eq!(push(&relay, &f, vec![a, b]).await, (6, 2));
}

#[tokio::test]
async fn long_poll_wakes_on_push() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(5);
    push(&relay, &f, f.seal_n(1, 10)).await;

    let waiter = {
        let relay = relay.clone();
        let req = post(
            "/v0/pull?wait_ms=20000",
            Some(&f.bearer()),
            f.pull_bytes(1, 10),
        );
        tokio::spawn(async move { call(&relay, req).await })
    };
    while relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let started = std::time::Instant::now();
    let item = f.seal_n(1, 10);
    assert_eq!(push(&relay, &f, item.clone()).await, (2, 1));
    let reply = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("long-poll did not wake")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(batch(reply.message(), &f), (2, false, item));
    assert_eq!(relay.poll_count(), 0);
}

#[tokio::test]
async fn long_poll_times_out_with_an_empty_batch() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(9);
    push(&relay, &f, f.seal_n(2, 10)).await;

    let started = std::time::Instant::now();
    assert_eq!(pull(&relay, &f, 2, 10, 300).await, (2, false, vec![]));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(290),
        "returned after {took:?}"
    );
    assert!(took < Duration::from_secs(5));

    // wait_ms=0 and a missing wait_ms answer at once.
    let started = std::time::Instant::now();
    assert_eq!(pull(&relay, &f, 2, 10, 0).await, (2, false, vec![]));
    let r = call(
        &relay,
        post("/v0/pull", Some(&f.bearer()), f.pull_bytes(2, 10)),
    )
    .await;
    assert_eq!(batch(r.message(), &f), (2, false, vec![]));
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(relay.poll_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn wait_ms_is_clamped_to_25_seconds() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(10);
    push(&relay, &f, f.seal_n(1, 10)).await;
    let started = tokio::time::Instant::now();
    // Virtual time: the test does not really sleep.
    assert_eq!(pull(&relay, &f, 1, 10, 3_600_000).await, (1, false, vec![]));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(25) && took < Duration::from_secs(26),
        "held for {took:?}"
    );
}

#[tokio::test]
async fn abandoned_long_polls_free_their_slot() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(11);
    push(&relay, &f, f.seal_n(1, 10)).await;
    let req = post(
        "/v0/pull?wait_ms=20000",
        Some(&f.bearer()),
        f.pull_bytes(1, 10),
    );
    let task = {
        let relay = relay.clone();
        tokio::spawn(async move { call(&relay, req).await })
    };
    while relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The client goes away: hyper drops the request future.
    task.abort();
    let _ = task.await;
    assert_eq!(relay.poll_count(), 0);
}

#[tokio::test]
async fn shutdown_releases_long_polls() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(12);
    push(&relay, &f, f.seal_n(1, 10)).await;
    let req = post(
        "/v0/pull?wait_ms=20000",
        Some(&f.bearer()),
        f.pull_bytes(1, 10),
    );
    let task = {
        let relay = relay.clone();
        tokio::spawn(async move { call(&relay, req).await })
    };
    while relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    relay.begin_shutdown();
    let reply = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch(reply.message(), &f), (1, false, vec![]));
}

#[tokio::test]
async fn first_push_registers_the_token_and_others_are_rejected() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(13);
    let stranger = Fragment::new(14);

    // Pull before anyone pushed: empty Batch, and nothing is registered, so
    // the stranger's token did not claim the fragment.
    let r = call(
        &relay,
        post("/v0/pull", Some(&stranger.bearer()), f.pull_bytes(0, 10)),
    )
    .await;
    assert_eq!(batch(r.message(), &f), (0, false, vec![]));
    assert_eq!(relay.fragment_count(), 0);

    // An empty push does not register either.
    let r = call(
        &relay,
        post("/v0/push", Some(&stranger.bearer()), f.push_bytes(vec![])),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(relay.fragment_count(), 0);

    let items = f.seal_n(2, 10);
    push(&relay, &f, items.clone()).await;
    assert_eq!(relay.fragment_count(), 1);

    // Wrong token: 401 on push (even an empty one) and on pull.
    for body in [f.push_bytes(f.seal_n(1, 10)), f.push_bytes(vec![])] {
        call(&relay, post("/v0/push", Some(&stranger.bearer()), body))
            .await
            .assert_error(401);
    }
    let r = call(
        &relay,
        post("/v0/pull", Some(&stranger.bearer()), f.pull_bytes(0, 10)),
    )
    .await;
    r.assert_error(401);
    assert_eq!(r.headers["www-authenticate"], "Bearer");
    assert!(!contains(&r.body, &items[0].ciphertext));

    // The rejected pushes stored nothing.
    assert_eq!(pull(&relay, &f, 0, 0, 0).await, (2, false, items));
}

#[tokio::test]
async fn missing_or_malformed_tokens_get_401() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(15);
    let good = b64url(&f.token);
    let body = f.push_bytes(f.seal_n(1, 10));

    let mut nonzero_tail = good.clone().into_bytes();
    // 43 characters carry two spare bits; a canonical encoding has them zero.
    *nonzero_tail.last_mut().unwrap() = b'B';
    let nonzero_tail = String::from_utf8(nonzero_tail).unwrap();

    let bad: Vec<Option<String>> = vec![
        None,
        Some(String::new()),
        Some("Bearer".into()),
        Some("Bearer ".into()),
        Some(good.clone()),
        Some(format!("Basic {good}")),
        Some(format!("Bearer {}", &good[..42])),
        Some(format!("Bearer {good}A")),
        Some(format!("Bearer {good}=")),
        Some(format!("Bearer +{}", &good[1..])),
        Some(format!("Bearer {} {}", &good[..21], &good[22..])),
        Some(format!("Bearer {}", b64url(&[7u8; 31]))),
        Some(format!("Bearer {}", b64url(&[7u8; 33]))),
        Some(format!("Bearer {nonzero_tail}")),
    ];
    for auth in bad {
        for path in ["/v0/push", "/v0/pull"] {
            let r = call(&relay, post(path, auth.as_deref(), body.clone())).await;
            assert_eq!(r.status, 401, "auth {auth:?} on {path}");
            r.assert_error(401);
        }
    }
    assert_eq!(relay.fragment_count(), 0);

    // The scheme is case-insensitive.
    let r = call(
        &relay,
        post("/v0/push", Some(&format!("bearer {good}")), body),
    )
    .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn sealed_items_must_be_addressed_to_the_pushed_fragment() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(16);
    let other = Fragment::new(17);
    let mut sealed = f.seal_n(2, 10);
    sealed.push(other.seal_n(1, 10).pop().unwrap());

    call(
        &relay,
        post("/v0/push", Some(&f.bearer()), f.push_bytes(sealed)),
    )
    .await
    .assert_error(400);
    // Rejected as a whole: nothing stored, nothing registered.
    assert_eq!(relay.fragment_count(), 0);
    assert_eq!(pull(&relay, &f, 0, 0, 0).await, (0, false, vec![]));
}

#[tokio::test]
async fn malformed_and_misdirected_frames_get_400() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(18);
    let auth = f.bearer();
    let push_body = f.push_bytes(f.seal_n(1, 10));
    let pull_body = f.pull_bytes(0, 1);

    let mut trailing = push_body.clone();
    trailing.push(0);
    let head = Message::Head {
        fragment_id: f.id.clone(),
        cursor: 0,
    }
    .to_bytes()
    .unwrap();
    let empty_id = Message::Pull {
        fragment_id: vec![],
        after: 0,
        limit: 1,
    }
    .to_bytes()
    .unwrap();
    let long_id = Message::Pull {
        fragment_id: vec![1; 65],
        after: 0,
        limit: 1,
    }
    .to_bytes()
    .unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("/v0/push", vec![]),
        ("/v0/push", b"not cbor".to_vec()),
        ("/v0/push", push_body[..push_body.len() - 1].to_vec()),
        ("/v0/push", trailing),
        ("/v0/push", pull_body.clone()),
        ("/v0/push", head.clone()),
        ("/v0/pull", vec![]),
        ("/v0/pull", push_body.clone()),
        ("/v0/pull", head),
        ("/v0/pull", empty_id),
        ("/v0/pull", long_id),
        ("/v0/pull?wait_ms=soon", pull_body.clone()),
        ("/v0/pull?wait_ms=-1", pull_body.clone()),
        ("/v0/pull?wait_ms=", pull_body.clone()),
    ];
    for (path, body) in cases {
        let r = call(&relay, post(path, Some(&auth), body)).await;
        assert_eq!(r.status, 400, "{path}");
        r.assert_error(400);
    }
    assert_eq!(relay.fragment_count(), 0);
}

#[tokio::test]
async fn item_request_and_count_limits_get_413() {
    let cfg = Config {
        max_item_bytes: 2000,
        max_request_bytes: 10_000,
        max_push_items: 4,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let f = Fragment::new(19);
    let auth = f.bearer();

    // One item over the item limit, inside a request under the request limit.
    let big_item = f.push_bytes(f.seal_n(1, 2000));
    assert!(big_item.len() < 10_000);
    call(&relay, post("/v0/push", Some(&auth), big_item))
        .await
        .assert_error(413);

    // Items under the item limit, request over the request limit.
    let big_request = f.push_bytes(f.seal_n(4, 1900))[..].to_vec();
    assert!(big_request.len() < 10_000);
    let big_request = [big_request, vec![0; 3000]].concat();
    call(&relay, post("/v0/push", Some(&auth), big_request))
        .await
        .assert_error(413);

    // Too many items.
    let many = f.push_bytes(f.seal_n(5, 10));
    call(&relay, post("/v0/push", Some(&auth), many))
        .await
        .assert_error(413);

    // A Pull frame is tiny; a large pull body is refused too.
    call(&relay, post("/v0/pull", Some(&auth), vec![0; 5000]))
        .await
        .assert_error(413);

    assert_eq!(relay.fragment_count(), 0);

    // Exactly at the limits is fine.
    let ok = f.seal_n(4, 1900);
    assert!(ok.iter().all(|s| s.to_bytes().unwrap().len() <= 2000));
    assert_eq!(push(&relay, &f, ok).await, (4, 4));
}

/// A body with no declared length that never ends, counting what was read.
struct Endless {
    chunk: usize,
    polled: Arc<AtomicUsize>,
}

impl Body for Endless {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.polled.fetch_add(self.chunk, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0x41; self.chunk])))))
    }
}

#[tokio::test]
async fn body_size_is_enforced_while_reading() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(20);
    for (path, cap) in [("/v0/push", 1024 * 1024), ("/v0/pull", 1024)] {
        let polled = Arc::new(AtomicUsize::new(0));
        let req = Request::post(path)
            .header("authorization", f.bearer())
            .body(Endless {
                chunk: 4096,
                polled: polled.clone(),
            })
            .unwrap();
        let r = collect(relay.handle(req).await).await;
        r.assert_error(413);
        // The relay stopped at the first chunk that crossed the cap.
        assert!(polled.load(Ordering::SeqCst) <= cap + 4096, "{path}");
    }
}

#[tokio::test]
async fn slow_bodies_time_out() {
    struct Never;
    impl Body for Never {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Pending
        }
    }
    let cfg = Config {
        read_timeout: Duration::from_millis(100),
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let f = Fragment::new(21);
    let req = Request::post("/v0/push")
        .header("authorization", f.bearer())
        .body(Never)
        .unwrap();
    collect(relay.handle(req).await).await.assert_error(408);
}

#[tokio::test]
async fn fragment_quota_gets_413_and_is_all_or_nothing() {
    // Each stored item is charged its length plus 64 bytes.
    let cfg = Config {
        fragment_quota_bytes: 2000,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let f = Fragment::new(22);
    let first = f.seal_n(2, 500);
    assert_eq!(push(&relay, &f, first.clone()).await, (2, 2));

    // Two more would cross the quota: nothing from this push is stored.
    let over = f.push_bytes(f.seal_n(2, 500));
    call(&relay, post("/v0/push", Some(&f.bearer()), over))
        .await
        .assert_error(413);
    assert_eq!(pull(&relay, &f, 0, 0, 0).await, (2, false, first.clone()));

    // Re-pushing stored items costs nothing, and a small item still fits.
    assert_eq!(push(&relay, &f, first).await, (2, 2));
    assert_eq!(push(&relay, &f, f.seal_n(1, 100)).await, (3, 1));

    // Another fragment has its own quota.
    let g = Fragment::new(23);
    assert_eq!(push(&relay, &g, g.seal_n(2, 500)).await, (2, 2));
}

#[tokio::test]
async fn relay_wide_caps_get_507() {
    // Total quota across fragments.
    let cfg = Config {
        total_quota_bytes: 2000,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let a = Fragment::new(24);
    let b = Fragment::new(25);
    push(&relay, &a, a.seal_n(2, 500)).await;
    let body = b.push_bytes(b.seal_n(2, 500));
    call(&relay, post("/v0/push", Some(&b.bearer()), body))
        .await
        .assert_error(507);
    assert_eq!(pull(&relay, &b, 0, 0, 0).await, (0, false, vec![]));
    assert_eq!(relay.fragment_count(), 1);
    // The failed push did not use up quota.
    assert_eq!(push(&relay, &b, b.seal_n(1, 100)).await, (1, 1));

    // Fragment count.
    let cfg = Config {
        max_fragments: 2,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let c = Fragment::new(26);
    push(&relay, &a, a.seal_n(1, 10)).await;
    push(&relay, &b, b.seal_n(1, 10)).await;
    let body = c.push_bytes(c.seal_n(1, 10));
    call(&relay, post("/v0/push", Some(&c.bearer()), body))
        .await
        .assert_error(507);
    assert_eq!(relay.fragment_count(), 2);
    // Existing fragments keep working.
    assert_eq!(push(&relay, &a, a.seal_n(1, 10)).await, (2, 1));
}

#[tokio::test]
async fn long_poll_caps_get_429() {
    let cfg = Config {
        max_polls_per_fragment: 2,
        max_polls: 3,
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let a = Fragment::new(27);
    let b = Fragment::new(28);
    let c = Fragment::new(29);
    for f in [&a, &b, &c] {
        push(&relay, f, f.seal_n(1, 10)).await;
    }
    let hold = |f: &Fragment| {
        let relay = relay.clone();
        let req = post(
            "/v0/pull?wait_ms=20000",
            Some(&f.bearer()),
            f.pull_bytes(1, 1),
        );
        tokio::spawn(async move { call(&relay, req).await })
    };
    let wait_for = |n: usize| {
        let relay = relay.clone();
        async move {
            while relay.poll_count() != n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    };

    let held = [hold(&a), hold(&a)];
    wait_for(2).await;

    // Third long-poll on the same fragment: per-fragment cap.
    let r = call(
        &relay,
        post(
            "/v0/pull?wait_ms=20000",
            Some(&a.bearer()),
            a.pull_bytes(1, 1),
        ),
    )
    .await;
    r.assert_error(429);
    assert_eq!(r.headers["retry-after"], "1");

    // A pull that does not wait is not a long-poll and is never capped.
    assert_eq!(pull(&relay, &a, 1, 1, 0).await, (1, false, vec![]));

    // Another fragment takes the third slot; a fourth hits the global cap.
    let held_b = hold(&b);
    wait_for(3).await;
    call(
        &relay,
        post(
            "/v0/pull?wait_ms=20000",
            Some(&c.bearer()),
            c.pull_bytes(1, 1),
        ),
    )
    .await
    .assert_error(429);

    // Slots come back when a poll ends.
    held_b.abort();
    let _ = held_b.await;
    wait_for(2).await;
    let held_c = hold(&c);
    wait_for(3).await;
    held_c.abort();
    for h in held {
        h.abort();
    }
}

#[tokio::test]
async fn cors_headers_and_preflight() {
    let relay = mem_relay(Config::default());
    let f = Fragment::new(30);

    for path in ["/v0/push", "/v0/pull", "/healthz"] {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri(path)
            .header("origin", "https://app.example")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,content-type",
            )
            .body(Full::new(Bytes::new()))
            .unwrap();
        let r = call(&relay, req).await;
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
        assert_eq!(r.headers["access-control-allow-origin"], "*");
        let allowed = r.headers["access-control-allow-headers"].to_str().unwrap();
        assert!(allowed.contains("authorization") && allowed.contains("content-type"));
        assert!(allowed.contains("x-gsp-registration"));
        assert!(
            r.headers["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .contains("POST")
        );
        assert!(!r.headers.contains_key("vary"));
    }

    // Success and error replies both carry the header, or a browser could
    // not read them.
    let ok = call(
        &relay,
        post("/v0/pull", Some(&f.bearer()), f.pull_bytes(0, 1)),
    )
    .await;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.headers["access-control-allow-origin"], "*");
    assert_eq!(ok.headers["content-type"], "application/cbor");
    let err = call(&relay, post("/v0/pull", None, f.pull_bytes(0, 1))).await;
    assert_eq!(err.status, 401);
    assert_eq!(err.headers["access-control-allow-origin"], "*");

    // A configured origin is echoed as configured, with `vary: origin`.
    let cfg = Config {
        cors_origin: "https://app.example".into(),
        ..Config::default()
    };
    let relay = mem_relay(cfg);
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v0/push")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let r = call(&relay, req).await;
    assert_eq!(
        r.headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(r.headers["vary"], "origin");

    // A bad origin is refused when the relay is built.
    let cfg = Config {
        cors_origin: "bad\r\nvalue".into(),
        ..Config::default()
    };
    assert!(Relay::new(cfg, MemStore::new()).is_err());
}

#[tokio::test]
async fn healthz_unknown_paths_and_wrong_methods() {
    let relay = mem_relay(Config::default());
    let get = |path: &str| Request::get(path).body(Full::new(Bytes::new())).unwrap();
    let r = call(&relay, get("/healthz")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ok");

    call(&relay, get("/")).await.assert_error(404);
    call(&relay, get("/v0/other")).await.assert_error(404);
    call(&relay, post("/v0/push/", None, vec![]))
        .await
        .assert_error(404);

    let r = call(&relay, get("/v0/pull")).await;
    r.assert_error(405);
    assert_eq!(r.headers["allow"], "POST, OPTIONS");
    call(&relay, post("/healthz", None, vec![]))
        .await
        .assert_error(405);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_pushers_get_a_gap_free_increasing_sequence() {
    const PUSHERS: usize = 8;
    const PUSHES: usize = 20;
    const PER_PUSH: usize = 3;
    for durable in [false, true] {
        let dir = TempDir::new();
        let relay = if durable {
            Relay::new(
                Config::default(),
                DirStore::open(dir.path(), Fsync::Never).unwrap(),
            )
            .unwrap()
        } else {
            mem_relay(Config::default())
        };

        let mut tasks = Vec::new();
        for p in 0..PUSHERS {
            let relay = relay.clone();
            tasks.push(tokio::spawn(async move {
                // Same fragment (same seed), separate nonce streams.
                let f = Fragment::with_stream(31, p as u64 + 1);
                let mut acks = Vec::new();
                let mut sent = Vec::new();
                for n in 0..PUSHES {
                    let items: Vec<_> = (0..PER_PUSH)
                        .map(|i| f.seal(format!("pusher {p} push {n} item {i}").as_bytes()))
                        .collect();
                    let (cursor, count) = push(&relay, &f, items.clone()).await;
                    assert_eq!(count as usize, PER_PUSH);
                    acks.push(cursor);
                    sent.push((cursor, items));
                }
                (acks, sent)
            }));
        }
        let mut all_acks = Vec::new();
        let mut all_sent = Vec::new();
        for t in tasks {
            let (acks, sent) = t.await.unwrap();
            // Each pusher sees strictly increasing cursors.
            assert!(acks.windows(2).all(|w| w[0] < w[1]));
            all_acks.extend(acks);
            all_sent.extend(sent);
        }
        let total = (PUSHERS * PUSHES * PER_PUSH) as u64;
        // Every push got its own block of PER_PUSH consecutive cursors and
        // the blocks tile 1..=total: no gaps, no overlaps.
        all_acks.sort_unstable();
        let expected: Vec<u64> = (1..=total / PER_PUSH as u64)
            .map(|k| k * PER_PUSH as u64)
            .collect();
        assert_eq!(all_acks, expected);

        // The log holds exactly those items at exactly those cursors.
        let f = Fragment::new(31);
        let mut log = Vec::new();
        let mut after = 0;
        loop {
            let (next, more, got) = pull(&relay, &f, after, 0, 0).await;
            assert_eq!(next, after + got.len() as u64);
            log.extend(got);
            after = next;
            if !more {
                break;
            }
        }
        assert_eq!(log.len() as u64, total);
        for (cursor, items) in all_sent {
            let start = cursor as usize - PER_PUSH;
            assert_eq!(&log[start..cursor as usize], &items[..]);
        }
    }
}

/// The confidentiality claim, stated as a test. The relay is handed only
/// `SealedOp`s; the plaintext is inside the AEAD ciphertext and the relay has
/// no key, so this holds by construction. The test exists to fail if someone
/// later adds a plaintext field (an index, a debug copy, a log line written
/// to the data directory) to what the relay stores or returns.
#[tokio::test]
async fn plaintext_marker_never_appears_in_what_the_relay_holds() {
    const MARKER: &[u8] = b"MARKER-7f3a-salary-of-the-owner-is-12345";
    let dir = TempDir::new();
    let mem = Arc::new(MemStore::new());

    let relays = [
        Relay::new(Config::default(), mem.clone()).unwrap(),
        Relay::new(
            Config::default(),
            DirStore::open(dir.path(), Fsync::Always).unwrap(),
        )
        .unwrap(),
    ];
    let f = Fragment::new(32);
    let sealed = f.seal(MARKER);
    // Sanity: the marker really is in there for someone with the key...
    assert_eq!(
        sealed.open(&f.key, &f.id).unwrap(),
        Plain::Op(MARKER.to_vec())
    );
    // ...and not visible in the bytes sent to the relay.
    let request = f.push_bytes(vec![sealed.clone()]);
    assert!(!contains(&request, MARKER));

    for relay in &relays {
        let r = call(relay, post("/v0/push", Some(&f.bearer()), request.clone())).await;
        assert_eq!(r.status, 200);
        assert!(!contains(&r.body, MARKER));
        let r = call(
            relay,
            post("/v0/pull", Some(&f.bearer()), f.pull_bytes(0, 0)),
        )
        .await;
        assert!(!contains(&r.body, MARKER));
        // What comes back is what went in, and still opens with the key.
        let (_, _, got) = batch(r.message(), &f);
        assert_eq!(got, std::slice::from_ref(&sealed));
    }

    // In-memory store: every byte it holds.
    let held = mem.dump();
    assert!(contains(&held, &sealed.ciphertext), "dump covers the items");
    assert!(!contains(&held, MARKER));

    // Directory store: every byte of every file, and every file name.
    let mut files = 0;
    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(d).unwrap() {
            let path = entry.unwrap().path();
            assert!(!contains(path.to_string_lossy().as_bytes(), MARKER));
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                assert!(!contains(&bytes, MARKER), "{}", path.display());
                if path.file_name().is_some_and(|n| n == "LOCK") {
                    // The directory lock: an empty file.
                    assert!(bytes.is_empty());
                    continue;
                }
                // Neither the token nor the fragment key is on disk; only
                // BLAKE3(token).
                assert!(!contains(&bytes, &f.token));
                assert!(contains(&bytes, blake3::hash(&f.token).as_bytes()));
                assert!(contains(&bytes, &sealed.ciphertext));
                files += 1;
            }
        }
    }
    assert_eq!(files, 1);
}
