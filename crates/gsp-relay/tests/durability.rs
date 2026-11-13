//! Restart behaviour of the directory store: cursors, token hashes and
//! dedupe survive; a torn tail is cut off.

mod common;

use common::*;
use gsp_relay::{Config, DirStore, Fsync, Relay};
use std::fs::OpenOptions;
use std::io::Write;

fn open(dir: &TempDir) -> Relay {
    Relay::new(
        Config::default(),
        DirStore::open(dir.path(), Fsync::Always).unwrap(),
    )
    .unwrap()
}

async fn pull_all(relay: &Relay, f: &Fragment) -> Vec<gsp_wire::SealedOp> {
    let mut out = Vec::new();
    let mut after = 0;
    loop {
        let (next, more, got) = pull(relay, f, after, 0, 0).await;
        out.extend(got);
        after = next;
        if !more {
            return out;
        }
    }
}

#[tokio::test]
async fn restart_keeps_cursors_tokens_and_dedupe() {
    let dir = TempDir::new();
    let a = Fragment::new(1);
    let b = Fragment::new(2);
    let stranger = Fragment::new(3);
    let a_items = a.seal_n(5, 200);
    let b_items = b.seal_n(2, 50);

    {
        let relay = open(&dir);
        assert_eq!(push(&relay, &a, a_items[..3].to_vec()).await, (3, 3));
        assert_eq!(push(&relay, &b, b_items.clone()).await, (2, 2));
        assert_eq!(push(&relay, &a, a_items[3..].to_vec()).await, (5, 2));
    }

    for _ in 0..2 {
        let relay = open(&dir);
        assert_eq!(relay.fragment_count(), 2);
        // Same items at the same cursors.
        assert_eq!(pull_all(&relay, &a).await, a_items);
        assert_eq!(pull_all(&relay, &b).await, b_items);
        let (next, more, got) = pull(&relay, &a, 2, 2, 0).await;
        assert_eq!((next, more), (4, true));
        assert_eq!(got, a_items[2..4]);
        // The registered token hash was persisted.
        call(
            &relay,
            post("/v0/pull", Some(&stranger.bearer()), a.pull_bytes(0, 0)),
        )
        .await
        .assert_error(401);
        let body = a.push_bytes(vec![a_items[0].clone()]);
        call(&relay, post("/v0/push", Some(&stranger.bearer()), body))
            .await
            .assert_error(401);
        // Dedupe still knows the old items.
        assert_eq!(push(&relay, &a, a_items.clone()).await, (5, 5));
    }

    // Numbering continues after a restart.
    let relay = open(&dir);
    let new = a.seal_n(1, 10);
    assert_eq!(push(&relay, &a, new.clone()).await, (6, 1));
    drop(relay);
    let relay = open(&dir);
    assert_eq!(pull(&relay, &a, 5, 0, 0).await, (6, false, new));
}

#[tokio::test]
async fn quota_accounting_is_rebuilt_on_restart() {
    let dir = TempDir::new();
    let cfg = Config {
        fragment_quota_bytes: 2000,
        ..Config::default()
    };
    let open = || {
        Relay::new(
            cfg.clone(),
            DirStore::open(dir.path(), Fsync::Always).unwrap(),
        )
        .unwrap()
    };
    let f = Fragment::new(4);
    push(&open(), &f, f.seal_n(2, 500)).await;
    let body = f.push_bytes(f.seal_n(2, 500));
    call(&open(), post("/v0/push", Some(&f.bearer()), body))
        .await
        .assert_error(413);
}

#[tokio::test]
async fn torn_tail_is_truncated_and_cursors_are_unchanged() {
    // Three ways a crash mid-append can leave the file.
    let record = |payload: &[u8], good_sum: bool| {
        let mut r = (payload.len() as u32).to_le_bytes().to_vec();
        let mut sum = *blake3::hash(payload).as_bytes();
        if !good_sum {
            sum[0] ^= 1;
        }
        r.extend_from_slice(&sum);
        r.extend_from_slice(payload);
        r
    };
    let tails: Vec<(&str, Vec<u8>)> = vec![
        ("partial record header", vec![0x10, 0x00, 0x00]),
        (
            "record cut short",
            record(&[7u8; 500], true)[..200].to_vec(),
        ),
        (
            "complete record, wrong checksum",
            record(&[7u8; 500], false),
        ),
        (
            "absurd length field",
            [vec![0xff; 4], vec![0u8; 64]].concat(),
        ),
        ("zero fill", vec![0u8; 4096]),
    ];

    for (what, tail) in tails {
        let dir = TempDir::new();
        let f = Fragment::new(5);
        let items = f.seal_n(4, 300);
        {
            let relay = open(&dir);
            assert_eq!(push(&relay, &f, items.clone()).await, (4, 4));
        }
        let log = dir.only_log();
        let good_len = std::fs::metadata(&log).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(&tail)
            .unwrap();

        let relay = open(&dir);
        assert_eq!(std::fs::metadata(&log).unwrap().len(), good_len, "{what}");
        assert_eq!(pull_all(&relay, &f).await, items, "{what}");
        // The next item takes the next cursor and lands on a clean boundary.
        let new = f.seal_n(1, 300);
        assert_eq!(push(&relay, &f, new.clone()).await, (5, 1), "{what}");
        drop(relay);
        let relay = open(&dir);
        assert_eq!(pull_all(&relay, &f).await, [items, new].concat(), "{what}");
    }
}

#[tokio::test]
async fn torn_last_record_of_a_real_push_is_dropped_whole() {
    let dir = TempDir::new();
    let f = Fragment::new(6);
    let items = f.seal_n(3, 300);
    {
        let relay = open(&dir);
        push(&relay, &f, items[..2].to_vec()).await;
        push(&relay, &f, items[2..].to_vec()).await;
    }
    // Cut the file in the middle of the third record.
    let log = dir.only_log();
    let len = std::fs::metadata(&log).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(len - 100)
        .unwrap();

    let relay = open(&dir);
    assert_eq!(pull_all(&relay, &f).await, items[..2]);
    // It was never (durably) stored, so pushing it again stores it as 3.
    assert_eq!(push(&relay, &f, items[2..].to_vec()).await, (3, 1));
    assert_eq!(pull_all(&relay, &f).await, items);
}

#[tokio::test]
async fn leftover_temp_files_are_removed_and_foreign_files_refused() {
    let dir = TempDir::new();
    let f = Fragment::new(7);
    let items = f.seal_n(1, 10);
    push(&open(&dir), &f, items.clone()).await;

    let tmp = dir.path().join("fragments").join("00ff.tmp");
    std::fs::write(&tmp, b"half a header").unwrap();
    std::fs::write(dir.path().join("fragments").join("notes.txt"), b"ignored").unwrap();
    let relay = open(&dir);
    assert!(!tmp.exists());
    assert_eq!(pull_all(&relay, &f).await, items);
    drop(relay);

    // A `.log` file that is not ours stops startup instead of being
    // truncated to nothing.
    let foreign = dir.path().join("fragments").join("abcd.log");
    std::fs::write(&foreign, b"something else entirely").unwrap();
    assert!(
        Relay::new(
            Config::default(),
            DirStore::open(dir.path(), Fsync::Always).unwrap()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&foreign).unwrap(), b"something else entirely");
}
