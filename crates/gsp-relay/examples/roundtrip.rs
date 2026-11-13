//! Minimal client against a running relay: pair a fragment, push sealed
//! items, pull them back, open them, and hold a long-poll.
//!
//! ```text
//! gsp-relay --addr 127.0.0.1:8787 &
//! cargo run -p gsp-relay --example roundtrip -- 127.0.0.1:8787
//! ```
//!
//! Plain `std::net`, one request per connection. It is a demonstration of
//! the HTTP mapping, not a sync client (that is `gsp-sync`).

use gsp_wire::{FragmentKey, Message, Plain, SealedOp};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn random<const N: usize>() -> Res<[u8; N]> {
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

fn b64url(bytes: &[u8]) -> String {
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

/// POST a frame, return `(status, reply frame)`.
fn post(addr: &str, path: &str, token: &[u8; 32], frame: &Message) -> Res<(u16, Message)> {
    let body = frame.to_bytes().map_err(|e| e.to_string())?;
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(40)))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\
         authorization: Bearer {}\r\ncontent-type: application/cbor\r\n\
         content-length: {}\r\n\r\n",
        b64url(token),
        body.len()
    )?;
    s.write_all(&body)?;
    let mut reply = Vec::new();
    s.read_to_end(&mut reply)?;
    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no response head")?;
    let status: u16 = std::str::from_utf8(reply.get(9..12).ok_or("short reply")?)?.parse()?;
    let message = Message::from_bytes(&reply[split + 4..]).map_err(|e| e.to_string())?;
    Ok((status, message))
}

fn main() -> Res<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".into());

    // Pairing (SYNC-V0 section 2): everything derives from the root secret.
    let root: [u8; 32] = random()?;
    let key = FragmentKey::new(blake3::derive_key("gsp/v0/fragment-key", &root));
    let id = blake3::derive_key("gsp/v0/fragment-id", &root)[..16].to_vec();
    let token = blake3::derive_key("gsp/v0/relay-token", &root);
    println!("relay {addr}, new fragment (id is {} bytes)", id.len());

    let texts = ["first op", "second op", "third op"];
    let mut sealed = Vec::new();
    for t in texts {
        // The relay never sees inside; any bytes will do for this demo.
        let plain = Plain::Op(t.as_bytes().to_vec());
        sealed.push(SealedOp::seal(&key, &id, random()?, &plain).map_err(|e| e.to_string())?);
    }

    let pull = |after, limit| Message::Pull {
        fragment_id: id.clone(),
        after,
        limit,
    };
    let push = |sealed: Vec<SealedOp>| Message::Push {
        fragment_id: id.clone(),
        sealed,
    };

    let (status, reply) = post(&addr, "/v0/pull", &token, &pull(0, 10))?;
    println!("pull before any push  -> {status} {reply:?}");

    let (status, reply) = post(&addr, "/v0/push", &token, &push(sealed.clone()))?;
    println!("push 3 items          -> {status} {reply:?}");
    let (status, reply) = post(&addr, "/v0/push", &token, &push(sealed.clone()))?;
    println!("push same 3 again     -> {status} {reply:?}");

    let (status, reply) = post(&addr, "/v0/pull", &token, &pull(0, 2))?;
    let Message::Batch {
        next,
        more,
        sealed: got,
        ..
    } = reply
    else {
        return Err(format!("expected Batch, got {status} {reply:?}").into());
    };
    println!(
        "pull after=0 limit=2  -> {status} next={next} more={more} items={}",
        got.len()
    );
    let (status, reply) = post(&addr, "/v0/pull", &token, &pull(next, 10))?;
    let Message::Batch {
        next: next2,
        more: more2,
        sealed: rest,
        ..
    } = reply
    else {
        return Err(format!("expected Batch, got {status} {reply:?}").into());
    };
    println!(
        "pull after={next} limit=10 -> {status} next={next2} more={more2} items={}",
        rest.len()
    );
    let all: Vec<SealedOp> = got.into_iter().chain(rest).collect();
    if all != sealed {
        return Err("pulled items differ from pushed items".into());
    }
    for (s, want) in all.iter().zip(texts) {
        match s.open(&key, &id).map_err(|e| e.to_string())? {
            Plain::Op(bytes) if bytes == want.as_bytes() => {}
            other => return Err(format!("opened to {other:?}, wanted {want:?}").into()),
        }
    }
    println!("opened all 3 with the fragment key: plaintexts match");

    let wrong = blake3::derive_key("gsp/v0/relay-token", &[0u8; 32]);
    let (status, reply) = post(&addr, "/v0/pull", &wrong, &pull(0, 10))?;
    println!("pull with wrong token -> {status} {reply:?}");

    // Long-poll: a second thread pushes after 500 ms.
    let started = Instant::now();
    let pusher = {
        let (addr, id) = (addr.clone(), id.clone());
        let extra = SealedOp::seal(&key, &id, random()?, &Plain::Op(b"late op".to_vec()))
            .map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            let frame = Message::Push {
                fragment_id: id,
                sealed: vec![extra],
            };
            post(&addr, "/v0/push", &token, &frame).map(|(s, _)| s)
        })
    };
    let (status, reply) = post(&addr, "/v0/pull?wait_ms=10000", &token, &pull(next2, 10))?;
    let Message::Batch { next, sealed, .. } = &reply else {
        return Err(format!("expected Batch, got {status} {reply:?}").into());
    };
    println!(
        "long-poll wait_ms=10000 -> {status} after {} ms: next={next} items={}",
        started.elapsed().as_millis(),
        sealed.len()
    );
    pusher.join().map_err(|_| "pusher panicked")??;

    let started = Instant::now();
    let (status, reply) = post(&addr, "/v0/pull?wait_ms=700", &token, &pull(*next, 10))?;
    println!(
        "long-poll wait_ms=700, nothing new -> {status} after {} ms: {reply:?}",
        started.elapsed().as_millis()
    );
    Ok(())
}
