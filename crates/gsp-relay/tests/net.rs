//! Tests against a real listener on port 0, with a hand-written HTTP/1.1
//! client so the wire behaviour (not just the handler) is covered.

mod common;

use common::*;
use gsp_relay::{Config, Relay, serve};
use gsp_wire::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct Server {
    addr: SocketAddr,
    relay: Relay,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<std::io::Result<()>>,
}

async fn start(cfg: Config) -> Server {
    let relay = mem_relay(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(serve(listener, relay.clone(), async {
        let _ = stopped.await;
    }));
    Server {
        addr,
        relay,
        stop: Some(stop),
        task,
    }
}

fn request(method: &str, path: &str, auth: Option<&str>, body: &[u8], close: bool) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nhost: relay.test\r\n");
    if let Some(a) = auth {
        r += &format!("authorization: {a}\r\n");
    }
    if close {
        r += "connection: close\r\n";
    }
    if method == "POST" {
        r += &format!(
            "content-type: application/cbor\r\ncontent-length: {}\r\n",
            body.len()
        );
    }
    r += "\r\n";
    [r.into_bytes(), body.to_vec()].concat()
}

/// Read one response: `(status, lower-cased head, body)`.
async fn read_response(s: &mut TcpStream) -> (u16, String, Vec<u8>) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before a full response head");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let status: u16 = head[9..12].parse().unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .map_or(0, |v| v.trim().parse().unwrap());
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed in the middle of a body");
        body.extend_from_slice(&chunk[..n]);
    }
    (status, head, body)
}

async fn once(addr: SocketAddr, req: Vec<u8>) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&req).await.unwrap();
    read_response(&mut s).await
}

/// True if the peer closes (or resets) the connection within `within`.
async fn closes(s: &mut TcpStream, within: Duration) -> bool {
    let mut sink = [0u8; 1024];
    tokio::time::timeout(within, async {
        loop {
            match s.read(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn push_pull_and_long_poll_over_tcp() {
    let server = start(Config::default()).await;
    let f = Fragment::new(1);
    let auth = f.bearer();

    let (status, head, body) = once(server.addr, request("GET", "/healthz", None, b"", true)).await;
    assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
    assert!(head.contains("access-control-allow-origin: *"));

    // Two requests on one keep-alive connection.
    let items = f.seal_n(3, 100);
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&request(
        "POST",
        "/v0/push",
        Some(&auth),
        &f.push_bytes(items.clone()),
        false,
    ))
    .await
    .unwrap();
    let (status, head, body) = read_response(&mut s).await;
    assert_eq!(status, 200);
    assert!(head.contains("content-type: application/cbor"));
    assert_eq!(
        Message::from_bytes(&body).unwrap(),
        Message::Ack {
            fragment_id: f.id.clone(),
            cursor: 3,
            count: 3
        }
    );
    s.write_all(&request(
        "POST",
        "/v0/pull?wait_ms=0",
        Some(&auth),
        &f.pull_bytes(0, 10),
        false,
    ))
    .await
    .unwrap();
    let (status, _, body) = read_response(&mut s).await;
    assert_eq!(status, 200);
    assert_eq!(
        batch(Message::from_bytes(&body).unwrap(), &f),
        (3, false, items)
    );

    // A long-poll held over TCP is answered when another connection pushes.
    let waiter = tokio::spawn(once(
        server.addr,
        request(
            "POST",
            "/v0/pull?wait_ms=20000",
            Some(&auth),
            &f.pull_bytes(3, 10),
            true,
        ),
    ));
    while server.relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let new = f.seal_n(1, 100);
    let (status, _, _) = once(
        server.addr,
        request(
            "POST",
            "/v0/push",
            Some(&auth),
            &f.push_bytes(new.clone()),
            true,
        ),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, body) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        batch(Message::from_bytes(&body).unwrap(), &f),
        (4, false, new)
    );

    // Preflight and an error reply, as bytes on the wire.
    let (status, head, _) =
        once(server.addr, request("OPTIONS", "/v0/push", None, b"", true)).await;
    assert_eq!(status, 204);
    assert!(head.contains("access-control-allow-headers: authorization, content-type"));
    let (status, _, body) = once(
        server.addr,
        request("POST", "/v0/pull", None, &f.pull_bytes(0, 1), true),
    )
    .await;
    assert_eq!(status, 401);
    assert!(matches!(
        Message::from_bytes(&body).unwrap(),
        Message::Error { code: 401, .. }
    ));
}

#[tokio::test]
async fn oversized_bodies_are_refused_over_tcp_without_reading_them_all() {
    let server = start(Config::default()).await;
    let f = Fragment::new(2);
    let head = format!(
        "POST /v0/push HTTP/1.1\r\nhost: relay.test\r\nauthorization: {}\r\n",
        f.bearer()
    );

    // Declared length over the limit: refused from the header alone; no
    // body byte is sent.
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(format!("{head}content-length: 50000000\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (status, _, body) = read_response(&mut s).await;
    assert_eq!(status, 413);
    assert!(matches!(
        Message::from_bytes(&body).unwrap(),
        Message::Error { code: 413, .. }
    ));

    // Chunked, no declared length: refused once the cap is crossed, while
    // the client has not finished (it never sends the last chunk).
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(format!("{head}transfer-encoding: chunked\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let chunk = [b"10000\r\n".to_vec(), vec![0x41; 0x10000], b"\r\n".to_vec()].concat();
    for _ in 0..17 {
        s.write_all(&chunk).await.unwrap();
    }
    let (status, _, _) = tokio::time::timeout(Duration::from_secs(5), read_response(&mut s))
        .await
        .expect("no reply while the body was still open");
    assert_eq!(status, 413);
}

#[tokio::test]
async fn slow_and_idle_connections_are_closed() {
    let cfg = Config {
        read_timeout: Duration::from_millis(300),
        ..Config::default()
    };
    let server = start(cfg).await;
    let f = Fragment::new(3);

    // Connects and sends nothing.
    let mut silent = TcpStream::connect(server.addr).await.unwrap();
    // Sends half a request head and stalls.
    let mut partial = TcpStream::connect(server.addr).await.unwrap();
    partial
        .write_all(b"POST /v0/push HTTP/1.1\r\nhost: re")
        .await
        .unwrap();
    // Sends a head, promises a body, stalls: answered 408.
    let mut stalled = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "POST /v0/push HTTP/1.1\r\nhost: relay.test\r\nauthorization: {}\r\ncontent-length: 100\r\n\r\nabc",
        f.bearer()
    );
    stalled.write_all(head.as_bytes()).await.unwrap();
    // Finishes a request, then idles on the keep-alive connection.
    let mut idle = TcpStream::connect(server.addr).await.unwrap();
    idle.write_all(&request("GET", "/healthz", None, b"", false))
        .await
        .unwrap();
    assert_eq!(read_response(&mut idle).await.0, 200);

    let (status, _, _) = tokio::time::timeout(Duration::from_secs(5), read_response(&mut stalled))
        .await
        .unwrap();
    assert_eq!(status, 408);
    assert!(closes(&mut silent, Duration::from_secs(5)).await);
    assert!(closes(&mut partial, Duration::from_secs(5)).await);
    assert!(closes(&mut idle, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn connections_past_the_cap_are_closed() {
    let cfg = Config {
        max_connections: 2,
        ..Config::default()
    };
    let server = start(cfg).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut s = TcpStream::connect(server.addr).await.unwrap();
        s.write_all(&request("GET", "/healthz", None, b"", false))
            .await
            .unwrap();
        assert_eq!(read_response(&mut s).await.0, 200);
        held.push(s);
    }
    let mut extra = TcpStream::connect(server.addr).await.unwrap();
    let _ = extra
        .write_all(&request("GET", "/healthz", None, b"", false))
        .await;
    assert!(closes(&mut extra, Duration::from_secs(5)).await);

    // Freeing a slot lets the next connection in.
    held.pop();
    let mut ok = false;
    for _ in 0..100 {
        let mut s = TcpStream::connect(server.addr).await.unwrap();
        if s.write_all(&request("GET", "/healthz", None, b"", true))
            .await
            .is_ok()
        {
            let mut out = Vec::new();
            if s.read_to_end(&mut out).await.is_ok() && out.starts_with(b"HTTP/1.1 200") {
                ok = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ok);
}

#[tokio::test]
async fn graceful_shutdown_answers_held_long_polls_and_stops_listening() {
    let mut server = start(Config::default()).await;
    let f = Fragment::new(4);
    let waiter = tokio::spawn(once(
        server.addr,
        request(
            "POST",
            "/v0/pull?wait_ms=25000",
            Some(&f.bearer()),
            &f.pull_bytes(0, 10),
            false,
        ),
    ));
    while server.relay.poll_count() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // An idle keep-alive connection must not hold shutdown up either.
    let mut idle = TcpStream::connect(server.addr).await.unwrap();
    idle.write_all(&request("GET", "/healthz", None, b"", false))
        .await
        .unwrap();
    assert_eq!(read_response(&mut idle).await.0, 200);

    server.stop.take().unwrap().send(()).unwrap();
    let (status, _, body) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("long-poll was not released")
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        batch(Message::from_bytes(&body).unwrap(), &f),
        (0, false, vec![])
    );
    tokio::time::timeout(Duration::from_secs(5), server.task)
        .await
        .expect("serve did not return")
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(server.addr).await.is_err());
}
