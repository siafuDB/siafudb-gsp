//! HTTP mapping of the relay (SYNC-V0 section 6) and the TCP server loop.

use crate::config::Config;
use crate::config::MAX_WAIT_MS;
use crate::log::{info, warning};
use crate::relay::{Auth, MAX_FRAGMENT_ID, Reject, Relay};
use crate::store::TokenHash;
use gsp_wire::Message;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Buf, Bytes};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Reply body type.
pub type ReplyBody = Full<Bytes>;

const CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
/// A `Pull` frame is under 100 bytes; no reason to read more.
const MAX_PULL_BODY: usize = 1024;

enum BodyError {
    TooLarge,
    Timeout,
    Read,
}

/// Decode an unpadded base64url string of exactly 32 bytes (43 characters).
fn decode_token(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    let mut out = [0u8; 33];
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut n = 0usize;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[n] = (acc >> bits) as u8;
            n += 1;
        }
    }
    // 43 characters carry 258 bits: 32 bytes plus two bits that must be zero.
    if n != 32 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&out[..32]);
    Some(token)
}

/// `Authorization: Bearer <token>` to `BLAKE3(token)`. The token itself is
/// not kept.
fn bearer<B>(req: &Request<B>) -> Result<TokenHash, Reject> {
    const MISSING: Reject = Reject::new(401, "missing or malformed bearer relay token");
    let value = req.headers().get(header::AUTHORIZATION).ok_or(MISSING)?;
    let value = value.as_bytes();
    if value.len() < 7 || !value[..7].eq_ignore_ascii_case(b"bearer ") {
        return Err(MISSING);
    }
    let token = decode_token(value[7..].trim_ascii()).ok_or(MISSING)?;
    Ok(*blake3::hash(&token).as_bytes())
}

/// Header carrying the operator's registration secret on a first push.
pub const REGISTRATION_HEADER: &str = "x-gsp-registration";

fn credentials<B>(req: &Request<B>) -> Result<Auth, Reject> {
    Ok(Auth {
        token: bearer(req)?,
        registration: req
            .headers()
            .get(REGISTRATION_HEADER)
            .map(|v| *blake3::hash(v.as_bytes().trim_ascii()).as_bytes()),
    })
}

const MALFORMED: Reject = Reject::new(400, "malformed frame");

/// Allocation-free walk over CBOR item heads, used to turn away bodies of
/// the wrong shape before paying for a full decode. It is a filter, not a
/// parser: everything it lets through is still decoded strictly by
/// `gsp-wire`, and it lets through every frame `gsp-wire` accepts.
struct Scan<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Scan<'a> {
    /// Next item head: `(major type, argument)`.
    fn head(&mut self) -> Option<(u8, u64)> {
        let first = *self.body.get(self.pos)?;
        self.pos += 1;
        let width = match first & 0x1f {
            n @ 0..=23 => return Some((first >> 5, u64::from(n))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return None,
        };
        let raw = self.body.get(self.pos..self.pos.checked_add(width)?)?;
        self.pos += width;
        let arg = raw.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
        Some((first >> 5, arg))
    }
    fn expect(&mut self, major: u8, arg: u64) -> Option<()> {
        (self.head()? == (major, arg)).then_some(())
    }
    fn uint(&mut self) -> Option<u64> {
        match self.head()? {
            (0, v) => Some(v),
            _ => None,
        }
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let (2, len) = self.head()? else {
            return None;
        };
        let end = self.pos.checked_add(usize::try_from(len).ok()?)?;
        let out = self.body.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    fn fragment_id(&mut self) -> Option<&'a [u8]> {
        self.bytes()
            .filter(|id| !id.is_empty() && id.len() <= MAX_FRAGMENT_ID)
    }
}

/// Shape check of a `Push` body: `[3, bstr, [* [uint, uint, bstr, bstr,
/// bstr]]]` and nothing else, with the item count and item sizes inside the
/// limits. Returns the fragment id. Cost: a few head reads per item, no
/// allocation, whatever the body contains.
fn precheck_push<'a>(body: &'a [u8], cfg: &Config) -> Result<&'a [u8], Reject> {
    let mut s = Scan { body, pos: 0 };
    s.expect(4, 3).ok_or(MALFORMED)?;
    s.expect(0, 3)
        .ok_or(Reject::new(400, "expected a Push frame"))?;
    let id = s.fragment_id().ok_or(MALFORMED)?;
    let count = match s.head() {
        Some((4, n)) => n,
        _ => return Err(MALFORMED),
    };
    if count > cfg.max_push_items as u64 {
        return Err(Reject::new(413, "too many items in one push"));
    }
    for _ in 0..count {
        let start = s.pos;
        let item = (|| {
            s.expect(4, 5)?;
            s.uint()?;
            s.uint()?;
            s.bytes()?;
            s.bytes()?;
            s.bytes()
        })();
        item.ok_or(MALFORMED)?;
        if s.pos - start > cfg.max_item_bytes {
            return Err(Reject::new(413, "item too large"));
        }
    }
    if s.pos != body.len() {
        return Err(MALFORMED);
    }
    Ok(id)
}

/// Shape check of a `Pull` body: `[4, bstr, uint, uint]`.
fn precheck_pull(body: &[u8]) -> Result<(), Reject> {
    let mut s = Scan { body, pos: 0 };
    s.expect(4, 4).ok_or(MALFORMED)?;
    s.expect(0, 4)
        .ok_or(Reject::new(400, "expected a Pull frame"))?;
    s.fragment_id().ok_or(MALFORMED)?;
    s.uint().ok_or(MALFORMED)?;
    s.uint().ok_or(MALFORMED)?;
    if s.pos != body.len() {
        return Err(MALFORMED);
    }
    Ok(())
}

/// Read a body, refusing as soon as more than `cap` bytes have arrived.
async fn read_body<B: Body>(body: B, cap: usize, limit: Duration) -> Result<Vec<u8>, BodyError> {
    if body.size_hint().lower() > cap as u64 {
        return Err(BodyError::TooLarge);
    }
    let read = async {
        let mut body = std::pin::pin!(body);
        let mut buf = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyError::Read)?;
            let Ok(mut data) = frame.into_data() else {
                continue;
            };
            if data.remaining() > cap - buf.len() {
                return Err(BodyError::TooLarge);
            }
            while data.has_remaining() {
                let chunk = data.chunk();
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                data.advance(n);
            }
        }
        Ok(buf)
    };
    tokio::time::timeout(limit, read)
        .await
        .unwrap_or(Err(BodyError::Timeout))
}

fn wait_ms(query: Option<&str>) -> Result<Duration, Reject> {
    let mut wait = 0u64;
    for pair in query.unwrap_or("").split('&') {
        if let Some(v) = pair.strip_prefix("wait_ms=") {
            wait = v
                .parse::<u64>()
                .map_err(|_| Reject::new(400, "wait_ms is not a number"))?;
        }
    }
    Ok(Duration::from_millis(wait.min(MAX_WAIT_MS)))
}

impl Relay {
    fn finish(&self, mut resp: Response<ReplyBody>) -> Response<ReplyBody> {
        let h = resp.headers_mut();
        let origin = &self.config().cors_origin;
        if let Ok(v) = HeaderValue::from_str(origin) {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
        if origin != "*" {
            h.insert(header::VARY, HeaderValue::from_static("origin"));
        }
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        resp
    }

    fn reply(
        &self,
        status: StatusCode,
        content_type: HeaderValue,
        body: Vec<u8>,
    ) -> Response<ReplyBody> {
        let mut resp = Response::new(Full::new(Bytes::from(body)));
        *resp.status_mut() = status;
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
        self.finish(resp)
    }

    fn frame(&self, status: StatusCode, m: &Message) -> Response<ReplyBody> {
        match m.to_bytes() {
            Ok(bytes) => self.reply(status, CBOR, bytes),
            Err(_) => self.reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderValue::from_static("text/plain"),
                b"encode error".to_vec(),
            ),
        }
    }

    fn reject(&self, r: Reject) -> Response<ReplyBody> {
        let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = self.frame(
            status,
            &Message::Error {
                code: r.status,
                message: r.message.into(),
            },
        );
        match r.status {
            401 => {
                resp.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            429 | 503 => {
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            _ => {}
        }
        resp
    }

    fn preflight(&self) -> Response<ReplyBody> {
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::NO_CONTENT;
        let h = resp.headers_mut();
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type, x-gsp-registration"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        self.finish(resp)
    }

    async fn body<B: Body>(&self, body: B, cap: usize) -> Result<Vec<u8>, Reject> {
        read_body(body, cap, self.config().read_timeout)
            .await
            .map_err(|e| match e {
                BodyError::TooLarge => Reject::new(413, "request body too large"),
                BodyError::Timeout => Reject::new(408, "request body not received in time"),
                BodyError::Read => Reject::new(400, "request body could not be read"),
            })
    }

    /// Order matters here: everything cheap comes before the full decode.
    /// Token syntax, body size (while reading), frame shape and limits (a
    /// scan without allocation), then the relay token or the registration
    /// secret; only then is the body decoded, off the async workers and
    /// under the decode budget.
    async fn push_route<B: Body>(&self, req: Request<B>) -> Result<Message, Reject> {
        let auth = credentials(&req)?;
        let cap = self.config().max_request_bytes;
        let body = self.body(req.into_body(), cap).await?;
        let fragment_id = precheck_push(&body, self.config())?;
        self.preauth(&auth, fragment_id)?;
        self.push_encoded(auth, body).await
    }

    async fn pull_route<B: Body>(&self, req: Request<B>) -> Result<Message, Reject> {
        let token = bearer(&req)?;
        let wait = wait_ms(req.uri().query())?;
        let cap = self.config().max_request_bytes.min(MAX_PULL_BODY);
        let body = self.body(req.into_body(), cap).await?;
        precheck_pull(&body)?;
        // At most 1 KiB of flat fields: decoded in place.
        match Message::from_bytes(&body).map_err(|_| MALFORMED)? {
            Message::Pull {
                fragment_id,
                after,
                limit,
            } => self.pull(token, &fragment_id, after, limit, wait).await,
            _ => Err(Reject::new(400, "expected a Pull frame")),
        }
    }

    /// Answer one HTTP request. Never panics on any input; every failure is
    /// a 4xx/5xx reply whose body is an `Error` frame.
    pub async fn handle<B: Body>(&self, req: Request<B>) -> Response<ReplyBody> {
        let path = req.uri().path();
        let known = matches!(path, "/v0/push" | "/v0/pull" | "/healthz");
        let is_health = path == "/healthz";
        let method = req.method().clone();
        if !known {
            return self.reject(Reject::new(404, "no such endpoint"));
        }
        if method == Method::OPTIONS {
            return self.preflight();
        }
        let result = match (is_health, &method) {
            (true, &Method::GET | &Method::HEAD) => {
                return self.reply(
                    StatusCode::OK,
                    HeaderValue::from_static("text/plain"),
                    b"ok".to_vec(),
                );
            }
            (false, &Method::POST) if path == "/v0/push" => self.push_route(req).await,
            (false, &Method::POST) => self.pull_route(req).await,
            _ => {
                let mut resp = self.reject(Reject::new(405, "method not allowed"));
                resp.headers_mut().insert(
                    header::ALLOW,
                    HeaderValue::from_static(if is_health {
                        "GET, HEAD, OPTIONS"
                    } else {
                        "POST, OPTIONS"
                    }),
                );
                return resp;
            }
        };
        match result {
            Ok(m) => self.frame(StatusCode::OK, &m),
            Err(r) => {
                if r.status != 429 && r.status != 503 {
                    info!("reject", "status={} reason={:?}", r.status, r.message);
                }
                self.reject(r)
            }
        }
    }
}

/// Serve HTTP/1.1 on `listener` until `shutdown` resolves, then stop
/// accepting, release held long-polls, and give in-flight requests
/// [`Config::shutdown_grace`](crate::Config::shutdown_grace) to finish.
pub async fn serve(
    listener: TcpListener,
    relay: Relay,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let cfg = relay.config().clone();
    let slots = Arc::new(Semaphore::new(cfg.max_connections));
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(cfg.read_timeout)
        .max_buf_size(32 * 1024);
    let mut shutdown = std::pin::pin!(shutdown);
    let mut refused = 0u64;

    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            () = &mut shutdown => break,
        };
        let stream = match accepted {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                // Out of file descriptors and the like: back off, keep going.
                warning!("accept_error", "kind={:?}", e.kind());
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            refused += 1;
            if refused.is_power_of_two() {
                warning!(
                    "connection_refused",
                    "reason=max_connections total={refused}"
                );
            }
            continue;
        };
        let _ = stream.set_nodelay(true);
        let relay = relay.clone();
        let service = hyper::service::service_fn(move |req| {
            let relay = relay.clone();
            async move { Ok::<_, std::convert::Infallible>(relay.handle(req).await) }
        });
        let conn =
            graceful.watch(http.serve_connection(hyper_util::rt::TokioIo::new(stream), service));
        tokio::spawn(async move {
            let _ = conn.await;
            drop(slot);
        });
    }

    drop(listener);
    relay.begin_shutdown();
    info!("shutdown", "grace_ms={}", cfg.shutdown_grace.as_millis());
    if tokio::time::timeout(cfg.shutdown_grace, graceful.shutdown())
        .await
        .is_err()
    {
        warning!("shutdown", "result=grace_expired");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(m: &Message) -> Vec<u8> {
        m.to_bytes().unwrap()
    }

    fn sealed(n: usize, id: &[u8]) -> Vec<gsp_wire::SealedOp> {
        (0..n)
            .map(|i| gsp_wire::SealedOp {
                aead_alg: 1,
                fragment_id: id.to_vec(),
                nonce: vec![i as u8; 24],
                ciphertext: vec![0xAB; 10 + i * 300],
            })
            .collect()
    }

    /// The scan must never refuse a frame `gsp-wire` produces.
    #[test]
    fn precheck_accepts_every_valid_frame_shape() {
        let cfg = Config::default();
        for id_len in [1usize, 16, 23, 24, 64] {
            let id = vec![7u8; id_len];
            for n in [0usize, 1, 2, 24, 64] {
                let body = frame(&Message::Push {
                    fragment_id: id.clone(),
                    sealed: sealed(n, &id),
                });
                assert_eq!(precheck_push(&body, &cfg), Ok(&id[..]));
            }
            for (after, limit) in [(0, 0), (23, 24), (u64::MAX, u32::MAX)] {
                let body = frame(&Message::Pull {
                    fragment_id: id.clone(),
                    after,
                    limit,
                });
                assert_eq!(precheck_pull(&body), Ok(()));
            }
        }
    }

    #[test]
    fn precheck_applies_the_limits() {
        let id = [7u8; 16];
        let cfg = Config {
            max_push_items: 3,
            max_item_bytes: 600,
            ..Config::default()
        };
        let push = |n| {
            frame(&Message::Push {
                fragment_id: id.to_vec(),
                sealed: sealed(n, &id),
            })
        };
        assert!(precheck_push(&push(2), &cfg).is_ok());
        // Third item is 10 + 2 * 300 bytes of ciphertext plus its header.
        assert_eq!(precheck_push(&push(3), &cfg).unwrap_err().status, 413);
        assert_eq!(precheck_push(&push(4), &cfg).unwrap_err().status, 413);
        // Wrong frame type, bad fragment ids, trailing bytes, truncation.
        let pull = frame(&Message::Pull {
            fragment_id: id.to_vec(),
            after: 0,
            limit: 1,
        });
        assert_eq!(precheck_push(&pull, &cfg).unwrap_err().status, 400);
        assert_eq!(precheck_pull(&push(1)).unwrap_err().status, 400);
        for bad_id in [vec![], vec![1u8; 65]] {
            let body = frame(&Message::Pull {
                fragment_id: bad_id,
                after: 0,
                limit: 1,
            });
            assert_eq!(precheck_pull(&body).unwrap_err().status, 400);
        }
        let good = push(2);
        for cut in 0..good.len() {
            assert_eq!(precheck_push(&good[..cut], &cfg).unwrap_err().status, 400);
        }
        let trailing = [good, vec![0]].concat();
        assert_eq!(precheck_push(&trailing, &cfg).unwrap_err().status, 400);
    }

    /// The reviewer's amplification bodies stop at the scan: at the first
    /// byte that is not the head of a five-element array, or at the item
    /// count, having read fewer than 16 bytes and allocated nothing.
    #[test]
    fn precheck_stops_amplification_bodies_at_the_first_wrong_byte() {
        let cfg = Config::default();
        let n: usize = (1024 * 1024 - 32) / 2;
        let mut map_body = vec![0x83, 0x03, 0x41, 0x01, 0x81, 0xba];
        map_body.extend_from_slice(&(n as u32).to_be_bytes());
        map_body.resize(map_body.len() + 2 * n, 0x60);
        assert_eq!(precheck_push(&map_body, &cfg), Err(MALFORMED));
        // Same verdict from the first 16 bytes alone: nothing past them
        // was needed to refuse.
        assert_eq!(precheck_push(&map_body[..16], &cfg), Err(MALFORMED));

        let n: usize = 1024 * 1024 - 16;
        let mut array_body = vec![0x83, 0x03, 0x41, 0x01, 0x9a];
        array_body.extend_from_slice(&(n as u32).to_be_bytes());
        array_body.resize(array_body.len() + n, 0xf6);
        assert_eq!(precheck_push(&array_body, &cfg).unwrap_err().status, 413);
        assert_eq!(
            precheck_push(&array_body[..9], &cfg).unwrap_err().status,
            413
        );

        // Length fields that point past the body or overflow.
        for liar in [
            &[
                0x83, 0x03, 0x41, 0x01, 0x81, 0x85, 0x00, 0x01, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff,
            ][..],
            &[
                0x83, 0x03, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ][..],
            &[0x83, 0x03, 0x41, 0x01, 0x9b, 0, 0, 0, 0, 0, 0, 0, 1][..],
            &[0x83, 0x03, 0x41, 0x01, 0x9f][..],
        ] {
            assert_eq!(precheck_push(liar, &cfg), Err(MALFORMED));
        }
    }
}
