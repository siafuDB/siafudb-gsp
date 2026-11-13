//! HTTP mapping of the relay (SYNC-V0 section 6) and the TCP server loop.

use crate::config::MAX_WAIT_MS;
use crate::log::{info, warning};
use crate::relay::{Reject, Relay};
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
            429 => {
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
            HeaderValue::from_static("authorization, content-type"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        self.finish(resp)
    }

    async fn frame_body<B: Body>(&self, body: B, cap: usize) -> Result<Message, Reject> {
        let bytes = read_body(body, cap, self.config().read_timeout)
            .await
            .map_err(|e| match e {
                BodyError::TooLarge => Reject::new(413, "request body too large"),
                BodyError::Timeout => Reject::new(408, "request body not received in time"),
                BodyError::Read => Reject::new(400, "request body could not be read"),
            })?;
        Message::from_bytes(&bytes).map_err(|_| Reject::new(400, "malformed frame"))
    }

    async fn push_route<B: Body>(&self, req: Request<B>) -> Result<Message, Reject> {
        let token = bearer(&req)?;
        let cap = self.config().max_request_bytes;
        match self.frame_body(req.into_body(), cap).await? {
            Message::Push {
                fragment_id,
                sealed,
            } => self.push_async(token, fragment_id, sealed).await,
            _ => Err(Reject::new(400, "expected a Push frame")),
        }
    }

    async fn pull_route<B: Body>(&self, req: Request<B>) -> Result<Message, Reject> {
        let token = bearer(&req)?;
        let wait = wait_ms(req.uri().query())?;
        let cap = self.config().max_request_bytes.min(MAX_PULL_BODY);
        match self.frame_body(req.into_body(), cap).await? {
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
                if r.status != 429 {
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
