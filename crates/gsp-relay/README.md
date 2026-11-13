# gsp-relay

Reference relay for the Graph Sync Protocol v0. It is an HTTP server that
stores sealed (encrypted) items per fragment in arrival order and hands them
back. The specification is `docs/SYNC-V0.md` section 6; frames are
`docs/WIRE-V0.md` section 10.

It is a library (`gsp_relay::Relay`, `serve`, the `Store` trait) and a binary
(`gsp-relay`). No `unsafe`. New, unaudited code.

## What it can and cannot see

The relay is given `SealedOp` items and never has a key to open them.

It can see:

- fragment ids (public routing ids);
- for each item: the AEAD algorithm id, the nonce, and the ciphertext, so
  also its length (v0 has no length padding);
- when items arrive and when clients poll, and how many items a fragment has;
- client network addresses, as any server does (this implementation does not
  log or store them; a proxy in front of it may);
- `BLAKE3(relay_token)` for each fragment, and the relay token itself in
  memory while a request is handled.

It cannot see: fragment keys, plaintext, author ids, per-author sequence
numbers, clocks, signatures, or op contents. A test
(`plaintext_marker_never_appears_in_what_the_relay_holds`) seals a marker
string, pushes it, and checks that the marker is in no stored byte and no
reply. That holds by construction; the test is there to catch a later change
that adds plaintext metadata.

It is not trusted for ordering, completeness or freshness. It can drop,
withhold, reorder or replay items, and it can refuse service. Clients must
validate what they receive. A relay token only controls who may read
ciphertext from, and append to, a fragment on this relay.

## Run

```sh
cargo build --release -p gsp-relay
GSP_RELAY_DATA_DIR=/var/lib/gsp-relay ./target/release/gsp-relay
# or
./target/release/gsp-relay --addr 127.0.0.1:8787 --data-dir /var/lib/gsp-relay
```

Storage has to be chosen. With neither `--data-dir` nor `--in-memory` the
relay exits with status 2 and a message saying so. `--in-memory` keeps nothing
on disk: every item, token registration and cursor is lost when the process
stops, and the relay prints a warning at startup. It is meant for tests and
demos. `--fsync never` also prints a warning at startup.

A relay reachable from the internet should set a registration secret
(`GSP_RELAY_REGISTRATION_TOKEN`, see Registration) or sit behind something
that authenticates callers. Without one, anyone who can reach it can register
fragments until its quotas are used up; the relay says so at startup.

SIGINT or SIGTERM stops accepting connections, answers
held long-polls with an empty `Batch`, and waits up to the shutdown grace for
requests in flight.

A small client that pushes, pulls, opens what it pulled and holds a
long-poll:

```sh
./target/release/gsp-relay --in-memory &
cargo run -p gsp-relay --example roundtrip -- 127.0.0.1:8787
```

The example sends `x-gsp-registration` if `GSP_RELAY_REGISTRATION_TOKEN` is
set in its environment.

## Endpoints

| Request                             | Body   | Reply    |
| ----------------------------------- | ------ | -------- |
| `POST /v0/push`                     | `Push` | `Ack`    |
| `POST /v0/pull?wait_ms=<0..=25000>` | `Pull` | `Batch`  |
| `GET /healthz`                      |        | `200 ok` |
| `OPTIONS` on any of the above       |        | `204`    |

Bodies are single CBOR frames. Push and pull need
`Authorization: Bearer <unpadded base64url of the 32-byte relay token>`.

- The first non-empty push to a fragment id registers `BLAKE3(token)`. After
  that any other token gets `401` on push and pull. Comparison is
  constant-time.
- Registration and storing the first items are one step. Every limit (item
  size, item count, fragment quota, relay-wide quota, fragment count,
  registration secret) is checked before anything is written. A first push
  that is refused, or that fails in the store, leaves nothing behind: the
  fragment is not registered and no file exists for it.
- A pull on a fragment nobody has pushed to returns an empty `Batch`
  (`next = 0`) at once and registers nothing. It is never held, whatever
  `wait_ms` says, and does not count against the long-poll caps: anyone can
  ask about any id, so holding such requests would let strangers use up the
  long-poll slots.
- Items are numbered from 1 per fragment. `Pull.after` is exclusive.
  `Batch.next` is the cursor of the last item returned; for an empty `Batch`
  it is the fragment's latest cursor. `Batch.more` is true when items exist
  past `next`. `Pull.limit = 0` means "as many as the relay allows".
- `Ack.cursor` is the fragment's latest cursor after the push; `Ack.count` is
  the number of items in the push, including ones already stored.
- An item whose exact bytes are already stored for the fragment is not stored
  again. (Equality is decided by BLAKE3 of the item bytes.)
- Every `SealedOp.fragment_id` in a push must equal `Push.fragment_id`.
- A push is all or nothing: if any check fails, none of its items is stored.
- `wait_ms` above 25000 is treated as 25000. A pull is held only when the
  fragment is registered, the token is right, and `after` equals the
  fragment's latest cursor. It then returns as soon as a new item exists, or
  with an empty `Batch` when the time is up.
- **Detecting a relay that lost its data.** A pull whose `after` is greater
  than the fragment's latest cursor is answered at once, never held, with an
  empty `Batch` whose `next` is the relay's latest cursor (0 if the relay
  does not know the fragment). So `Batch.next < Pull.after` always means: this
  relay has fewer items than the client has already seen from it. It has
  been reset or replaced and is numbering from 1 again. A client that sees
  this should pull again from 0 (items it already has are harmless
  duplicates) and push again whatever it cannot assume the relay still has.
  There is no other signal in v0; a relay that was reset and has since grown
  past the client's cursor cannot be told apart this way.

Error replies carry an `Error` frame whose `code` is the HTTP status:

| Status       | When                                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`        | Body is not a well-formed frame, is the wrong frame type, has an invalid fragment id, has an item addressed to another fragment, or `wait_ms` is not a number |
| `401`        | Missing or malformed bearer token, or not the token registered for the fragment                                                                               |
| `403`        | First push to a new fragment without the registration secret this relay requires (missing or wrong `x-gsp-registration`)                                      |
| `404`, `405` | Unknown path, wrong method                                                                                                                                    |
| `408`        | Request body not received within the read timeout                                                                                                             |
| `413`        | Request body, item, or item count over the limit; or the push would exceed the fragment quota                                                                 |
| `429`        | Too many concurrent long-polls (per fragment or overall); `retry-after: 1`                                                                                    |
| `500`        | Storage error                                                                                                                                                 |
| `503`        | The decode budget is in use by other pushes right now; `retry-after: 1`                                                                                       |
| `507`        | The relay-wide quota or fragment count is exhausted                                                                                                           |

Past a long-poll cap the reply is `429`, not an immediate empty `Batch`: an
empty reply would look like a normal timeout and a client would poll again at
once. Pulls with `wait_ms=0` are never counted as long-polls.

CORS: every reply has `access-control-allow-origin` (default `*`, plus
`vary: origin` when configured to something else). Preflight replies allow
`GET, POST, OPTIONS` and the headers `authorization, content-type,
x-gsp-registration`.

### Registration

By default anyone who can reach the relay may register a fragment. With
`--registration-token` / `GSP_RELAY_REGISTRATION_TOKEN` set, the first push
to a new fragment must also carry `x-gsp-registration: <secret>`; without it,
or with a wrong value, the reply is `403` and nothing is registered. The
comparison is constant-time (BLAKE3 of both values).

- Only registration is affected. Once a fragment exists, pushes and pulls
  need only its relay token, so other devices of the same fragment do not
  need the secret, and changing or removing the secret does not affect
  existing fragments.
- The secret does not replace a relay token and gives no access to existing
  fragments.
- It is one shared value for the whole relay, held in memory, never written
  to the data directory and never logged. Prefer the environment variable:
  command-line flags are visible in process listings.
- It is sent on every first push, so it is only as private as the people and
  apps it is given to. For anything finer (per-user accounts, revocation),
  authenticate in front of the relay.

### Order of checks on a push

The cheap checks come first, so an unauthenticated request cannot make the
relay do expensive work:

1. bearer token syntax (before the body is read);
2. body size, enforced while reading;
3. a scan of the body's shape without allocation: it must be
   `[3, bstr, [* [uint, uint, bstr, bstr, bstr]]]` and nothing else, with the
   item count and each item's size inside the limits. Bodies of any other
   shape (nested arrays, maps, wrong lengths) are refused here;
4. the relay token if the fragment is registered, otherwise the registration
   secret if the relay has one;
5. only then the full strict decode by `gsp-wire` and the push itself, on a
   blocking thread, not on the async workers. At most `--max-decode-bytes`
   of request bodies are in this stage at once; a push that does not fit
   gets `503` with `retry-after: 1` instead of being queued.

A body that passes step 3 is flat, so decoding it costs time and memory
proportional to its size. Pull bodies are at most 1 KiB and are decoded in
place after the same kind of scan.

## Configuration

Each flag can also be set through the environment variable. A flag wins.

| Flag                       | Environment                        | Default          | Meaning                                                                                |
| -------------------------- | ---------------------------------- | ---------------- | -------------------------------------------------------------------------------------- |
| `--addr`                   | `GSP_RELAY_ADDR`                   | `127.0.0.1:8787` | Listen address                                                                         |
| `--data-dir`               | `GSP_RELAY_DATA_DIR`               | unset            | Directory for the durable store. Required unless `--in-memory`                         |
| `--in-memory`              | `GSP_RELAY_IN_MEMORY=1`            | off              | Keep nothing on disk; all data and cursors are lost on exit. Excludes `--data-dir`     |
| `--registration-token`     | `GSP_RELAY_REGISTRATION_TOKEN`     | unset (open)     | Secret a first push to a new fragment must send in `x-gsp-registration`                |
| `--max-decode-bytes`       | `GSP_RELAY_MAX_DECODE_BYTES`       | 8388608          | Request-body bytes being decoded and processed at once; at least `max-request-bytes`   |
| `--cors-origin`            | `GSP_RELAY_CORS_ORIGIN`            | `*`              | `access-control-allow-origin` value                                                    |
| `--fsync`                  | `GSP_RELAY_FSYNC`                  | `always`         | `always` or `never`, see Durability                                                    |
| `--max-item-bytes`         | `GSP_RELAY_MAX_ITEM_BYTES`         | 262144           | Largest encoded `SealedOp`                                                             |
| `--max-request-bytes`      | `GSP_RELAY_MAX_REQUEST_BYTES`      | 1048576          | Largest request body                                                                   |
| `--max-push-items`         | `GSP_RELAY_MAX_PUSH_ITEMS`         | 64               | Items per `Push`                                                                       |
| `--max-batch-items`        | `GSP_RELAY_MAX_BATCH_ITEMS`        | 256              | Items per `Batch`                                                                      |
| `--max-batch-bytes`        | `GSP_RELAY_MAX_BATCH_BYTES`        | 1048576          | Item bytes per `Batch` (at least one item is always sent)                              |
| `--fragment-quota-bytes`   | `GSP_RELAY_FRAGMENT_QUOTA_BYTES`   | 67108864         | Per-fragment quota                                                                     |
| `--total-quota-bytes`      | `GSP_RELAY_TOTAL_QUOTA_BYTES`      | 4294967296       | Quota across all fragments                                                             |
| `--max-fragments`          | `GSP_RELAY_MAX_FRAGMENTS`          | 4096             | Fragments that can be registered                                                       |
| `--max-polls-per-fragment` | `GSP_RELAY_MAX_POLLS_PER_FRAGMENT` | 8                | Concurrent long-polls on one fragment                                                  |
| `--max-polls`              | `GSP_RELAY_MAX_POLLS`              | 512              | Concurrent long-polls overall                                                          |
| `--max-connections`        | `GSP_RELAY_MAX_CONNECTIONS`        | 1024             | Open TCP connections; more are closed on accept                                        |
| `--read-timeout-ms`        | `GSP_RELAY_READ_TIMEOUT_MS`        | 15000            | Time to receive request headers (also the keep-alive idle time), and separately a body |
| `--shutdown-grace-ms`      | `GSP_RELAY_SHUTDOWN_GRACE_MS`      | 10000            | Wait for in-flight requests on shutdown                                                |

Quotas charge each stored item its length plus 64 bytes, so that many tiny
items cannot use unbounded disk and index memory under a byte quota. Nothing
is ever deleted: a fragment that reaches its quota stays full.

## Durability

With `--data-dir`, each fragment is one append-only file,
`<data-dir>/fragments/<hex fragment id>.log`:

```text
header = "GSPRLY01" id_len:u8 fragment_id token_hash:32 blake3(all before):32
record = len:u32le blake3(item):32 item
```

The n-th record is cursor n. Records are never rewritten, so cursors are the
same after a restart.

- A new fragment file (with the token hash) is written under a temporary
  name, synced, renamed, and the directory is synced, under either policy.
- `--fsync always` (default): one `fdatasync` per push, before the `Ack`. An
  acknowledged item survives a crash or power loss, as far as the disk honours
  the sync.
- `--fsync never`: no sync for items. After an OS crash or power loss,
  acknowledged items may be missing, and their cursors are then given to
  later items; a client that already pulled past them will not see those
  later items unless it pulls again from an earlier cursor.
- On startup every file is replayed and each record's checksum verified. The
  first record that is incomplete or fails its checksum, and everything after
  it, is cut off, and the number of bytes dropped is logged. This is meant
  for a torn tail after a crash. Damage in the middle of a file is handled
  the same way and loses the records after it.
- A `.log` file with a bad header stops startup rather than being discarded.
- A fragment file that holds no items after replay is deleted at startup and
  its registration is not restored. Such a file can only come from a crash
  between creating a fragment and storing its first item, or from a torn
  first record; no push to it was ever acknowledged (with `--fsync always`).
  While the relay runs, a registered fragment always has at least one item,
  so there are no empty registrations to expire and no idle timer for them.
- `<data-dir>/LOCK` is held with an exclusive advisory file lock while the
  relay runs. A second relay started on the same directory exits with an
  error naming the directory. The OS releases the lock when the process
  ends, however it ends, so a leftover `LOCK` file never blocks a start. On
  network file systems advisory locks may not be reliable.

## Behind TLS

The relay speaks plain HTTP/1.1 and has no TLS code. Keep it on loopback or a
private network and put a TLS-terminating reverse proxy in front. Relay tokens
are bearer credentials: do not expose the plain port.

The proxy must allow a response to take longer than the 25 s long-poll, pass
the `Authorization` header and `OPTIONS` requests through, and not buffer
request bodies larger than you intend to accept.

Caddy:

```caddyfile
relay.example.org {
    reverse_proxy 127.0.0.1:8787
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.org;
    # ssl_certificate ...; ssl_certificate_key ...;

    client_max_body_size 1m;
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_read_timeout 40s;
        proxy_buffering off;
    }
}
```

The relay has no per-client rate limiting and never looks at
`X-Forwarded-For`. If you need per-address limits, apply them in the proxy.

## Logs

One `key=value` line per event on stderr: startup, fragment registration,
pushes and non-empty pulls (fragment id prefix, item counts, byte counts,
cursor), rejections (status and a fixed reason), storage errors, shutdown.
Tokens, token hashes, item bytes and client addresses are not logged. The
first four bytes of a fragment id are.

## Limits and known weaknesses

- Without a registration secret, anyone who can reach the relay can register
  new fragments and store items until `max-fragments` or the total quota is
  used up, after which nobody can store anything new. Set
  `GSP_RELAY_REGISTRATION_TOKEN` or restrict access in front of the relay.
  With the secret, the same is true of anyone who holds it. There are no
  accounts and no rate limits.
- Fragments that hold items never expire, and nothing is ever deleted. The
  only way to free space is to stop the relay and delete fragment files.
- Whoever pushes first to a fragment id owns it on this relay. Fragment ids
  are 128-bit values derived from the root secret, so guessing one is not
  practical, but someone who learns an id before its owner's first push can
  take it. The owner then gets `401` and must use another relay or fragment.
- A caller can tell whether a fragment id is registered: a registered one
  answers `401` to a wrong token, an unregistered one answers `200` with an
  empty `Batch`.
- There is no deletion, compaction, expiry, or token rotation.
- A pull on a fragment waits for a push to the same fragment that is in the
  middle of its disk write.
- Request bodies are buffered before the decode budget applies: up to
  `max-connections` times `max-request-bytes` can be held while bodies
  arrive.
- All fragment indexes are loaded at startup and kept in memory: about 40 to
  80 bytes per stored item (a 32-byte hash for dedupe plus an offset).
- HTTP/1.1 only. No HTTP/2, no WebSocket; one long-poll holds one connection.
- Connections over `max-connections` are closed without an HTTP reply.
- Idle keep-alive connections are closed after the read timeout. A proxy that
  reuses upstream connections can occasionally hit a connection the relay
  just closed and should retry (most do for idempotent methods only; pulls
  and pushes are safe to retry because of cursors and dedupe).
- The `Error.code` registry is not defined by WIRE-V0 yet; this relay uses
  the HTTP status. `Hello`, `Auth` and `Head` frames are not used.
- Blocking disk I/O runs on tokio's blocking pool. With `--fsync always`,
  push throughput per fragment is bounded by the disk's sync latency.
- Not load-tested beyond the test suite. Not audited.

## Tests

```sh
cargo test -p gsp-relay
```

`tests/relay.rs` drives the handler in-process (round trip, cursors, paging,
dedupe, long-poll, tokens, every limit, CORS, concurrent pushers, the
confidentiality marker test). `tests/durability.rs` covers restarts and torn
tails. `tests/net.rs` uses a real listener and a hand-written HTTP client.
`tests/fuzz.rs` feeds random, truncated and mutated bodies to both endpoints.
`tests/hardening.rs` holds the regression tests for resource exhaustion:
long-poll slots, refused first pushes, decode cost and budget, the
registration secret, empty fragments after a crash, cursors beyond the head,
and the directory lock.
