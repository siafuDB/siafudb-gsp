# GSP sync v0

Status: **draft, unaudited.** Builds on [WIRE-V0.md](WIRE-V0.md), which defines
ops, signatures, key logs, sealed ops and frames. This document defines what
WIRE-V0 left open: the op payload, the merge rules, how devices pair, and how
they talk to a relay.

Goal of v0: **two devices of one person converge through a relay that stores
only ciphertext.** Personal fragments only. Sharing between people, device
revocation and history compaction are not in v0 (see Limits).

## 1. Crates

| Crate       | Role                                                                                    |
| ----------- | --------------------------------------------------------------------------------------- |
| `gsp-wire`  | Encoding, signatures, key log, sealing, frames. `no_std + alloc`.                       |
| `gsp-sync`  | The replica: pairing secrets, payload, merge, outbox, cursor. No I/O, no clock, no RNG. |
| `gsp-relay` | Reference relay: an HTTP server that stores and forwards sealed items.                  |

`gsp-sync` knows nothing about any database engine. An engine adapter (for
SiafuDB: in `siafuDB/siafudb`) turns local commits into `Change`s and applies
the `Change`s a replica emits.

## 2. Pairing

A fragment is created from a 32-byte random **root secret**. Showing it to a
second device (QR code, typed code) is pairing. Everything else is derived
with BLAKE3 `derive_key(context, root)`:

| Value          | Context string        | Use                                               |
| -------------- | --------------------- | ------------------------------------------------- |
| `fragment_key` | `gsp/v0/fragment-key` | 32 bytes. Seals everything sent to the relay.     |
| `fragment_id`  | `gsp/v0/fragment-id`  | First 16 bytes. Public routing id.                |
| `relay_token`  | `gsp/v0/relay-token`  | 32 bytes. Bearer token for the relay (section 6). |

The text form of the root secret is `gsp0-` followed by unpadded base64url of
the 32 bytes.

**Trust rule in v0:** whoever can seal under the fragment key is a device of
the owner. A replica accepts the genesis key-log entry of any author that
arrives sealed under the fragment key. Signatures still give per-device
attribution, hash-chained history and equivocation detection, but they are not
an access-control boundary inside the fragment.

Each device has its own author identity: a 32-byte random device seed, an
Ed25519 key derived from it, and a key log whose genesis policy is `[Ed25519]`.
Hybrid Ed25519 + ML-DSA-65 is supported by the wire format and can be chosen
at genesis; it is not the default for Personal fragments because an ML-DSA-65
signature adds about 3.3 KB to every op, which matters on metered mobile data.
Confidentiality does not depend on the signature algorithm.

## 3. What travels

`Plain` (WIRE-V0 section 9) gains a third kind:

| Kind | Content              |
| ---- | -------------------- |
| 1    | signed op            |
| 2    | signed batch         |
| 3    | signed key-log entry |

A device's first push is its genesis key-log entry (kind 3), then ops. An op
whose author's key log is not known yet is held as pending, not dropped.

## 4. Payload

`OpBody.payload` is an array of one or more changes. One op is one local
commit; its changes are applied together.

```text
payload      = [+ change]
change       = node_put / node_del / edge_put / edge_del
node_put     = [1, gid, labels_add: [* text], labels_remove: [* text], set: {* text => value}, unset: [* text]]
node_del     = [2, gid]
edge_put     = [3, gid, src: gid, dst: gid, type: text, set: {* text => value}, unset: [* text]]
edge_del     = [4, gid]
gid          = bstr .size 16        ; random, assigned by the device that creates the entity
value        = null / bool / int / float / text / bstr / [* value] / {* text => value}
```

Arrays `labels_add`, `labels_remove` and `unset` are sorted bytewise and have
no duplicates. A key must not appear in both `set` and `unset`, nor a label in
both label lists. Limits: 1024 changes per op, 64 KiB per encoded payload,
256 bytes per key or label. An op that breaks these rules is `Invalid`.

Engine-local ids never appear on the wire. Ids are 16 random bytes so two
offline devices cannot collide.

## 5. Merge

Every write carries the stamp `(hlc, op_id)` of its op. Stamps are ordered by
HLC, then by the bytes of the op id. All rules below are functions of the
_set_ of ops applied, so replicas that have applied the same set hold the same
state regardless of arrival order.

1. **Deletes win.** `node_del` / `edge_del` tombstone the gid for good. Any
   put for a tombstoned gid, earlier or later, has no effect. Tombstones are
   never collected in v0.
2. **Properties** are last-writer-wins registers per `(gid, key)`. `unset`
   writes "absent" with the op's stamp. The highest stamp wins.
3. **Labels** are last-writer-wins per `(gid, label)` between present and
   absent.
4. **Edge endpoints and type** are fixed by the put with the lowest stamp for
   that gid. Later puts only contribute properties.
5. **Visibility.** A node is visible if it has at least one put and no
   tombstone. An edge is visible if it has at least one put, no tombstone, and
   both endpoints are visible. Deleting a node therefore hides its edges; this
   is permanent because tombstones are.

A replica applies an op only when its causal context is complete: the author's
key log is known, the author's previous op (`seq - 1`) has been applied, and
every id in `deps` has been applied. Otherwise it is pending. Ops that are
`Invalid` are dropped and counted. Two different ops at the same `(author,
seq)` are an equivocation: the first seen stays, the second is rejected and the
proof is kept.

**Effects.** After applying ops, the replica emits the _difference in visible
state_ as a list of `Change`s for the engine adapter: only winning writes, a
`node_put` the first time a node becomes visible, `edge_del` for edges hidden
by a node delete, and so on. Applying the same sealed item twice emits nothing
the second time.

**Local writes.** The adapter hands the replica the changes of a local commit.
The replica stamps them with `Hlc::tick`, updates its own state, signs one op
with `deps` set to the current heads of other authors, seals it and puts it in
the outbox. The adapter must hand over local changes before applying remote
effects, so the engine and the replica never disagree about what was local.

## 6. Relay

The relay stores sealed items per fragment in arrival order and hands them
back. It cannot read them. It is not trusted for ordering, completeness or
freshness: `relay_seq` is only a resume cursor, and a replica validates
everything it receives.

HTTP, CBOR bodies (`content-type: application/cbor`), frames from WIRE-V0
section 10:

| Request                             | Body   | Reply    |
| ----------------------------------- | ------ | -------- |
| `POST /v0/push`                     | `Push` | `Ack`    |
| `POST /v0/pull?wait_ms=<0..=25000>` | `Pull` | `Batch`  |
| `GET /healthz`                      |        | `200 ok` |

- `Authorization: Bearer <base64url relay_token>` on push and pull. The first
  push to a fragment id registers `BLAKE3(relay_token)`; after that the relay
  rejects any other token for that fragment with `401`. This keeps strangers
  who learn a fragment id from reading ciphertext or filling the log.
- Items are numbered from 1 per fragment. `Pull.after` is exclusive. A pull
  with `wait_ms > 0` and nothing new is held until an item arrives or the time
  is up (long poll), then answers with an empty `Batch`.
- An item whose exact bytes are already stored for the fragment is not stored
  again; it still counts as accepted in the `Ack`.
- Limits (configurable): 256 KiB per item, 1 MiB per request, 64 items per
  push, 256 items per `Batch`, and a per-fragment byte quota. Over-limit
  requests get `413`; malformed frames `400`; the body of an error reply is an
  `Error` frame.
- CORS: `access-control-allow-origin` from configuration (default `*`);
  `authorization` and `content-type` allowed; preflight answered.
- TLS is terminated in front of the relay.

What the relay learns: fragment ids, item sizes and timing, client addresses.
What it never has: keys, plaintext, author ids, op contents.

## 7. Replica state

A replica can serialise its whole state to bytes and restore from them: device
seed, root secret, key logs, per-author chain heads, merge state (stamps and
tombstones), pending items, outbox, and the pull cursor. The bytes contain
secrets and must be stored encrypted. An adapter must store them **atomically
with the engine's data** (one write), so the two cannot disagree after a
crash.

## 8. Limits of v0

- One trust domain per fragment: no per-author permissions, no removing a
  device without creating a new fragment.
- Tombstones and merge stamps grow without bound.
- A new device replays the whole history from the relay; there is no snapshot
  transfer.
- No transport security of its own, no session key exchange; the hybrid
  X25519 + ML-KEM-768 registry ids remain unused.
- The relay token is registered on first use. Whoever pushes first to a
  fragment id owns it on that relay.
- Not audited.
