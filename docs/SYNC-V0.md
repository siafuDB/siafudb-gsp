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
with BLAKE3 `derive_key(context, key_material)`:

| Value          | Context string        | Key material    | Use                                               |
| -------------- | --------------------- | --------------- | ------------------------------------------------- |
| `fragment_key` | `gsp/v0/fragment-key` | `root`          | 32 bytes. Seals everything sent to the relay.     |
| `fragment_id`  | `gsp/v0/fragment-id`  | `root`          | First 16 bytes. Public routing id.                |
| `relay_token`  | `gsp/v0/relay-token`  | `root ‖ origin` | 32 bytes. Bearer token for one relay (section 6). |

**The relay token is per relay.** `origin` is the UTF-8 bytes of the relay's
canonical origin, appended to the 32 bytes of the root. A relay operator sees
the token of its own relay only, so it cannot use it to register the fragment
on another relay before the owner does.

The canonical origin is `scheme://host[:port]` with nothing after it:

- `scheme` is `http` or `https`, in lowercase;
- `host` is an ASCII host name or IPv4 address in lowercase
  (internationalised names in their `xn--` form), or an IPv6 address in square
  brackets with lowercase hex digits;
- `port` is decimal without leading zeros, `1 ..= 65535`, and is **omitted**
  when it is the default for the scheme (80 for `http`, 443 for `https`);
- no path, no trailing slash, no query, no fragment, no user info.

So `https://relay.example`, `http://localhost:8787` and `https://[2001:db8::1]`
are canonical; `HTTPS://Relay.Example:443/` is not, and an implementation
normalises it to the first before deriving. IPv6 zero compression is not
normalised: write the address the way the relay is configured. A relay reached
under two origins has two tokens, and is two relays as far as registration
goes.

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

**When an op applies.** A replica applies an op when the author's key log is
known and the author's previous op (`seq - 1`) has been applied. Nothing else
is required. In particular `deps` are **advisory**: a writer still records the
heads of the other authors it had applied, as causal metadata for tools and
for later versions, but a receiver does not wait for them. Merge is a function
of the set of ops, so waiting adds nothing to convergence, and it would let
one author's missing, invalid or forked op hold back every author who had seen
it.

An op that cannot apply yet is **pending**, for one of these reasons:

| Reason           | Waits for                                                       |
| ---------------- | --------------------------------------------------------------- |
| unknown author   | the author's genesis key-log entry                              |
| missing previous | the author's op at `seq - 1`                                    |
| clock ahead      | local time: the op's `wall_ms` is more than `max_drift` ahead   |
| unverifiable     | newer software (WIRE-V0 section 6); re-checked on every restore |

Ops that are `Invalid` are dropped and counted.

**Pending is bounded** per author and in total (defaults: 256 ops and 2 MiB
per author, 4096 ops and 16 MiB in all). When a bound is reached an op is
dropped: for an author over its share, its pending op with the highest `seq`;
when the whole store is full, the incoming one. The replica marks the author
as having a gap and reports that it needs a **resync**: pulling the relay log
again from position 0. Replay is idempotent, so a resync is always safe; a
transport does it with a growing delay, since the reason an author's ops cannot
apply (a missing op, a wrong clock) may still be there. The pull cursor is
never held back by an item the replica could not use.

**Clocks.** An op whose `wall_ms` is more than `max_drift` (300 000 ms) ahead
of the receiver's clock is held and applied once the receiver's clock has
caught up; until then its timestamp is not merged into the receiver's HLC. An
op more than `max_clock_ahead` (default 24 hours) ahead is **rejected**: a
device with such a clock would otherwise win every last-writer-wins comparison
for as long as its lead lasts. Later ops of that author then wait behind the
rejected one, within the author's bound, and a resync applies them once real
time has reached their stamps. A replica reports, per author, by how much the
last op it looked at was ahead, so that an application can say which device's
clock is wrong.

**Authors are bounded.** A replica accepts at most `max_authors` key logs
(default 64, its own included); a further genesis is rejected and counted.
Which 64 are accepted depends on arrival order, so a fragment with more
devices than that does not converge. Raise the bound on every device if a
fragment needs more.

**Equivocation.** Two different ops at the same `(author, seq)` are an
equivocation: the first seen stays, the second is rejected, and the proof is
kept (at most 64 records). Replicas that saw different ones first then follow
different branches of that author's chain, and each rejects the ops of the
other branch as they arrive (`prev` does not match). Because `deps` do not
gate, this affects only what the equivocating author wrote; see section 8.

**A device's own chain.** A replica can receive a validly signed op of _its
own_ author that it did not record. Then its state was rolled back (restored
from a backup, or saved separately from a push), or a second device is
running with a copy of its seed. There are two cases.

_Fast-forward._ The op is beyond the replica's head and continues from it
(`seq = head + 1`, `prev` = the head). Nothing conflicts: the replica applies
it like any other op, with effects, and its own head, next `seq` and HLC move
forward with it. An op further ahead waits for the ones between, as for any
author. The drift and horizon rules above are not applied to a replica's own
ops: they carry its own earlier stamps, and it cannot rejoin its chain without
them. From the first moment the replica has _seen_ an own op it has not yet
applied, it refuses local commits (a distinct "own chain ahead" error) until
its chain is applied up to the highest position seen. After that it writes as
before, as the same author; nobody else can tell that anything happened.

_Fork._ The op is at a position where the replica recorded a **different**
op, or it claims to be the next op and does not continue from the head. The
replica wrote after the rollback and before it had caught up, so one position
now has two ops, and peers will have rejected one of them without telling
anyone. Signing anything more as that author would repeat this. The replica
enters a **forked** state: local commits are refused with a distinct error,
ingest goes on. It follows the version of its old chain that the relay has
(applying those ops, and setting aside the conflicting ones it wrote itself,
which stay merged locally). The application recovers by **resetting the
identity**: a fresh device seed, a new genesis, and under it one new op for
every set-aside op whose bytes the replica still holds (section 6), carrying
the same changes under new stamps. To the other devices this is a new device
joining.

A replica cannot know how many of its own ops a relay holds, so it cannot
close the gap between the two cases by itself: **after restoring state that
may be old, a client pulls to the relay's head before it lets the application
write.**

**Effects.** After applying ops, the replica emits the _difference in visible
state_ as a list of `Change`s for the engine adapter: only winning writes, a
`node_put` the first time a node becomes visible, `edge_del` for edges hidden
by a node delete, and so on. Applying the same sealed item twice emits nothing
the second time.

**Local writes.** The adapter hands the replica the changes of a local commit.
The replica stamps them with `Hlc::tick`, updates its own state, signs one op
with `deps` set to the current heads of other authors (at most 64, the most
recent), seals it and puts it in the outbox. The adapter must hand over local changes before applying remote
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

- `Authorization: Bearer <base64url relay_token>` on push and pull, where
  `relay_token` is the one derived for this relay's origin (section 2). The first
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

### 6.1 What a client does

One round of a transport, for a replica `r`:

1. **Push** the head of the outbox. On `Ack`, take the acknowledged items out
   of the outbox but **keep them** until each has come back in a pull (an
   _echo_, recognised by its exact bytes). They normally echo in the next
   pull. At most 1024 are kept; beyond that the oldest are forgotten.
2. **Pull** after the cursor. Hand every item to the replica with its
   position; the cursor moves to the highest position handed over, whatever
   became of the item. A transport never stops at, or retries, an item
   because the replica could not use it.
3. **Check `Batch.next` against the cursor.** A relay never holds fewer items
   than it has handed out, unless it lost its log and is numbering from 1
   again. If `next` is below the cursor, that is what happened: set the cursor
   to 0, and put every kept, un-echoed item back at the front of the outbox.
   (A relay answers a pull whose `after` is beyond its head at once, with an
   empty `Batch` and `next` = its head, so that this can be seen.) Without
   this step a client would skip everything other devices push to the new log
   up to its old cursor.
4. **Resync when the replica asks** (section 5): cursor to 0 and pull again,
   with a growing delay between attempts.
5. **Tell the application when the replica is forked** (section 5).
6. **After a restore, pull before writing.** When the state may be older than
   what was last pushed (it came from a backup, or the client cannot tell),
   pull until a `Batch` has `more = false` before accepting local writes.
   The replica then fast-forwards over its own ops (section 5). A write made
   before that is a fork.

## 7. Replica state

A replica can serialise its whole state to bytes and restore from them: device
seed, root secret, key logs, per-author chain heads and status, merge state
(stamps and tombstones), pending items, outbox, acknowledged items not yet
echoed, the pull cursor, whether it is forked, counters and equivocation
records. The encoding is deterministic CBOR with a tag and a version; a
replica refuses a version it does not know.

Three rules for whoever stores the bytes:

- They contain the root secret and the device seed.
- Restoring checks **form, not integrity**: the bytes must be the one
  canonical encoding of the state they describe, and every key log in them
  must verify, but bytes changed into _another_ well-formed state are
  accepted. Whoever can modify the stored state can move the cursor, remove an
  op from an author's list, or alter merge stamps. Store the state under
  **authenticated encryption** (an AEAD), not merely encrypted.
- Store it **atomically with the engine's data** (one write), so the two
  cannot disagree after a crash, and never restore an older copy while keeping
  the device identity: a rolled-back replica re-signs positions it has already
  used. A replica detects this when its own ops come back from the relay
  (section 5), which is after the fact.

Pending ops are evaluated afresh after a restore, so an op that an older build
could only keep as unverifiable is applied by a newer one.

## 8. Limits of v0

- One trust domain per fragment: no per-author permissions, no removing a
  device without creating a new fragment.
- **Equivocation leaves a permanent, bounded disagreement.** "First seen
  stays" is not a function of the set of ops: two replicas that saw different
  ops first at one `(author, seq)` keep different ones, and from there follow
  different branches of that author's chain, for good. The damage is confined
  to that author's own ops (everything every other author writes still
  converges) but it is not repaired: v0 has no deterministic re-merge, and no
  way to expel the author. Each replica holds a proof and flags the author. An
  author that equivocates is by the trust rule of section 2 a device of the
  owner, so in practice this is a device whose state was rolled back; see the
  next point.
- **Rollback is safe only if the client pulls first.** A rolled-back replica
  that pulls before writing fast-forwards over its own ops and loses nothing
  (section 5). One that writes first forks, and recovers by taking a new
  identity. That recovery is partial: the ops it wrote on its own branch are
  re-issued only if their bytes are still held (not yet echoed, or still in the
  outbox), which is the normal case because detection happens at the first
  pull after the rollback; and if a concurrent write by another device fixed
  the endpoints of the same edge in between, the forked device and the others
  can keep different endpoints for that edge. Fast-forward also depends on the
  relay still holding the device's ops: if one is missing, the replica stays
  in the "own chain ahead" state and only an identity reset gets it writing
  again.
- **A copied seed looks like a rollback.** Two devices running with one device
  seed fast-forward over each other's ops until both write at the same
  position; then both are forked. v0 has no way to tell this from a restore.
- **A wiped relay loses history.** A client notices the reset and pushes again
  what was in flight (section 6.1). Ops that only the relay held (for a device
  that had not pulled them yet) are gone, and so are the key logs and early
  ops a new device would need: after a relay loses its log, devices that were
  not up to date, and devices that join later, cannot reach the others' state.
  There is no snapshot transfer to repair this in v0.
- **Clock horizon.** An op more than 24 hours ahead of a receiver's clock is
  rejected by that receiver, and its author's later ops wait behind it. If the
  _receiver's_ clock is the wrong one, it rejects everybody until its clock is
  fixed and it has resynced.
- At most 64 devices per fragment by default (section 5).
- `deps` are recorded but not enforced: a replica can apply an op before the
  ops its writer had seen. The merged state is the same in the end; the
  effects an engine sees in between can show a later write before an earlier
  one.
- Tombstones and merge stamps grow without bound.
- A new device replays the whole history from the relay; there is no snapshot
  transfer.
- No transport security of its own, no session key exchange; the hybrid
  X25519 + ML-KEM-768 registry ids remain unused.
- The relay token is registered on first use. Whoever pushes first to a
  fragment id owns it on that relay. The token is bound to the relay's origin,
  so one relay's operator cannot do this on another relay; anyone else would
  need the root secret.
- Not audited.
