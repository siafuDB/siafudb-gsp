# siafudb-gsp

The Graph Sync Protocol for [SiafuDB](https://siafudb.org), a Bundu Foundation
open project. Apache-2.0.

- `crates/siafudb-sync`: the existing GSP code, moved out of `siafuDB/siafudb`
  with its git history.
- Planned: `crates/gsp-wire`, an engine-independent crate for the signed,
  crypto-agile op envelope and wire messages (no database dependency, builds
  for wasm and mobile).

The relay is untrusted by design: it sees ciphertext and opaque cursors only.
