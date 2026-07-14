# DUCTEI v0.1.0 — channel layer for LIMEN / Qallow / VEYN

Licensed under Apache-2.0 (see `LICENSE`).

Channel, not merger. Per-repo adapters over shared structs.

## Design rules
0. Deny-by-default selective-broadcast scopes, first-class envelope
   fields, checked at the channel boundary at `send()`. One forbidden
   scope poisons the whole envelope. Receivers never filter.
1. Channel-side persistence. Append-only fsynced JSONL log with
   `replay(cursor)`. Nothing is acked before it is in the log.
2. Bounded sessions only (`SessionBound`); unbounded unrepresentable.
3. Causal-delta gate: pre-sync filter on (lamport, node_id) per
   (key, scope-set). Stale/out-of-order deltas rejected, logged to a
   JSONL reject log, never applied or re-broadcast. Ties break
   deterministically by node_id. Gate state rebuilds from the accepted
   log on restart.

## Hard invariants
- LIMEN credentials and quantum link traffic never enter payloads.
  Closed adapter types; serde drops unknown fields (`api_token`,
  `qpu_instance`) before anything reaches the channel.
- Byte-level wire compatibility with Qallow `sync_wire.c` (proto v1).
  Conformance oracle must pass after every change.

## Crates
| crate | role |
|---|---|
| `ductei-core` | Scope, ScopePolicy, Envelope, LogStore, Channel, SessionBound, `gate` (causal-delta), `transport` (TCP) |
| `ductei-limen` | LIMEN cert JSON -> `qallow.semantic.cert` envelopes (closed type) |
| `ductei-qallow` | Envelope <-> Qallow QSW proto v1 bytes (pure Rust, byte-compatible) |
| `ductei-veyn` | VEYN sensor events -> scoped envelopes (`veyn.sensor.*`, deny-by-default) |
| `conformance/` | Rust emitter + C verifier linking Qallow's real `sync_wire.c` |

## Transport (Build 1)
TCP, length-prefixed frames (u32 LE len | JSON envelope), matching the
incremental-decoder pattern. Vendor-neutral `Transport` trait so
gRPC/QUIC can slot in later. Inbound path per frame:
scope policy -> causal gate -> fsynced JSONL append -> ack byte.
Ack=1 means the remote has persisted; ack=0 means denied/stale
(logged channel-side, never applied). QSW wire translation for
Qallow ingestion lives in `ductei-qallow` unchanged.

## Test status (2026-07-13)
- `cargo test --workspace`: 11/11 pass
  - v0.1.1 suite: scope deny-by-default, poisoned envelope, restart
    survival, credential drop, unbounded-session unrepresentable,
    session bound enforced with exit always available
  - Build 0: in-order accept / stale reject, tie-break determinism,
    replay-after-restart consistency
  - Build 1: two-node loopback (accept, stale nack, scope-denied nack,
    persistence-first ack)
  - Build 2: synthetic OSC/EEG event -> VEYN adapter -> gate ->
    transport -> second node log -> QSW bytes roundtrip intact
- Conformance oracle: PASS (Qallow's C `qsw_decode()` fed one byte at a
  time accepts the Rust HELLO/HELLO_ACK/ENVELOPE/BATCH_END/BYE stream)

## Run conformance
```
cargo build -p conformance-emitter
./target/debug/emit /tmp/stream.bin
gcc -I<qallow>/include -o conformance/verify conformance/verify.c <qallow>/src/mind/sync_wire.c
./conformance/verify /tmp/stream.bin
```

## Known gaps (v0.1.0)
- **Qallow-side ingestion is a stub in practice.** The roadmap and the
  VEYN test both stop at "lands in a second node's JSONL log." The
  `ql_persist_merge_blob()` call that would make a synced envelope show
  up in Qallow's real LMDB store lives in the Qallow repo and doesn't
  exist yet. This is a functional gap, not cosmetic: VEYN -> DUCTEI ->
  Qallow is proven at the wire level but not at the persistence level
  on the receiving end.
- QSW proto v2 (scopes as a native wire field instead of the current
  key-prefix shim) — open.
- gRPC/QUIC transport — the `Transport` trait is vendor-neutral by
  design, but only TCP is implemented.
- Outside DUCTEI but blocking the full loop: the LIMEN README patch is
  unapplied, and ML-KEM (encryption/key-exchange) is unevaluated —
  only ML-DSA-65 signing exists.

## Roadmap
- QSW proto v2: scopes as native wire field (drop key-prefix shim)
- gRPC/QUIC transport behind the same trait
- Qallow-side ingestion daemon calling `ql_persist_merge_blob()` on
  decoded envelopes (lives in Qallow repo, not here)
