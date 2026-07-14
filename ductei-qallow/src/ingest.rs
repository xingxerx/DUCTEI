//! Qallow-side ingestion seam. Today, envelopes only prove out at the wire
//! level: a synced envelope lands in a second node's JSONL log, and stops
//! there. The gap is that nothing calls Qallow's real `ql_persist_merge_blob()`
//! to make it show up in Qallow's actual LMDB store — that function lives in
//! the Qallow repo (C), not here, and doesn't exist yet.
//!
//! This module is the seam, not the fix: a trait shaped exactly like the
//! eventual FFI call, plus a local stand-in so DUCTEI's own tests can
//! exercise "envelope decoded -> merge called" without linking Qallow.
//! Swapping in the real ingestion daemon means writing one impl of
//! `QallowSink` that calls into Qallow (FFI/cxx bridge) — nothing else here
//! should need to change.
use ductei_core::Envelope;

/// Mirrors the shape of `ql_persist_merge_blob(key, blob)`: last-write-wins
/// merge of a blob under a key into Qallow's persistent store.
pub trait QallowSink {
    fn merge_blob(&mut self, key: &str, blob: &[u8]) -> Result<(), String>;
}

/// Decode a QSW v1 ENVELOPE body and merge it into `sink`. This is the one
/// call site that will point at the real `ql_persist_merge_blob()` once a
/// `QallowSink` impl backed by Qallow exists.
pub fn ingest_envelope(sink: &mut impl QallowSink, env: &Envelope) -> Result<(), String> {
    sink.merge_blob(&env.key, &env.blob)
}

/// In-memory stand-in for local tests and dev boxes without Qallow
/// checked out. Not a substitute for the real LMDB-backed merge.
#[derive(Default)]
pub struct MemorySink {
    pub merged: Vec<(String, Vec<u8>)>,
}
impl QallowSink for MemorySink {
    fn merge_blob(&mut self, key: &str, blob: &[u8]) -> Result<(), String> {
        self.merged.push((key.to_string(), blob.to_vec()));
        Ok(())
    }
}
