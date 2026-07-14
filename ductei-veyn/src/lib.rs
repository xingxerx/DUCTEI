//! Phase 3: VEYN adapter (per-repo adapter; VEYN types never enter core).
//! Translates VEYN sensor/actuator events (HealthKit / BLE / EEG-OSC /
//! Apple Watch -- the sources VEYN's MCP server on :7700 exposes) into
//! DUCTEI envelopes with explicit, narrow scopes. Deny-by-default: sensor
//! data broadcasts only to scopes the receiving policy explicitly allows
//! -- e.g. Qallow can allow just `veyn.rem_event` to drive REM-triggered
//! job scheduling, while LIMEN allows almost nothing.
//!
//! Sensor data is high-volume; a scope alone doesn't stop a 1 Hz HRV
//! stream from flooding the channel. `Adapter` applies a `CoalescePolicy`
//! per (scope, node, kind) stream before conversion -- raw firehose stays
//! inside VEYN, DUCTEI only ever sees the throttled stream. Discrete
//! events like REM triggers aren't sampled, so they pass through
//! uncoalesced by default: every one matters.
use ductei_core::{scoped, Envelope};
use serde::Deserialize;
use std::collections::HashMap;

/// Closed type mirroring a VEYN event JSON. Unknown fields dropped;
/// no device credentials or pairing keys are representable.
#[derive(Debug, Deserialize)]
pub struct VeynEvent {
    pub source: String,   // "osc.eeg" | "healthkit" | "ble" | "watch" | "mqtt"
    pub kind: String,     // e.g. "eeg.sample", "hr", "hrv", "rem.detected", "haptic.ack"
    pub node_hex: String, // origin VEYN node id (32 hex chars)
    pub lamport: u64,
    pub payload: serde_json::Value,
}

pub const REM_EVENT_SCOPE: &str = "veyn.rem_event";
pub const HRV_SCOPE: &str = "veyn.hrv";
pub const EEG_SCOPE: &str = "veyn.sensor.eeg";
pub const HEALTH_SCOPE: &str = "veyn.sensor.health";
pub const WATCH_SCOPE: &str = "veyn.actuator.watch";
pub const BLE_SCOPE: &str = "veyn.sensor.ble";
pub const MISC_SCOPE: &str = "veyn.sensor.misc";

/// Scope is derived from (source, kind), not source alone: a REM trigger
/// or an HRV sample gets its own narrow scope so a subscriber only has to
/// allow exactly what it needs (Qallow: REM triggers; LIMEN: almost
/// nothing) instead of the whole `veyn.sensor.*` firehose.
pub fn scope_for(source: &str, kind: &str) -> &'static str {
    if kind.contains("rem") {
        return REM_EVENT_SCOPE;
    }
    if kind == "hrv" {
        return HRV_SCOPE;
    }
    match source {
        "osc.eeg" => EEG_SCOPE,
        "healthkit" => HEALTH_SCOPE,
        "watch" => WATCH_SCOPE,
        "ble" => BLE_SCOPE,
        _ => MISC_SCOPE,
    }
}

fn node_from_hex(hex: &str) -> [u8; 16] {
    let mut node = [0u8; 16];
    let bytes = (0..16)
        .map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect::<Vec<_>>();
    node.copy_from_slice(&bytes);
    node
}

/// One-shot conversion, no coalescing. For callers that already coalesce
/// upstream, or for scopes never coalesced (REM triggers).
pub fn event_to_envelope(json: &str) -> Result<Envelope, String> {
    let e: VeynEvent = serde_json::from_str(json).map_err(|x| x.to_string())?;
    let blob = serde_json::to_vec(&e.payload).map_err(|x| x.to_string())?;
    Ok(scoped(
        &format!("veyn.{}.{}", e.source, e.kind),
        &[scope_for(&e.source, &e.kind)],
        node_from_hex(&e.node_hex),
        e.lamport,
        &blob,
    ))
}

/// Per-scope minimum spacing between envelopes reaching the channel for
/// the same (scope, node, kind) stream. Scopes with no entry pass
/// through uncoalesced.
#[derive(Debug, Clone, Default)]
pub struct CoalescePolicy {
    min_interval_ms: HashMap<&'static str, u64>,
}
impl CoalescePolicy {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn coalesce(mut self, scope: &'static str, min_interval_ms: u64) -> Self {
        self.min_interval_ms.insert(scope, min_interval_ms);
        self
    }
    /// Phase 3 default: HRV sampled down to 1/min. REM triggers and
    /// everything else pass through uncoalesced.
    pub fn default_policy() -> Self {
        Self::new().coalesce(HRV_SCOPE, 60_000)
    }
}

/// Stateful adapter: applies `CoalescePolicy` per (scope, node, kind)
/// stream before converting to an Envelope. Coalesced samples are
/// dropped, not queued or buffered -- VEYN keeps the raw firehose
/// locally; DUCTEI only ever sees the throttled stream.
pub struct Adapter {
    policy: CoalescePolicy,
    last_emit_ms: HashMap<(&'static str, [u8; 16], String), u64>,
}
impl Adapter {
    pub fn new(policy: CoalescePolicy) -> Self {
        Self { policy, last_emit_ms: HashMap::new() }
    }

    /// Returns Ok(None) when the sample was coalesced away -- not an
    /// error, the adapter working as designed.
    pub fn ingest(&mut self, json: &str, now_ms: u64) -> Result<Option<Envelope>, String> {
        let e: VeynEvent = serde_json::from_str(json).map_err(|x| x.to_string())?;
        let scope = scope_for(&e.source, &e.kind);
        let node = node_from_hex(&e.node_hex);
        let stream_key = (scope, node, e.kind.clone());
        if let Some(&interval) = self.policy.min_interval_ms.get(scope) {
            if let Some(&last) = self.last_emit_ms.get(&stream_key) {
                if now_ms.saturating_sub(last) < interval {
                    return Ok(None);
                }
            }
        }
        self.last_emit_ms.insert(stream_key, now_ms);
        let blob = serde_json::to_vec(&e.payload).map_err(|x| x.to_string())?;
        Ok(Some(scoped(
            &format!("veyn.{}.{}", e.source, e.kind),
            &[scope],
            node,
            e.lamport,
            &blob,
        )))
    }
}
