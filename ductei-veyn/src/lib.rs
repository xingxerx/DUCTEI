//! Build 2: VEYN adapter (per-repo adapter; VEYN types never enter core).
//! Translates VEYN sensor events (HealthKit / BLE / EEG-OSC / Apple Watch /
//! MQTT — the sources VEYN's MCP server on :7700 exposes) into DUCTEI
//! envelopes with explicit scopes. Deny-by-default: sensor data broadcasts
//! only to scopes the receiving policy explicitly allows.
use ductei_core::{scoped, Envelope};
use serde::Deserialize;

/// Closed type mirroring a VEYN event JSON. Unknown fields dropped;
/// no device credentials or pairing keys are representable.
#[derive(Debug, Deserialize)]
pub struct VeynEvent {
    pub source: String,   // "osc.eeg" | "healthkit" | "ble" | "watch" | "mqtt"
    pub kind: String,     // e.g. "eeg.sample", "hr", "haptic.ack"
    pub node_hex: String, // origin VEYN node id (32 hex chars)
    pub lamport: u64,
    pub payload: serde_json::Value,
}

pub fn scope_for(source: &str) -> &'static str {
    match source {
        "osc.eeg" => "veyn.sensor.eeg",
        "healthkit" => "veyn.sensor.health",
        "watch" => "veyn.actuator.watch",
        "ble" => "veyn.sensor.ble",
        _ => "veyn.sensor.misc",
    }
}

pub fn event_to_envelope(json: &str) -> Result<Envelope, String> {
    let e: VeynEvent = serde_json::from_str(json).map_err(|x| x.to_string())?;
    let mut node = [0u8; 16];
    let bytes = (0..16)
        .map(|i| u8::from_str_radix(e.node_hex.get(2 * i..2 * i + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect::<Vec<_>>();
    node.copy_from_slice(&bytes);
    let blob = serde_json::to_vec(&e.payload).map_err(|x| x.to_string())?;
    Ok(scoped(&format!("veyn.{}.{}", e.source, e.kind), &[scope_for(&e.source)], node, e.lamport, &blob))
}
