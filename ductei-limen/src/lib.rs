//! LIMEN adapter. Closed type: only certificate summary fields exist —
//! api tokens / qpu credentials / raw quantum traffic are unrepresentable.
//! serde silently drops unknown fields before anything reaches the channel.
use ductei_core::{scoped, Envelope};
use serde::Deserialize;

/// Closed type. No credential fields. Unknown JSON fields are dropped.
#[derive(Debug, Deserialize)]
pub struct CertSummary {
    pub job_id: String,
    pub backend: String,
    pub tier: u8,
    pub fidelity_estimate: f64,
    pub lamport: u64,
}

pub const CERT_SCOPE: &str = "qallow.semantic.cert";

pub fn cert_to_envelope(json: &str, node: [u8; 16]) -> Result<Envelope, serde_json::Error> {
    let c: CertSummary = serde_json::from_str(json)?;
    let blob = serde_json::to_vec(&serde_json::json!({
        "job_id": c.job_id, "backend": c.backend,
        "tier": c.tier, "fidelity_estimate": c.fidelity_estimate,
    }))?;
    Ok(scoped(&format!("limen.cert.{}", c.job_id), &[CERT_SCOPE], node, c.lamport, &blob))
}
