//! ductei-limen-relay: the first real consumer of ductei-limen. Tails
//! spool/certs/ for {job_id}.json files written by limend (see LIMEN's
//! limend/), converts each to an Envelope via cert_to_envelope, and sends
//! it through a bounded, one-session-per-job Channel::session(). Never
//! touches credentials -- CertSummary is a closed type, so there is
//! nothing to leak by construction.
//!
//! Usage:
//!   ductei-limen-relay <spool_dir> [--poll-interval-ms N] [--once]
//!
//! Channel state (accepted/rejected logs) and this relay's persisted node
//! id live in a `ductei/` directory that is a *sibling* of <spool_dir>,
//! not inside it -- spool/ is limend's tree, ductei/ is this relay's.
use ductei_core::{Channel, ScopePolicy, SessionBound};
use ductei_limen::{cert_to_envelope, CERT_SCOPE};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn to_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_node_id(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut node = [0u8; 16];
    for i in 0..16 {
        node[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(node)
}

/// A fresh 16-byte id for "this limend producer". Only ever generated once
/// per relay install and persisted -- see `load_or_create_node_id` -- since
/// a different id per restart would make the causal gate treat every
/// post-restart envelope as a brand new, unrelated producer.
fn generate_node_id() -> [u8; 16] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let h = RandomState::new().build_hasher().finish();
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    bytes
}

fn load_or_create_node_id(ductei_dir: &Path) -> std::io::Result<[u8; 16]> {
    let path = ductei_dir.join("relay-node-id");
    if let Ok(existing) = fs::read_to_string(&path) {
        if let Some(id) = parse_node_id(existing.trim()) {
            return Ok(id);
        }
    }
    let id = generate_node_id();
    fs::write(&path, to_hex(&id))?;
    Ok(id)
}

fn ensure_dirs(spool: &Path, ductei_dir: &Path) -> std::io::Result<(PathBuf, PathBuf, PathBuf)> {
    let certs = spool.join("certs");
    let sent = certs.join("sent");
    let failed = spool.join("failed");
    fs::create_dir_all(&certs)?;
    fs::create_dir_all(&sent)?;
    fs::create_dir_all(&failed)?;
    fs::create_dir_all(ductei_dir)?;
    Ok((certs, sent, failed))
}

/// Move `path` into `failed_dir`, wrapping the original bytes with an
/// "error" field so the failure is human-readable without needing the
/// original schema to have anticipated it.
fn write_failed(failed_dir: &Path, file_name: &str, original: &str, error: &str) {
    let record = serde_json::json!({
        "error": error,
        "original": serde_json::from_str::<serde_json::Value>(original)
            .unwrap_or_else(|_| serde_json::Value::String(original.to_string())),
    });
    let dest = failed_dir.join(file_name);
    if let Err(e) = fs::write(&dest, serde_json::to_vec_pretty(&record).unwrap_or_default()) {
        eprintln!("relay: failed to write failure record {}: {e}", dest.display());
    }
}

fn process_one(
    path: &Path,
    node: [u8; 16],
    channel: &mut Channel,
    sent_dir: &Path,
    failed_dir: &Path,
) {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => return,
    };
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("relay: could not read {}: {e}", path.display());
            return;
        }
    };

    let envelope = match cert_to_envelope(&raw, node) {
        Ok(e) => e,
        Err(e) => {
            write_failed(failed_dir, &file_name, &raw, &format!("cert_to_envelope: {e}"));
            let _ = fs::remove_file(path);
            return;
        }
    };

    let mut session = channel.session(
        SessionBound::new(Some(1), None).expect("max_envelopes=Some(1) is a valid bound"),
    );
    match session.send(envelope, 1) {
        Ok(()) => {
            session.close();
            let dest = sent_dir.join(&file_name);
            if let Err(e) = fs::rename(path, &dest) {
                eprintln!("relay: sent but failed to archive {}: {e}", path.display());
            }
        }
        Err(err) => {
            session.close();
            write_failed(failed_dir, &file_name, &raw, &format!("{err:?}"));
            let _ = fs::remove_file(path);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: {} <spool_dir> [--poll-interval-ms N] [--once]",
            args[0]
        );
        std::process::exit(2);
    }
    let spool = PathBuf::from(&args[1]);
    let mut poll_interval_ms: u64 = 1000;
    let mut once = false;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--poll-interval-ms" && i + 1 < args.len() {
            poll_interval_ms = args[i + 1].parse().unwrap_or(1000);
            i += 2;
        } else if args[i] == "--once" {
            once = true;
            i += 1;
        } else {
            i += 1;
        }
    }

    // ductei/ is a sibling of spool/, never nested inside it: spool/ is
    // limend's tree, ductei/ is this relay's own persistence.
    let ductei_dir = spool
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("ductei");

    let (certs_dir, sent_dir, failed_dir) =
        ensure_dirs(&spool, &ductei_dir).expect("failed to create relay directories");
    let node = load_or_create_node_id(&ductei_dir).expect("failed to load/create relay node id");

    let policy = ScopePolicy::new().allow(CERT_SCOPE);
    let mut channel = Channel::open(
        policy,
        ductei_dir.join("accepted.jsonl"),
        ductei_dir.join("rejected.jsonl"),
    )
    .expect("failed to open channel log");

    println!(
        "ductei-limen-relay: watching {} (node={})",
        certs_dir.display(),
        to_hex(&node)
    );

    loop {
        let mut entries: Vec<PathBuf> = fs::read_dir(&certs_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        entries.sort();

        for path in entries {
            process_one(&path, node, &mut channel, &sent_dir, &failed_dir);
        }

        if once {
            return;
        }

        std::thread::sleep(Duration::from_millis(poll_interval_ms));
    }
}
