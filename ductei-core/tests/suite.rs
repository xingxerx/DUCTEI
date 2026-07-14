use ductei_core::gate::{CausalGate, Verdict};
use ductei_core::transport::{serve_connection, TcpClient, Transport};
use ductei_core::*;
use std::net::TcpListener;

fn node(n: u8) -> [u8; 16] { [n; 16] }
fn tmp(name: &str) -> String { format!("{}/{}-{}", std::env::temp_dir().display(), std::process::id(), name) }
fn env(key: &str, sc: &[&str], nd: u8, lam: u64) -> Envelope { scoped(key, sc, node(nd), lam, b"x") }
fn chan(name: &str) -> Channel {
    Channel::open(ScopePolicy::new().allow("qallow.semantic.cert").allow("veyn.sensor.eeg"),
        tmp(&format!("{name}.jsonl")), tmp(&format!("{name}-rej.jsonl"))).unwrap()
}

#[test]
fn scope_deny_by_default() {
    let mut ch = chan("t0");
    assert!(ch.send(env("a", &["qallow.semantic.cert"], 1, 1)).is_ok());
    assert!(matches!(ch.send(env("b", &["limen.credentials"], 1, 2)), Err(ChannelError::ScopeDenied(_))));
    assert!(matches!(ch.send(env("c", &[], 1, 3)), Err(ChannelError::ScopeDenied(_))));
}

#[test]
fn poisoned_envelope() {
    let mut ch = chan("t1");
    assert!(matches!(ch.send(env("a", &["qallow.semantic.cert", "secret"], 1, 1)), Err(ChannelError::ScopeDenied(_))));
}

#[test]
fn restart_survival() {
    let p = tmp("t2.jsonl"); let r = tmp("t2r.jsonl");
    let _ = std::fs::remove_file(&p);
    {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        ch.send(env("a", &["qallow.semantic.cert"], 1, 1)).unwrap();
        ch.send(env("b", &["qallow.semantic.cert"], 1, 2)).unwrap();
    }
    let ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
    let (envs, cur) = ch.replay(0).unwrap();
    assert_eq!(envs.len(), 2); assert_eq!(cur, 2);
    assert_eq!(envs[1].key, "b");
}

#[test]
fn credential_drop_closed_type() {
    let json = r#"{"job_id":"j1","backend":"ibm_fez","tier":2,"fidelity_estimate":0.97,
                   "lamport":9,"api_token":"SECRET","qpu_instance":"h/g/p"}"#;
    let e = ductei_limen::cert_to_envelope(json, node(7)).unwrap();
    let s = serde_json::to_string(&e).unwrap();
    assert!(!s.contains("SECRET") && !s.contains("api_token") && !s.contains("h/g/p"));
}

#[test]
fn unbounded_session_unrepresentable() { assert!(SessionBound::new(None, None).is_none()); }

#[test]
fn session_bound_enforced() {
    let mut ch = chan("t3");
    let mut s = ch.session(SessionBound::new(Some(2), None).unwrap());
    s.send(env("a", &["qallow.semantic.cert"], 1, 1), 1).unwrap();
    s.send(env("b", &["qallow.semantic.cert"], 1, 2), 1).unwrap();
    assert!(matches!(s.send(env("c", &["qallow.semantic.cert"], 1, 3), 1), Err(ChannelError::BoundReached)));
    assert!(s.is_closed());
    assert_eq!(s.close(), 2);
}

// ---- Build 0: causal-delta gate ----

#[test]
fn gate_in_order_accept_stale_reject() {
    let mut g = CausalGate::new();
    assert_eq!(g.admit(&env("k", &["s"], 1, 5)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 1, 6)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 1, 6)), Verdict::Stale);
    assert_eq!(g.admit(&env("k", &["s"], 1, 4)), Verdict::Stale);
    assert_eq!(g.admit(&env("k2", &["s"], 1, 1)), Verdict::Accept);
}

#[test]
fn gate_tie_break_deterministic_by_node_id() {
    let mut g = CausalGate::new();
    assert_eq!(g.admit(&env("k", &["s"], 3, 5)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 2, 5)), Verdict::Stale);
    assert_eq!(g.admit(&env("k", &["s"], 4, 5)), Verdict::Accept);
    let mut g2 = CausalGate::new();
    assert_eq!(g2.admit(&env("k", &["s"], 3, 5)), Verdict::Accept);
    assert_eq!(g2.admit(&env("k", &["s"], 2, 5)), Verdict::Stale);
}

#[test]
fn gate_replay_after_restart_consistent() {
    let p = tmp("t4.jsonl"); let r = tmp("t4r.jsonl");
    let _ = std::fs::remove_file(&p);
    {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        ch.send(env("k", &["qallow.semantic.cert"], 1, 10)).unwrap();
    }
    let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
    assert!(matches!(ch.send(env("k", &["qallow.semantic.cert"], 1, 9)),
        Err(ChannelError::StaleDelta { .. })));
    assert!(ch.send(env("k", &["qallow.semantic.cert"], 1, 11)).is_ok());
    let (envs, _) = ch.replay(0).unwrap();
    assert_eq!(envs.len(), 2);
}

// ---- Build 1: transport (two-node loopback acceptance gate) ----

#[test]
fn transport_two_node_loopback() {
    let p = tmp("t5.jsonl"); let r = tmp("t5r.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let accepted = serve_connection(stream, &mut ch).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        (accepted, envs)
    });
    let mut c = TcpClient::connect(addr).unwrap();
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    assert!(!c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    assert!(!c.send_envelope(&env("b", &["limen.credentials"], 1, 2)).unwrap());
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 2)).unwrap());
    drop(c);
    let (accepted, envs) = server.join().unwrap();
    assert_eq!(accepted, 2);
    assert_eq!(envs.len(), 2);
}

// ---- Build 2: VEYN adapter end-to-end (synthetic OSC/EEG sample) ----

#[test]
fn veyn_event_flows_gate_transport_qallow() {
    let p = tmp("t6.jsonl"); let r = tmp("t6r.jsonl");
    let _ = std::fs::remove_file(&p);
    let json = r#"{"source":"osc.eeg","kind":"eeg.sample","node_hex":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                   "lamport":42,"payload":{"ch":[1.2,3.4],"band":"theta"}}"#;
    let e = ductei_veyn::event_to_envelope(json).unwrap();
    assert_eq!(e.scopes[0].0, "veyn.sensor.eeg");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let e2 = e.clone();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("veyn.sensor.eeg"), &p, &r).unwrap();
        let (s, _) = listener.accept().unwrap();
        serve_connection(s, &mut ch).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        envs
    });
    let mut c = TcpClient::connect(addr).unwrap();
    assert!(c.send_envelope(&e2).unwrap());
    drop(c);
    let envs = server.join().unwrap();
    assert_eq!(envs.len(), 1);

    let wire = ductei_qallow::encode_envelope(&envs[0]);
    assert_eq!(wire[0], ductei_qallow::F_ENVELOPE);
    let back = ductei_qallow::decode_envelope_body(&wire[5..]).unwrap();
    assert_eq!(back, envs[0]);
}
