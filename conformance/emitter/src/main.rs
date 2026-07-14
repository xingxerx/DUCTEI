// Emits a HELLO / HELLO_ACK / ENVELOPE / BATCH_END / BYE stream for the
// C-side verifier (linked against Qallow's real sync_wire.c).
use ductei_core::scoped;
fn main() {
    let path = std::env::args().nth(1).expect("usage: emit <out>");
    let node = [7u8; 16];
    let env = scoped("limen.cert.j1", &["qallow.semantic.cert"], node, 42, br#"{"tier":2}"#);
    let mut out = Vec::new();
    out.extend(ductei_qallow::encode_hello(ductei_qallow::F_HELLO, &node, 41));
    out.extend(ductei_qallow::encode_hello(ductei_qallow::F_HELLO_ACK, &node, 41));
    out.extend(ductei_qallow::encode_envelope(&env));
    out.extend(ductei_qallow::encode_batch_end(43));
    out.extend(ductei_qallow::encode_bye());
    std::fs::write(path, out).unwrap();
}
