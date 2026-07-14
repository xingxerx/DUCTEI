//! Post-quantum key exchange (feature `pq`), ML-KEM-768 (FIPS 203) via
//! `pqcrypto-mlkem`. This secures session-key establishment for the
//! transport layer (e.g. wrapping frames before they hit TCP/gRPC/QUIC);
//! it does not touch the `Envelope` wire format or scope model. Matches
//! the existing ML-DSA-65 signing story one repo over in LIMEN: LIMEN
//! signs, DUCTEI's transport now has a matching post-quantum
//! key-exchange primitive rather than only classical TLS.
use pqcrypto_mlkem::mlkem768::{decapsulate, encapsulate, keypair, PublicKey, SecretKey};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as _, SharedSecret as _};

pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    secret_key: SecretKey,
}

/// Generate a fresh ML-KEM-768 keypair. `public_key` is safe to publish
/// (e.g. alongside a QUIC self-signed cert) so a peer can encapsulate a
/// shared secret to us.
pub fn generate_keypair() -> KemKeyPair {
    let (pk, sk) = keypair();
    KemKeyPair { public_key: pk.as_bytes().to_vec(), secret_key: sk }
}

/// Encapsulate against a peer's published public key. Returns the bytes
/// to send the peer (`ciphertext`) and the 32-byte shared secret to derive
/// a session key from on our side.
pub fn encapsulate_to(peer_public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let pk = PublicKey::from_bytes(peer_public_key).map_err(|e| e.to_string())?;
    let (shared_secret, ciphertext) = encapsulate(&pk);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared_secret.as_bytes());
    Ok((ciphertext.as_bytes().to_vec(), ss))
}

/// Recover the shared secret from a peer's ciphertext using our secret key.
pub fn decapsulate_from(pair: &KemKeyPair, ciphertext: &[u8]) -> Result<[u8; 32], String> {
    let ct = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|e| e.to_string())?;
    let shared_secret = decapsulate(&ct, &pair.secret_key);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared_secret.as_bytes());
    Ok(ss)
}
