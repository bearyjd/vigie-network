//! Request signing (PRP section 4):
//! `HMAC-SHA256(key, collector_id|key_id|boot_id|seq|sent_ts|batch_id|hex(SHA256(raw body)))`,
//! hex-encoded. The body is signed as the exact bytes sent.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The signed header fields. Field order in the signing string is fixed by the server.
pub struct Envelope<'a> {
    pub collector_id: &'a str,
    pub key_id: &'a str,
    pub boot_id: &'a str,
    pub seq: u64,
    pub sent_ts: u64,
    pub batch_id: &'a str,
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

pub fn signing_string(env: &Envelope, body: &[u8]) -> Vec<u8> {
    let digest = hex(&Sha256::digest(body));
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        env.collector_id, env.key_id, env.boot_id, env.seq, env.sent_ts, env.batch_id, digest
    )
    .into_bytes()
}

pub fn sign(key: &[u8], env: &Envelope, body: &[u8]) -> String {
    // HMAC accepts keys of any length, so new_from_slice cannot fail.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&signing_string(env, body));
    hex(&mac.finalize().into_bytes())
}
