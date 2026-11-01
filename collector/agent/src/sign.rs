//! Request signing (PRP section 4):
//! `HMAC-SHA256(key, collector_id|key_id|boot_id|seq|sent_ts|batch_id|hex(SHA256(raw body)))`,
//! hex-encoded. The body is signed as the exact bytes sent.

use hmac::{Hmac, KeyInit, Mac};
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector computed independently with Python stdlib `hmac`/`hashlib`
    /// (the server-side verifier in vigie_ingest/auth.py), pinning wire compatibility.
    #[test]
    fn sign_matches_python_known_answer() {
        let key: Vec<u8> = (0u8..32).collect();
        let env = Envelope {
            collector_id: "col-1",
            key_id: "k1",
            boot_id: "boot-1",
            seq: 42,
            sent_ts: 1_700_000_000,
            batch_id: "batch-1",
        };
        let body = br#"{"batch":"kat"}"#;
        assert_eq!(
            String::from_utf8(signing_string(&env, body)).unwrap(),
            "col-1|k1|boot-1|42|1700000000|batch-1|8986dc41e3751b7d0346962421986d54d7f326e8c0480d304c067fafdda126e1"
        );
        assert_eq!(
            sign(&key, &env, body),
            "b69d126d0459b6e09b83ae725ff75e634ed5d4801b4435bf52617d0b7dfa7f03"
        );
    }
}
