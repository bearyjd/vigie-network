//! `https_selftest <server_url> <pin>`: sends one real, signed batch through the production
//! `HttpsTransport` and the send engine, simulating a lost ACK so the second attempt must come back
//! as a duplicate. Used by tests/vectors/test_https_against_ingest.py against the real Python
//! server. Key: bytes 0..32. Not part of the shipped binary.
//!
//! Prints one line per attempt and exits 0 only for: attempt 1 = Retry (reply discarded),
//! attempt 2 = Sent { duplicate: true }.

use std::time::{SystemTime, UNIX_EPOCH};

use vigie_agent::builder::{build, BATCH_CAP};
use vigie_agent::https::HttpsTransport;
use vigie_agent::ids;
use vigie_agent::model::{Health, Meta, Sections};
use vigie_agent::sender::{Engine, Headers, HttpReply, Identity, Tick, Transport, TransportError};
use vigie_agent::transport::PinnedTransport;

/// Delivers the first request, then loses the reply (the lost-ACK case that causes duplicates).
struct LoseFirstReply<T> {
    inner: T,
    first: bool,
}

impl<T: Transport> Transport for LoseFirstReply<T> {
    fn post(&mut self, h: &Headers, b: &[u8]) -> Result<HttpReply, TransportError> {
        let reply = self.inner.post(h, b);
        if std::mem::take(&mut self.first) {
            println!("attempt 1 server reply: {reply:?}");
            return Err(TransportError("simulated lost ACK".into()));
        }
        reply
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, url, pin] = args.as_slice() else {
        eprintln!("usage: https_selftest <server_url> <pin>");
        std::process::exit(64);
    };
    let pinned = PinnedTransport::new(url, &[pin.as_str()]).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(64);
    });
    let https = HttpsTransport::new(pinned).unwrap_or_else(|e| {
        eprintln!("{}", e.0);
        std::process::exit(64);
    });
    let mut transport = LoseFirstReply {
        inner: https,
        first: true,
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let wall = now.as_secs();
    let key: Vec<u8> = (0u8..32).collect();
    let id = Identity {
        collector_id: "router-1".into(),
        key_id: "k2026-10".into(),
        boot_id: "0123456789abcdef".into(),
    };
    let mut engine = Engine::new(id, key, 1_700_000_000, 4 * BATCH_CAP);
    let meta = Meta {
        collector_id: "router-1".into(),
        key_id: "k2026-10".into(),
        boot_id: "0123456789abcdef".into(),
        seq: 1,
        batch_id: ids::uuid7(now.as_millis() as u64, [7; 10]),
        window_start: wall - 60,
        window_end: wall,
    };
    engine.enqueue(build(&meta, Sections::default(), &Health::default(), BATCH_CAP).encoded);

    let first = engine.tick(&mut transport, wall, 0, 1);
    println!("attempt 1: {first:?}");
    let second = engine.tick(&mut transport, wall, 100_000, 1);
    println!("attempt 2: {second:?}");
    let ok = matches!(first, Tick::Retry { status: None, .. })
        && second == (Tick::Sent { duplicate: true });
    std::process::exit(if ok { 0 } else { 1 });
}
