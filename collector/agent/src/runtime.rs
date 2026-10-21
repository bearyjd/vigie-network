//! Thin OS helpers for the binary: clocks, randomness, running `ip neigh`. No logic worth
//! unit-testing lives here; it is kept out of `main.rs` to keep that readable.

use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::Neighbor;
use crate::neigh::parse_ip_neigh;

pub const MAX_CMD_OUTPUT: usize = 1024 * 1024;

pub fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Random bytes from the kernel. Used for batch/boot ids and jitter only (never for the HMAC
/// key); on failure falls back to clock bits, which is acceptable for those uses.
pub fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    let ok = File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !ok {
        let mut x = wall_ms() ^ 0x9E37_79B9_7F4A_7C15;
        for b in &mut buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
    buf
}

pub fn random_u64() -> u64 {
    u64::from_le_bytes(random::<8>())
}

/// IPv4 and IPv6 neighbor tables (`ip -4 neigh show`, `ip -6 neigh show`).
pub fn read_neighbors() -> Vec<Neighbor> {
    let mut text = String::new();
    for fam in ["-4", "-6"] {
        match Command::new("ip").args([fam, "neigh", "show"]).output() {
            Ok(out) if out.status.success() => {
                let n = out.stdout.len().min(MAX_CMD_OUTPUT);
                text.push_str(&String::from_utf8_lossy(&out.stdout[..n]));
                text.push('\n');
            }
            Ok(out) => eprintln!("ip {fam} neigh failed: {}", out.status),
            Err(e) => eprintln!("cannot run ip {fam} neigh: {e}"),
        }
    }
    parse_ip_neigh(&text)
}
