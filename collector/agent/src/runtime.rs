//! Thin OS helpers for the binary: clocks, randomness, running `ip neigh`. No logic worth
//! unit-testing lives here; it is kept out of `main.rs` to keep that readable.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
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

/// Exactly `N` random bytes from `path`. Any failure, including a short read, is an error: ids
/// must never repeat, so there is deliberately no weaker fallback.
pub fn random_from<const N: usize>(path: &Path) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(buf)
}

/// Random bytes from the kernel, for batch/boot ids and jitter (never for the HMAC key).
pub fn random<const N: usize>() -> io::Result<[u8; N]> {
    random_from(Path::new("/dev/urandom"))
}

pub fn random_u64() -> io::Result<u64> {
    random::<8>().map(u64::from_le_bytes)
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
