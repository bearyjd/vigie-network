//! `/etc/vigie/collector.conf` parsing and HMAC key file handling.
//!
//! Format: `name=value` lines, `#` comments. Unknown or duplicate names are errors (a typo in
//! `pin2` must not silently disable a pin). The key file must be a regular file (no symlink),
//! owned by the running user, with no group/other permissions (mode 0600 or 0400).

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const MAX_KEY_FILE_BYTES: usize = 1024;
pub const MIN_KEY_BYTES: usize = 32;
const DEFAULT_KEY_FILE: &str = "/etc/vigie/key";
const DEFAULT_DNSMASQ_LOG: &str = "/tmp/vigie/dnsmasq.log";
const DEFAULT_LEASES_FILE: &str = "/tmp/dhcp.leases";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server_url: String,
    pub collector_id: String,
    pub key_id: String,
    /// SHA-256 of the server certificate SubjectPublicKeyInfo (lowercase hex). Two, for rotation.
    pub pins: [String; 2],
    pub key_file: PathBuf,
    pub dnsmasq_log: PathBuf,
    pub leases_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(k) => write!(f, "missing required option {k}"),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    NotRegularFile,
    BadMode(u32),
    WrongOwner,
    BadDirMode(u32),
    WrongDirOwner,
    TooShort,
    TooLarge,
    NotHex,
    Io(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegularFile => {
                f.write_str("key file is not a regular file (symlinks refused)")
            }
            Self::BadMode(m) => write!(
                f,
                "key file mode {m:o} grants group/other access; need 0600"
            ),
            Self::WrongOwner => f.write_str("key file is not owned by the collector user"),
            Self::BadDirMode(m) => write!(
                f,
                "key directory mode {m:o} is writable by group/other (or not private)"
            ),
            Self::WrongDirOwner => {
                f.write_str("key directory is not owned by root or the collector")
            }
            Self::TooShort => write!(f, "key shorter than {MIN_KEY_BYTES} bytes"),
            Self::TooLarge => write!(f, "key file larger than {MAX_KEY_FILE_BYTES} bytes"),
            Self::NotHex => f.write_str("key file must hold hex text"),
            Self::Io(e) => write!(f, "cannot read key file: {e}"),
        }
    }
}

fn is_ident(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_pin(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const KNOWN: [&str; 8] = [
    "server_url",
    "collector_id",
    "key_id",
    "pin1",
    "pin2",
    "key_file",
    "dnsmasq_log",
    "leases_file",
];

pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    let mut vals: Vec<(&str, &str)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| ConfigError::Invalid(format!("line {}: expected name=value", i + 1)))?;
        let (k, v) = (k.trim(), v.trim());
        if !KNOWN.contains(&k) {
            return Err(ConfigError::Invalid(format!(
                "line {}: unknown option {k}",
                i + 1
            )));
        }
        if vals.iter().any(|(seen, _)| *seen == k) {
            return Err(ConfigError::Invalid(format!(
                "line {}: duplicate option {k}",
                i + 1
            )));
        }
        vals.push((k, v));
    }
    let get = |k: &'static str| -> Result<&str, ConfigError> {
        vals.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| *v)
            .filter(|v| !v.is_empty())
            .ok_or(ConfigError::Missing(k))
    };
    let opt = |k: &str, default: &str| -> PathBuf {
        PathBuf::from(
            vals.iter()
                .find(|(n, _)| *n == k)
                .map_or(default, |(_, v)| *v),
        )
    };

    let server_url = get("server_url")?;
    if !server_url.starts_with("https://") || server_url.len() <= "https://".len() {
        return Err(ConfigError::Invalid(
            "server_url must be an https:// URL".into(),
        ));
    }
    let collector_id = get("collector_id")?;
    let key_id = get("key_id")?;
    if !is_ident(collector_id) || !is_ident(key_id) {
        return Err(ConfigError::Invalid(
            "collector_id and key_id must match [A-Za-z0-9_.-]{1,64}".into(),
        ));
    }
    let (p1, p2) = (get("pin1")?, get("pin2")?);
    if !is_pin(p1) || !is_pin(p2) {
        return Err(ConfigError::Invalid(
            "pins must be 64 lowercase hex characters".into(),
        ));
    }
    if p1 == p2 {
        return Err(ConfigError::Invalid("pin1 and pin2 must differ".into()));
    }
    Ok(Config {
        server_url: server_url.into(),
        collector_id: collector_id.into(),
        key_id: key_id.into(),
        pins: [p1.into(), p2.into()],
        key_file: opt("key_file", DEFAULT_KEY_FILE),
        dnsmasq_log: opt("dnsmasq_log", DEFAULT_DNSMASQ_LOG),
        leases_file: opt("leases_file", DEFAULT_LEASES_FILE),
    })
}

/// `mode` is the raw st_mode (type bits included).
pub fn check_key_meta(mode: u32, file_uid: u32, euid: u32, regular: bool) -> Result<(), KeyError> {
    if !regular {
        return Err(KeyError::NotRegularFile);
    }
    if mode & 0o077 != 0 {
        return Err(KeyError::BadMode(mode & 0o7777));
    }
    if file_uid != euid {
        return Err(KeyError::WrongOwner);
    }
    Ok(())
}

/// The directory holding the key must be a real directory that only root or the agent can
/// change: no group/other write bit (a sticky /tmp-style directory does not count as private).
/// `mode` is the raw st_mode.
pub fn check_dir_meta(mode: u32, uid: u32, euid: u32, is_dir: bool) -> Result<(), KeyError> {
    if !is_dir {
        return Err(KeyError::NotRegularFile);
    }
    if mode & 0o022 != 0 {
        return Err(KeyError::BadDirMode(mode & 0o7777));
    }
    if uid != 0 && uid != euid {
        return Err(KeyError::WrongDirOwner);
    }
    Ok(())
}

/// Overwrite secret bytes in place. `black_box` keeps the optimizer from treating the stores as
/// dead; without `unsafe` (volatile writes) this is best effort, not a guarantee.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&*buf);
}

/// Hex text (whitespace around it ignored) of at least 32 bytes.
pub fn parse_key_hex(text: &str) -> Result<Vec<u8>, KeyError> {
    if text.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyError::TooLarge);
    }
    let t = text.trim();
    if !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(KeyError::NotHex);
    }
    let key: Vec<u8> = (0..t.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect();
    if key.len() < MIN_KEY_BYTES {
        return Err(KeyError::TooShort);
    }
    Ok(key)
}

/// Effective uid of this process, from /proc (std has no getuid and we forbid unsafe).
fn current_euid() -> Result<u32, KeyError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|e| KeyError::Io(e.to_string()))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| KeyError::Io("cannot determine effective uid".into()))
}

/// `O_NOFOLLOW` per architecture (std exposes no constant and the agent has no libc dependency).
#[cfg(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "m68k"
))]
const O_NOFOLLOW: i32 = 0x8000;
#[cfg(not(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "m68k"
)))]
const O_NOFOLLOW: i32 = 0x20000;

/// Reads the key. Every check runs on the opened descriptor (no check-then-open race): the open
/// refuses a symlink, then `fstat` gives type, mode and owner of the file actually read. The
/// parent directory must not be writable by group/other.
pub fn load_key(path: &Path) -> Result<Vec<u8>, KeyError> {
    let io = |e: std::io::Error| KeyError::Io(e.to_string());
    let euid = current_euid()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = fs::symlink_metadata(parent).map_err(io)?;
    check_dir_meta(dir.mode(), dir.uid(), euid, dir.file_type().is_dir())?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        // ELOOP (40 on Linux) is what O_NOFOLLOW reports for a symlink.
        .map_err(|e| match e.raw_os_error() {
            Some(40) => KeyError::NotRegularFile,
            _ => io(e),
        })?;
    let meta = file.metadata().map_err(io)?;
    check_key_meta(meta.mode(), meta.uid(), euid, meta.file_type().is_file())?;
    let mut buf = Vec::new();
    let read = file
        .take(MAX_KEY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf);
    let parsed = read
        .map_err(io)
        .and_then(|_| std::str::from_utf8(&buf).map_err(|_| KeyError::NotHex))
        .and_then(parse_key_hex);
    wipe(&mut buf);
    parsed
}
