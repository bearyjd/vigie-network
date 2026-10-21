//! Validated parameters for the (not yet written) SPKI-pinned HTTPS transport.
//!
//! A future TLS transport must be built from a `PinnedTransport`, which can only be made with an
//! https URL without userinfo and at least one valid SHA-256 SPKI pin, so "TLS without pins" is not
//! constructible. Nothing here talks to the network and `PinnedTransport` is not a `sender::Transport`:
//! `NoTransport` in `main.rs` remains the only implementation shipped.

use std::fmt;

/// SHA-256 digest of a certificate's SubjectPublicKeyInfo.
pub type Pin = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    Scheme,
    Userinfo,
    Host,
    Port,
    NoPins,
    BadPin(usize),
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => f.write_str("server URL must start with https://"),
            Self::Userinfo => f.write_str("server URL must not contain userinfo (user:pass@)"),
            Self::Host => f.write_str("server URL has an empty or invalid host"),
            Self::Port => f.write_str("server URL has an invalid port"),
            Self::NoPins => f.write_str("at least one SPKI pin is required"),
            Self::BadPin(i) => write!(f, "pin {} is not a 32-byte SHA-256 (base64 or hex)", i + 1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTransport {
    host: String,
    port: u16,
    path: String,
    pins: Vec<Pin>,
}

impl PinnedTransport {
    /// `pins`: each a standard-base64 SHA-256 (44 chars) or the lowercase hex (64 chars) the
    /// config file uses; the two lengths cannot be confused.
    pub fn new<S: AsRef<str>>(url: &str, pins: &[S]) -> Result<Self, PinError> {
        let (host, port, path) = parse_url(url)?;
        if pins.is_empty() {
            return Err(PinError::NoPins);
        }
        let pins = pins
            .iter()
            .enumerate()
            .map(|(i, p)| parse_pin(p.as_ref()).ok_or(PinError::BadPin(i)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            host,
            port,
            path,
            pins,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn pins(&self) -> &[Pin] {
        &self.pins
    }
}

fn parse_url(url: &str) -> Result<(String, u16, String), PinError> {
    const SCHEME: &str = "https://";
    let head = url.get(..SCHEME.len()).ok_or(PinError::Scheme)?;
    if !head.eq_ignore_ascii_case(SCHEME) {
        return Err(PinError::Scheme);
    }
    let rest = &url[SCHEME.len()..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') || authority.contains("%40") {
        return Err(PinError::Userinfo);
    }
    let (host, port) = split_host_port(authority)?;
    let path = match tail {
        "" => "/".to_string(),
        t if t.starts_with('/') => t.to_string(),
        t => format!("/{t}"),
    };
    if path.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'\\') {
        return Err(PinError::Host);
    }
    Ok((host.to_string(), port, path))
}

fn split_host_port(authority: &str) -> Result<(&str, u16), PinError> {
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or(PinError::Host)?;
        let (h, after) = authority.split_at(close + 1);
        let inner = &h[1..h.len() - 1];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(PinError::Host);
        }
        match after {
            "" => (h, None),
            a => (h, Some(a.strip_prefix(':').ok_or(PinError::Host)?)),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let bracketed = host.starts_with('[');
    let host_ok = !host.is_empty()
        && (bracketed
            || host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'));
    if !host_ok {
        return Err(PinError::Host);
    }
    let port = match port {
        None => 443,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 5 => {
            match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return Err(PinError::Port),
            }
        }
        Some(_) => return Err(PinError::Port),
    };
    Ok((host, port))
}

fn parse_pin(s: &str) -> Option<Pin> {
    match s.len() {
        64 => decode_hex(s),
        44 => decode_b64(s),
        _ => None,
    }
}

fn decode_hex(s: &str) -> Option<Pin> {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = s.get(2 * i..2 * i + 2)?;
        if !pair
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return None;
        }
        *b = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Strict standard base64 of exactly 32 bytes: 43 symbols, one `=`, zero trailing bits.
fn decode_b64(s: &str) -> Option<Pin> {
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' || b[..43].contains(&b'=') {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (g, chunk) in b[..40].chunks(4).enumerate() {
        let n = chunk
            .iter()
            .try_fold(0u32, |acc, &c| Some(acc << 6 | val(c)?))?;
        out[g * 3] = (n >> 16) as u8;
        out[g * 3 + 1] = (n >> 8) as u8;
        out[g * 3 + 2] = n as u8;
    }
    // Last group: 3 symbols + '=' encode 2 bytes; the low 2 bits of the 3rd symbol must be 0.
    let n = (val(b[40])? << 12) | (val(b[41])? << 6) | val(b[42])?;
    if n & 0b11 != 0 {
        return None;
    }
    out[30] = (n >> 10) as u8;
    out[31] = (n >> 2) as u8;
    Some(out)
}
