//! Parser for the conntrack helper's snapshot line (newline-delimited JSON, one object per
//! line). Hand-written and bounds-checked: the line comes from a root-owned socket, but a bug or
//! a swapped socket must not be able to crash or stall the agent (`panic = "abort"` in release).
//!
//! A snapshot is rejected as a whole on any structural problem: a line over `MAX_LINE`, control
//! bytes (NUL included), invalid UTF-8, a duplicate or escaped key, a wrong type or version, a
//! missing required field, too many records, nesting deeper than `MAX_DEPTH`, trailing bytes.
//! Unknown fields are skipped. Counters that do not fit u64 saturate.

use std::net::IpAddr;

use crate::model::Proto;

/// Longest accepted line, newline excluded. The helper allows 2 MiB (`MAX_SNAPSHOT_BYTES`).
pub const MAX_LINE: usize = 2 * 1024 * 1024;
pub const MAX_RECORDS: usize = 8192;
pub const MAX_DEPTH: usize = 8;
const MAX_KEY: usize = 64;
const MAX_STR: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooLong,
    NotUtf8,
    ControlByte,
    Syntax(&'static str),
    DuplicateKey(&'static str),
    BadVersion,
    Missing(&'static str),
    BadField(&'static str),
    TooDeep,
    TooManyRecords,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => write!(f, "line longer than {MAX_LINE} bytes"),
            Self::NotUtf8 => f.write_str("not valid UTF-8"),
            Self::ControlByte => f.write_str("control byte in line"),
            Self::Syntax(w) => write!(f, "malformed JSON: {w}"),
            Self::DuplicateKey(k) => write!(f, "duplicate key {k}"),
            Self::BadVersion => f.write_str("unsupported snapshot version"),
            Self::Missing(k) => write!(f, "missing field {k}"),
            Self::BadField(k) => write!(f, "bad value for {k}"),
            Self::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
            Self::TooManyRecords => write!(f, "more than {MAX_RECORDS} records"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A full `(src, dst, dport, proto)` row.
    Tuple,
    /// Per-source overflow bucket.
    Other,
    /// The helper's single remainder record for sources it could not keep (src `0.0.0.0`).
    OtherGlobal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub src: IpAddr,
    pub kind: Kind,
    pub dst: Option<IpAddr>,
    pub dport: Option<u16>,
    pub proto: Proto,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flows: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub seq: u64,
    pub ts: u64,
    pub interval_s: u64,
    pub acct_off: bool,
    pub table_pressure: bool,
    pub recounted_flows: u64,
    pub dropped_new_keys: u64,
    pub records: Vec<Record>,
}

pub fn parse_snapshot(line: &[u8]) -> Result<Snapshot, ParseError> {
    if line.len() > MAX_LINE {
        return Err(ParseError::TooLong);
    }
    if line
        .iter()
        .any(|&b| b < 0x20 && !matches!(b, b' ' | b'\t' | b'\r'))
    {
        return Err(ParseError::ControlByte);
    }
    std::str::from_utf8(line).map_err(|_| ParseError::NotUtf8)?;
    let mut p = Cursor { b: line, i: 0 };
    p.ws();
    let snap = p.snapshot()?;
    p.ws();
    if p.i != line.len() {
        return Err(ParseError::Syntax("trailing bytes"));
    }
    Ok(snap)
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

/// Each key may appear once per object; `seen` is a bitset over the known keys.
fn once(seen: &mut u32, bit: usize, name: &'static str) -> Result<(), ParseError> {
    if *seen & (1 << bit) != 0 {
        return Err(ParseError::DuplicateKey(name));
    }
    *seen |= 1 << bit;
    Ok(())
}

const TOP_KEYS: [&str; 9] = [
    "v",
    "seq",
    "ts",
    "interval_s",
    "acct_off",
    "table_pressure",
    "recounted_flows",
    "dropped_new_keys",
    "records",
];
const REC_KEYS: [&str; 9] = [
    "src",
    "dst",
    "dport",
    "proto",
    "other",
    "other_global",
    "bytes_up",
    "bytes_down",
    "flows",
];

impl<'a> Cursor<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8, what: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(ParseError::Syntax(what))
        }
    }

    /// A string without escapes, at most `max` bytes. Used for every key and every value we read.
    fn plain_str(&mut self, max: usize) -> Result<&'a str, ParseError> {
        self.eat(b'"', "expected string")?;
        let start = self.i;
        loop {
            match self.peek() {
                None => return Err(ParseError::Syntax("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => return Err(ParseError::Syntax("escape in a field we use")),
                Some(_) => self.i += 1,
            }
            if self.i - start > max {
                return Err(ParseError::Syntax("string too long"));
            }
        }
        let s = &self.b[start..self.i];
        self.i += 1;
        // The whole line was validated as UTF-8 and the quotes are ASCII.
        std::str::from_utf8(s).map_err(|_| ParseError::NotUtf8)
    }

    fn boolean(&mut self, name: &'static str) -> Result<bool, ParseError> {
        for (lit, v) in [(&b"true"[..], true), (&b"false"[..], false)] {
            if self.b[self.i..].starts_with(lit) {
                self.i += lit.len();
                return Ok(v);
            }
        }
        Err(ParseError::BadField(name))
    }

    /// Non-negative integer, no sign, fraction, exponent or leading zero; saturates at u64::MAX.
    fn uint(&mut self, name: &'static str) -> Result<u64, ParseError> {
        let start = self.i;
        let mut n: u64 = 0;
        while let Some(d @ b'0'..=b'9') = self.peek() {
            n = n.saturating_mul(10).saturating_add(u64::from(d - b'0'));
            self.i += 1;
        }
        let len = self.i - start;
        let leading_zero = len > 1 && self.b[start] == b'0';
        let more = matches!(self.peek(), Some(b'.' | b'e' | b'E'));
        if len == 0 || leading_zero || more {
            return Err(ParseError::BadField(name));
        }
        Ok(n)
    }

    /// Skips any JSON value (used for fields we ignore). Escapes are allowed in skipped strings.
    fn skip(&mut self, depth: usize) -> Result<(), ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        match self.peek() {
            Some(b'"') => self.skip_string(),
            Some(b'{') => self.skip_seq(depth, b'}', true),
            Some(b'[') => self.skip_seq(depth, b']', false),
            Some(b'-' | b'0'..=b'9') => {
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                Ok(())
            }
            _ => {
                for lit in [&b"true"[..], b"false", b"null"] {
                    if self.b[self.i..].starts_with(lit) {
                        self.i += lit.len();
                        return Ok(());
                    }
                }
                Err(ParseError::Syntax("bad value"))
            }
        }
    }

    fn skip_string(&mut self) -> Result<(), ParseError> {
        self.eat(b'"', "expected string")?;
        loop {
            match self.peek() {
                None => return Err(ParseError::Syntax("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(b'\\') => self.i += 2,
                Some(_) => self.i += 1,
            }
        }
    }

    fn skip_seq(&mut self, depth: usize, close: u8, object: bool) -> Result<(), ParseError> {
        self.i += 1;
        self.ws();
        if self.peek() == Some(close) {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            if object {
                self.skip_string()?;
                self.ws();
                self.eat(b':', "expected ':'")?;
                self.ws();
            }
            self.skip(depth + 1)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(c) if c == close => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(ParseError::Syntax("expected ',' or closing bracket")),
            }
        }
    }

    /// Calls `field(key)` for each member. It returns `true` when it consumed the value, `false`
    /// to have it skipped (unknown field).
    fn object(
        &mut self,
        mut field: impl FnMut(&mut Self, &'a str) -> Result<bool, ParseError>,
    ) -> Result<(), ParseError> {
        self.eat(b'{', "expected object")?;
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            let key = self.plain_str(MAX_KEY)?;
            self.ws();
            self.eat(b':', "expected ':'")?;
            self.ws();
            if !field(self, key)? {
                self.skip(1)?;
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(ParseError::Syntax("expected ',' or '}'")),
            }
        }
    }

    fn snapshot(&mut self) -> Result<Snapshot, ParseError> {
        let mut s = Snapshot::default();
        let (mut seen, mut version, mut have_records) = (0u32, false, false);
        self.object(|p, key| {
            let Some(idx) = TOP_KEYS.iter().position(|k| *k == key) else {
                return Ok(false);
            };
            let name = TOP_KEYS[idx];
            once(&mut seen, idx, name)?;
            match name {
                "v" => {
                    if p.uint(name)? != 1 {
                        return Err(ParseError::BadVersion);
                    }
                    version = true;
                }
                "seq" => s.seq = p.uint(name)?,
                "ts" => s.ts = p.uint(name)?,
                "interval_s" => s.interval_s = p.uint(name)?,
                "acct_off" => s.acct_off = p.boolean(name)?,
                "table_pressure" => s.table_pressure = p.boolean(name)?,
                "recounted_flows" => s.recounted_flows = p.uint(name)?,
                "dropped_new_keys" => s.dropped_new_keys = p.uint(name)?,
                _ => {
                    s.records = p.records()?;
                    have_records = true;
                }
            }
            Ok(true)
        })?;
        if !version {
            return Err(ParseError::Missing("v"));
        }
        if !have_records {
            return Err(ParseError::Missing("records"));
        }
        Ok(s)
    }

    fn records(&mut self) -> Result<Vec<Record>, ParseError> {
        self.eat(b'[', "records must be an array")?;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(out);
        }
        loop {
            self.ws();
            if out.len() >= MAX_RECORDS {
                return Err(ParseError::TooManyRecords);
            }
            out.push(self.record()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(out);
                }
                _ => return Err(ParseError::Syntax("expected ',' or ']'")),
            }
        }
    }

    fn record(&mut self) -> Result<Record, ParseError> {
        let mut seen = 0u32;
        let (mut src, mut dst, mut dport, mut proto) = (None, None, None, None);
        let (mut other, mut global) = (false, false);
        let (mut up, mut down, mut flows) = (None, None, None);
        self.object(|p, key| {
            let Some(idx) = REC_KEYS.iter().position(|k| *k == key) else {
                return Ok(false);
            };
            let name = REC_KEYS[idx];
            once(&mut seen, idx, name)?;
            match name {
                "src" => src = Some(parse_ip(p.plain_str(MAX_STR)?, name)?),
                "dst" => dst = Some(parse_ip(p.plain_str(MAX_STR)?, name)?),
                "dport" => {
                    let n = p.uint(name)?;
                    dport = Some(u16::try_from(n).map_err(|_| ParseError::BadField(name))?);
                }
                "proto" => proto = Some(parse_proto(p.plain_str(MAX_STR)?)?),
                "other" => other = p.boolean(name)?,
                "other_global" => global = p.boolean(name)?,
                "bytes_up" => up = Some(p.uint(name)?),
                "bytes_down" => down = Some(p.uint(name)?),
                _ => flows = Some(p.uint(name)?),
            }
            Ok(true)
        })?;
        let src = src.ok_or(ParseError::Missing("src"))?;
        let (kind, dst, dport, proto) = if global {
            (Kind::OtherGlobal, None, None, Proto::Other)
        } else if other {
            (Kind::Other, None, None, Proto::Other)
        } else {
            let d = dst.ok_or(ParseError::Missing("dst"))?;
            let port = dport.ok_or(ParseError::Missing("dport"))?;
            let pr = proto.ok_or(ParseError::Missing("proto"))?;
            (Kind::Tuple, Some(d), Some(port), pr)
        };
        Ok(Record {
            src,
            kind,
            dst,
            dport,
            proto,
            bytes_up: up.ok_or(ParseError::Missing("bytes_up"))?,
            bytes_down: down.ok_or(ParseError::Missing("bytes_down"))?,
            flows: flows.ok_or(ParseError::Missing("flows"))?,
        })
    }
}

fn parse_ip(s: &str, name: &'static str) -> Result<IpAddr, ParseError> {
    s.parse().map_err(|_| ParseError::BadField(name))
}

fn parse_proto(s: &str) -> Result<Proto, ParseError> {
    match s {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "icmp" => Ok(Proto::Icmp),
        "icmpv6" => Ok(Proto::Icmpv6),
        _ => match s.strip_prefix("proto-") {
            Some(n) if !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()) => {
                Ok(Proto::Other)
            }
            _ => Err(ParseError::BadField("proto")),
        },
    }
}
