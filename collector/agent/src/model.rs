//! Batch model that serializes to exactly `api/batch.schema.json`.
//!
//! Item constructors enforce the schema limits (lengths, MAC form, IP validity, charset) so a
//! hostile LAN string can never produce a batch the server would reject wholesale.

use std::net::IpAddr;

use crate::json;
use crate::mac;

pub const MAX_HOSTNAME: usize = 253;
pub const MAX_TEXT: usize = 255;
pub const MAX_QNAME: usize = 253;
pub const MAX_OPT55: usize = 64;
pub const MAX_LEASES: usize = 1000;
pub const MAX_NEIGH: usize = 2000;
pub const MAX_DNS: usize = 5000;
pub const MAX_CONNTRACK: usize = 5000;
pub const MAX_SIGHTINGS: usize = 1000;
/// Schema: epoch seconds must be <= 2^40.
pub const MAX_EPOCH: u64 = 1 << 40;
/// Schema: counters are <= i64::MAX.
pub const MAX_COUNT: u64 = i64::MAX as u64;
/// Upper bound of the bytes appended after the stored head (`sent_ts` + `dropped_batches`).
pub const TAIL_RESERVE: usize = 64;

/// Replace control characters with `?` and cap to `max` chars (schema limits are in chars).
pub fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn valid_ip(s: &str) -> Option<String> {
    s.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub opt55: Vec<u8>,
    pub opt60: Option<String>,
}

impl Lease {
    pub fn new(
        mac_s: &str,
        ip: &str,
        hostname: Option<&str>,
        opt55: &[u8],
        opt60: Option<&str>,
    ) -> Option<Self> {
        Some(Self {
            mac: mac::normalize(mac_s)?,
            ip: valid_ip(ip)?,
            hostname: hostname
                .map(|h| clean_text(h, MAX_HOSTNAME))
                .filter(|h| !h.is_empty()),
            opt55: opt55.iter().copied().take(MAX_OPT55).collect(),
            opt60: opt60
                .map(|v| clean_text(v, MAX_TEXT))
                .filter(|v| !v.is_empty()),
        })
    }

    pub fn write(&self, out: &mut String) {
        out.push('{');
        json::key(out, true, "mac");
        json::push_str(out, &self.mac);
        json::key(out, false, "ip");
        json::push_str(out, &self.ip);
        json::key(out, false, "hostname");
        json::push_opt_str(out, self.hostname.as_deref());
        json::key(out, false, "opt55");
        out.push('[');
        for (i, v) in self.opt55.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&v.to_string());
        }
        out.push(']');
        json::key(out, false, "opt60");
        json::push_opt_str(out, self.opt60.as_deref());
        out.push('}');
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: String,
    pub mac: String,
    pub family: Family,
}

impl Neighbor {
    pub fn new(ip: &str, mac_s: &str) -> Option<Self> {
        let parsed: IpAddr = ip.parse().ok()?;
        Some(Self {
            ip: parsed.to_string(),
            mac: mac::normalize(mac_s)?,
            family: if parsed.is_ipv4() {
                Family::Inet
            } else {
                Family::Inet6
            },
        })
    }

    pub fn write(&self, out: &mut String) {
        out.push('{');
        json::key(out, true, "ip");
        json::push_str(out, &self.ip);
        json::key(out, false, "mac");
        json::push_str(out, &self.mac);
        json::key(out, false, "family");
        json::push_str(
            out,
            match self.family {
                Family::Inet => "inet",
                Family::Inet6 => "inet6",
            },
        );
        out.push('}');
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub ts: u64,
    pub mac: String,
    pub qname: String,
    pub qtype: String,
    pub answer_ip: Option<String>,
}

impl DnsQuery {
    pub fn new(
        ts: u64,
        mac_s: &str,
        qname: &str,
        qtype: &str,
        answer_ip: Option<&str>,
    ) -> Option<Self> {
        let qname = clean_text(qname, MAX_QNAME);
        let qtype = qtype.to_ascii_uppercase();
        let qtype_ok = (1..=16).contains(&qtype.len())
            && qtype
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if qname.is_empty() || !qtype_ok || ts > MAX_EPOCH {
            return None;
        }
        Some(Self {
            ts,
            mac: mac::normalize(mac_s)?,
            qname,
            qtype,
            answer_ip: answer_ip.and_then(valid_ip),
        })
    }

    pub fn write(&self, out: &mut String) {
        out.push('{');
        json::key(out, true, "ts");
        out.push_str(&self.ts.to_string());
        json::key(out, false, "mac");
        json::push_str(out, &self.mac);
        json::key(out, false, "qname");
        json::push_str(out, &self.qname);
        json::key(out, false, "qtype");
        json::push_str(out, &self.qtype);
        json::key(out, false, "answer_ip");
        json::push_opt_str(out, self.answer_ip.as_deref());
        out.push('}');
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackSummary {
    pub mac: String,
    /// `None` only for the per-MAC `other` overflow bucket.
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub proto: Proto,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flows: u64,
}

impl ConntrackSummary {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_up.saturating_add(self.bytes_down)
    }

    pub fn write(&self, out: &mut String) {
        out.push('{');
        json::key(out, true, "mac");
        json::push_str(out, &self.mac);
        json::key(out, false, "dst_ip");
        json::push_opt_str(out, self.dst_ip.as_deref());
        json::key(out, false, "dst_port");
        match self.dst_port {
            Some(p) => out.push_str(&p.to_string()),
            None => out.push_str("null"),
        }
        json::key(out, false, "proto");
        json::push_str(out, self.proto.as_str());
        json::key(out, false, "bytes_up");
        out.push_str(&self.bytes_up.min(MAX_COUNT).to_string());
        json::key(out, false, "bytes_down");
        out.push_str(&self.bytes_down.min(MAX_COUNT).to_string());
        json::key(out, false, "flows");
        out.push_str(&self.flows.min(MAX_COUNT).to_string());
        out.push('}');
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SightingKind {
    Mdns,
    Ssdp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub mac: String,
    pub kind: SightingKind,
    pub name: Option<String>,
    pub service: Option<String>,
    pub ua: Option<String>,
}

impl Sighting {
    pub fn new(
        mac_s: &str,
        kind: SightingKind,
        name: Option<&str>,
        service: Option<&str>,
        ua: Option<&str>,
    ) -> Option<Self> {
        let f = |v: Option<&str>| v.map(|s| clean_text(s, MAX_TEXT)).filter(|s| !s.is_empty());
        Some(Self {
            mac: mac::normalize(mac_s)?,
            kind,
            name: f(name),
            service: f(service),
            ua: f(ua),
        })
    }

    pub fn write(&self, out: &mut String) {
        out.push('{');
        json::key(out, true, "mac");
        json::push_str(out, &self.mac);
        json::key(out, false, "kind");
        json::push_str(
            out,
            match self.kind {
                SightingKind::Mdns => "mdns",
                SightingKind::Ssdp => "ssdp",
            },
        );
        json::key(out, false, "name");
        json::push_opt_str(out, self.name.as_deref());
        json::key(out, false, "service");
        json::push_opt_str(out, self.service.as_deref());
        json::key(out, false, "ua");
        json::push_opt_str(out, self.ua.as_deref());
        out.push('}');
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Health {
    pub dns_log_quiet: bool,
    pub rss_kb: Option<u64>,
    pub spool_batches: Option<u64>,
    pub uptime_s: Option<u64>,
}

impl Health {
    pub fn write(&self, out: &mut String) {
        let opt = |out: &mut String, v: Option<u64>| match v {
            Some(n) => out.push_str(&n.min(MAX_COUNT).to_string()),
            None => out.push_str("null"),
        };
        out.push('{');
        json::key(out, true, "dns_log_quiet");
        out.push_str(if self.dns_log_quiet { "true" } else { "false" });
        json::key(out, false, "rss_kb");
        opt(out, self.rss_kb);
        json::key(out, false, "spool_batches");
        opt(out, self.spool_batches);
        json::key(out, false, "uptime_s");
        opt(out, self.uptime_s);
        out.push('}');
    }
}

/// Identity and window of one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub collector_id: String,
    pub key_id: String,
    pub boot_id: String,
    pub seq: u64,
    pub batch_id: String,
    pub window_start: u64,
    pub window_end: u64,
}

/// Content of one batch (already truncated to fit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sections {
    pub leases: Vec<Lease>,
    pub neigh: Vec<Neighbor>,
    pub dns: Vec<DnsQuery>,
    pub conntrack: Vec<ConntrackSummary>,
    pub sightings: Vec<Sighting>,
}

/// A batch serialized except for the per-send tail (`sent_ts`, `dropped_batches`), so it can be
/// kept in the RAM spool as bytes and re-stamped and re-signed on every send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBatch {
    pub seq: u64,
    pub batch_id: String,
    head: String,
}

fn write_array<T>(out: &mut String, name: &str, items: &[T], w: impl Fn(&T, &mut String)) {
    json::key(out, false, name);
    out.push('[');
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        w(it, out);
    }
    out.push(']');
}

/// Serialize everything except `,"sent_ts":N,"dropped_batches":D}`.
pub fn encode(
    meta: &Meta,
    sections: &Sections,
    truncated: &std::collections::BTreeMap<String, u64>,
    health: &Health,
) -> EncodedBatch {
    let mut out = String::new();
    out.push('{');
    json::key(&mut out, true, "collector_id");
    json::push_str(&mut out, &meta.collector_id);
    json::key(&mut out, false, "key_id");
    json::push_str(&mut out, &meta.key_id);
    json::key(&mut out, false, "boot_id");
    json::push_str(&mut out, &meta.boot_id);
    json::key(&mut out, false, "seq");
    out.push_str(&meta.seq.to_string());
    json::key(&mut out, false, "batch_id");
    json::push_str(&mut out, &meta.batch_id);
    json::key(&mut out, false, "window_start");
    out.push_str(&meta.window_start.to_string());
    json::key(&mut out, false, "window_end");
    out.push_str(&meta.window_end.to_string());
    json::key(&mut out, false, "truncated");
    out.push('{');
    for (i, (k, v)) in truncated.iter().enumerate() {
        json::key(&mut out, i == 0, k);
        out.push_str(&(*v).min(MAX_COUNT).to_string());
    }
    out.push('}');
    write_array(&mut out, "leases", &sections.leases, Lease::write);
    write_array(&mut out, "neigh", &sections.neigh, Neighbor::write);
    write_array(&mut out, "dns", &sections.dns, DnsQuery::write);
    write_array(
        &mut out,
        "conntrack",
        &sections.conntrack,
        ConntrackSummary::write,
    );
    write_array(&mut out, "sightings", &sections.sightings, Sighting::write);
    json::key(&mut out, false, "health");
    health.write(&mut out);
    json::key(&mut out, false, "sent_ts");
    EncodedBatch {
        seq: meta.seq,
        batch_id: meta.batch_id.clone(),
        head: out,
    }
}

impl EncodedBatch {
    /// Final request body for one send attempt.
    pub fn body(&self, sent_ts: u64, dropped_batches: u64) -> Vec<u8> {
        let mut out = String::with_capacity(self.head.len() + TAIL_RESERVE);
        out.push_str(&self.head);
        out.push_str(&sent_ts.min(MAX_EPOCH).to_string());
        json::key(&mut out, false, "dropped_batches");
        out.push_str(&dropped_batches.min(MAX_COUNT).to_string());
        out.push('}');
        out.into_bytes()
    }

    /// Bytes this batch occupies in the spool (and, +tail, on the wire).
    pub fn len(&self) -> usize {
        self.head.len() + TAIL_RESERVE
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}
