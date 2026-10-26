//! dnsmasq log line parsers (pure, over text).
//!
//! FORMATS ARE ASSUMED, NOT VERIFIED ON THE ROUTER. DNS lines follow dnsmasq >= 2.84
//! `log-queries=extra` (serial, client address/port, then the usual message). DHCP lines follow
//! the `log-dhcp` messages in dnsmasq's source/docs (`requested options:`, `vendor class:`,
//! `client provides name:`, `DHCPACK(...)`), and the P0 sample fixture. P0 items 2 and 3
//! ("Does `log-dhcp` log option 55/60", "do lines match") are still open. If the router's lines
//! differ these parsers silently yield no events (they never panic), and `dns_log_quiet` /
//! missing fingerprints are the visible symptoms.
//!
//! Timestamps in the log have no year or zone, so queries are stamped with the time they were
//! read (the tail polls every few seconds), not the log time.

use std::collections::{HashMap, VecDeque};

pub use crate::dhcp_assembler::DhcpAssembler;
use std::net::IpAddr;

use crate::model::{DnsQuery, MAX_OPT55};

const MAX_PENDING_DNS: usize = 1024;
/// Most pending queries one client IP may hold, so a flood from one device cannot evict the
/// others' queries between two polls.
const MAX_PENDING_PER_CLIENT: usize = 256;
/// Longest `tags:` value accepted. The value is never used (the line only has to be recognised so
/// it does not break the attach context), so a router with many or non-ASCII tag names must still
/// parse; the cap only bounds what a hostile line can carry. Lines failing it are unparsed (the
/// context breaks) and not separately counted: there is no health counter for them.
const MAX_TAGS_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEvent {
    Query {
        id: String,
        client_ip: String,
        qtype: String,
        name: String,
    },
    Answer {
        id: String,
        client_ip: String,
        ip: String,
    },
    /// `DHCPREQUEST` or (`discover`) `DHCPDISCOVER`: opens an attach context for its MAC.
    DhcpRequest {
        id: String,
        mac: String,
        discover: bool,
    },
    /// Any other DHCP packet line. `poison`: it has no MAC we can trust for this serial
    /// (INFORM, RELEASE, DECLINE, NAK), so the serial's entry is tainted.
    DhcpBoundary {
        id: String,
        poison: bool,
    },
    /// `<xid> tags: <iface>`: informational, between the packet line and its companions.
    /// Neutral: it keeps the attach context of the same xid and never opens one.
    DhcpTags {
        id: String,
    },
    /// `<xid> available DHCP range: ...`: dnsmasq's first line of a packet. It opens the
    /// preamble that the packet's `vendor class:` / `client provides name:` lines (which precede
    /// the `DHCPREQUEST`) are collected in.
    DhcpPacketStart {
        id: String,
    },
    DhcpOptions {
        id: String,
        opt55: Vec<u8>,
    },
    DhcpVendor {
        id: String,
        class: String,
    },
    DhcpName {
        id: String,
        name: String,
    },
    DhcpAck {
        id: String,
        mac: String,
        ip: String,
        name: Option<String>,
    },
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit())
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The pid and the message after the exact dnsmasq syslog prefix
/// `<Mon> <d> hh:mm:ss dnsmasq[-dhcp][pid]: `, anchored at the start of the line. Any text before it (for instance the tail end of a line a
/// DHCP client wrote into the log) means this is not a line dnsmasq started, so it is refused.
fn strip_prefix(line: &str) -> Option<(u64, &str)> {
    let rest = line
        .get(..3)
        .filter(|m| MONTHS.contains(m))
        .and(line.get(3..))?;
    let rest = rest.strip_prefix(' ')?;
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let day_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    let rest = rest.get(day_len..).filter(|_| (1..=2).contains(&day_len))?;
    let rest = rest.strip_prefix(' ')?;
    let t = rest.as_bytes().get(..8)?;
    let shape = |i: usize| t[i].is_ascii_digit();
    if !(shape(0) && shape(1) && t[2] == b':' && shape(3) && shape(4) && t[5] == b':')
        || !(shape(6) && shape(7))
    {
        return None;
    }
    let rest = rest.get(8..)?.strip_prefix(' ')?;
    let rest = rest.strip_prefix("dnsmasq")?;
    let rest = rest.strip_prefix("-dhcp").unwrap_or(rest);
    let rest = rest.strip_prefix('[')?;
    let pid_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=10).contains(&pid_len) {
        return None;
    }
    // At most 10 digits: always fits.
    let pid = rest.get(..pid_len)?.parse().ok()?;
    Some((pid, rest.get(pid_len..)?.strip_prefix("]: ")?))
}

pub fn parse_line(line: &str) -> Option<LogEvent> {
    parse_line_pid(line).map(|(_, ev)| ev)
}

/// Like `parse_line`, with the pid of the dnsmasq process that wrote the line. Several
/// processes may share one log file and each numbers its packets itself, so the DHCP assembler
/// joins lines only when pid and serial both match.
pub fn parse_line_pid(line: &str) -> Option<(u64, LogEvent)> {
    let (pid, msg) = strip_prefix(line)?;
    let (id, rest) = msg.trim().split_once(' ')?;
    if !valid_id(id) {
        return None;
    }
    let ev = parse_dhcp(id, rest).or_else(|| parse_dns(id, rest))?;
    Some((pid, ev))
}

fn parse_dns(id: &str, rest: &str) -> Option<LogEvent> {
    let toks: Vec<&str> = rest.split_whitespace().collect();
    let (addr_port, kind) = (toks.first()?, toks.get(1)?);
    // Scoped IPv6 clients may be logged as `fe80::1%br-lan/port` (assumed); drop the scope.
    let host = addr_port.rsplit_once('/')?.0;
    let client_ip: IpAddr = host.split('%').next()?.parse().ok()?;
    let client_ip = client_ip.to_string();
    if let Some(t) = kind
        .strip_prefix("query[")
        .and_then(|k| k.strip_suffix(']'))
    {
        // "<id> <ip>/<port> query[A] <name> from <ip>": exactly five tokens after the serial, so a "name"
        // containing spaces is rejected rather than guessed at.
        if toks.len() != 5 || toks[3] != "from" {
            return None;
        }
        let qtype = t.replace("type=", "TYPE");
        return Some(LogEvent::Query {
            id: id.into(),
            client_ip,
            qtype,
            name: (*toks.get(2)?).into(),
        });
    }
    if matches!(*kind, "reply" | "cached") && toks.len() == 5 && toks[3] == "is" {
        let ip: IpAddr = toks[4].parse().ok()?;
        return Some(LogEvent::Answer {
            id: id.into(),
            client_ip,
            ip: ip.to_string(),
        });
    }
    None
}

fn parse_dhcp(id: &str, rest: &str) -> Option<LogEvent> {
    let id = id.to_string();
    if let Some(v) = rest.strip_prefix("tags:") {
        // The value is ignored: any charset, bounded length, no control characters.
        let v = v.trim();
        let sane = v.len() <= MAX_TAGS_LEN && !v.chars().any(char::is_control);
        return sane.then_some(LogEvent::DhcpTags { id });
    }
    if let Some(v) = rest.strip_prefix("available DHCP range:") {
        let v = v.trim();
        let sane = v.len() <= MAX_TAGS_LEN && !v.chars().any(char::is_control);
        return sane.then_some(LogEvent::DhcpPacketStart { id });
    }
    if let Some(v) = rest.strip_prefix("requested options:") {
        let opt55 = v
            .split(',')
            .filter_map(|p| p.trim().split(':').next()?.trim().parse::<u8>().ok())
            .take(MAX_OPT55)
            .collect();
        return Some(LogEvent::DhcpOptions { id, opt55 });
    }
    if let Some(v) = rest.strip_prefix("vendor class:") {
        return Some(LogEvent::DhcpVendor {
            id,
            class: v.trim().to_string(),
        });
    }
    if let Some(v) = rest.strip_prefix("client provides name:") {
        return Some(LogEvent::DhcpName {
            id,
            name: v.trim().to_string(),
        });
    }
    let toks: Vec<&str> = rest.split_whitespace().collect();
    let first = toks.first()?;
    if first.starts_with("DHCPREQUEST(") && toks.len() >= 3 {
        return Some(LogEvent::DhcpRequest {
            id,
            mac: toks[2].into(),
            discover: false,
        });
    }
    if first.starts_with("DHCPDISCOVER(") && toks.len() >= 2 {
        return Some(LogEvent::DhcpRequest {
            id,
            mac: toks[1].into(),
            discover: true,
        });
    }
    for (verb, poison) in [
        ("DHCPINFORM(", true),
        ("DHCPRELEASE(", true),
        ("DHCPDECLINE(", true),
        ("DHCPNAK(", true),
        ("DHCPOFFER(", false),
    ] {
        if first.starts_with(verb) {
            return Some(LogEvent::DhcpBoundary { id, poison });
        }
    }
    if first.starts_with("DHCPACK(") && toks.len() >= 3 {
        let name = (toks.len() > 3).then(|| toks[3..].join(" "));
        return Some(LogEvent::DhcpAck {
            id,
            mac: toks[2].into(),
            ip: toks[1].into(),
            name,
        });
    }
    None
}

#[derive(Debug)]
struct PendingQuery {
    id: String,
    client_ip: String,
    qtype: String,
    name: String,
    ts: u64,
    answer: Option<String>,
}

/// Pairs each query with its first IP answer (same serial and client) and attributes it to a
/// MAC through the neighbor table.
#[derive(Debug, Default)]
pub struct DnsCorrelator {
    pending: VecDeque<PendingQuery>,
    evicted: u64,
    throttled: u64,
}

impl DnsCorrelator {
    pub fn feed(&mut self, ev: &LogEvent, now_ts: u64) {
        match ev {
            LogEvent::Query {
                id,
                client_ip,
                qtype,
                name,
            } => {
                if self
                    .pending
                    .iter()
                    .filter(|p| &p.client_ip == client_ip)
                    .count()
                    >= MAX_PENDING_PER_CLIENT
                {
                    self.throttled += 1;
                    return;
                }
                if self.pending.len() >= MAX_PENDING_DNS {
                    self.pending.pop_front();
                    self.evicted += 1;
                }
                self.pending.push_back(PendingQuery {
                    id: id.clone(),
                    client_ip: client_ip.clone(),
                    qtype: qtype.clone(),
                    name: name.clone(),
                    ts: now_ts,
                    answer: None,
                });
            }
            LogEvent::Answer { id, client_ip, ip } => {
                if let Some(p) = self
                    .pending
                    .iter_mut()
                    .rev()
                    .find(|p| &p.id == id && &p.client_ip == client_ip && p.answer.is_none())
                {
                    p.answer = Some(ip.clone());
                }
            }
            _ => {}
        }
    }

    /// Drained counters of queries lost before they reached the window, by `truncated` key.
    pub fn take_counts(&mut self) -> std::collections::BTreeMap<String, u64> {
        let mut out = std::collections::BTreeMap::new();
        for (k, v) in [
            ("dns_pending_evicted", std::mem::take(&mut self.evicted)),
            ("dns_client_throttled", std::mem::take(&mut self.throttled)),
        ] {
            if v > 0 {
                out.insert(k.to_string(), v);
            }
        }
        out
    }

    /// Everything pending, with MACs resolved; queries from unknown clients are dropped.
    pub fn take_ready(&mut self, ip_to_mac: &HashMap<String, String>) -> Vec<DnsQuery> {
        self.pending
            .drain(..)
            .filter_map(|p| {
                let mac = ip_to_mac.get(&p.client_ip)?;
                DnsQuery::new(p.ts, mac, &p.name, &p.qtype, p.answer.as_deref())
            })
            .collect()
    }
}
