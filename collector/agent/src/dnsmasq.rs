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
use std::net::IpAddr;

use crate::model::{DnsQuery, Lease, MAX_OPT55};

const MAX_PENDING_DNS: usize = 1024;
/// Most pending queries one client IP may hold, so a flood from one device cannot evict the
/// others' queries between two polls.
const MAX_PENDING_PER_CLIENT: usize = 256;
const MAX_PENDING_DHCP: usize = 256;

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
    DhcpRequest {
        id: String,
        mac: String,
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

pub fn parse_line(line: &str) -> Option<LogEvent> {
    let (head, msg) = line.split_once("]: ")?;
    if !head.contains("dnsmasq") {
        return None;
    }
    let (id, rest) = msg.trim().split_once(' ')?;
    if !valid_id(id) {
        return None;
    }
    parse_dhcp(id, rest).or_else(|| parse_dns(id, rest))
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
        });
    }
    if first.starts_with("DHCPDISCOVER(") && toks.len() >= 2 {
        return Some(LogEvent::DhcpRequest {
            id,
            mac: toks[1].into(),
        });
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

#[derive(Debug, Default)]
struct DhcpPartial {
    /// MAC of the `DHCPREQUEST`/`DHCPDISCOVER` that opened this entry (normalized).
    mac: Option<String>,
    /// Two different MACs (or data without a request) shared this serial: nothing here can be
    /// attributed to the ACKed MAC, so no fingerprint fields are emitted.
    tainted: bool,
    opt55: Vec<u8>,
    class: Option<String>,
    name: Option<String>,
}

/// Joins the per-transaction DHCP lines (by serial) into one lease on `DHCPACK`.
#[derive(Debug, Default)]
pub struct DhcpAssembler {
    partial: HashMap<String, DhcpPartial>,
    order: VecDeque<String>,
}

impl DhcpAssembler {
    fn entry(&mut self, id: &str) -> &mut DhcpPartial {
        if !self.partial.contains_key(id) {
            if self.order.len() >= MAX_PENDING_DHCP {
                if let Some(old) = self.order.pop_front() {
                    self.partial.remove(&old);
                }
            }
            self.order.push_back(id.to_string());
        }
        self.partial.entry(id.to_string()).or_default()
    }

    pub fn feed(&mut self, ev: &LogEvent) -> Option<Lease> {
        match ev {
            LogEvent::DhcpRequest { id, mac } => {
                let mac = crate::mac::normalize(mac);
                let p = self.entry(id);
                // The serial is attacker-chosen: a second MAC on it, or fingerprint lines that
                // came before any request, poison the entry for good.
                let foreign = match (&p.mac, &mac) {
                    (Some(old), new) => Some(old) != new.as_ref(),
                    (None, _) => p.has_fingerprint(),
                };
                if foreign || mac.is_none() {
                    p.taint();
                }
                if p.mac.is_none() {
                    p.mac = mac;
                }
            }
            // dnsmasq may split a long list over several lines (assumed); accumulate.
            LogEvent::DhcpOptions { id, opt55 } => {
                let p = self.entry(id);
                if !p.tainted {
                    p.opt55.extend(opt55.iter().copied());
                    p.opt55.truncate(MAX_OPT55);
                }
            }
            LogEvent::DhcpVendor { id, class } => {
                let p = self.entry(id);
                if !p.tainted {
                    p.class = Some(class.clone());
                }
            }
            LogEvent::DhcpName { id, name } => {
                let p = self.entry(id);
                if !p.tainted {
                    p.name = Some(name.clone());
                }
            }
            LogEvent::DhcpAck { id, mac, ip, name } => {
                let mut p = self.partial.remove(id).unwrap_or_default();
                self.order.retain(|o| o != id);
                if p.mac.is_none() || p.mac != crate::mac::normalize(mac) {
                    p.taint();
                }
                let host = name.as_deref().or(p.name.as_deref());
                return Lease::new(mac, ip, host, &p.opt55, p.class.as_deref());
            }
            LogEvent::Query { .. } | LogEvent::Answer { .. } => {}
        }
        None
    }
}

impl DhcpPartial {
    fn has_fingerprint(&self) -> bool {
        !self.opt55.is_empty() || self.class.is_some() || self.name.is_some()
    }
    fn taint(&mut self) {
        self.tainted = true;
        self.opt55.clear();
        self.class = None;
        self.name = None;
    }
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
