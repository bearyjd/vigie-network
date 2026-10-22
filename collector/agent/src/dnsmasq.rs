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
const MAX_TAGS_LEN: usize = 64;

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

/// The message after the exact dnsmasq syslog prefix `<Mon> <d> hh:mm:ss dnsmasq[-dhcp][pid]: `,
/// anchored at the start of the line. Any text before it (for instance the tail end of a line a
/// DHCP client wrote into the log) means this is not a line dnsmasq started, so it is refused.
fn strip_prefix(line: &str) -> Option<&str> {
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
    rest.get(pid_len..)?.strip_prefix("]: ")
}

pub fn parse_line(line: &str) -> Option<LogEvent> {
    let msg = strip_prefix(line)?;
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
    if let Some(v) = rest.strip_prefix("tags:") {
        // Tag names only: bounded, printable, so the line cannot carry anything else.
        let v = v.trim();
        let sane = v.len() <= MAX_TAGS_LEN && v.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        return sane.then_some(LogEvent::DhcpTags { id });
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

#[derive(Debug, Default)]
struct DhcpPartial {
    /// MAC of the `DHCPREQUEST`/`DHCPDISCOVER` that opened this entry (normalized).
    mac: Option<String>,
    /// Two different MACs (or a MAC-less verb) shared this serial: nothing here can be
    /// attributed to the ACKed MAC, so no fingerprint fields are emitted.
    tainted: bool,
    opt55: Vec<u8>,
    class: Option<String>,
    name: Option<String>,
}

/// The packet line that the option/vendor/name lines now being read belong to.
#[derive(Debug)]
struct Context {
    id: String,
    mac: Option<String>,
    /// An options line has already been attached in this context (later ones extend it; the
    /// first one replaces what an earlier packet of the same transaction left).
    opts_started: bool,
}

/// Joins the per-transaction DHCP lines into one lease on `DHCPACK`.
///
/// The serial (xid) is chosen by the client, so it proves nothing. The log is therefore read as
/// a sequential stream: a fingerprint line is attached only to the packet line directly before
/// it (same serial, nothing in between). Every other line, including every DHCP verb we do not
/// build leases from, ends that context; INFORM/RELEASE/DECLINE/NAK also poison the serial.
#[derive(Debug, Default)]
pub struct DhcpAssembler {
    partial: HashMap<String, DhcpPartial>,
    order: VecDeque<String>,
    ctx: Option<Context>,
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

    /// A log line that is not one of ours (unparsed, or DNS) ends the attach context.
    pub fn break_context(&mut self) {
        self.ctx = None;
    }

    /// The entry a fingerprint line may be attached to, or `None` (and the context is dropped
    /// when the line does not directly continue it).
    fn attach_target(&mut self, id: &str) -> Option<(&mut DhcpPartial, &mut bool)> {
        if self.ctx.as_ref()?.id != id {
            self.ctx = None;
            return None;
        }
        let c = self.ctx.as_mut()?;
        let p = self.partial.get_mut(id)?;
        (!p.tainted && p.mac == c.mac).then_some((p, &mut c.opts_started))
    }

    pub fn feed(&mut self, ev: &LogEvent) -> Option<Lease> {
        match ev {
            LogEvent::DhcpRequest { id, mac, discover } => {
                let mac = crate::mac::normalize(mac);
                let p = self.entry(id);
                // The serial is attacker-chosen: a second MAC on it poisons the entry for good.
                let foreign =
                    matches!((&p.mac, &mac), (Some(old), new) if Some(old) != new.as_ref());
                if foreign || mac.is_none() {
                    p.taint();
                } else if *discover {
                    p.clear_fingerprint();
                }
                if p.mac.is_none() {
                    p.mac = mac.clone();
                }
                self.ctx = Some(Context {
                    id: id.clone(),
                    mac,
                    opts_started: false,
                });
            }
            // dnsmasq may split a long list over several lines (assumed); accumulate.
            LogEvent::DhcpOptions { id, opt55 } => {
                if let Some((p, started)) = self.attach_target(id) {
                    if !*started {
                        p.opt55.clear();
                        *started = true;
                    }
                    p.opt55.extend(opt55.iter().copied());
                    p.opt55.truncate(MAX_OPT55);
                }
            }
            LogEvent::DhcpVendor { id, class } => {
                if let Some((p, _)) = self.attach_target(id) {
                    p.class = Some(class.clone());
                }
            }
            LogEvent::DhcpName { id, name } => {
                if let Some((p, _)) = self.attach_target(id) {
                    p.name = Some(name.clone());
                }
            }
            // Neutral: the context survives only if it is this xid's; it is never created here.
            LogEvent::DhcpTags { id } => {
                if self.ctx.as_ref().is_some_and(|c| &c.id != id) {
                    self.ctx = None;
                }
            }
            LogEvent::DhcpBoundary { id, poison } => {
                self.ctx = None;
                if *poison {
                    self.entry(id).taint();
                }
            }
            LogEvent::DhcpAck { id, mac, ip, name } => {
                self.ctx = None;
                let mut p = self.partial.remove(id).unwrap_or_default();
                self.order.retain(|o| o != id);
                if p.mac.is_none() || p.mac != crate::mac::normalize(mac) {
                    p.taint();
                }
                let host = name.as_deref().or(p.name.as_deref());
                return Lease::new(mac, ip, host, &p.opt55, p.class.as_deref());
            }
            LogEvent::Query { .. } | LogEvent::Answer { .. } => self.ctx = None,
        }
        None
    }
}

impl DhcpPartial {
    fn clear_fingerprint(&mut self) {
        self.opt55.clear();
        self.class = None;
        self.name = None;
    }
    fn taint(&mut self) {
        self.tainted = true;
        self.clear_fingerprint();
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
