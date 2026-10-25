//! Joins the per-transaction DHCP log lines into leases.
//!
//! The serial (xid) is chosen by the client and numbered per dnsmasq process, so it proves
//! nothing: the log is read as a sequential stream and every join is keyed on (pid, serial).
//! A fingerprint line is attached only where it directly continues the packet it belongs to
//! (same pid and serial, nothing in between):
//! - `vendor class:` / `client provides name:` right after a packet-start marker, up to the
//!   `DHCPREQUEST` of the same serial (`Preamble`);
//! - `requested options:` right after a verified `DHCPACK` (`PostAck`);
//! - (older assumed order) any of the three right after the `DHCPREQUEST` (`Context`).
//!
//! Every other line, including every DHCP verb we do not build leases from, ends all contexts;
//! INFORM/RELEASE/DECLINE/NAK also poison the serial.
//!
//! Publication: the `DHCPACK` publishes the lease (address, hostname) with the fingerprint
//! "not known" (empty options, no vendor class), which the window reads as "keep what you
//! have". The fingerprint (options + vendor class) of the post-ACK block is published ONCE,
//! when the block is finished: by the next line that is not the block's own options/tags line,
//! or by `end_poll` on the second poll the block has been open at the end of. A gap
//! (`lose_context`) discards an unfinished block unpublished, so a truncated list never leaves.
//!
//! Lines of another dnsmasq process (different pid) pass through every open context untouched;
//! the contexts are keyed on the pid and are closed by a line of their own pid, a gap, or the
//! second `end_poll`. A new verified ACK of another pid replaces (drops unpublished) a held block.
//!
//! Known limit of the timeout design: it assumes dnsmasq writes one `requested options:` list
//! contiguously. An unparsed line between two option lines, or a writer that stalls for
//! `BLOCK_HOLD_POLLS` polls mid-list, closes the block and publishes the truncated list.
//!
//! Lines this module deliberately does not recognise end the contexts (safe drop, fingerprint
//! lost, never leaked): a `user class:` line between vendor class and request, and
//! `available DHCP subnet:` (static/proxy ranges), which is not a packet-start marker.

use std::collections::{HashMap, VecDeque};

use crate::dnsmasq::LogEvent;
use crate::model::{Lease, MAX_OPT55};

const MAX_PENDING_DHCP: usize = 256;
/// Polls an open post-ACK block is held at the end of before it is closed.
const BLOCK_HOLD_POLLS: u8 = 2;

/// Process id and serial: the only identity a join may rely on.
type Key = (u64, String);

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

/// The packet line that the option/vendor/name lines now being read belong to.
#[derive(Debug)]
struct Context {
    key: Key,
    mac: Option<String>,
    /// An options line has already been attached in this context (later ones extend it; the
    /// first one replaces what an earlier packet of the same transaction left).
    opts_started: bool,
}

/// Vendor class and client name lines that dnsmasq logs BEFORE the `DHCPREQUEST` of the same
/// packet, collected after a packet-start marker. At most one is open; it moves into the
/// `DHCPREQUEST` of the same key that directly follows, and is dropped on anything else.
#[derive(Debug)]
struct Preamble {
    key: Key,
    class: Option<String>,
    name: Option<String>,
}

/// The verified `DHCPACK` whose `requested options:` lines (logged AFTER the ACK) are being
/// read. Only one block is ever open; its fingerprint is held back until it is finished.
#[derive(Debug)]
struct PostAck {
    key: Key,
    /// The ACK's lease (no fingerprint); the finished fingerprint is added to a copy of it.
    base: Lease,
    opt55: Vec<u8>,
    class: Option<String>,
    /// An options line has already been attached (later ones extend, the first replaces).
    started: bool,
    /// The ACK itself already published a fingerprint (older order: options before the ACK).
    published: bool,
    /// Polls this block has been open at the end of.
    polls: u8,
}

impl PostAck {
    fn add_options(&mut self, opt55: &[u8]) {
        if !self.started {
            self.opt55.clear();
            self.started = true;
        }
        self.opt55.extend_from_slice(opt55);
        self.opt55.truncate(MAX_OPT55);
    }

    /// The one fingerprint publication, if the block has anything to say.
    fn finish(self) -> Option<Lease> {
        if !(self.started || (!self.published && self.class.is_some())) {
            return None;
        }
        let b = &self.base;
        Lease::new(
            &b.mac,
            &b.ip,
            b.hostname.as_deref(),
            &self.opt55,
            self.class.as_deref(),
        )
    }
}

#[derive(Debug, Default)]
pub struct DhcpAssembler {
    partial: HashMap<Key, DhcpPartial>,
    order: VecDeque<Key>,
    ctx: Option<Context>,
    pre: Option<Preamble>,
    post: Option<PostAck>,
}

impl DhcpAssembler {
    fn entry(&mut self, key: &Key) -> &mut DhcpPartial {
        if !self.partial.contains_key(key) {
            if self.order.len() >= MAX_PENDING_DHCP {
                if let Some(old) = self.order.pop_front() {
                    self.partial.remove(&old);
                }
            }
            self.order.push_back(key.clone());
        }
        self.partial.entry(key.clone()).or_default()
    }

    /// A line that is not one of ours (unparsed) ends every attach context; a finished
    /// post-ACK block is published.
    pub fn break_context(&mut self) -> Vec<Lease> {
        self.ctx = None;
        self.pre = None;
        self.post
            .take()
            .and_then(PostAck::finish)
            .into_iter()
            .collect()
    }

    /// Bytes were lost here: nothing may attach across it, and an unfinished block is dropped
    /// unpublished (its list may be truncated).
    pub fn lose_context(&mut self) {
        self.ctx = None;
        self.pre = None;
        self.post = None;
    }

    /// End of one poll of the log. A block still open after `BLOCK_HOLD_POLLS` polls is closed
    /// and published, so it cannot wait forever on a quiet log.
    pub fn end_poll(&mut self) -> Vec<Lease> {
        let Some(pa) = self.post.as_mut() else {
            return Vec::new();
        };
        pa.polls += 1;
        if pa.polls < BLOCK_HOLD_POLLS {
            return Vec::new();
        }
        self.post
            .take()
            .and_then(PostAck::finish)
            .into_iter()
            .collect()
    }

    /// The entry a fingerprint line may be attached to, or `None` (and the context is dropped
    /// when the line does not directly continue it).
    fn attach_target(&mut self, key: &Key) -> Option<(&mut DhcpPartial, &mut bool)> {
        if &self.ctx.as_ref()?.key != key {
            self.ctx = None;
            return None;
        }
        let c = self.ctx.as_mut()?;
        let p = self.partial.get_mut(key)?;
        (!p.tainted && p.mac == c.mac).then_some((p, &mut c.opts_started))
    }

    /// Feeds one event of the dnsmasq process without a known pid (pid 0).
    pub fn feed(&mut self, ev: &LogEvent) -> Vec<Lease> {
        self.feed_pid(0, ev)
    }

    /// Feeds one event written by dnsmasq process `pid`; returns the leases it publishes.
    pub fn feed_pid(&mut self, pid: u64, ev: &LogEvent) -> Vec<Lease> {
        // A line of another dnsmasq process touches none of the open contexts (their keys
        // include the pid, so nothing can attach across): they are set aside and put back.
        let held = (
            self.ctx.take_if(|c| c.key.0 != pid),
            self.pre.take_if(|p| p.key.0 != pid),
            self.post.take_if(|p| p.key.0 != pid),
        );
        let out = self.feed_own(pid, ev);
        self.ctx = self.ctx.take().or(held.0);
        self.pre = self.pre.take().or(held.1);
        self.post = self.post.take().or(held.2);
        out
    }

    /// `feed_pid` for a line of the process the open contexts (if any) belong to.
    fn feed_own(&mut self, pid: u64, ev: &LogEvent) -> Vec<Lease> {
        // Preamble and post-ACK contexts survive only the lines that directly continue them.
        let pre = self
            .pre
            .take()
            .filter(|p| continues_preamble(ev, pid, &p.key));
        let (post, ended) = match self.post.take() {
            Some(p) if continues_post_ack(ev, pid, &p.key) => (Some(p), None),
            other => (None, other),
        };
        let mut out: Vec<Lease> = ended.and_then(PostAck::finish).into_iter().collect();
        let key = |id: &String| (pid, id.clone());
        match ev {
            LogEvent::DhcpPacketStart { id } => {
                self.ctx = None;
                self.pre = Some(Preamble {
                    key: key(id),
                    class: None,
                    name: None,
                });
            }
            LogEvent::DhcpRequest { id, mac, discover } => {
                self.on_request(&key(id), mac, *discover, pre.as_ref());
            }
            // dnsmasq may split a long list over several lines (assumed); accumulate.
            LogEvent::DhcpOptions { id, opt55 } => {
                if let Some(mut pa) = post {
                    pa.add_options(opt55);
                    self.post = Some(pa);
                } else if let Some((p, started)) = self.attach_target(&key(id)) {
                    if !*started {
                        p.opt55.clear();
                        *started = true;
                    }
                    p.opt55.extend(opt55.iter().copied());
                    p.opt55.truncate(MAX_OPT55);
                }
            }
            LogEvent::DhcpVendor { id, class } => match pre {
                Some(pre) => {
                    self.pre = Some(Preamble {
                        class: Some(class.clone()),
                        ..pre
                    })
                }
                None => {
                    if let Some((p, _)) = self.attach_target(&key(id)) {
                        p.class = Some(class.clone());
                    }
                }
            },
            LogEvent::DhcpName { id, name } => match pre {
                Some(pre) => {
                    self.pre = Some(Preamble {
                        name: Some(name.clone()),
                        ..pre
                    })
                }
                None => {
                    if let Some((p, _)) = self.attach_target(&key(id)) {
                        p.name = Some(name.clone());
                    }
                }
            },
            // Neutral: every context survives only if it is this key's; none is created here.
            LogEvent::DhcpTags { id } => {
                if self.ctx.as_ref().is_some_and(|c| c.key != key(id)) {
                    self.ctx = None;
                }
                self.pre = pre;
                self.post = post;
            }
            LogEvent::DhcpBoundary { id, poison } => {
                self.ctx = None;
                if *poison {
                    self.entry(&key(id)).taint();
                }
            }
            LogEvent::DhcpAck { id, mac, ip, name } => {
                self.ctx = None;
                out.extend(self.on_ack(&key(id), mac, ip, name.as_deref()));
            }
            LogEvent::Query { .. } | LogEvent::Answer { .. } => self.ctx = None,
        }
        out
    }

    fn on_request(&mut self, key: &Key, mac: &str, discover: bool, pre: Option<&Preamble>) {
        let mac = crate::mac::normalize(mac);
        let p = self.entry(key);
        // The serial is attacker-chosen: a second MAC on it poisons the entry for good.
        let foreign = matches!((&p.mac, &mac), (Some(old), new) if Some(old) != new.as_ref());
        if foreign || mac.is_none() {
            p.taint();
        } else if discover {
            p.clear_fingerprint();
        }
        if p.mac.is_none() {
            p.mac = mac.clone();
        }
        if let (Some(pre), false) = (pre, p.tainted) {
            // A marked packet states its own vendor/name: nothing is inherited from a retry.
            p.class = pre.class.clone();
            p.name = pre.name.clone();
        }
        self.ctx = Some(Context {
            key: key.clone(),
            mac,
            opts_started: false,
        });
    }

    /// Publishes the ACK's lease. Its fingerprint stays "not known" unless the options were
    /// already complete before the ACK (older order); otherwise it is published when the
    /// post-ACK block is finished.
    fn on_ack(&mut self, key: &Key, mac: &str, ip: &str, name: Option<&str>) -> Option<Lease> {
        let mut p = self.partial.remove(key).unwrap_or_default();
        self.order.retain(|o| o != key);
        if p.mac.is_none() || p.mac != crate::mac::normalize(mac) {
            p.taint();
        }
        let host = name.or(p.name.as_deref());
        let published = !p.opt55.is_empty();
        let known: (&[u8], Option<&str>) = if published {
            (&p.opt55, p.class.as_deref())
        } else {
            (&[], None)
        };
        let lease = Lease::new(mac, ip, host, known.0, known.1)?;
        if !p.tainted {
            let base = Lease::new(mac, ip, host, &[], None)?;
            self.post = Some(PostAck {
                key: key.clone(),
                base,
                opt55: p.opt55,
                class: p.class,
                started: false,
                published,
                polls: 0,
            });
        }
        Some(lease)
    }
}

fn same(pid: u64, id: &str, key: &Key) -> bool {
    key.0 == pid && key.1 == id
}

/// Lines that directly continue an open preamble: the packet's own vendor/name/tags lines and
/// the `DHCPREQUEST` that consumes it.
fn continues_preamble(ev: &LogEvent, pid: u64, key: &Key) -> bool {
    matches!(
        ev,
        LogEvent::DhcpVendor { id, .. }
            | LogEvent::DhcpName { id, .. }
            | LogEvent::DhcpTags { id }
            | LogEvent::DhcpRequest { id, .. }
        if same(pid, id, key)
    )
}

/// Lines that directly continue a verified ACK: its own options (and neutral tags) lines.
fn continues_post_ack(ev: &LogEvent, pid: u64, key: &Key) -> bool {
    matches!(
        ev,
        LogEvent::DhcpOptions { id, .. } | LogEvent::DhcpTags { id } if same(pid, id, key)
    )
}
