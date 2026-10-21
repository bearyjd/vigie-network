//! mDNS and SSDP listener: one reader thread over the P1 spike's socket setup (`net_spike::sock`:
//! bound to the group address, `IP_MULTICAST_ALL` off, so it shares UDP 5353 with avahi and never
//! sees unicast meant for it), its source filter (own and off-link packets are dropped) and its
//! receive-error policy. Parsed packets go to the main loop over a bounded channel; a full
//! channel drops the newest and counts it, so a multicast flood costs the main loop nothing.
//!
//! Mapping to MACs and the per-device quotas happen in the main loop (`wiring::Sources`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use net_spike::filter::{parse_if_inet6, Filter, Verdict};
use net_spike::recv::{is_timeout, ErrTracker, ERROR_BACKOFF};
use net_spike::sock;
use vigie_parse::{mdns, ssdp};

use crate::ctsock::backoff_ms;

pub const QUEUE: usize = 256;
const RECV_BUF: usize = 9216;
const BURST: usize = 64;
const REBIND_BASE_MS: u64 = 1_000;
const REBIND_CAP_MS: u64 = 60_000;

#[derive(Debug)]
pub enum Pkt {
    Mdns(mdns::Parsed),
    Ssdp(ssdp::Parsed),
}

#[derive(Debug)]
pub struct McMsg {
    pub src: IpAddr,
    pub pkt: Pkt,
}

#[derive(Debug, Clone)]
pub struct McConfig {
    pub lan: Ipv4Addr,
    pub prefix: u8,
    pub iface: String,
    /// Test hook: treat the host's own packets as a neighbor's (one machine cannot be two).
    pub include_own: bool,
}

#[derive(Debug, Default)]
pub struct McShared {
    /// Some socket could not be bound or joined (or the mandatory one failed and is being retried).
    pub bind_failed: AtomicBool,
    /// Parsed packets handed to the queue.
    pub accepted: AtomicU64,
    /// Packets lost before the main loop: parse errors, queue full.
    pub dropped: AtomicU64,
    /// Own and off-link packets ignored (expected noise, not an error).
    pub ignored: AtomicU64,
    /// Sockets that opened, for tests.
    pub sockets: AtomicU64,
}

pub struct McReader {
    pub rx: Receiver<McMsg>,
    pub shared: Arc<McShared>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Mdns,
    Ssdp,
}

struct Src {
    sock: UdpSocket,
    kind: Kind,
    errs: ErrTracker,
}

impl McReader {
    pub fn spawn(cfg: McConfig) -> io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE);
        let shared = Arc::new(McShared::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (shared.clone(), stop.clone());
        let handle = thread::Builder::new()
            .name("vigie-mc".into())
            .spawn(move || run(&cfg, &tx, &s2, &st2))?;
        Ok(Self {
            rx,
            shared,
            stop,
            handle: Some(handle),
        })
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for McReader {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Opened {
    srcs: Vec<Src>,
    filter: Filter,
    /// The IPv4 mDNS socket is up (serving is pointless without it).
    mandatory_ok: bool,
    /// Any socket failed.
    failed: bool,
}

/// Mandatory: IPv4 mDNS. SSDP and IPv6 mDNS are best effort; any failure sets `bind_failed`.
fn open(cfg: &McConfig, sh: &McShared) -> Opened {
    let own_v6 = std::fs::read_to_string("/proc/net/if_inet6")
        .map(|t| parse_if_inet6(&t, &cfg.iface))
        .unwrap_or_default();
    let filter = Filter {
        lan: cfg.lan,
        prefix: cfg.prefix,
        own_v6: own_v6.clone(),
        include_own: cfg.include_own,
    };
    let mut srcs = Vec::new();
    let mut failed = false;
    let mut mandatory_ok = false;
    let mut add = |r: io::Result<UdpSocket>, kind: Kind, what: &str, mandatory: bool| match r {
        Ok(sock) => {
            srcs.push(Src {
                sock,
                kind,
                errs: ErrTracker::default(),
            });
            mandatory_ok |= mandatory;
        }
        Err(e) => {
            eprintln!("multicast {what}: {e}");
            failed = true;
        }
    };
    add(sock::mdns_v4(cfg.lan), Kind::Mdns, "mDNS IPv4", true);
    add(sock::ssdp_v4(cfg.lan), Kind::Ssdp, "SSDP IPv4", false);
    // Without our own link-local addresses we cannot tell our packets from a neighbor's.
    if !own_v6.is_empty() {
        add(sock::mdns_v6(&cfg.iface), Kind::Mdns, "mDNS IPv6", false);
    }
    sh.sockets.store(srcs.len() as u64, Ordering::Relaxed);
    Opened {
        srcs,
        filter,
        mandatory_ok,
        failed,
    }
}

fn run(cfg: &McConfig, tx: &SyncSender<McMsg>, sh: &McShared, stop: &AtomicBool) {
    let mut attempt = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let mut o = open(cfg, sh);
        sh.bind_failed.store(o.failed, Ordering::Relaxed);
        if o.mandatory_ok {
            attempt = 0;
            serve(&mut o.srcs, &o.filter, tx, sh, stop);
        }
        drop(o);
        let wait = backoff_ms(attempt, REBIND_BASE_MS, REBIND_CAP_MS);
        attempt = attempt.saturating_add(1);
        sh.bind_failed.store(true, Ordering::Relaxed);
        let end = std::time::Instant::now() + Duration::from_millis(wait);
        while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < end {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Returns when a socket fails persistently (the caller re-opens everything) or on stop.
fn serve(srcs: &mut [Src], f: &Filter, tx: &SyncSender<McMsg>, sh: &McShared, stop: &AtomicBool) {
    let mut buf = [0u8; RECV_BUF];
    while !stop.load(Ordering::Relaxed) {
        for s in srcs.iter_mut() {
            for _ in 0..BURST {
                match s.sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        s.errs.on_ok();
                        handle(s.kind, f, from.ip(), &from, &buf[..n], tx, sh);
                    }
                    Err(e) if is_timeout(e.kind()) => {
                        s.errs.on_ok();
                        break;
                    }
                    Err(e) => {
                        eprintln!("multicast read: {e}");
                        if s.errs.on_error() {
                            return;
                        }
                        thread::sleep(ERROR_BACKOFF);
                        break;
                    }
                }
            }
        }
    }
}

fn handle(
    kind: Kind,
    f: &Filter,
    ip: IpAddr,
    from: &std::net::SocketAddr,
    pkt: &[u8],
    tx: &SyncSender<McMsg>,
    sh: &McShared,
) {
    if f.verdict(from) != Verdict::Accept {
        sh.ignored.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let parsed = match kind {
        Kind::Mdns => mdns::parse(pkt).map(Pkt::Mdns).ok(),
        Kind::Ssdp => ssdp::parse(pkt).map(Pkt::Ssdp).ok(),
    };
    let Some(pkt) = parsed else {
        sh.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    match tx.try_send(McMsg { src: ip, pkt }) {
        Ok(()) => {
            sh.accepted.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}
