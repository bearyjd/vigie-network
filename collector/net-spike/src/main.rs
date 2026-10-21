#![forbid(unsafe_code)]
//! P1 spike: can an unprivileged process share UDP 5353 with avahi and hear mDNS/SSDP?

mod json;
mod sock;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vigie_parse::{mdns, ssdp};

const USAGE: &str = "usage: net-spike --addr <lan-ipv4> [--iface <name>] [--v6] [--secs N]\n  \
    --addr   router LAN IPv4 (e.g. 192.168.1.1), used for the IGMP join\n  \
    --iface  LAN interface name (e.g. br-lan); required with --v6 for the interface index\n  \
    --v6     also join [ff02::fb]:5353\n  \
    --secs   listen duration, default 30";
/// Cap on distinct strings retained per set (memory is bounded regardless of LAN behavior).
const MAX_ITEMS: usize = 256;

struct Args {
    addr: Ipv4Addr,
    iface: Option<String>,
    v6: bool,
    secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut addr = None;
    let mut iface = None;
    let mut v6 = false;
    let mut secs = 30u64;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => {
                let v = it.next().ok_or("--addr needs a value")?;
                addr = Some(v.parse::<Ipv4Addr>().map_err(|e| format!("--addr: {e}"))?);
            }
            "--iface" => iface = Some(it.next().ok_or("--iface needs a value")?),
            "--secs" => {
                let v = it.next().ok_or("--secs needs a value")?;
                secs = v.parse().map_err(|e| format!("--secs: {e}"))?;
            }
            "--v6" => v6 = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if v6 && iface.is_none() {
        return Err("--v6 requires --iface".into());
    }
    Ok(Args {
        addr: addr.ok_or("--addr is required")?,
        iface,
        v6,
        secs,
    })
}

#[derive(Default)]
struct Stats {
    mdns4_packets: u64,
    mdns6_packets: u64,
    ssdp_packets: u64,
    parse_errors: u64,
    mdns_names: BTreeSet<String>,
    mdns_services: BTreeSet<String>,
    ssdp_servers: BTreeSet<String>,
    ssdp_nt: BTreeSet<String>,
    ssdp_usn: BTreeSet<String>,
    ssdp_methods: BTreeMap<&'static str, u64>,
}

fn add_capped(set: &mut BTreeSet<String>, v: String) {
    if set.len() < MAX_ITEMS {
        set.insert(v);
    }
}

impl Stats {
    fn on_mdns(&mut self, pkt: &[u8]) {
        match mdns::parse(pkt) {
            Ok(p) => {
                p.names
                    .into_iter()
                    .for_each(|n| add_capped(&mut self.mdns_names, n));
                p.services
                    .into_iter()
                    .for_each(|n| add_capped(&mut self.mdns_services, n));
            }
            Err(_) => self.parse_errors += 1,
        }
    }

    fn on_ssdp(&mut self, pkt: &[u8]) {
        match ssdp::parse(pkt) {
            Ok(p) => {
                let m = match p.method {
                    ssdp::Method::Notify => "NOTIFY",
                    ssdp::Method::MSearch => "M-SEARCH",
                };
                *self.ssdp_methods.entry(m).or_insert(0) += 1;
                for (set, v) in [
                    (&mut self.ssdp_servers, p.server.or(p.user_agent)),
                    (&mut self.ssdp_nt, p.nt.or(p.st)),
                    (&mut self.ssdp_usn, p.usn),
                ] {
                    if let Some(v) = v {
                        add_capped(set, v);
                    }
                }
            }
            Err(_) => self.parse_errors += 1,
        }
    }
}

/// Drain one socket for up to its read timeout; returns on timeout/error.
fn drain(sock: &UdpSocket, buf: &mut [u8], mut handle: impl FnMut(&[u8])) {
    // Bounded burst so one chatty socket cannot starve the others.
    for _ in 0..64 {
        match sock.recv_from(buf) {
            Ok((n, _)) => handle(&buf[..n]),
            Err(_) => return,
        }
    }
}

fn run(args: &Args) -> Result<String, String> {
    let m4 = sock::mdns_v4(args.addr)
        .map_err(|e| format!("mDNS 224.0.0.251:5353 bind/join failed: {e}"))?;
    let ss = sock::ssdp_v4(args.addr)
        .map_err(|e| format!("SSDP 239.255.255.250:1900 bind/join failed: {e}"))?;
    let (m6, m6_note) = match (args.v6, args.iface.as_deref()) {
        (true, Some(i)) => match sock::mdns_v6(i) {
            Ok(s) => (Some(s), "joined".to_string()),
            Err(e) => (None, format!("failed: {e}")),
        },
        _ => (None, "not requested".to_string()),
    };
    let mut stats = Stats::default();
    let mut buf = [0u8; 9216];
    let deadline = Instant::now() + Duration::from_secs(args.secs);
    while Instant::now() < deadline {
        let mut n4 = 0u64;
        drain(&m4, &mut buf, |p| {
            n4 += 1;
            stats.on_mdns(p);
        });
        stats.mdns4_packets += n4;
        let mut ns = 0u64;
        drain(&ss, &mut buf, |p| {
            ns += 1;
            stats.on_ssdp(p);
        });
        stats.ssdp_packets += ns;
        if let Some(s) = &m6 {
            let mut n6 = 0u64;
            drain(s, &mut buf, |p| {
                n6 += 1;
                stats.on_mdns(p);
            });
            stats.mdns6_packets += n6;
        }
    }
    Ok(json::summary(args, &stats, &m6_note))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("net-spike: {e}\n{USAGE}");
            return ExitCode::from(64);
        }
    };
    match run(&args) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("net-spike: {e}");
            ExitCode::from(2)
        }
    }
}
