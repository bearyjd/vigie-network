#![forbid(unsafe_code)]
//! P1 spike: can an unprivileged process share UDP 5353 with avahi and hear mDNS/SSDP?

mod evidence;
mod filter;
mod json;
mod recv;
mod sock;
mod stats;

use std::net::{Ipv4Addr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use filter::Filter;
use recv::{is_timeout, ErrTracker, ERROR_BACKOFF};
use stats::Stats;

const USAGE: &str =
    "usage: net-spike --addr <lan-ipv4> [--prefix N] [--iface <name>] [--v6] [--secs N]\n  \
    --addr    router LAN IPv4 (e.g. 192.168.1.1), used for the IGMP join and source filter\n  \
    --prefix  LAN prefix length for the on-link source filter, 1-32, default 24\n  \
    --iface   LAN interface name (e.g. br-lan); required with --v6\n  \
    --v6      also join [ff02::fb]:5353\n  \
    --include-own  parse our own packets too (single-host testing only)\n  \
    --secs    listen duration, default 30, clamped to 3600";
const MAX_SECS: u64 = 3600;
const BURST: usize = 64;

pub struct Args {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub iface: Option<String>,
    pub v6: bool,
    pub include_own: bool,
    pub secs: u64,
}

fn parse_from(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut addr = None;
    let mut prefix = 24u8;
    let mut iface = None;
    let mut v6 = false;
    let mut include_own = false;
    let mut secs = 30u64;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => {
                let v = it.next().ok_or("--addr needs a value")?;
                addr = Some(v.parse::<Ipv4Addr>().map_err(|e| format!("--addr: {e}"))?);
            }
            "--prefix" => {
                let v = it.next().ok_or("--prefix needs a value")?;
                prefix = v.parse().map_err(|e| format!("--prefix: {e}"))?;
                if !(1..=32).contains(&prefix) {
                    return Err("--prefix must be 1-32".into());
                }
            }
            "--iface" => iface = Some(it.next().ok_or("--iface needs a value")?),
            "--secs" => {
                let v = it.next().ok_or("--secs needs a value")?;
                secs = v
                    .parse::<u64>()
                    .map_err(|e| format!("--secs: {e}"))?
                    .min(MAX_SECS);
            }
            "--v6" => v6 = true,
            "--include-own" => include_own = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if v6 && iface.is_none() {
        return Err("--v6 requires --iface".into());
    }
    Ok(Args {
        addr: addr.ok_or("--addr is required")?,
        prefix,
        iface,
        v6,
        include_own,
        secs,
    })
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Mdns4,
    Mdns6,
    Ssdp,
}

struct Src {
    sock: UdpSocket,
    kind: Kind,
    tracker: ErrTracker,
    packets: u64,
}

impl Src {
    fn new(sock: UdpSocket, kind: Kind) -> Self {
        Self {
            sock,
            kind,
            tracker: ErrTracker::default(),
            packets: 0,
        }
    }

    /// Read up to `BURST` packets. Err only when the socket is persistently failing.
    fn drain(&mut self, buf: &mut [u8], st: &mut Stats, f: &Filter) -> Result<(), String> {
        for _ in 0..BURST {
            match self.sock.recv_from(buf) {
                Ok((n, from)) => {
                    self.tracker.on_ok();
                    self.packets += 1;
                    match self.kind {
                        Kind::Mdns4 | Kind::Mdns6 => st.on_mdns(f, from, &buf[..n]),
                        Kind::Ssdp => st.on_ssdp(f, from, &buf[..n]),
                    }
                }
                Err(e) if is_timeout(e.kind()) => {
                    self.tracker.on_ok();
                    return Ok(());
                }
                Err(e) => {
                    if self.tracker.on_error() {
                        return Err(format!(
                            "{:?} socket: {} consecutive read errors, last: {e}",
                            self.kind,
                            recv::MAX_CONSECUTIVE_ERRORS
                        ));
                    }
                    std::thread::sleep(ERROR_BACKOFF);
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Exit-code-carrying failure: 2 = setup (bind/join), 3 = runtime read failure.
struct Fail(u8, String);

fn open_sources(args: &Args) -> Result<(Vec<Src>, String), Fail> {
    let setup = |what: &str, e: std::io::Error| Fail(2, format!("{what} bind/join failed: {e}"));
    let m4 = sock::mdns_v4(args.addr).map_err(|e| setup("mDNS 224.0.0.251:5353", e))?;
    let ss = sock::ssdp_v4(args.addr).map_err(|e| setup("SSDP 239.255.255.250:1900", e))?;
    let mut srcs = vec![Src::new(m4, Kind::Mdns4), Src::new(ss, Kind::Ssdp)];
    let note = match args.iface.as_deref().filter(|_| args.v6) {
        None => "not requested".to_string(),
        Some(i) => match sock::mdns_v6(i) {
            Ok(s) => {
                srcs.push(Src::new(s, Kind::Mdns6));
                "joined".to_string()
            }
            Err(e) => format!("failed: {e}"),
        },
    };
    Ok((srcs, note))
}

fn own_v6(args: &Args) -> Vec<std::net::Ipv6Addr> {
    match (args.v6, args.iface.as_deref()) {
        (true, Some(i)) => std::fs::read_to_string("/proc/net/if_inet6")
            .map(|t| filter::parse_if_inet6(&t, i))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn run(args: &Args) -> Result<String, Fail> {
    let (mut srcs, v6_note) = open_sources(args)?;
    let f = Filter {
        lan: args.addr,
        prefix: args.prefix,
        own_v6: own_v6(args),
        include_own: args.include_own,
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.secs))
        .ok_or_else(|| Fail(64, "--secs overflows the clock".into()))?;
    let mut st = Stats::default();
    let mut buf = [0u8; 9216];
    while Instant::now() < deadline {
        for s in srcs.iter_mut() {
            s.drain(&mut buf, &mut st, &f).map_err(|e| Fail(3, e))?;
        }
    }
    for s in &srcs {
        st.read_errors += s.tracker.total;
        match s.kind {
            Kind::Mdns4 => st.mdns4_packets = s.packets,
            Kind::Mdns6 => st.mdns6_packets = s.packets,
            Kind::Ssdp => st.ssdp_packets = s.packets,
        }
    }
    Ok(json::summary(args, &f, &st, &v6_note))
}

fn main() -> ExitCode {
    let args = match parse_from(std::env::args().skip(1)) {
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
        Err(Fail(code, e)) => {
            eprintln!("net-spike: {e}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Args, String> {
        parse_from(s.split_whitespace().map(String::from))
    }

    #[test]
    fn secs_is_clamped_not_overflowed() {
        assert_eq!(
            args("--addr 1.2.3.4 --secs 18446744073709551615")
                .unwrap()
                .secs,
            3600
        );
        assert_eq!(args("--addr 1.2.3.4 --secs 3601").unwrap().secs, 3600);
        assert_eq!(args("--addr 1.2.3.4 --secs 3600").unwrap().secs, 3600);
        assert_eq!(args("--addr 1.2.3.4 --secs 3599").unwrap().secs, 3599);
        assert_eq!(args("--addr 1.2.3.4").unwrap().secs, 30);
    }

    #[test]
    fn huge_secs_does_not_panic_in_deadline_math() {
        let a = args("--addr 1.2.3.4 --secs 18446744073709551615").unwrap();
        assert!(Instant::now()
            .checked_add(Duration::from_secs(a.secs))
            .is_some());
    }

    #[test]
    fn prefix_validation() {
        assert_eq!(args("--addr 1.2.3.4").unwrap().prefix, 24);
        assert_eq!(args("--addr 1.2.3.4 --prefix 16").unwrap().prefix, 16);
        assert!(args("--addr 1.2.3.4 --prefix 0").is_err());
        assert!(args("--addr 1.2.3.4 --prefix 33").is_err());
        assert!(args("--addr 1.2.3.4 --prefix x").is_err());
    }

    #[test]
    fn required_and_dependent_flags() {
        assert!(args("--secs 5").is_err());
        assert!(args("--addr 1.2.3.4 --v6").is_err());
        assert!(args("--addr 1.2.3.4 --v6 --iface br-lan").is_ok());
        assert!(args("--addr 1.2.3.4 --bogus").is_err());
    }
}
