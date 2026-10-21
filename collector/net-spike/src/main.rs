#![forbid(unsafe_code)]
//! P1 spike: can an unprivileged process share UDP 5353 with avahi and hear mDNS/SSDP?

mod evidence;
mod filter;
mod json;
mod recv;
mod sock;
mod stats;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::IntErrorKind;
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
    --include-own  parse our own packets too (single-host testing only; never on the router)\n  \
    --secs    listen duration, default 30; larger values (even beyond u64) clamp to 3600";
const MAX_SECS: u64 = 3600;
const BURST: usize = 64;
/// Receive buffer: larger than the biggest mDNS packet we parse (9000 bytes).
const RECV_BUF: usize = 9216;

pub struct Args {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub iface: Option<String>,
    pub v6: bool,
    pub include_own: bool,
    pub secs: u64,
}

fn parse_secs(v: &str) -> Result<u64, String> {
    match v.parse::<u64>() {
        Ok(n) => Ok(n.min(MAX_SECS)),
        Err(e) if *e.kind() == IntErrorKind::PosOverflow => Ok(MAX_SECS),
        Err(e) => Err(format!("--secs: {e}")),
    }
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
            "--secs" => secs = parse_secs(&it.next().ok_or("--secs needs a value")?)?,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Mdns4,
    Mdns6,
    Ssdp,
}

/// Exit-code-carrying failure: 2 = mDNS bind/join, 3 = runtime read failure, 64 = usage.
#[derive(Debug)]
struct Fail(u8, String);

/// Per-socket receive state, separate from the socket so it can be driven by a fake reader.
struct State {
    kind: Kind,
    tracker: ErrTracker,
    packets: u64,
}

type Recv<'a> = &'a mut dyn FnMut(&mut [u8]) -> io::Result<(usize, SocketAddr)>;

impl State {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            tracker: ErrTracker::default(),
            packets: 0,
        }
    }

    /// Read up to `BURST` packets. Err only when the socket is persistently failing.
    fn drain_with(
        &mut self,
        recv: Recv<'_>,
        sleep: &mut dyn FnMut(Duration),
        buf: &mut [u8],
        st: &mut Stats,
        f: &Filter,
    ) -> Result<(), Fail> {
        for _ in 0..BURST {
            match recv(buf) {
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
                        return Err(Fail(
                            3,
                            format!(
                                "{:?} socket: {} consecutive read errors, last: {e}",
                                self.kind,
                                recv::MAX_CONSECUTIVE_ERRORS
                            ),
                        ));
                    }
                    sleep(ERROR_BACKOFF);
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

struct Src {
    sock: UdpSocket,
    state: State,
}

impl Src {
    fn new(sock: UdpSocket, kind: Kind) -> Self {
        Self {
            sock,
            state: State::new(kind),
        }
    }

    fn drain(&mut self, buf: &mut [u8], st: &mut Stats, f: &Filter) -> Result<(), Fail> {
        let sock = &self.sock;
        self.state.drain_with(
            &mut |b| sock.recv_from(b),
            &mut std::thread::sleep,
            buf,
            st,
            f,
        )
    }
}

/// What happened to each optional socket, reported in the JSON.
#[derive(Default)]
pub struct Notes {
    pub mdns6: String,
    pub ssdp: String,
    pub own_v6_unknown: bool,
}

enum V6Open {
    NotRequested,
    Skipped(String),
    Opened(io::Result<UdpSocket>),
}

fn note_of(r: io::Result<UdpSocket>, kind: Kind, srcs: &mut Vec<Src>) -> String {
    match r {
        Ok(s) => {
            srcs.push(Src::new(s, kind));
            "joined".to_string()
        }
        Err(e) => format!("failed: {e}"),
    }
}

/// Only the IPv4 mDNS socket is mandatory (exit 2); SSDP and IPv6 failures are recorded.
fn open_with(
    m4: io::Result<UdpSocket>,
    ss: io::Result<UdpSocket>,
    m6: V6Open,
) -> Result<(Vec<Src>, Notes), Fail> {
    let m4 = m4.map_err(|e| Fail(2, format!("mDNS 224.0.0.251:5353 bind/join failed: {e}")))?;
    let mut srcs = vec![Src::new(m4, Kind::Mdns4)];
    let ssdp = note_of(ss, Kind::Ssdp, &mut srcs);
    let mdns6 = match m6 {
        V6Open::NotRequested => "not requested".to_string(),
        V6Open::Skipped(why) => format!("skipped: {why}"),
        V6Open::Opened(r) => note_of(r, Kind::Mdns6, &mut srcs),
    };
    Ok((
        srcs,
        Notes {
            mdns6,
            ssdp,
            own_v6_unknown: false,
        },
    ))
}

/// Our own link-local v6 addresses, or None when they cannot be determined. Without them we
/// cannot tell our own packets from a neighbour's, so IPv6 must not be used.
fn own_v6_from(read: io::Result<String>, iface: &str) -> Option<Vec<Ipv6Addr>> {
    let found = filter::parse_if_inet6(&read.ok()?, iface);
    (!found.is_empty()).then_some(found)
}

fn finalize(st: &mut Stats, srcs: &[&State]) {
    for s in srcs {
        st.read_errors += s.tracker.total;
        match s.kind {
            Kind::Mdns4 => st.mdns4_packets = s.packets,
            Kind::Mdns6 => st.mdns6_packets = s.packets,
            Kind::Ssdp => st.ssdp_packets = s.packets,
        }
    }
}

fn run(args: &Args) -> Result<String, Fail> {
    let iface = args.iface.as_deref().unwrap_or("");
    let own = args
        .v6
        .then(|| own_v6_from(std::fs::read_to_string("/proc/net/if_inet6"), iface));
    let unknown = matches!(own, Some(None));
    let v6 = match (&own, args.v6) {
        (_, false) => V6Open::NotRequested,
        (Some(None), true) => V6Open::Skipped("cannot determine own IPv6 addresses".into()),
        _ => V6Open::Opened(sock::mdns_v6(iface)),
    };
    let (mut srcs, mut notes) = open_with(sock::mdns_v4(args.addr), sock::ssdp_v4(args.addr), v6)?;
    notes.own_v6_unknown = unknown;
    let f = Filter {
        lan: args.addr,
        prefix: args.prefix,
        own_v6: own.flatten().unwrap_or_default(),
        include_own: args.include_own,
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.secs))
        .ok_or_else(|| Fail(64, "--secs overflows the clock".into()))?;
    let mut st = Stats::default();
    let mut buf = [0u8; RECV_BUF];
    while Instant::now() < deadline {
        for s in srcs.iter_mut() {
            s.drain(&mut buf, &mut st, &f)?;
        }
    }
    let states: Vec<&State> = srcs.iter().map(|s| &s.state).collect();
    finalize(&mut st, &states);
    Ok(json::summary(args, &f, &st, &notes))
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
    use std::io::ErrorKind;

    fn args(s: &str) -> Result<Args, String> {
        parse_from(s.split_whitespace().map(String::from))
    }

    fn secs(s: &str) -> Result<u64, String> {
        args(&format!("--addr 1.2.3.4 --secs {s}")).map(|a| a.secs)
    }

    #[test]
    fn secs_is_clamped_not_overflowed() {
        assert_eq!(secs("18446744073709551615"), Ok(3600));
        assert_eq!(secs("18446744073709551616"), Ok(3600)); // u64::MAX + 1
        assert_eq!(secs("99999999999999999999999999"), Ok(3600));
        assert_eq!(secs("3601"), Ok(3600));
        assert_eq!(secs("3600"), Ok(3600));
        assert_eq!(secs("3599"), Ok(3599));
        assert_eq!(secs("0"), Ok(0));
        assert_eq!(args("--addr 1.2.3.4").unwrap().secs, 30);
    }

    #[test]
    fn secs_rejects_non_numbers() {
        for bad in ["-1", "abc", "1.5", "1e3"] {
            assert!(secs(bad).is_err(), "{bad}");
        }
        assert!(args("--addr 1.2.3.4 --secs").is_err());
    }

    #[test]
    fn clamped_secs_never_panics_the_deadline_math() {
        let a = args("--addr 1.2.3.4 --secs 99999999999999999999999999").unwrap();
        assert!(Instant::now()
            .checked_add(Duration::from_secs(a.secs))
            .is_some());
    }

    #[test]
    fn prefix_validation() {
        assert_eq!(args("--addr 1.2.3.4").unwrap().prefix, 24);
        assert_eq!(args("--addr 1.2.3.4 --prefix 16").unwrap().prefix, 16);
        assert_eq!(args("--addr 1.2.3.4 --prefix 1").unwrap().prefix, 1);
        assert_eq!(args("--addr 1.2.3.4 --prefix 32").unwrap().prefix, 32);
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
        assert!(args("--addr 1.2.3.4 --include-own").unwrap().include_own);
    }

    // --- receive loop -------------------------------------------------------------------

    fn filter() -> Filter {
        Filter {
            lan: "192.168.1.1".parse().unwrap(),
            prefix: 24,
            own_v6: vec![],
            include_own: false,
        }
    }

    fn peer() -> SocketAddr {
        "192.168.1.50:5353".parse().unwrap()
    }

    #[test]
    fn persistent_errors_back_off_then_fail_with_exit_3_after_exactly_100() {
        let mut state = State::new(Kind::Mdns4);
        let mut st = Stats::default();
        let mut buf = [0u8; 16];
        let mut sleeps: Vec<Duration> = Vec::new();
        let mut recv = |_: &mut [u8]| Err(io::Error::from(ErrorKind::PermissionDenied));
        for i in 1..100 {
            let r = state.drain_with(
                &mut recv,
                &mut |d| sleeps.push(d),
                &mut buf,
                &mut st,
                &filter(),
            );
            assert!(r.is_ok(), "call {i}");
        }
        let r = state.drain_with(
            &mut recv,
            &mut |d| sleeps.push(d),
            &mut buf,
            &mut st,
            &filter(),
        );
        let Err(Fail(code, msg)) = r else {
            panic!("expected failure on the 100th error")
        };
        assert_eq!(code, 3);
        assert!(msg.contains("100 consecutive"), "{msg}");
        assert_eq!(sleeps, vec![Duration::from_millis(50); 99]);
        assert_eq!(state.tracker.total, 100);
    }

    #[test]
    fn a_received_packet_resets_the_error_run() {
        let mut state = State::new(Kind::Ssdp);
        let mut st = Stats::default();
        let mut buf = [0u8; 64];
        let mut err = |_: &mut [u8]| Err(io::Error::from(ErrorKind::PermissionDenied));
        for _ in 0..99 {
            state
                .drain_with(&mut err, &mut |_| {}, &mut buf, &mut st, &filter())
                .unwrap();
        }
        // one packet followed by an error: only the packet can have reset the run
        let mut k = 0;
        let mut ok_then_err = |b: &mut [u8]| {
            k += 1;
            if k == 1 {
                b[0] = b'x';
                return Ok((1, peer()));
            }
            Err(io::Error::from(ErrorKind::PermissionDenied))
        };
        state
            .drain_with(&mut ok_then_err, &mut |_| {}, &mut buf, &mut st, &filter())
            .unwrap();
        for i in 0..98 {
            let r = state.drain_with(&mut err, &mut |_| {}, &mut buf, &mut st, &filter());
            assert!(r.is_ok(), "error {i} after reset");
        }
    }

    #[test]
    fn a_timeout_resets_the_error_run() {
        let mut state = State::new(Kind::Ssdp);
        let mut st = Stats::default();
        let mut buf = [0u8; 64];
        let mut err = |_: &mut [u8]| Err(io::Error::from(ErrorKind::PermissionDenied));
        let mut timeout = |_: &mut [u8]| Err(io::Error::from(ErrorKind::TimedOut));
        for _ in 0..99 {
            state
                .drain_with(&mut err, &mut |_| {}, &mut buf, &mut st, &filter())
                .unwrap();
        }
        state
            .drain_with(&mut timeout, &mut |_| {}, &mut buf, &mut st, &filter())
            .unwrap();
        for i in 0..99 {
            let r = state.drain_with(&mut err, &mut |_| {}, &mut buf, &mut st, &filter());
            assert!(r.is_ok(), "error {i} after timeout");
        }
    }

    #[test]
    fn ssdp_kind_uses_the_ssdp_parser() {
        let mut state = State::new(Kind::Ssdp);
        let mut st = Stats::default();
        let mut buf = [0u8; 128];
        let m = b"NOTIFY * HTTP/1.1\r\nSERVER: S/1\r\n\r\n";
        let mut n = 0;
        let mut recv = |b: &mut [u8]| {
            n += 1;
            if n > 1 {
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            b[..m.len()].copy_from_slice(m);
            Ok((m.len(), peer()))
        };
        state
            .drain_with(&mut recv, &mut |_| {}, &mut buf, &mut st, &filter())
            .unwrap();
        assert_eq!(st.ssdp_methods.get("NOTIFY"), Some(&1));
        assert_eq!(st.parse_errors, 0);
    }

    #[test]
    fn timeouts_neither_sleep_nor_count() {
        let mut state = State::new(Kind::Ssdp);
        let mut st = Stats::default();
        let mut buf = [0u8; 16];
        let mut slept = 0;
        let mut recv = |_: &mut [u8]| Err(io::Error::from(ErrorKind::WouldBlock));
        assert!(state
            .drain_with(&mut recv, &mut |_| slept += 1, &mut buf, &mut st, &filter())
            .is_ok());
        assert_eq!((slept, state.tracker.total, state.packets), (0, 0, 0));
    }

    #[test]
    fn a_burst_is_exactly_64_packets_and_each_is_counted_and_parsed() {
        let mut state = State::new(Kind::Ssdp);
        let mut st = Stats::default();
        let mut buf = [0u8; 64];
        let mut calls = 0u32;
        let mut recv = |b: &mut [u8]| {
            calls += 1;
            let m = b"GET / HTTP/1.1\r\n\r\n"; // not SSDP: counts as a parse error
            b[..m.len()].copy_from_slice(m);
            Ok((m.len(), peer()))
        };
        assert!(state
            .drain_with(&mut recv, &mut |_| {}, &mut buf, &mut st, &filter())
            .is_ok());
        assert_eq!(calls, 64);
        assert_eq!((state.packets, st.parse_errors), (64, 64));
    }

    #[test]
    fn mdns_kinds_use_the_mdns_parser() {
        for kind in [Kind::Mdns4, Kind::Mdns6] {
            let mut state = State::new(kind);
            let mut st = Stats::default();
            let mut buf = [0u8; 64];
            let q = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 12, 0, 1];
            let mut n = 0;
            let mut recv = |b: &mut [u8]| {
                n += 1;
                if n > 1 {
                    return Err(io::Error::from(ErrorKind::WouldBlock));
                }
                b[..q.len()].copy_from_slice(&q);
                Ok((q.len(), peer()))
            };
            state
                .drain_with(&mut recv, &mut |_| {}, &mut buf, &mut st, &filter())
                .unwrap();
            assert!(st.mdns_names.contains("a"), "{kind:?}");
        }
    }

    #[test]
    fn finalize_accumulates_errors_and_assigns_packets_per_kind() {
        let mut a = State::new(Kind::Mdns4);
        a.packets = 7;
        a.tracker.total = 5;
        let mut b = State::new(Kind::Ssdp);
        b.packets = 11;
        b.tracker.total = 3;
        let mut c = State::new(Kind::Mdns6);
        c.packets = 13;
        let mut st = Stats::default();
        finalize(&mut st, &[&a, &b, &c]);
        assert_eq!(
            (
                st.read_errors,
                st.mdns4_packets,
                st.ssdp_packets,
                st.mdns6_packets
            ),
            (8, 7, 11, 13)
        );
    }

    #[test]
    fn receive_buffer_holds_a_maximum_size_mdns_packet() {
        assert!(std::hint::black_box(RECV_BUF) > 9000);
        assert_eq!(std::hint::black_box(BURST), 64);
    }

    // --- socket opening -----------------------------------------------------------------

    fn local() -> io::Result<UdpSocket> {
        UdpSocket::bind("127.0.0.1:0")
    }

    fn broken() -> io::Result<UdpSocket> {
        Err(io::Error::from(ErrorKind::AddrInUse))
    }

    #[test]
    fn mdns_v4_failure_is_exit_2() {
        let Err(Fail(code, msg)) = open_with(broken(), local(), V6Open::NotRequested) else {
            panic!("must fail")
        };
        assert_eq!(code, 2);
        assert!(msg.contains("224.0.0.251:5353"), "{msg}");
    }

    #[test]
    fn ssdp_failure_does_not_abort_the_run() {
        let (srcs, notes) = open_with(local(), broken(), V6Open::NotRequested).unwrap();
        assert_eq!(srcs.len(), 1);
        assert_eq!(srcs[0].state.kind, Kind::Mdns4);
        assert!(notes.ssdp.starts_with("failed: "), "{}", notes.ssdp);
        assert_eq!(notes.mdns6, "not requested");
    }

    #[test]
    fn all_sockets_open_and_are_noted() {
        let (srcs, notes) = open_with(local(), local(), V6Open::Opened(local())).unwrap();
        let kinds: Vec<Kind> = srcs.iter().map(|s| s.state.kind).collect();
        assert_eq!(kinds, vec![Kind::Mdns4, Kind::Ssdp, Kind::Mdns6]);
        assert_eq!(
            (notes.ssdp.as_str(), notes.mdns6.as_str()),
            ("joined", "joined")
        );
    }

    #[test]
    fn v6_failure_and_skip_are_recorded_not_fatal() {
        let (srcs, n) = open_with(local(), local(), V6Open::Opened(broken())).unwrap();
        assert_eq!(srcs.len(), 2);
        assert!(n.mdns6.starts_with("failed: "));
        let (srcs, n) = open_with(local(), local(), V6Open::Skipped("why".into())).unwrap();
        assert_eq!(srcs.len(), 2);
        assert_eq!(n.mdns6, "skipped: why");
    }

    // --- own IPv6 addresses ----------------------------------------------------------------

    const IF_INET6: &str = "fe800000000000000000000000000001 04 40 20 80 br-lan\n";

    #[test]
    fn own_v6_unknown_when_unreadable_or_absent() {
        assert_eq!(
            own_v6_from(Err(io::Error::from(ErrorKind::NotFound)), "br-lan"),
            None
        );
        assert_eq!(own_v6_from(Ok(IF_INET6.into()), "eth9"), None);
        assert_eq!(own_v6_from(Ok(String::new()), "br-lan"), None);
        assert_eq!(
            own_v6_from(Ok(IF_INET6.into()), "br-lan"),
            Some(vec!["fe80::1".parse().unwrap()])
        );
    }
}
