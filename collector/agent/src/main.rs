#![forbid(unsafe_code)]
//! vigie-collector: unprivileged agent. Tails the dnsmasq log, reads neighbors and leases,
//! builds a signed batch every window and pushes it through a `Transport`.
//!
//! NOT DONE in this build: the HTTPS transport with SPKI pinning (the `NoTransport` below
//! refuses to send, so nothing ever leaves the router in clear text), the root conntrack helper
//! socket, and the multicast (mDNS/SSDP) listener wiring. Never run on the router yet.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vigie_agent::builder::{build, build_with_drops, BATCH_CAP};
use vigie_agent::config::{load_key, parse_config, wipe, Config};
use vigie_agent::dnsmasq::{parse_line, DhcpAssembler, DnsCorrelator, LogEvent};
use vigie_agent::dropin::{check_dropin, QuietDetector, DROPIN_PATH, LOG_DIR};
use vigie_agent::ids;
use vigie_agent::leases::parse_leases;
use vigie_agent::model::{Health, Meta, Sections};
use vigie_agent::neigh::ip_to_mac;
use vigie_agent::procstat::read_rss_kb;
use vigie_agent::runtime::{random, random_u64, read_neighbors, wall_ms, wall_secs};
use vigie_agent::sender::{Engine, Headers, HttpReply, Identity, Tick, Transport, TransportError};
use vigie_agent::spool::SPOOL_CAP;
use vigie_agent::syncstate::{FlushPlan, SyncState};
use vigie_agent::tail::Tail;
use vigie_agent::transport::PinnedTransport;
use vigie_agent::urgent::Urgent;
use vigie_agent::window::{SnapshotDelta, Window, WindowClock};

const BUILD_TS: u64 = parse_build_ts(env!("VIGIE_BUILD_TS"));
const DEFAULT_CONFIG: &str = "/etc/vigie/collector.conf";
const POLL: Duration = Duration::from_secs(2);
const NEIGH_REFRESH_S: u64 = 10;
const EXIT_CONFIG: u8 = 78;
const EXIT_NO_RANDOM: u8 = 71;

const fn parse_build_ts(s: &str) -> u64 {
    let b = s.as_bytes();
    let (mut i, mut n) = (0, 0u64);
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    n
}

/// Placeholder transport. TODO: HTTPS client with two SPKI pins (see docs/spikes/p2-collector-agent.md).
struct NoTransport;

impl Transport for NoTransport {
    fn post(&mut self, _h: &Headers, _b: &[u8]) -> Result<HttpReply, TransportError> {
        Err(TransportError(
            "HTTPS/SPKI-pinned transport not implemented in this build".into(),
        ))
    }
}

struct Args {
    config: String,
    check_only: bool,
    window_s: u64,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        config: DEFAULT_CONFIG.into(),
        check_only: false,
        window_s: 60,
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => a.config = it.next().ok_or("--config needs a path")?,
            "--check" => a.check_only = true,
            // Test hook: shorter window for soak/RSS measurements.
            "--window-s" => {
                let v = it.next().ok_or("--window-s needs a number")?;
                a.window_s = v.parse::<u64>().map_err(|e| e.to_string())?.clamp(1, 3600);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(a)
}

fn load(args: &Args) -> Result<(Config, Vec<u8>), String> {
    let text =
        std::fs::read_to_string(&args.config).map_err(|e| format!("{}: {e}", args.config))?;
    let cfg = parse_config(&text).map_err(|e| format!("config: {e}"))?;
    // The real TLS transport will be built from this value; validating here makes a URL with
    // userinfo or a bad pin a startup (and `--check`) failure.
    PinnedTransport::new(&cfg.server_url, &cfg.pins)
        .map_err(|e| format!("server_url/pins: {e}"))?;
    let key = load_key(&cfg.key_file).map_err(|e| format!("key: {e}"))?;
    Ok((cfg, key))
}

struct Agent {
    cfg: Config,
    engine: Engine,
    boot_id: String,
    seq: u64,
    window: Window,
    clock: WindowClock,
    sync: SyncState,
    tail: Tail,
    dhcp: DhcpAssembler,
    dns: DnsCorrelator,
    delta: SnapshotDelta,
    urgent: Urgent,
    quiet: QuietDetector,
    ip_to_mac: HashMap<String, String>,
    started: Instant,
}

impl Agent {
    /// `None` when no random batch id can be had; the caller keeps its data and retries later.
    fn meta(&mut self, now: u64) -> Option<Meta> {
        let rand = match random::<10>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("/dev/urandom: {e}; batch not built");
                return None;
            }
        };
        self.seq += 1;
        Some(Meta {
            collector_id: self.cfg.collector_id.clone(),
            key_id: self.cfg.key_id.clone(),
            boot_id: self.boot_id.clone(),
            seq: self.seq,
            batch_id: ids::uuid7(wall_ms(), rand),
            window_start: self.clock.start(now, self.started.elapsed().as_secs()),
            window_end: now,
        })
    }

    fn health(&self, quiet: bool) -> Health {
        Health {
            dns_log_quiet: quiet,
            rss_kb: read_rss_kb(),
            spool_batches: Some(self.engine.spool.len() as u64),
            uptime_s: Some(self.started.elapsed().as_secs()),
        }
    }

    fn poll_log(&mut self, now: u64) {
        match self.tail.poll() {
            Ok(lines) => {
                for ev in lines.iter().filter_map(|l| parse_line(l)) {
                    self.dns.feed(&ev, now);
                    self.on_dhcp(&ev);
                }
            }
            Err(e) => eprintln!("dnsmasq log: {e}"),
        }
        for q in self.dns.take_ready(&self.ip_to_mac) {
            self.window.add_dns(q);
        }
        for (kind, n) in self.dns.take_counts() {
            self.window.note_drops(&kind, n);
        }
    }

    fn on_dhcp(&mut self, ev: &LogEvent) {
        if let Some(lease) = self.dhcp.feed(ev) {
            let new_mac = self.urgent.on_lease(&lease.mac, started_ms(self.started));
            self.window.add_lease(lease);
            if new_mac {
                // A new device is the case where the 10 s neighbor snapshot is stale: refresh
                // now so its first queries are attributed and its neighbor entry rides along.
                self.refresh_neighbors();
                self.push_identity();
            }
        }
    }

    fn refresh_neighbors(&mut self) {
        let all = read_neighbors();
        self.ip_to_mac = ip_to_mac(&all);
        for n in self.delta.new_neighbors(&all) {
            self.window.add_neighbor(n);
        }
    }

    fn push_identity(&mut self) {
        let now = wall_secs();
        // Same gate as a regular window: nothing is built from an unverified wall clock.
        let mono = self.started.elapsed().as_secs();
        if !self.sync.is_synced() || !self.engine.gate.is_sane(now, mono) {
            return;
        }
        let Some(meta) = self.meta(now) else { return };
        let sections = self.window.take_identity();
        let b = build(&meta, sections, &self.health(false), BATCH_CAP);
        self.engine.enqueue(b.encoded);
    }

    /// Before the first server `Date` the only thing sent is an empty probe: its reply, accepted
    /// or rejected, tells us the time. Data stays in the window (bounded) with monotonic stamps.
    fn queue_probe(&mut self, now: u64) {
        if !self.engine.spool.is_empty() {
            return;
        }
        let Some(meta) = self.meta(now) else { return };
        let b = build(&meta, Sections::default(), &self.health(false), BATCH_CAP);
        self.engine.enqueue(b.encoded);
    }

    fn flush_window(&mut self, now: u64, mono_s: u64) {
        let plan = self.sync.plan(self.engine.gate.is_sane(now, mono_s));
        if plan == FlushPlan::Probe {
            self.queue_probe(now);
            return;
        }
        if plan == FlushPlan::Hold {
            // No sane clock: batches would carry wrong times. Drop the window and count it.
            drop(self.window.take());
            self.engine.spool.note_dropped(1);
            self.clock.mark_flush(mono_s);
            return;
        }
        self.refresh_neighbors();
        match std::fs::read_to_string(&self.cfg.leases_file) {
            Ok(t) => {
                for l in self.delta.changed_leases(parse_leases(&t)) {
                    self.window.add_lease(l);
                }
            }
            Err(e) => eprintln!("leases file: {e}"),
        }
        let dropin = std::fs::read_to_string(DROPIN_PATH).ok();
        let state = check_dropin(dropin.as_deref(), LOG_DIR);
        let quiet = self
            .quiet
            .observe(self.window.dns_count(), self.window.flow_count(), state);
        let Some(meta) = self.meta(now) else { return };
        let (sections, drops): (Sections, _) = self.window.take_with_drops();
        let b = build_with_drops(&meta, sections, &self.health(quiet), BATCH_CAP, &drops);
        self.clock.mark_flush(mono_s);
        self.engine.enqueue(b.encoded);
    }
}

fn started_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("vigie-collector: {e}");
            return ExitCode::from(64);
        }
    };
    let (cfg, mut key) = match load(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vigie-collector: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if args.check_only {
        wipe(&mut key);
        println!("config and key ok");
        return ExitCode::SUCCESS;
    }
    run(cfg, key, &args)
}

fn run(cfg: Config, key: Vec<u8>, args: &Args) -> ExitCode {
    let boot_id = match random::<8>() {
        Ok(r) => ids::boot_id(r),
        Err(e) => {
            eprintln!("vigie-collector: /dev/urandom: {e}; refusing to start without unique ids");
            return ExitCode::from(EXIT_NO_RANDOM);
        }
    };
    let id = Identity {
        collector_id: cfg.collector_id.clone(),
        key_id: cfg.key_id.clone(),
        boot_id: boot_id.clone(),
    };
    let mut agent = Agent {
        tail: Tail::new(cfg.dnsmasq_log.clone()),
        cfg,
        engine: Engine::new(id, key, BUILD_TS, SPOOL_CAP),
        boot_id,
        seq: 0,
        window: Window::default(),
        clock: WindowClock::new(0),
        sync: SyncState::new(),
        dhcp: DhcpAssembler::default(),
        dns: DnsCorrelator::default(),
        delta: SnapshotDelta::default(),
        urgent: Urgent::new(),
        quiet: QuietDetector::default(),
        ip_to_mac: HashMap::new(),
        started: Instant::now(),
    };
    // Leases already on the router at startup are not "new MACs": no urgent-push storm.
    if let Ok(t) = std::fs::read_to_string(&agent.cfg.leases_file) {
        let known = parse_leases(&t);
        agent.urgent.prime(known.iter().map(|l| l.mac.as_str()));
    }
    let mut transport = NoTransport;
    let (mut last_flush, mut last_neigh) = (0u64, 0u64);
    loop {
        let mono = agent.started.elapsed().as_secs();
        let wall = wall_secs();
        if mono.saturating_sub(last_neigh) >= NEIGH_REFRESH_S {
            agent.refresh_neighbors();
            last_neigh = mono;
        }
        agent.poll_log(agent.sync.stamp(wall, mono));
        if agent.urgent.take_pending(started_ms(agent.started)) {
            agent.push_identity();
        }
        if mono.saturating_sub(last_flush) >= args.window_s {
            agent.flush_window(wall, mono);
            last_flush = mono;
        }
        // Jitter only spreads retries; if the kernel RNG is unavailable it is 0 (batch ids, which
        // must be unique, are never built without it: see `Agent::meta`).
        let jitter = random_u64().unwrap_or(0);
        let tick = agent.engine.tick(&mut transport, wall, mono, jitter);
        let date_seen = agent.engine.gate.has_server_date();
        if let Some(offset) = agent.sync.observe(date_seen, wall, mono) {
            agent.window.rebase_dns(offset);
        }
        match tick {
            Tick::Retry { status, delay_s } => {
                eprintln!("send failed (status {status:?}); retry in {delay_s}s");
            }
            Tick::DiscardedStale => eprintln!(
                "server rejected a batch whose window is older than the spool age; \
                 dropped_stale={}",
                agent.engine.dropped_stale
            ),
            Tick::Discarded(s) => eprintln!("server rejected a batch with status {s}; discarded"),
            Tick::Idle | Tick::Held | Tick::Waiting | Tick::Sent { .. } => {}
        }
        std::thread::sleep(POLL);
    }
}
