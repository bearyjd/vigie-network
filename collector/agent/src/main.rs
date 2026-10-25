#![forbid(unsafe_code)]
//! vigie-collector: unprivileged agent. Tails the dnsmasq log, reads neighbors and leases,
//! builds a signed batch every window and pushes it through a `Transport`.
//!
//! The conntrack helper client and the mDNS/SSDP listener are wired in through `wiring::Sources`
//! (reader threads behind bounded channels, drained by `Agent::step`).
//!
//! The transport is HTTPS with SPKI pinning (`transport::make`, rustls + ring); a bad URL or pin
//! makes every send fail instead of falling back to anything weaker. Never run on the router yet.
//! Shutdown: std has no safe signal handler, so SIGTERM takes the default action and ends the
//! process; all state is in RAM by design (spool, window) and the reader threads die with it.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vigie_agent::builder::{build, build_with_drops, BATCH_CAP};
use vigie_agent::config::{load_key, parse_config, wipe, Config};
use vigie_agent::dnsmasq::{parse_line_pid, DhcpAssembler, DnsCorrelator, LogEvent};
use vigie_agent::dropin::{check_dropin, QuietDetector};
use vigie_agent::ids;
use vigie_agent::leases::parse_leases;
use vigie_agent::model::{Health, Lease, Meta, Neighbor, Sections};
use vigie_agent::neigh::{ip_to_mac, pairing_changed};
use vigie_agent::procstat::{read_rss_kb, read_status, root_refusal};
use vigie_agent::runtime::{random, random_u64, read_neighbors, wall_ms, wall_secs};
use vigie_agent::sender::{Engine, Identity, Tick, Transport};
use vigie_agent::spool::SPOOL_CAP;
use vigie_agent::syncstate::{FlushPlan, SyncState};
use vigie_agent::tail::Tail;
use vigie_agent::transport::PinnedTransport;
use vigie_agent::urgent::Urgent;
use vigie_agent::window::{SnapshotDelta, Window, WindowClock};
use vigie_agent::wiring::Sources;

const BUILD_TS: u64 = parse_build_ts(env!("VIGIE_BUILD_TS"));
const DEFAULT_CONFIG: &str = "/etc/vigie/collector.conf";
const POLL: Duration = Duration::from_secs(2);
const NEIGH_REFRESH_S: u64 = 10;
const EXIT_CONFIG: u8 = 78;
const EXIT_NO_RANDOM: u8 = 71;
const EXIT_NO_PERM: u8 = 77;

const fn parse_build_ts(s: &str) -> u64 {
    let b = s.as_bytes();
    let (mut i, mut n) = (0, 0u64);
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    n
}

struct Args {
    config: String,
    check_only: bool,
    /// Test hook: run even as root. Production never passes it.
    allow_root: bool,
    window_s: u64,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        config: DEFAULT_CONFIG.into(),
        check_only: false,
        allow_root: false,
        window_s: 60,
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => a.config = it.next().ok_or("--config needs a path")?,
            "--check" => a.check_only = true,
            "--allow-root" => a.allow_root = true,
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
    /// Monotonic seconds of the current loop step (injected clock in tests).
    mono: u64,
    sources: Sources,
    /// `read_neighbors` in production; tests substitute a fake table.
    neigh_source: fn() -> Vec<vigie_agent::model::Neighbor>,
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
        match self.tail.poll_with_gaps() {
            Ok(lines) => {
                for line in &lines {
                    // `None`: bytes were lost here, so nothing may attach across it.
                    let Some(line) = line else {
                        self.dhcp.lose_context();
                        continue;
                    };
                    match parse_line_pid(line) {
                        Some((pid, ev)) => {
                            self.dns.feed(&ev, now);
                            self.on_dhcp(pid, &ev);
                        }
                        // Anything unparsed sits between packet lines: no attaching across it.
                        None => {
                            let done = self.dhcp.break_context();
                            self.on_leases(done);
                        }
                    }
                }
            }
            Err(e) => eprintln!("dnsmasq log: {e}"),
        }
        let done = self.dhcp.end_poll();
        self.on_leases(done);
        for q in self.dns.take_ready(&self.ip_to_mac) {
            self.window.add_dns(q);
        }
        for (kind, n) in self
            .dns
            .take_counts()
            .into_iter()
            .chain(self.tail.take_counts())
        {
            self.window.note_drops(&kind, n);
        }
    }

    fn on_dhcp(&mut self, pid: u64, ev: &LogEvent) {
        let leases = self.dhcp.feed_pid(pid, ev);
        self.on_leases(leases);
    }

    fn on_leases(&mut self, leases: Vec<Lease>) {
        for lease in leases {
            self.on_lease(lease);
        }
    }

    fn on_lease(&mut self, lease: Lease) {
        let new_mac = self.urgent.on_lease(&lease.mac, started_ms(self.started));
        // The lease states the pairing now: a table that disagrees (address moved to this MAC,
        // or not seen yet) is stale and would bill this device's traffic to the old owner.
        let moved = pairing_changed(&self.ip_to_mac, &lease.ip, &lease.mac);
        self.window.add_lease(lease);
        // A new device always refreshes (its first queries must be attributed and its neighbor
        // entry rides along); a changed pairing refreshes at most once per `REFRESH_MIN_S`.
        if new_mac || (moved && self.sources.refresh_due(self.mono)) {
            self.refresh_neighbors();
        }
        if new_mac {
            self.push_identity();
        }
    }

    fn refresh_neighbors(&mut self) {
        let all = (self.neigh_source)();
        self.sources.note_refresh(self.mono);
        self.adopt_neighbors(&all);
    }

    /// Makes `all` the attribution map and reports its entries that are new since the last read.
    fn adopt_neighbors(&mut self, all: &[Neighbor]) {
        self.ip_to_mac = ip_to_mac(all);
        for n in self.delta.new_neighbors(all) {
            self.window.add_neighbor(n);
        }
    }

    /// Drains the sources; a snapshot's table read (if any) becomes the agent's map.
    fn pump_sources(&mut self, mono: u64) {
        let read = self.neigh_source;
        if let Some(all) = self.sources.pump_refreshing(
            &mut self.window,
            &self.ip_to_mac,
            Some(&mut || read()),
            mono,
        ) {
            self.adopt_neighbors(&all);
        }
    }

    fn push_identity(&mut self) {
        let now = wall_secs();
        // Same gate as a regular window: nothing is built from an unverified wall clock.
        let mono = self.started.elapsed().as_secs();
        if !self
            .sync
            .allow_identity_push(self.engine.gate.is_sane(now, mono))
        {
            return;
        }
        let Some(meta) = self.meta(now) else { return };
        let sections = self.window.take_identity();
        let b = build(&meta, sections, &self.health(false), BATCH_CAP);
        self.engine.enqueue(b.encoded.as_probe());
    }

    /// Before the first server `Date` the only thing sent is an empty probe: its reply, accepted
    /// or rejected, tells us the time. Data stays in the window (bounded) with monotonic stamps.
    fn queue_probe(&mut self, now: u64) {
        if !self.engine.spool.is_empty() {
            return;
        }
        let Some(meta) = self.meta(now) else { return };
        let b = build(&meta, Sections::default(), &self.health(false), BATCH_CAP);
        self.engine.enqueue(b.encoded.as_probe());
    }

    fn flush_window(&mut self, now: u64, mono_s: u64) {
        self.mono = mono_s;
        let plan = self.sync.plan(self.engine.gate.is_sane(now, mono_s));
        if plan == FlushPlan::Probe {
            self.queue_probe(now);
            return;
        }
        if plan == FlushPlan::Hold {
            // No sane clock: batches would carry wrong times. Drop the window and count it.
            self.sources.finish_window(&mut self.window, mono_s);
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
        self.pump_sources(mono_s);
        self.sources.finish_window(&mut self.window, mono_s);
        let dropin = std::fs::read_to_string(&self.cfg.dropin_path).ok();
        let state = check_dropin(dropin.as_deref(), &self.cfg.log_dir.to_string_lossy());
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

/// The time inputs of one loop step (injected, so tests use a fake clock).
#[derive(Clone, Copy)]
struct Clock {
    wall: u64,
    mono: u64,
    jitter: u64,
}

impl Agent {
    /// One pass of the main loop: refresh neighbors, read the log and the sources, push a new
    /// device's identity, flush the window when due, and let the send engine try the spool.
    /// `last` holds the monotonic seconds of the last window flush and neighbor refresh.
    fn step<T: Transport>(
        &mut self,
        when: Clock,
        window_s: u64,
        last: (&mut u64, &mut u64),
        transport: &mut T,
    ) -> Tick {
        let Clock { wall, mono, jitter } = when;
        self.mono = mono;
        let (last_flush, last_neigh) = last;
        if mono.saturating_sub(*last_neigh) >= NEIGH_REFRESH_S {
            self.refresh_neighbors();
            *last_neigh = mono;
        }
        self.poll_log(self.sync.stamp(wall, mono));
        self.pump_sources(mono);
        if self.urgent.take_pending(started_ms(self.started)) {
            self.push_identity();
        }
        if mono.saturating_sub(*last_flush) >= window_s {
            self.flush_window(wall, mono);
            *last_flush = mono;
        }
        let tick = self.engine.tick(transport, wall, mono, jitter);
        if let Some(offset) = self.sync.observe(&self.engine.gate) {
            self.window.rebase_dns(offset);
        }
        tick
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
    if let Some(why) = root_refusal(read_status().as_deref(), args.allow_root) {
        eprintln!("vigie-collector: {why}");
        return ExitCode::from(EXIT_NO_PERM);
    }
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
        sources: Sources::start(&cfg, 0),
        neigh_source: read_neighbors,
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
        mono: 0,
    };
    // Leases already on the router at startup are not "new MACs": no urgent-push storm.
    if let Ok(t) = std::fs::read_to_string(&agent.cfg.leases_file) {
        let known = parse_leases(&t);
        agent.urgent.prime(known.iter().map(|l| l.mac.as_str()));
    }
    let mut transport = vigie_agent::transport::make(&agent.cfg);
    let (mut last_flush, mut last_neigh) = (0u64, 0u64);
    loop {
        let mono = agent.started.elapsed().as_secs();
        let wall = wall_secs();
        // Jitter only spreads retries; if the kernel RNG is unavailable it is 0 (batch ids, which
        // must be unique, are never built without it: see `Agent::meta`).
        let jitter = random_u64().unwrap_or(0);
        let when = Clock { wall, mono, jitter };
        let tick = agent.step(
            when,
            args.window_s,
            (&mut last_flush, &mut last_neigh),
            &mut transport,
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use vigie_agent::model::DnsQuery;
    use vigie_agent::sender::{Headers, HttpReply, TransportError};

    const MAC: &str = "aa:bb:cc:dd:ee:01";

    fn agent() -> Agent {
        let cfg = parse_config(&format!(
            "server_url=https://vigie.example.lan:8443/v1/batch\ncollector_id=router-1\n\
             key_id=k1\npin1={}\npin2={}\n",
            "0".repeat(64),
            "1".repeat(64)
        ))
        .expect("test config");
        let id = Identity {
            collector_id: cfg.collector_id.clone(),
            key_id: cfg.key_id.clone(),
            boot_id: "boot1".into(),
        };
        Agent {
            tail: Tail::new(cfg.dnsmasq_log.clone()),
            cfg,
            engine: Engine::new(id, vec![7; 32], BUILD_TS, SPOOL_CAP),
            boot_id: "boot1".into(),
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
            mono: 0,
            sources: Sources::inert(),
            neigh_source: Vec::new,
        }
    }

    fn add_row(a: &mut Agent) {
        a.window
            .add_dns(DnsQuery::new(5, MAC, "a.example.com", "A", None).unwrap());
        a.window
            .add_lease(Lease::new(MAC, "192.168.1.50", Some("Pixel"), &[1, 3], None).unwrap());
    }

    #[test]
    fn unsynced_flush_queues_exactly_one_empty_probe_and_keeps_the_data() {
        let mut a = agent();
        add_row(&mut a);
        let now = BUILD_TS + 100;
        a.flush_window(now, 61);
        assert_eq!(a.engine.spool.len(), 1, "one probe");
        let value: serde_json::Value =
            serde_json::from_slice(&a.engine.spool.front().unwrap().body(now, 0)).unwrap();
        assert_eq!(value["observation_kind"], "probe");
        assert_eq!(
            a.window.dns_count(),
            1,
            "window data kept, not built or dropped"
        );
        a.flush_window(now + 60, 121);
        assert_eq!(
            a.engine.spool.len(),
            1,
            "no second probe while one is queued"
        );
        assert_eq!(a.window.dns_count(), 1);
        let kept = a.window.take_identity();
        assert_eq!(kept.leases.len(), 1, "lease kept too");
    }

    #[test]
    fn identity_push_builds_nothing_until_a_server_date_was_seen() {
        let mut a = agent();
        add_row(&mut a);
        assert!(!a.engine.gate.has_server_date());
        a.push_identity();
        assert!(
            a.engine.spool.is_empty(),
            "nothing queued before the first Date"
        );
        assert_eq!(
            a.window.take_identity().leases.len(),
            1,
            "identity kept for later"
        );
    }

    fn log_agent(tag: &str) -> (Agent, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("vigie-main-{}-{tag}.log", std::process::id()));
        std::fs::write(&path, "").unwrap();
        let mut a = agent();
        a.tail = Tail::new(path.clone());
        a.poll_log(0);
        (a, path)
    }

    fn append(path: &std::path::Path, text: &str) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn tail_counters_reach_the_batch_drops() {
        let (mut a, path) = log_agent("counts");
        append(&path, &format!("{}\n", "z".repeat(5000)));
        a.poll_log(1);
        let (_, drops) = a.window.take_with_drops();
        assert_eq!(drops.get("tail_bytes_skipped"), Some(&5000), "{drops:?}");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn an_unparsed_line_between_request_and_options_detaches_them() {
        let (mut a, path) = log_agent("break");
        let p = "Oct 20 14:00:00 dnsmasq-dhcp[5]:";
        append(
            &path,
            &format!(
                "{p} 7 DHCPREQUEST(br-lan) 192.168.1.50 {MAC}\nnot a dnsmasq line\n\
                 {p} 7 vendor class: injected\n{p} 7 DHCPACK(br-lan) 192.168.1.50 {MAC}\n"
            ),
        );
        a.poll_log(1);
        let leases = a.window.take_identity().leases;
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].opt60, None);
        std::fs::remove_file(path).ok();
    }

    mod dhcp_log_tests;

    struct Recorder(Vec<Vec<u8>>);

    impl Transport for Recorder {
        fn post(&mut self, _h: &Headers, body: &[u8]) -> Result<HttpReply, TransportError> {
            self.0.push(body.to_vec());
            Ok(HttpReply {
                status: 200,
                date: None,
                body: Vec::new(),
            })
        }
    }

    /// `dns_log_quiet` of the first regular batch, with the drop-in at `dropin` checked against
    /// `log_dir` (both come from the config).
    fn quiet_flag(tag: &str, content: Option<&str>, log_dir: &str) -> bool {
        let path =
            std::env::temp_dir().join(format!("vigie-main-{}-{tag}.conf", std::process::id()));
        std::fs::remove_file(&path).ok();
        if let Some(c) = content {
            std::fs::write(&path, c).unwrap();
        }
        let mut a = agent();
        a.cfg.dropin_path = path.clone();
        a.cfg.log_dir = log_dir.into();
        let t0 = BUILD_TS + 1000;
        a.engine.gate.observe_server_date(t0, 0);
        assert!(a.sync.observe(&a.engine.gate).is_some());
        let mut tr = Recorder(Vec::new());
        let mut last = (0u64, 0u64);
        let when = Clock {
            wall: t0 + 60,
            mono: 60,
            jitter: 0,
        };
        a.step(when, 60, (&mut last.0, &mut last.1), &mut tr);
        std::fs::remove_file(path).ok();
        let j: serde_json::Value = serde_json::from_slice(&tr.0[0]).unwrap();
        j["health"]["dns_log_quiet"].as_bool().unwrap()
    }

    #[test]
    fn configured_dropin_path_and_log_dir_drive_the_quiet_flag() {
        use vigie_agent::dropin::dropin_content;
        let good = dropin_content("/run/vl");
        assert!(
            !quiet_flag("ok", Some(&good), "/run/vl"),
            "matching drop-in"
        );
        assert!(quiet_flag("missing", None, "/run/vl"), "missing drop-in");
        assert!(
            quiet_flag("differs", Some(&good), "/other"),
            "wrong log dir"
        );
    }

    static NEIGH: std::sync::Mutex<Vec<vigie_agent::model::Neighbor>> =
        std::sync::Mutex::new(Vec::new());

    fn fake_neighbors() -> Vec<vigie_agent::model::Neighbor> {
        NEIGH.lock().unwrap().clone()
    }

    /// The loop with fake sources, a fake clock, a fake neighbor table and a recording transport.
    #[test]
    fn the_loop_flushes_on_the_sixty_second_tick_with_source_data_and_flags() {
        use std::sync::atomic::Ordering;
        use std::sync::mpsc::sync_channel;
        use vigie_agent::ctparse::{Kind, Record, Snapshot};
        use vigie_agent::ctsock::CtShared;
        use vigie_agent::mcast::{McMsg, McShared, Pkt};
        use vigie_agent::model::{Neighbor, Proto};

        *NEIGH.lock().unwrap() = vec![Neighbor::new("192.168.8.10", MAC).unwrap()];
        let (ct_tx, ct_rx) = sync_channel(4);
        let (mc_tx, mc_rx) = sync_channel(16);
        let (ct, mc) = (
            std::sync::Arc::new(CtShared::default()),
            std::sync::Arc::new(McShared::default()),
        );
        ct.connected.store(true, Ordering::Relaxed);
        let mut a = agent();
        a.sources = Sources::from_parts(Some((ct_rx, ct.clone())), Some((mc_rx, mc)), 0);
        a.neigh_source = fake_neighbors;
        let t0 = BUILD_TS + 1000;
        a.engine.gate.observe_server_date(t0, 0);
        assert!(a.sync.observe(&a.engine.gate).is_some());

        let snap = Snapshot {
            table_pressure: true,
            records: vec![Record {
                src: "192.168.8.10".parse().unwrap(),
                kind: Kind::Tuple,
                dst: Some("1.1.1.1".parse().unwrap()),
                dport: Some(443),
                proto: Proto::Tcp,
                bytes_up: 11,
                bytes_down: 22,
                flows: 1,
            }],
            ..Snapshot::default()
        };
        ct_tx.send(snap).unwrap();
        let ssdp = vigie_parse::ssdp::Parsed {
            method: vigie_parse::ssdp::Method::Notify,
            server: Some("Fake/1.0".into()),
            usn: Some("uuid:fake".into()),
            nt: None,
            st: None,
            user_agent: None,
        };
        mc_tx
            .send(McMsg {
                src: "192.168.8.10".parse().unwrap(),
                pkt: Pkt::Ssdp(ssdp),
            })
            .unwrap();

        let mut tr = Recorder(Vec::new());
        let (mut last_flush, mut last_neigh) = (0u64, 0u64);
        let mut at = |a: &mut Agent, t: u64, tr: &mut Recorder| {
            let when = Clock {
                wall: t0 + t,
                mono: t,
                jitter: 0,
            };
            a.step(when, 60, (&mut last_flush, &mut last_neigh), tr)
        };
        for t in [10, 30, 59] {
            at(&mut a, t, &mut tr);
            assert!(
                tr.0.is_empty(),
                "nothing is sent before the window ends (t={t})"
            );
        }
        assert_eq!(
            a.ip_to_mac.get("192.168.8.10").map(String::as_str),
            Some(MAC)
        );
        at(&mut a, 60, &mut tr);
        assert_eq!(tr.0.len(), 1, "one batch at the 60 s tick");
        let j: serde_json::Value = serde_json::from_slice(&tr.0[0]).unwrap();
        assert_eq!(j["conntrack"][0]["mac"], MAC);
        assert_eq!(j["conntrack"][0]["bytes_down"], 22);
        assert_eq!(j["sightings"][0]["mac"], MAC);
        assert_eq!(
            j["truncated"]["source_flags"], 1,
            "table_pressure only: {j}"
        );
        assert!(j["health"]["dns_log_quiet"].is_boolean());

        // second window: the helper goes away
        ct.connected.store(false, Ordering::Relaxed);
        at(&mut a, 119, &mut tr);
        assert_eq!(tr.0.len(), 1, "no early flush");
        at(&mut a, 120, &mut tr);
        assert_eq!(tr.0.len(), 2);
        let j: serde_json::Value = serde_json::from_slice(&tr.0[1]).unwrap();
        assert_eq!(j["truncated"]["source_flags"], 4, "socket down only: {j}");
        assert_eq!(j["conntrack"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn parse_args_takes_allow_root_only_when_given() {
        let none = parse_args(["--config".to_string(), "/x".to_string()].into_iter()).unwrap();
        assert!(!none.allow_root);
        let some = parse_args(["--allow-root".to_string()].into_iter()).unwrap();
        assert!(some.allow_root);
        assert!(parse_args(["--allow-roo".to_string()].into_iter()).is_err());
    }

    thread_local! {
        static TL_NEIGH: RefCell<Vec<(&'static str, &'static str)>> = const { RefCell::new(Vec::new()) };
        static TL_READS: RefCell<usize> = const { RefCell::new(0) };
    }

    fn tl_fake_neigh() -> Vec<Neighbor> {
        TL_READS.with(|r| *r.borrow_mut() += 1);
        TL_NEIGH.with(|n| {
            n.borrow()
                .iter()
                .map(|(ip, mac)| Neighbor::new(ip, mac).unwrap())
                .collect()
        })
    }

    fn lease_for(mac: &str, ip: &str) -> Lease {
        Lease::new(mac, ip, None, &[], None).unwrap()
    }

    #[test]
    fn a_lease_that_changes_an_ip_mac_pairing_refreshes_the_neighbor_table() {
        const B: &str = "aa:bb:cc:dd:ee:02";
        let mut a = agent();
        a.neigh_source = tl_fake_neigh;
        TL_NEIGH.with(|n| *n.borrow_mut() = vec![("192.168.1.50", MAC)]);
        TL_READS.with(|r| *r.borrow_mut() = 0);
        // MAC is known (not a new device) and the table agrees with the lease: no read.
        a.urgent.prime([MAC, B]);
        a.mono = 100;
        a.refresh_neighbors();
        assert_eq!(TL_READS.with(|r| *r.borrow()), 1);
        a.mono = 200;
        a.on_lease(lease_for(MAC, "192.168.1.50"));
        assert_eq!(
            TL_READS.with(|r| *r.borrow()),
            1,
            "same pairing: no refresh"
        );
        // The address moves to B (known MAC): the table is stale, refresh once.
        TL_NEIGH.with(|n| *n.borrow_mut() = vec![("192.168.1.50", B)]);
        a.on_lease(lease_for(B, "192.168.1.50"));
        assert_eq!(TL_READS.with(|r| *r.borrow()), 2, "moved pairing refreshes");
        assert_eq!(a.ip_to_mac.get("192.168.1.50").map(String::as_str), Some(B));
        // Another changed pairing within the rate-limit window does not read again.
        a.on_lease(lease_for(MAC, "192.168.1.51"));
        assert_eq!(TL_READS.with(|r| *r.borrow()), 2, "rate-limited");
        a.mono = 201;
        a.on_lease(lease_for(MAC, "192.168.1.51"));
        assert_eq!(TL_READS.with(|r| *r.borrow()), 3);
    }
}
