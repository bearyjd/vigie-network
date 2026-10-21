//! The agent's data sources as seen by the main loop: the conntrack helper client and the
//! multicast listener, each a reader thread behind a bounded channel.
//!
//! `pump` drains what has arrived (bounded work per call, never blocks) and maps it to MACs with
//! the neighbor table; `finish_window` moves the window's conntrack rows, counters and condition
//! flags into the `Window` just before the batch is built. Time is passed in (monotonic seconds),
//! so tests drive it with a fake clock.
//!
//! Schema note: `health` is a closed object (only `dns_log_quiet`, `rss_kb`, `spool_batches`,
//! `uptime_s`), so these conditions travel in the batch `truncated` map: counters under
//! `ct_*`/`mcast_*` and the bitmask `source_flags` (see `flag`). The server accepts any
//! `[a-z_]{1,32}` key with a non-negative integer, at most 16 keys (the builder enforces that).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use crate::config::Config;
use crate::ctfold::CtAccum;
use crate::ctparse::Snapshot;
use crate::ctsock::{trusted_uids, CtConfig, CtReader, CtShared};
use crate::mcast::{McConfig, McMsg, McReader, McShared, Pkt};
use crate::sightings::{from_mdns, from_ssdp};
use crate::window::Window;

/// Bits of the `source_flags` value in `truncated`.
pub mod flag {
    /// The helper reported `table_pressure`: its tracking table was near its cap.
    pub const CT_TABLE_PRESSURE: u64 = 1;
    /// The helper saw conntrack lines without byte counters (`nf_conntrack_acct` is off).
    pub const CT_ACCT_OFF: u64 = 2;
    /// The helper socket is down, refused, or has been silent for `CT_STALE_S`.
    pub const CT_SOCKET_DOWN: u64 = 4;
    /// A multicast socket could not be bound or joined.
    pub const MULTICAST_BIND_FAILED: u64 = 8;
}

/// A connected helper that sends nothing for this long counts as down (it sends every interval).
pub const CT_STALE_S: u64 = 180;
/// Multicast packets handled per `pump`, so a flood cannot stall the loop.
pub const MAX_MC_PER_PUMP: usize = 512;

enum CtSide {
    Real(CtReader),
    Fake(Receiver<Snapshot>, Arc<CtShared>),
}

impl CtSide {
    fn rx(&self) -> &Receiver<Snapshot> {
        match self {
            Self::Real(r) => &r.rx,
            Self::Fake(rx, _) => rx,
        }
    }
    fn shared(&self) -> &CtShared {
        match self {
            Self::Real(r) => &r.shared,
            Self::Fake(_, s) => s,
        }
    }
}

enum McSide {
    Real(McReader),
    Fake(Receiver<McMsg>, Arc<McShared>),
}

impl McSide {
    fn rx(&self) -> &Receiver<McMsg> {
        match self {
            Self::Real(r) => &r.rx,
            Self::Fake(rx, _) => rx,
        }
    }
    fn shared(&self) -> &McShared {
        match self {
            Self::Real(r) => &r.shared,
            Self::Fake(_, s) => s,
        }
    }
}

#[derive(Default)]
pub struct Sources {
    ct: Option<CtSide>,
    mc: Option<McSide>,
    acc: CtAccum,
    /// `flag::CT_TABLE_PRESSURE`/`CT_ACCT_OFF` seen in this window.
    window_flags: u64,
    ct_last_mono: u64,
    ct_errors: u64,
    ct_recounted: u64,
    ct_dropped_keys: u64,
    mc_unmapped: u64,
    mc_dropped: u64,
    /// A reader could not even be started (thread spawn or uid lookup failed).
    start_failed: u64,
}

impl Sources {
    /// No sources at all (tests of the rest of the agent).
    pub fn inert() -> Self {
        Self::default()
    }

    /// Injected channels instead of reader threads (fake sources).
    pub fn from_parts(
        ct: Option<(Receiver<Snapshot>, Arc<CtShared>)>,
        mc: Option<(Receiver<McMsg>, Arc<McShared>)>,
        mono_s: u64,
    ) -> Self {
        Self {
            ct: ct.map(|(rx, s)| CtSide::Fake(rx, s)),
            mc: mc.map(|(rx, s)| McSide::Fake(rx, s)),
            ct_last_mono: mono_s,
            ..Self::default()
        }
    }

    /// Already-spawned readers (tests drive real sockets with their own configuration).
    pub fn from_readers(ct: Option<CtReader>, mc: Option<McReader>, mono_s: u64) -> Self {
        Self {
            ct: ct.map(CtSide::Real),
            mc: mc.map(McSide::Real),
            ct_last_mono: mono_s,
            ..Self::default()
        }
    }

    /// Starts both reader threads. A failure to start is logged and reported as the matching
    /// condition flag; the agent keeps running without that source.
    pub fn start(cfg: &Config, mono_s: u64) -> Self {
        let mut s = Self {
            ct_last_mono: mono_s,
            ..Self::default()
        };
        let ct = trusted_uids()
            .and_then(|t| CtReader::spawn(CtConfig::new(cfg.conntrack_socket.clone(), t)));
        match ct {
            Ok(r) => s.ct = Some(CtSide::Real(r)),
            Err(e) => {
                eprintln!("conntrack client not started: {e}");
                s.start_failed |= flag::CT_SOCKET_DOWN;
            }
        }
        let mc = McConfig {
            lan: cfg.lan_addr,
            prefix: cfg.lan_prefix,
            iface: cfg.lan_iface.clone(),
            include_own: false,
        };
        match McReader::spawn(mc) {
            Ok(r) => s.mc = Some(McSide::Real(r)),
            Err(e) => {
                eprintln!("multicast listener not started: {e}");
                s.start_failed |= flag::MULTICAST_BIND_FAILED;
            }
        }
        s
    }

    /// Drains both queues into the window. Never blocks.
    pub fn pump(&mut self, w: &mut Window, ip_to_mac: &HashMap<String, String>, mono_s: u64) {
        if let Some(ct) = &self.ct {
            while let Ok(snap) = ct.rx().try_recv() {
                self.ct_last_mono = mono_s;
                self.acc.add_snapshot(&snap, ip_to_mac);
                if snap.table_pressure {
                    self.window_flags |= flag::CT_TABLE_PRESSURE;
                }
                if snap.acct_off {
                    self.window_flags |= flag::CT_ACCT_OFF;
                }
                self.ct_recounted = self.ct_recounted.saturating_add(snap.recounted_flows);
                self.ct_dropped_keys = self.ct_dropped_keys.saturating_add(snap.dropped_new_keys);
            }
            let sh = ct.shared();
            let lost = sh.errors.swap(0, Ordering::Relaxed) + sh.dropped.swap(0, Ordering::Relaxed);
            self.ct_errors = self.ct_errors.saturating_add(lost);
        }
        if let Some(mc) = &self.mc {
            for _ in 0..MAX_MC_PER_PUMP {
                let Ok(m) = mc.rx().try_recv() else { break };
                let Some(mac) = ip_to_mac.get(&m.src.to_string()) else {
                    self.mc_unmapped += 1;
                    continue;
                };
                match &m.pkt {
                    Pkt::Mdns(p) => from_mdns(mac, p)
                        .into_iter()
                        .for_each(|s| w.add_sighting(s)),
                    Pkt::Ssdp(p) => from_ssdp(mac, p)
                        .into_iter()
                        .for_each(|s| w.add_sighting(s)),
                }
            }
            self.mc_dropped = self
                .mc_dropped
                .saturating_add(mc.shared().dropped.swap(0, Ordering::Relaxed));
        }
    }

    fn ct_down(&self, mono_s: u64) -> bool {
        match &self.ct {
            Some(ct) => {
                !ct.shared().connected.load(Ordering::Relaxed)
                    || mono_s.saturating_sub(self.ct_last_mono) > CT_STALE_S
            }
            None => self.start_failed & flag::CT_SOCKET_DOWN != 0,
        }
    }

    fn mc_failed(&self) -> bool {
        match &self.mc {
            Some(mc) => mc.shared().bind_failed.load(Ordering::Relaxed),
            None => self.start_failed & flag::MULTICAST_BIND_FAILED != 0,
        }
    }

    /// Moves the window's conntrack rows, counters and flags into `w`; call right before the
    /// batch is built (after a final `pump`). Resets the per-window state.
    pub fn finish_window(&mut self, w: &mut Window, mono_s: u64) {
        let (rows, unmapped_bytes, _) = self.acc.take();
        for r in rows {
            w.add_conntrack(r);
        }
        let mut bits = std::mem::take(&mut self.window_flags);
        if self.ct_down(mono_s) {
            bits |= flag::CT_SOCKET_DOWN;
        }
        if self.mc_failed() {
            bits |= flag::MULTICAST_BIND_FAILED;
        }
        w.note_flags(bits);
        let counters = [
            ("ct_errors", std::mem::take(&mut self.ct_errors)),
            ("ct_recounted", std::mem::take(&mut self.ct_recounted)),
            ("ct_dropped_keys", std::mem::take(&mut self.ct_dropped_keys)),
            ("ct_unmapped_bytes", unmapped_bytes),
            ("mcast_unmapped", std::mem::take(&mut self.mc_unmapped)),
            ("mcast_dropped", std::mem::take(&mut self.mc_dropped)),
        ];
        for (kind, n) in counters {
            w.note_drops(kind, n);
        }
    }
}
