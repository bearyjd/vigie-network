#![forbid(unsafe_code)]

use std::fs::File;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vigie_conntrack::agg::{AggConfig, Aggregator, Snapshot};
use vigie_conntrack::cli::{check_root_needs_uid, parse_args, Opts, USAGE};
use vigie_conntrack::json::{snapshot_json, Meta};
use vigie_conntrack::lan::default_lan;
use vigie_conntrack::limits::{recheck_due, recheck_pressure, resolve_max_flows, stub_cap, CtMax};
use vigie_conntrack::parse::scan_flows;
use vigie_conntrack::sock::{bind_secure, current_ids, Outcome, Publisher};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Streams the source file into `agg` and ends the sample.
fn sample(opts: &Opts, agg: &mut Aggregator) -> Result<(Snapshot, Meta), String> {
    let name = opts.source.display();
    let f = File::open(&opts.source).map_err(|e| format!("{name}: {e}"))?;
    agg.begin();
    let st = scan_flows(f, |flow| agg.add(&flow)).map_err(|e| format!("{name}: {e}"))?;
    let snap = agg.finish();
    let meta = Meta {
        seq: 0,
        ts: unix_now(),
        interval_s: opts.interval_s,
        skipped_lines: st.skipped,
        acct_off: st.no_acct > 0,
    };
    Ok((snap, meta))
}

fn agg_config(opts: &Opts, max_flows: usize, baseline_first: bool) -> AggConfig {
    AggConfig {
        max_flows,
        max_stubs: stub_cap(max_flows),
        top_n: opts.top_n,
        k_lan: opts.k_lan,
        k_wan: opts.k_wan,
        lan: if opts.lan_cidrs.is_empty() {
            default_lan()
        } else {
            opts.lan_cidrs.clone()
        },
        baseline_first,
    }
}

fn run_once(opts: &Opts) -> Result<(), String> {
    let mut agg = Aggregator::new(agg_config(opts, opts.max_flows, false));
    let (snap, meta) = sample(opts, &mut agg)?;
    let meta = Meta {
        interval_s: 0,
        ..meta
    };
    drop(agg);
    println!("{}", snapshot_json(&meta, &snap));
    Ok(())
}

/// Resolves the flow cap and reports what could not be verified. The returned flag is the
/// initial `table_pressure` state (an explicit cap below 3 x the kernel limit).
fn check_table_limit(opts: &Opts) -> Result<(usize, bool), String> {
    let (max_flows, ct) =
        resolve_max_flows(&opts.conntrack_max_file, opts.max_flows, opts.max_flows_set)?;
    match ct {
        CtMax::Unknown => eprintln!(
            "warning: {} not found, the table size is NOT verified against --max-flows {max_flows}",
            opts.conntrack_max_file.display()
        ),
        CtMax::Known {
            max,
            below_3x: true,
        } => eprintln!(
            "WARNING: nf_conntrack_max {max} needs --max-flows >= {} but --max-flows is \
             {max_flows}: a busy table will evict live flows and may count their bytes again \
             (table_pressure is reported)",
            max.saturating_mul(3)
        ),
        CtMax::Known { .. } => {}
    }
    Ok((max_flows, matches!(ct, CtMax::Known { below_3x: true, .. })))
}

fn run_daemon(opts: &Opts) -> Result<(), String> {
    let (euid, _) = current_ids().map_err(|e| format!("cannot determine own uid: {e}"))?;
    check_root_needs_uid(euid, opts.uid)?;
    let (max_flows, mut pressure) = check_table_limit(opts)?;
    let listener = bind_secure(&opts.socket, opts.uid, opts.gid)
        .map_err(|e| format!("socket {}: {e}", opts.socket.display()))?;
    let mut publisher = Publisher::new(listener);
    let mut agg = Aggregator::new(agg_config(opts, max_flows, true));
    let interval = Duration::from_secs(opts.interval_s);
    let mut next = Instant::now();
    let mut seq = 0u64;
    loop {
        match sample(opts, &mut agg) {
            Ok((mut snap, meta)) => {
                seq += 1;
                if recheck_due(seq, opts.ct_recheck_samples) {
                    let found = recheck_pressure(&opts.conntrack_max_file, max_flows);
                    if let Some(why) = &found {
                        eprintln!("seq {seq}: table_pressure: {why}");
                    }
                    pressure = found.is_some();
                }
                snap.table_pressure |= pressure;
                let meta = Meta { seq, ..meta };
                match publisher.publish(snapshot_json(&meta, &snap)) {
                    Outcome::DroppedBusy => {
                        eprintln!("seq {seq}: reader is behind, snapshot dropped")
                    }
                    Outcome::DroppedTooLarge => eprintln!("seq {seq}: snapshot too large, dropped"),
                    _ => {}
                }
            }
            Err(e) => eprintln!("sample failed: {e}"),
        }
        next = (next + interval).max(Instant::now());
        loop {
            publisher.poll();
            let left = next.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            sleep(left.min(Duration::from_millis(500)));
        }
    }
}

fn run() -> Result<(), String> {
    let opts = parse_args(std::env::args().skip(1)).map_err(|e| format!("{e}\n{USAGE}"))?;
    if opts.once {
        run_once(&opts)
    } else {
        run_daemon(&opts)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vigie-conntrack: {e}");
            ExitCode::from(2)
        }
    }
}
