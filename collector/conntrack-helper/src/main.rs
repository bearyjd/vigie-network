#![forbid(unsafe_code)]

use std::fs::File;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vigie_conntrack::agg::{AggConfig, Aggregator, Snapshot};
use vigie_conntrack::cli::{parse_args, Opts, USAGE};
use vigie_conntrack::json::{snapshot_json, Meta};
use vigie_conntrack::limits::{check_conntrack_max, CtMax};
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

fn agg_config(opts: &Opts, baseline_first: bool) -> AggConfig {
    AggConfig {
        max_flows: opts.max_flows,
        top_n: opts.top_n,
        other_k: opts.other_k,
        baseline_first,
    }
}

fn run_once(opts: &Opts) -> Result<(), String> {
    let mut agg = Aggregator::new(agg_config(opts, false));
    let (snap, meta) = sample(opts, &mut agg)?;
    let meta = Meta {
        interval_s: 0,
        ..meta
    };
    drop(agg);
    println!("{}", snapshot_json(&meta, &snap));
    Ok(())
}

fn check_table_limit(opts: &Opts) -> Result<(), String> {
    match check_conntrack_max(&opts.conntrack_max_file, opts.max_flows, opts.max_flows_set)? {
        CtMax::Unknown => eprintln!(
            "warning: {} unreadable, cannot check the table size against --max-flows",
            opts.conntrack_max_file.display()
        ),
        CtMax::Known {
            max,
            over_explicit_cap: true,
        } => eprintln!(
            "warning: nf_conntrack_max {max} exceeds --max-flows {}; a full table will evict flows",
            opts.max_flows
        ),
        CtMax::Known { .. } => {}
    }
    Ok(())
}

fn run_daemon(opts: &Opts) -> Result<(), String> {
    let (euid, _) = current_ids().map_err(|e| format!("cannot determine own uid: {e}"))?;
    if euid == 0 && opts.uid.is_none() {
        return Err(
            "running as root requires --uid (and --gid) of the unprivileged agent, \
                    otherwise the agent could not connect to the socket"
                .to_string(),
        );
    }
    check_table_limit(opts)?;
    let listener = bind_secure(&opts.socket, opts.uid, opts.gid)
        .map_err(|e| format!("socket {}: {e}", opts.socket.display()))?;
    let mut publisher = Publisher::new(listener);
    let mut agg = Aggregator::new(agg_config(opts, true));
    let interval = Duration::from_secs(opts.interval_s);
    let mut next = Instant::now();
    let mut seq = 0u64;
    loop {
        match sample(opts, &mut agg) {
            Ok((snap, meta)) => {
                seq += 1;
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
