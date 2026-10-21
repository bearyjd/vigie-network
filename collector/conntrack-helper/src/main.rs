#![forbid(unsafe_code)]

use std::fs::File;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vigie_conntrack::agg::{AggConfig, Aggregator};
use vigie_conntrack::cli::{parse_args, Opts, USAGE};
use vigie_conntrack::json::{snapshot_json, Meta};
use vigie_conntrack::parse::{read_flows, Flow};
use vigie_conntrack::sock::{bind_secure, current_ids, Outcome, Publisher};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sample(opts: &Opts) -> Result<(Vec<Flow>, usize), String> {
    let f = File::open(&opts.source).map_err(|e| format!("{}: {e}", opts.source.display()))?;
    read_flows(f).map_err(|e| format!("{}: {e}", opts.source.display()))
}

fn agg_config(opts: &Opts, baseline_first: bool) -> AggConfig {
    AggConfig {
        max_flows: opts.max_flows,
        top_n: opts.top_n,
        baseline_first,
    }
}

fn run_once(opts: &Opts) -> Result<(), String> {
    let (flows, skipped_lines) = sample(opts)?;
    let snap = Aggregator::new(agg_config(opts, false)).ingest(&flows);
    let meta = Meta {
        seq: 0,
        ts: unix_now(),
        interval_s: 0,
        skipped_lines,
    };
    println!("{}", snapshot_json(&meta, &snap));
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
    let listener = bind_secure(&opts.socket, opts.uid, opts.gid)
        .map_err(|e| format!("socket {}: {e}", opts.socket.display()))?;
    let mut publisher = Publisher::new(listener);
    let mut agg = Aggregator::new(agg_config(opts, true));
    let interval = Duration::from_secs(opts.interval_s);
    let mut next = Instant::now();
    let mut seq = 0u64;
    loop {
        match sample(opts) {
            Ok((flows, skipped_lines)) => {
                let snap = agg.ingest(&flows);
                seq += 1;
                let meta = Meta {
                    seq,
                    ts: unix_now(),
                    interval_s: opts.interval_s,
                    skipped_lines,
                };
                match publisher.publish(&snapshot_json(&meta, &snap)) {
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
