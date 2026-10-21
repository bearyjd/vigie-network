//! Startup and periodic sanity checks: the flow table the kernel may hold must fit the tracking
//! cap with room for two samples of tombstones (3 x `nf_conntrack_max`), or the aggregator would
//! have to evict live flows. Anything unverifiable fails closed unless `--max-flows` was given.

use std::io;
use std::path::Path;

/// Tracking cap as a multiple of the kernel table size: live flows + two samples of tombstones.
pub const FLOWS_PER_CT: u64 = 3;
/// Largest cap derived automatically (~30 MB of state); more needs an explicit `--max-flows`.
pub const MAX_DERIVED_FLOWS: u64 = FLOWS_PER_CT * 65_536;
/// Samples between re-reads of `nf_conntrack_max` in the daemon.
pub const DEFAULT_RECHECK_SAMPLES: u64 = 60;

/// Result of reading `nf_conntrack_max`.
#[derive(Debug, PartialEq, Eq)]
pub enum CtMax {
    /// Not found, but `--max-flows` was given: unverified, the caller must warn.
    Unknown,
    /// Kernel limit, and whether the explicit cap is below `FLOWS_PER_CT` x it.
    Known { max: u64, below_3x: bool },
}

fn read_max(path: &Path) -> Result<Option<u64>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    text.trim()
        .parse()
        .map(Some)
        .map_err(|_| format!("{}: not a number: {:?}", path.display(), text.trim()))
}

fn not_found(path: &Path) -> String {
    format!(
        "{} not found: cannot size the flow table (is nf_conntrack loaded?); pass --max-flows to \
         accept an unverified cap",
        path.display()
    )
}

/// The cap used when `--max-flows` is absent: `FLOWS_PER_CT` x `nf_conntrack_max`. Fails closed
/// when the file is missing, and refuses a table too large to track by default.
pub fn default_max_flows(path: &Path) -> Result<usize, String> {
    let max = read_max(path)?.ok_or_else(|| not_found(path))?;
    let want = max.saturating_mul(FLOWS_PER_CT);
    if want > MAX_DERIVED_FLOWS {
        return Err(format!(
            "nf_conntrack_max is {max}: tracking {FLOWS_PER_CT}x that would need {want} flows \
             (limit {MAX_DERIVED_FLOWS} by default); pass --max-flows {want} to accept the \
             memory cost"
        ));
    }
    Ok(want as usize)
}

/// Stub table size for a given flow cap: two thirds of it, i.e. 2 x `nf_conntrack_max`.
pub fn stub_cap(max_flows: usize) -> usize {
    max_flows / FLOWS_PER_CT as usize * 2
}

/// Refuses (Err) when `nf_conntrack_max` is unreadable or `max_flows` is below
/// `FLOWS_PER_CT` x it, unless `--max-flows` was given: that is the owner's decision, reported
/// through the result (`Unknown` / `below_3x`) so the caller can warn loudly.
pub fn check_conntrack_max(
    path: &Path,
    max_flows: usize,
    max_flows_explicit: bool,
) -> Result<CtMax, String> {
    let Some(max) = read_max(path)? else {
        return if max_flows_explicit {
            Ok(CtMax::Unknown)
        } else {
            Err(not_found(path))
        };
    };
    let below_3x = (max_flows as u64) < max.saturating_mul(FLOWS_PER_CT);
    if below_3x && !max_flows_explicit {
        return Err(format!(
            "nf_conntrack_max is {max} but --max-flows is {max_flows}: a full table plus \
             tombstones needs {FLOWS_PER_CT}x ({}) or live flows get evicted and their bytes \
             may be counted twice; pass --max-flows {} (or more)",
            max.saturating_mul(FLOWS_PER_CT),
            max.saturating_mul(FLOWS_PER_CT)
        ));
    }
    Ok(CtMax::Known { max, below_3x })
}

/// Cap to run with, plus the table check. Without `--max-flows` the cap is derived from the
/// kernel limit (fail closed if it cannot be read).
pub fn resolve_max_flows(
    path: &Path,
    configured: usize,
    explicit: bool,
) -> Result<(usize, CtMax), String> {
    let max_flows = if explicit {
        configured
    } else {
        default_max_flows(path)?
    };
    check_conntrack_max(path, max_flows, explicit).map(|c| (max_flows, c))
}

/// Whether sample number `seq` (1-based) should re-read `nf_conntrack_max`.
pub fn recheck_due(seq: u64, every: u64) -> bool {
    every > 0 && seq.is_multiple_of(every)
}

/// Periodic re-read: `Some(reason)` when the table may now outgrow the cap (the kernel limit
/// grew beyond `max_flows / FLOWS_PER_CT`) or cannot be read. Never silent.
pub fn recheck_pressure(path: &Path, max_flows: usize) -> Option<String> {
    match read_max(path) {
        Ok(Some(max)) if max > max_flows as u64 / FLOWS_PER_CT => Some(format!(
            "nf_conntrack_max grew to {max}, above max-flows/{FLOWS_PER_CT} ({}): live flows \
             may be evicted",
            max_flows as u64 / FLOWS_PER_CT
        )),
        Ok(Some(_)) => None,
        Ok(None) => Some(format!("{} disappeared", path.display())),
        Err(e) => Some(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn file(tag: &str, content: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vigie-ctmax-{}-{tag}", std::process::id()));
        fs::write(&p, content).unwrap();
        p
    }

    fn missing() -> std::path::PathBuf {
        std::env::temp_dir().join("vigie-ctmax-definitely-missing")
    }

    #[test]
    fn three_times_the_kernel_limit_is_required() {
        let p = file("ok", "16384\n");
        let known = |below_3x| {
            Ok(CtMax::Known {
                max: 16384,
                below_3x,
            })
        };
        assert_eq!(check_conntrack_max(&p, 49152, false), known(false));
        let e = check_conntrack_max(&p, 49151, false).unwrap_err();
        assert!(e.contains("49152") && e.contains("--max-flows"), "{e}");
        assert!(
            check_conntrack_max(&p, 16384, false).is_err(),
            "1x is not enough"
        );
        assert!(
            check_conntrack_max(&p, 32768, false).is_err(),
            "2x is not enough"
        );
        // explicit: the owner's call, reported loudly by the caller
        assert_eq!(check_conntrack_max(&p, 16384, true), known(true));
        assert_eq!(check_conntrack_max(&p, 100_000, true), known(false));
    }

    #[test]
    fn default_cap_is_three_times_the_kernel_limit_with_a_ceiling() {
        assert_eq!(default_max_flows(&file("d1", "16384")), Ok(49152));
        assert_eq!(default_max_flows(&file("d2", "1000\n")), Ok(3000));
        assert_eq!(default_max_flows(&file("d3", "65536")), Ok(196_608));
        let e = default_max_flows(&file("d4", "262144")).unwrap_err();
        assert!(e.contains("262144") && e.contains("--max-flows"), "{e}");
        assert_eq!(stub_cap(49152), 32768);
    }

    #[test]
    fn missing_limit_file_fails_closed_unless_max_flows_is_explicit() {
        let e = check_conntrack_max(&missing(), 49152, false).unwrap_err();
        assert!(e.contains("--max-flows"), "{e}");
        assert!(default_max_flows(&missing()).is_err());
        assert!(resolve_max_flows(&missing(), 49152, false).is_err());
        assert_eq!(
            check_conntrack_max(&missing(), 49152, true),
            Ok(CtMax::Unknown)
        );
        assert_eq!(
            resolve_max_flows(&missing(), 777, true),
            Ok((777, CtMax::Unknown))
        );
    }

    #[test]
    fn garbage_limit_is_refused_even_when_explicit() {
        assert!(check_conntrack_max(&file("bad", "lots\n"), 1, true).is_err());
        assert!(check_conntrack_max(&file("neg", "-5"), 1, true).is_err());
    }

    #[test]
    fn resolve_derives_the_cap_from_the_kernel_limit_unless_explicit() {
        let p = file("res", "1000");
        assert_eq!(
            resolve_max_flows(&p, 49152, false),
            Ok((
                3000,
                CtMax::Known {
                    max: 1000,
                    below_3x: false
                }
            ))
        );
        assert_eq!(
            resolve_max_flows(&p, 1200, true),
            Ok((
                1200,
                CtMax::Known {
                    max: 1000,
                    below_3x: true
                }
            ))
        );
    }

    #[test]
    fn recheck_runs_every_n_samples() {
        assert!(!recheck_due(59, 60) && recheck_due(60, 60) && recheck_due(120, 60));
        assert!(!recheck_due(1, 60));
        assert!(recheck_due(1, 1) && recheck_due(2, 1));
        assert!(!recheck_due(5, 0), "0 disables");
    }

    #[test]
    fn recheck_flags_growth_beyond_a_third_of_the_cap_and_never_stays_silent() {
        let p = file("grow", "1000");
        assert_eq!(recheck_pressure(&p, 3000), None);
        assert_eq!(recheck_pressure(&p, 3003), None);
        let g = file("grow2", "1001");
        let msg = recheck_pressure(&g, 3000).expect("1001 > 3000/3");
        assert!(msg.contains("1001") && msg.contains("1000"), "{msg}");
        assert!(
            recheck_pressure(&missing(), 3000).is_some(),
            "vanished file"
        );
        assert!(
            recheck_pressure(&file("junk", "x"), 3000).is_some(),
            "unparsable file"
        );
    }
}
