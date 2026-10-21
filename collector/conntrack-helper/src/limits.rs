//! Startup sanity check: the flow table the kernel may hold must fit the tracking cap, or the
//! aggregator would evict live flows and later count their lifetime bytes again.

use std::io;
use std::path::Path;

/// Result of reading `nf_conntrack_max`.
#[derive(Debug, PartialEq, Eq)]
pub enum CtMax {
    /// Could not be read (module not loaded, not Linux): unverified, the caller should warn.
    Unknown,
    /// Kernel limit, and whether it exceeds the cap the owner chose explicitly.
    Known { max: u64, over_explicit_cap: bool },
}

/// Refuses (Err) when the kernel limit exceeds `max_flows` and `--max-flows` was not given.
/// An explicit `--max-flows` is the owner's decision and is only reported.
pub fn check_conntrack_max(
    path: &Path,
    max_flows: usize,
    max_flows_explicit: bool,
) -> Result<CtMax, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(CtMax::Unknown),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let max: u64 = text
        .trim()
        .parse()
        .map_err(|_| format!("{}: not a number: {:?}", path.display(), text.trim()))?;
    let over = max > max_flows as u64;
    if over && !max_flows_explicit {
        return Err(format!(
            "nf_conntrack_max is {max} but --max-flows is {max_flows}: a full table would evict \
             live flows and count their bytes twice; pass --max-flows {max} (or more) to accept \
             the memory cost"
        ));
    }
    Ok(CtMax::Known {
        max,
        over_explicit_cap: over,
    })
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

    #[test]
    fn at_or_below_the_cap_is_fine() {
        let p = file("ok", "16384\n");
        let r = check_conntrack_max(&p, 16384, false).unwrap();
        assert_eq!(
            r,
            CtMax::Known {
                max: 16384,
                over_explicit_cap: false
            }
        );
        assert!(check_conntrack_max(&p, 32768, false).is_ok());
    }

    #[test]
    fn above_the_cap_is_refused_unless_max_flows_was_given() {
        let p = file("over", "262144\n");
        let e = check_conntrack_max(&p, 32768, false).unwrap_err();
        assert!(e.contains("262144") && e.contains("--max-flows"), "{e}");
        let r = check_conntrack_max(&p, 32768, true).unwrap();
        assert_eq!(
            r,
            CtMax::Known {
                max: 262144,
                over_explicit_cap: true
            }
        );
    }

    #[test]
    fn missing_file_is_unknown_but_garbage_is_refused() {
        let p = std::env::temp_dir().join("vigie-ctmax-definitely-missing");
        assert_eq!(check_conntrack_max(&p, 1, false), Ok(CtMax::Unknown));
        assert!(check_conntrack_max(&file("bad", "lots\n"), 1, false).is_err());
        assert!(check_conntrack_max(&file("neg", "-5"), 1, false).is_err());
    }
}
