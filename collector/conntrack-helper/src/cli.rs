//! Minimal std-only argument parsing.

use std::path::PathBuf;

pub const DEFAULT_SOURCE: &str = "/proc/net/nf_conntrack";
pub const DEFAULT_SOCKET: &str = "/tmp/vigie/conntrack.sock";
pub const DEFAULT_INTERVAL_S: u64 = 60;
pub const DEFAULT_CT_MAX_FILE: &str = "/proc/sys/net/netfilter/nf_conntrack_max";
/// Bounds keep one snapshot line far below the publisher's 2 MiB cap (~230 bytes per record).
pub const MAX_TOP_N: usize = 2048;
pub const MAX_OTHER_K: usize = 2048;
/// uids that other services commonly share; a dedicated one is required unless overridden.
pub const SHARED_UIDS: [u32; 2] = [0, 65534];

pub const USAGE: &str =
    "usage: vigie-conntrack [--once] [--file PATH] [--socket PATH] [--interval SECS]\n\
  [--top-n N] [--max-flows N] [--uid UID] [--gid GID]\n\
  --once --file PATH   aggregate one file, print the snapshot JSON, exit (no socket)\n\
  defaults: --file /proc/net/nf_conntrack --socket /tmp/vigie/conntrack.sock --interval 60\n\
            --top-n 512 --other-k 64 --max-flows 32768 --conntrack-max-file
            /proc/sys/net/netfilter/nf_conntrack_max
  --uid must be a dedicated user; 0 and 65534 (nobody) need --allow-shared-uid
  the daemon refuses to start when nf_conntrack_max exceeds --max-flows (unless --max-flows is
  given explicitly)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub once: bool,
    pub source: PathBuf,
    pub socket: PathBuf,
    pub interval_s: u64,
    pub top_n: usize,
    pub other_k: usize,
    pub max_flows: usize,
    /// `--max-flows` was given, so the nf_conntrack_max startup check is the owner's call.
    pub max_flows_set: bool,
    pub conntrack_max_file: PathBuf,
    pub allow_shared_uid: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            once: false,
            source: PathBuf::from(DEFAULT_SOURCE),
            socket: PathBuf::from(DEFAULT_SOCKET),
            interval_s: DEFAULT_INTERVAL_S,
            top_n: crate::agg::DEFAULT_TOP_N,
            other_k: crate::agg::DEFAULT_OTHER_K,
            max_flows: crate::agg::DEFAULT_MAX_FLOWS,
            max_flows_set: false,
            conntrack_max_file: PathBuf::from(DEFAULT_CT_MAX_FILE),
            allow_shared_uid: false,
            uid: None,
            gid: None,
        }
    }
}

fn ranged<T: std::str::FromStr + PartialOrd>(
    flag: &str,
    v: &str,
    lo: T,
    hi: T,
) -> Result<T, String> {
    match v.parse::<T>() {
        Ok(n) if n >= lo && n <= hi => Ok(n),
        _ => Err(format!("{flag}: invalid value {v:?}")),
    }
}

pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--once" => {
                o.once = true;
                continue;
            }
            "--allow-shared-uid" => {
                o.allow_shared_uid = true;
                continue;
            }
            _ => {}
        }
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag:?}"));
        }
        let v = it.next().ok_or_else(|| format!("{flag}: missing value"))?;
        match flag.as_str() {
            "--file" => o.source = PathBuf::from(v),
            "--socket" => o.socket = PathBuf::from(v),
            "--interval" => o.interval_s = ranged(&flag, &v, 1, 86_400)?,
            "--top-n" => o.top_n = ranged(&flag, &v, 1, MAX_TOP_N)?,
            "--other-k" => o.other_k = ranged(&flag, &v, 0, MAX_OTHER_K)?,
            "--max-flows" => {
                o.max_flows = ranged(&flag, &v, 1, usize::MAX)?;
                o.max_flows_set = true;
            }
            "--conntrack-max-file" => o.conntrack_max_file = PathBuf::from(v),
            "--uid" => o.uid = Some(ranged(&flag, &v, 0, u32::MAX)?),
            "--gid" => o.gid = Some(ranged(&flag, &v, 0, u32::MAX)?),
            _ => return Err(format!("unknown flag {flag:?}")),
        }
    }
    check_uid(&o)?;
    Ok(o)
}

/// The dedicated-uid rule, applied after parsing: see the shared-uid section of the doc.
fn check_uid(o: &Opts) -> Result<(), String> {
    match o.uid {
        Some(u) if SHARED_UIDS.contains(&u) && !o.allow_shared_uid => Err(format!(
            "--uid {u} is shared with other services; use a dedicated uid or pass --allow-shared-uid"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Opts, String> {
        parse_args(a.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults() {
        let o = p(&[]).unwrap();
        assert_eq!(o, Opts::default());
        assert_eq!(o.interval_s, 60);
        assert_eq!(o.top_n, 512);
        assert_eq!(o.max_flows, 32768);
        assert!(!o.once);
        assert_eq!(o.other_k, 64);
        assert!(!o.max_flows_set && !o.allow_shared_uid);
    }

    #[test]
    fn once_file_and_overrides() {
        let o = p(&[
            "--once",
            "--file",
            "/x/ct",
            "--socket",
            "/run/s",
            "--interval",
            "30",
            "--top-n",
            "7",
            "--max-flows",
            "99",
            "--uid",
            "20001",
            "--gid",
            "20002",
            "--other-k",
            "9",
        ])
        .unwrap();
        assert!(o.once);
        assert_eq!(o.source, PathBuf::from("/x/ct"));
        assert_eq!(o.socket, PathBuf::from("/run/s"));
        assert_eq!((o.interval_s, o.top_n, o.max_flows), (30, 7, 99));
        assert!(o.max_flows_set);
        assert_eq!(o.other_k, 9);
        assert_eq!((o.uid, o.gid), (Some(20001), Some(20002)));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(p(&["--bogus"]).is_err());
        assert!(p(&["--file"]).is_err());
        assert!(p(&["--interval", "abc"]).is_err());
        assert!(p(&["--interval", "0"]).is_err());
        assert!(p(&["--interval", "86401"]).is_err());
        assert!(p(&["--top-n", "0"]).is_err());
        assert!(p(&["--max-flows", "0"]).is_err());
        assert!(p(&["--uid", "-1"]).is_err());
        assert!(p(&["positional"]).is_err());
    }

    #[test]
    fn shared_uids_are_refused_unless_explicitly_allowed() {
        for uid in ["0", "65534"] {
            let e = p(&["--uid", uid]).unwrap_err();
            assert!(e.contains("--allow-shared-uid"), "{e}");
            let o = p(&["--uid", uid, "--allow-shared-uid"]).unwrap();
            assert!(o.allow_shared_uid);
            assert_eq!(o.uid, uid.parse().ok());
        }
        assert!(p(&["--uid", "65533"]).is_ok());
        assert!(p(&["--uid", "1"]).is_ok());
        assert!(p(&[]).is_ok());
    }

    #[test]
    fn record_caps_are_bounded() {
        assert!(p(&["--top-n", "2049"]).is_err());
        assert!(p(&["--other-k", "2049"]).is_err());
        assert!(p(&["--other-k", "0"]).is_ok());
    }
}
