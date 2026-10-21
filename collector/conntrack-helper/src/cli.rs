//! Minimal std-only argument parsing.

use crate::lan::Cidr;
use std::path::PathBuf;

pub const DEFAULT_SOURCE: &str = "/proc/net/nf_conntrack";
pub const DEFAULT_SOCKET: &str = "/tmp/vigie/conntrack.sock";
pub const DEFAULT_INTERVAL_S: u64 = 60;
pub const DEFAULT_CT_MAX_FILE: &str = "/proc/sys/net/netfilter/nf_conntrack_max";
/// Bounds keep one snapshot line far below the publisher's 2 MiB cap (~230 bytes per record).
pub const MAX_TOP_N: usize = 2048;
pub const MAX_K: usize = 2048;
/// uids that other services commonly share; a dedicated one is required unless overridden.
pub const SHARED_UIDS: [u32; 2] = [0, 65534];
/// Below this are system uids (daemons, root-adjacent accounts); not a dedicated agent user.
pub const MIN_DEDICATED_UID: u32 = 1000;

pub const USAGE: &str =
    "usage: vigie-conntrack [--once] [--file PATH] [--socket PATH] [--interval SECS]\n\
  [--top-n N] [--k-lan N] [--k-wan N] [--lan-cidr NET] [--max-flows N] [--stub-ttl-samples N] [--uid UID] [--gid GID]\n\
  --once --file PATH   aggregate one file, print the snapshot JSON, exit (no socket)\n\
  defaults: --file /proc/net/nf_conntrack --socket /tmp/vigie/conntrack.sock --interval 60\n\
            --top-n 512 --k-lan 192 --k-wan 64 --conntrack-max-file
            /proc/sys/net/netfilter/nf_conntrack_max --ct-recheck-samples 60 --stub-ttl-samples 30
  --lan-cidr NET (repeatable) replaces the default LAN prefixes (10/8 172.16/12 192.168/16
  100.64/10 fe80::/10 fc00::/7); LAN and other sources get separate record quotas, so list the
  real LAN prefixes: spoofed private sources arriving from the WAN can fill the LAN quota
  --max-flows defaults to 3 x nf_conntrack_max; the daemon refuses to start when that file is
  unreadable or the cap is below 3 x it, unless --max-flows is given explicitly (then a lower
  cap only warns loudly and sets table_pressure)
  --uid must be a dedicated user with uid >= 1000; 0, 65534 (nobody) and system uids below
  1000 need --allow-shared-uid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub once: bool,
    pub source: PathBuf,
    pub socket: PathBuf,
    pub interval_s: u64,
    pub top_n: usize,
    pub k_lan: usize,
    pub k_wan: usize,
    /// `--lan-cidr` values; empty means the defaults (see `lan::default_lan`).
    pub lan_cidrs: Vec<Cidr>,
    pub max_flows: usize,
    /// `--max-flows` was given, so the nf_conntrack_max startup check is the owner's call.
    pub max_flows_set: bool,
    /// Samples between re-reads of `nf_conntrack_max` in the daemon.
    pub ct_recheck_samples: u64,
    pub conntrack_max_file: PathBuf,
    pub allow_shared_uid: bool,
    /// Samples an eviction stub is kept (see `agg::AggConfig::stub_ttl_samples`).
    pub stub_ttl_samples: u64,
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
            k_lan: crate::agg::DEFAULT_K_LAN,
            k_wan: crate::agg::DEFAULT_K_WAN,
            lan_cidrs: Vec::new(),
            max_flows: crate::agg::DEFAULT_MAX_FLOWS,
            max_flows_set: false,
            ct_recheck_samples: crate::limits::DEFAULT_RECHECK_SAMPLES,
            conntrack_max_file: PathBuf::from(DEFAULT_CT_MAX_FILE),
            allow_shared_uid: false,
            stub_ttl_samples: crate::agg::DEFAULT_STUB_TTL_SAMPLES,
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
            "--k-lan" => o.k_lan = ranged(&flag, &v, 0, MAX_K)?,
            "--k-wan" => o.k_wan = ranged(&flag, &v, 0, MAX_K)?,
            "--lan-cidr" => o.lan_cidrs.push(Cidr::parse(&v)?),
            "--max-flows" => {
                o.max_flows = ranged(&flag, &v, 1, usize::MAX)?;
                o.max_flows_set = true;
            }
            "--stub-ttl-samples" => o.stub_ttl_samples = ranged(&flag, &v, 1, 1_000_000)?,
            "--ct-recheck-samples" => o.ct_recheck_samples = ranged(&flag, &v, 1, 1_000_000)?,
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
        Some(u) if (SHARED_UIDS.contains(&u) || u < MIN_DEDICATED_UID) && !o.allow_shared_uid => Err(format!(
            "--uid {u} is a system or shared uid; use a dedicated uid >= {MIN_DEDICATED_UID} or pass --allow-shared-uid"
        )),
        _ => Ok(()),
    }
}

/// Root must name the unprivileged agent's uid, or the agent could not connect to the socket.
pub fn check_root_needs_uid(euid: u32, uid: Option<u32>) -> Result<(), String> {
    if euid == 0 && uid.is_none() {
        return Err(
            "running as root requires --uid (and --gid) of the unprivileged agent, \
                    otherwise the agent could not connect to the socket"
                .to_string(),
        );
    }
    Ok(())
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
        assert_eq!(o.max_flows, 49152);
        assert!(!o.once);
        assert_eq!((o.k_lan, o.k_wan), (192, 64));
        assert!(o.lan_cidrs.is_empty());
        assert!(!o.max_flows_set && !o.allow_shared_uid);
        assert_eq!(o.stub_ttl_samples, 30);
    }

    #[test]
    fn stub_ttl_flag_is_parsed_and_bounded() {
        assert_eq!(p(&["--stub-ttl-samples", "5"]).unwrap().stub_ttl_samples, 5);
        assert!(p(&["--stub-ttl-samples", "0"]).is_err());
        assert!(p(&["--stub-ttl-samples", "1000001"]).is_err());
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
            "--k-lan",
            "9",
            "--k-wan",
            "3",
            "--lan-cidr",
            "192.168.8.0/24",
            "--lan-cidr",
            "fd00::/8",
        ])
        .unwrap();
        assert!(o.once);
        assert_eq!(o.source, PathBuf::from("/x/ct"));
        assert_eq!(o.socket, PathBuf::from("/run/s"));
        assert_eq!((o.interval_s, o.top_n, o.max_flows), (30, 7, 99));
        assert!(o.max_flows_set);
        assert_eq!((o.k_lan, o.k_wan), (9, 3));
        assert_eq!(o.lan_cidrs.len(), 2);
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
    fn shared_and_low_uids_are_refused_unless_explicitly_allowed() {
        for uid in ["0", "1", "999", "65534"] {
            let e = p(&["--uid", uid]).unwrap_err();
            assert!(e.contains("--allow-shared-uid"), "{e}");
            let o = p(&["--uid", uid, "--allow-shared-uid"]).unwrap();
            assert!(o.allow_shared_uid);
            assert_eq!(o.uid, uid.parse().ok());
        }
        for uid in ["1000", "20001", "65533"] {
            assert!(p(&["--uid", uid]).is_ok(), "uid {uid}");
        }
        assert!(p(&[]).is_ok());
    }

    #[test]
    fn root_requires_an_explicit_uid() {
        let e = check_root_needs_uid(0, None).unwrap_err();
        assert!(e.contains("--uid"), "{e}");
        assert!(check_root_needs_uid(0, Some(20001)).is_ok());
        assert!(
            check_root_needs_uid(1000, None).is_ok(),
            "non-root needs no --uid"
        );
        assert!(check_root_needs_uid(1000, Some(20001)).is_ok());
    }

    #[test]
    fn record_caps_are_bounded() {
        assert!(p(&["--top-n", "2049"]).is_err());
        assert!(p(&["--k-lan", "2049"]).is_err());
        assert!(p(&["--k-wan", "2049"]).is_err());
        assert!(p(&["--k-lan", "0", "--k-wan", "0"]).is_ok());
        assert!(p(&["--lan-cidr", "10.0.0.0/33"]).is_err());
        assert!(p(&["--lan-cidr", "garbage"]).is_err());
    }
}
