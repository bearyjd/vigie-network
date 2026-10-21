//! Minimal std-only argument parsing.

use std::path::PathBuf;

pub const DEFAULT_SOURCE: &str = "/proc/net/nf_conntrack";
pub const DEFAULT_SOCKET: &str = "/tmp/vigie/conntrack.sock";
pub const DEFAULT_INTERVAL_S: u64 = 60;

pub const USAGE: &str =
    "usage: vigie-conntrack [--once] [--file PATH] [--socket PATH] [--interval SECS]\n\
  [--top-n N] [--max-flows N] [--uid UID] [--gid GID]\n\
  --once --file PATH   aggregate one file, print the snapshot JSON, exit (no socket)\n\
  defaults: --file /proc/net/nf_conntrack --socket /tmp/vigie/conntrack.sock --interval 60\n\
            --top-n 512 --max-flows 32768";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub once: bool,
    pub source: PathBuf,
    pub socket: PathBuf,
    pub interval_s: u64,
    pub top_n: usize,
    pub max_flows: usize,
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
            max_flows: crate::agg::DEFAULT_MAX_FLOWS,
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
        if flag == "--once" {
            o.once = true;
            continue;
        }
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag:?}"));
        }
        let v = it.next().ok_or_else(|| format!("{flag}: missing value"))?;
        match flag.as_str() {
            "--file" => o.source = PathBuf::from(v),
            "--socket" => o.socket = PathBuf::from(v),
            "--interval" => o.interval_s = ranged(&flag, &v, 1, 86_400)?,
            "--top-n" => o.top_n = ranged(&flag, &v, 1, usize::MAX)?,
            "--max-flows" => o.max_flows = ranged(&flag, &v, 1, usize::MAX)?,
            "--uid" => o.uid = Some(ranged(&flag, &v, 0, u32::MAX)?),
            "--gid" => o.gid = Some(ranged(&flag, &v, 0, u32::MAX)?),
            _ => return Err(format!("unknown flag {flag:?}")),
        }
    }
    Ok(o)
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
            "65534",
            "--gid",
            "65533",
        ])
        .unwrap();
        assert!(o.once);
        assert_eq!(o.source, PathBuf::from("/x/ct"));
        assert_eq!(o.socket, PathBuf::from("/run/s"));
        assert_eq!((o.interval_s, o.top_n, o.max_flows), (30, 7, 99));
        assert_eq!((o.uid, o.gid), (Some(65534), Some(65533)));
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
}
