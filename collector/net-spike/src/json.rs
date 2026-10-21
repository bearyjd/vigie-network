//! Tiny hand-rolled JSON writer (avoids a serde dependency in the spike).

use std::collections::BTreeSet;
use std::fs;

use crate::filter::Filter;
use crate::stats::Stats;
use crate::{Args, Notes};

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn arr(set: &BTreeSet<String>) -> String {
    let items: Vec<String> = set.iter().map(|s| esc(s)).collect();
    format!("[{}]", items.join(","))
}

/// Pull a `Key:   123 kB` line out of /proc/self/status.
fn proc_kb(key: &str) -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix(key)?
            .trim_start_matches(':')
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn kb_json(key: &str) -> String {
    proc_kb(key).map_or("null".to_string(), |v| v.to_string())
}

pub fn summary(args: &Args, f: &Filter, s: &Stats, notes: &Notes) -> String {
    let methods: Vec<String> = s
        .ssdp_methods
        .iter()
        .map(|(k, v)| format!("{}:{v}", esc(k)))
        .collect();
    format!(
        concat!(
            "{{\"secs\":{},\"addr\":{},\"prefix\":{},\"iface\":{},",
            "\"mdns6\":{},\"ssdp_socket\":{},\"own_v6_unknown\":{},",
            "\"packets\":{{\"mdns4\":{},\"mdns6\":{},\"ssdp\":{}}},",
            "\"own_packets\":{},\"offlink_packets\":{},\"read_errors\":{},",
            "\"parse_errors\":{},\"mdns_truncated\":{},\"evidence_dropped\":{},\"own_v6_addrs\":{},",
            "\"mdns\":{{\"names\":{},\"services\":{}}},",
            "\"ssdp\":{{\"methods\":{{{}}},\"server\":{},\"nt_st\":{},\"usn\":{}}},",
            "\"VmRSS_kB\":{},\"VmHWM_kB\":{}}}"
        ),
        args.secs,
        esc(&args.addr.to_string()),
        args.prefix,
        args.iface.as_deref().map_or("null".to_string(), esc),
        esc(&notes.mdns6),
        esc(&notes.ssdp),
        notes.own_v6_unknown,
        s.mdns4_packets,
        s.mdns6_packets,
        s.ssdp_packets,
        s.own_packets,
        s.offlink_packets,
        s.read_errors,
        s.parse_errors,
        s.mdns_truncated,
        s.evidence.dropped,
        f.own_v6.len(),
        arr(&s.mdns_names),
        arr(&s.mdns_services),
        methods.join(","),
        arr(&s.ssdp_servers),
        arr(&s.ssdp_nt),
        arr(&s.ssdp_usn),
        kb_json("VmRSS"),
        kb_json("VmHWM"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reports_filter_and_drop_counters() {
        let args = Args {
            addr: "192.168.1.1".parse().unwrap(),
            prefix: 24,
            iface: None,
            v6: false,
            include_own: false,
            secs: 1,
        };
        let f = Filter {
            lan: args.addr,
            prefix: 24,
            own_v6: vec![],
            include_own: false,
        };
        let mut st = Stats {
            own_packets: 3,
            offlink_packets: 4,
            read_errors: 5,
            mdns_truncated: 6,
            ..Stats::default()
        };
        st.evidence.dropped = 7;
        let j = summary(
            &args,
            &f,
            &st,
            &Notes {
                mdns6: "x\"y".into(),
                ssdp: "failed: busy".into(),
                own_v6_unknown: true,
            },
        );
        for want in [
            "\"own_packets\":3",
            "\"offlink_packets\":4",
            "\"read_errors\":5",
            "\"mdns_truncated\":6",
            "\"evidence_dropped\":7",
            "\"prefix\":24",
            "\"mdns6\":\"x\\\"y\"",
            "\"ssdp_socket\":\"failed: busy\"",
            "\"own_v6_unknown\":true",
        ] {
            assert!(j.contains(want), "{want} missing in {j}");
        }
    }
}
