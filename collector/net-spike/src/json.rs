//! Tiny hand-rolled JSON writer (avoids a serde dependency in the spike).

use std::collections::BTreeSet;
use std::fs;

use crate::{Args, Stats};

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

pub fn summary(args: &Args, s: &Stats, m6_note: &str) -> String {
    let methods: Vec<String> = s
        .ssdp_methods
        .iter()
        .map(|(k, v)| format!("{}:{v}", esc(k)))
        .collect();
    format!(
        concat!(
            "{{\"secs\":{},\"addr\":{},\"iface\":{},",
            "\"mdns6\":{},",
            "\"packets\":{{\"mdns4\":{},\"mdns6\":{},\"ssdp\":{}}},",
            "\"parse_errors\":{},",
            "\"mdns\":{{\"names\":{},\"services\":{}}},",
            "\"ssdp\":{{\"methods\":{{{}}},\"server\":{},\"nt_st\":{},\"usn\":{}}},",
            "\"VmRSS_kB\":{},\"VmHWM_kB\":{}}}"
        ),
        args.secs,
        esc(&args.addr.to_string()),
        args.iface.as_deref().map_or("null".to_string(), esc),
        esc(m6_note),
        s.mdns4_packets,
        s.mdns6_packets,
        s.ssdp_packets,
        s.parse_errors,
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
