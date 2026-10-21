use std::fs::File;
use vigie_conntrack::agg::{AggConfig, Aggregator};
use vigie_conntrack::parse::read_flows;

fn fixture(name: &str) -> File {
    File::open(format!(
        "{}/tests/fixtures/conntrack/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn ipv4_fixture_parses_all_lines() {
    let (flows, skipped) = read_flows(fixture("ipv4_tcp_udp.txt")).unwrap();
    assert_eq!((flows.len(), skipped), (6, 0));
}

#[test]
fn ipv6_fixture_parses_all_lines() {
    let (flows, skipped) = read_flows(fixture("ipv6.txt")).unwrap();
    assert_eq!((flows.len(), skipped), (3, 0));
    assert!(flows.iter().all(|f| f.key.src.is_ipv6()));
}

#[test]
fn nat_and_garbage_fixture_skips_only_bad_lines() {
    let (flows, skipped) = read_flows(fixture("nat_and_odd.txt")).unwrap();
    assert_eq!(flows.len(), 3);
    assert_eq!(skipped, 4, "blank lines must not count");
}

#[test]
fn non_utf8_and_overlong_lines_are_skipped_not_fatal() {
    let good = "ipv4 2 udp 17 29 src=192.168.8.10 dst=8.8.8.8 sport=1 dport=53 packets=1 bytes=70 src=8.8.8.8 dst=192.168.8.10 sport=53 dport=1 packets=1 bytes=120\n";
    let mut data = Vec::new();
    data.extend_from_slice(good.as_bytes());
    data.extend_from_slice(b"ipv4 2 tcp \xff\xfe\xfd garbage\n");
    data.extend_from_slice("A".repeat(100_000).as_bytes());
    data.push(b'\n');
    data.extend_from_slice(good.as_bytes());
    // final line without trailing newline
    data.extend_from_slice(good.trim_end().as_bytes());
    let (flows, skipped) = read_flows(&data[..]).unwrap();
    assert_eq!(flows.len(), 3);
    assert_eq!(skipped, 2);
}

#[test]
fn input_beyond_the_byte_cap_is_truncated() {
    let line = "ipv4 2 udp 17 29 src=192.168.8.10 dst=8.8.8.8 sport=1 dport=53\n";
    let n = (vigie_conntrack::parse::MAX_INPUT_BYTES as usize / line.len()) + 1000;
    let data = line.repeat(n);
    let (flows, _) = read_flows(data.as_bytes()).unwrap();
    assert!(flows.len() < n);
    assert!(flows.len() * line.len() <= vigie_conntrack::parse::MAX_INPUT_BYTES as usize);
}

#[test]
fn fixture_aggregates_end_to_end() {
    let (flows, _) = read_flows(fixture("ipv4_tcp_udp.txt")).unwrap();
    let mut a = Aggregator::new(AggConfig {
        baseline_first: false,
        ..AggConfig::default()
    });
    let snap = a.ingest(&flows);
    assert_eq!(snap.records.len(), 6);
    let dns = snap
        .records
        .iter()
        .find(|r| r.dport == Some(53) && r.proto == Some(17))
        .unwrap();
    assert_eq!((dns.bytes_up, dns.bytes_down), (70, 120));
    assert_eq!(dns.src.to_string(), "192.168.8.10");
}
