//! Snapshot parser: valid lines (including the helper's real serializer), and every hostile shape.

use std::net::IpAddr;

use vigie_agent::ctparse::{parse_snapshot, Kind, ParseError, MAX_DEPTH, MAX_LINE, MAX_RECORDS};
use vigie_agent::model::Proto;

const HEAD: &str = r#""v":1,"seq":3,"ts":1700000000,"interval_s":60,"skipped_lines":0,"acct_off":false,"folded":0,"evicted":0,"recounted_flows":0,"dropped_new_keys":0,"table_pressure":false"#;

fn line(records: &str) -> String {
    format!(r#"{{{HEAD},"records":[{records}]}}"#)
}

const TUPLE: &str = r#"{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"packets_up":1,"packets_down":1,"flows":1,"new_flows":0}"#;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn a_valid_snapshot_parses_every_field() {
    let other = r#"{"src":"fd00::1","other":true,"bytes_up":7,"bytes_down":8,"packets_up":9,"packets_down":10,"flows":11,"new_flows":12}"#;
    let global = r#"{"src":"0.0.0.0","other_global":true,"bytes_up":1,"bytes_down":2,"packets_up":0,"packets_down":0,"flows":3,"new_flows":0}"#;
    let s = parse_snapshot(line(&format!("{TUPLE},{other},{global}")).as_bytes()).unwrap();
    assert_eq!((s.seq, s.ts, s.interval_s), (3, 1_700_000_000, 60));
    assert_eq!(s.records.len(), 3);
    let t = &s.records[0];
    assert_eq!(t.src, ip("192.168.8.10"));
    assert_eq!(
        (t.kind, t.dst, t.dport),
        (Kind::Tuple, Some(ip("8.8.8.8")), Some(53))
    );
    assert_eq!(
        (t.proto, t.bytes_up, t.bytes_down, t.flows),
        (Proto::Udp, 70, 120, 1)
    );
    assert_eq!(s.records[1].kind, Kind::Other);
    assert_eq!((s.records[1].dst, s.records[1].dport), (None, None));
    assert_eq!(s.records[1].proto, Proto::Other);
    assert_eq!(s.records[2].kind, Kind::OtherGlobal);
}

#[test]
fn flags_and_counters_are_read() {
    let l = r#"{"v":1,"seq":1,"ts":2,"interval_s":3,"acct_off":true,"recounted_flows":7,"dropped_new_keys":9,"table_pressure":true,"records":[]}"#;
    let s = parse_snapshot(l.as_bytes()).unwrap();
    assert!(s.acct_off && s.table_pressure);
    assert_eq!((s.recounted_flows, s.dropped_new_keys), (7, 9));
    let clear = parse_snapshot(line("").as_bytes()).unwrap();
    assert!(!clear.acct_off && !clear.table_pressure);
}

#[test]
fn protocol_names_map_and_unknown_ones_become_other() {
    for (name, want) in [
        ("tcp", Proto::Tcp),
        ("udp", Proto::Udp),
        ("icmp", Proto::Icmp),
        ("icmpv6", Proto::Icmpv6),
        ("proto-47", Proto::Other),
    ] {
        let r = TUPLE.replace("\"udp\"", &format!("\"{name}\""));
        let s = parse_snapshot(line(&r).as_bytes()).unwrap();
        assert_eq!(s.records[0].proto, want, "{name}");
    }
    let bad = TUPLE.replace("\"udp\"", "\"sctp-ish\"");
    assert!(
        parse_snapshot(line(&bad).as_bytes()).is_err(),
        "free text is not a protocol"
    );
}

#[test]
fn the_helpers_own_serializer_round_trips() {
    use vigie_conntrack::agg::{Record, Snapshot};
    use vigie_conntrack::json::{snapshot_json, Meta};
    let rec = |src: &str, dst: Option<&str>, global: bool, n: u64| Record {
        src: ip(src),
        dst: dst.map(ip),
        dport: dst.map(|_| 443),
        proto: dst.map(|_| 6),
        bytes_up: n,
        bytes_down: n * 2,
        packets_up: 1,
        packets_down: 2,
        flows: n,
        new_flows: 1,
        global,
    };
    let snap = Snapshot {
        records: vec![
            rec("192.168.8.10", Some("93.184.216.34"), false, 5),
            rec("fe80::1", Some("2001:db8::1"), false, 6),
            rec("192.168.8.11", None, false, 7),
            rec("0.0.0.0", None, true, 8),
        ],
        folded: 4,
        evicted: 5,
        recounted_flows: 6,
        dropped_new_keys: 7,
        table_pressure: true,
    };
    let meta = Meta {
        seq: 9,
        ts: 1_700_000_001,
        interval_s: 60,
        skipped_lines: 2,
        acct_off: true,
    };
    let json = snapshot_json(&meta, &snap);
    let s = parse_snapshot(json.as_bytes()).unwrap();
    assert_eq!((s.seq, s.ts, s.interval_s), (9, 1_700_000_001, 60));
    assert!(s.acct_off && s.table_pressure);
    assert_eq!((s.recounted_flows, s.dropped_new_keys), (6, 7));
    let kinds: Vec<Kind> = s.records.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [Kind::Tuple, Kind::Tuple, Kind::Other, Kind::OtherGlobal]
    );
    assert_eq!(s.records[1].dst, Some(ip("2001:db8::1")));
    assert_eq!(s.records[0].proto, Proto::Tcp);
    assert_eq!(s.records[3].flows, 8);
}

#[test]
fn unknown_fields_of_any_shape_are_ignored() {
    let l = format!(
        r#"{{{HEAD},"future":{{"a":[1,2,{{"b":null}}],"c":"x\"y"}},"neg":-5,"f":1.5e3,"records":[{}]}}"#,
        TUPLE.replace(r#""flows":1"#, r#""flows":1,"extra":[true,false,null,"s"]"#)
    );
    let s = parse_snapshot(l.as_bytes()).unwrap();
    assert_eq!(s.records.len(), 1);
}

#[test]
fn garbage_and_truncated_lines_are_errors_not_panics() {
    let full = line(TUPLE);
    for n in 0..full.len() {
        assert!(
            parse_snapshot(&full.as_bytes()[..n]).is_err(),
            "prefix of {n} bytes"
        );
    }
    for g in [
        "",
        " ",
        "null",
        "[]",
        "42",
        "{",
        "}",
        "{}",
        "garbage",
        "{\"v\":1}",
        "\u{feff}{}",
    ] {
        assert!(parse_snapshot(g.as_bytes()).is_err(), "{g:?}");
    }
    assert!(parse_snapshot(&[0xff, 0xfe, b'{', b'}']).is_err());
}

#[test]
fn trailing_bytes_after_the_object_are_refused() {
    assert!(parse_snapshot(format!("{} x", line("")).as_bytes()).is_err());
    assert!(parse_snapshot(format!("{}{}", line(""), line("")).as_bytes()).is_err());
    assert!(
        parse_snapshot(format!("{}  ", line("")).as_bytes()).is_ok(),
        "whitespace is fine"
    );
}

#[test]
fn nul_and_control_bytes_are_refused_anywhere() {
    for b in [0u8, 1, 8, 0x1f] {
        let l = line(TUPLE).replace("8.8.8.8", &format!("8.8.8.{}", b as char));
        assert!(parse_snapshot(l.as_bytes()).is_err(), "byte {b}");
    }
    let l = format!(r#"{{{HEAD},"note":"a{}b","records":[]}}"#, '\0');
    assert_eq!(parse_snapshot(l.as_bytes()), Err(ParseError::ControlByte));
    let l = line("").replacen('{', "{\0", 1);
    assert!(parse_snapshot(l.as_bytes()).is_err());
}

#[test]
fn a_line_over_the_cap_is_refused_before_parsing() {
    let pad = "x".repeat(MAX_LINE);
    let l = format!(r#"{{{HEAD},"pad":"{pad}","records":[]}}"#);
    assert!(l.len() > MAX_LINE);
    assert_eq!(parse_snapshot(l.as_bytes()), Err(ParseError::TooLong));
    // exactly at the cap is allowed
    let head = format!(r#"{{{HEAD},"pad":"","records":[]}}"#);
    let fill = MAX_LINE - head.len();
    let at_cap = format!(r#"{{{HEAD},"pad":"{}","records":[]}}"#, "x".repeat(fill));
    assert_eq!(at_cap.len(), MAX_LINE);
    assert!(parse_snapshot(at_cap.as_bytes()).is_ok());
    let one_over = format!(
        r#"{{{HEAD},"pad":"{}","records":[]}}"#,
        "x".repeat(fill + 1)
    );
    assert_eq!(
        parse_snapshot(one_over.as_bytes()),
        Err(ParseError::TooLong)
    );
}

#[test]
fn backslashes_in_keys_and_used_values_are_refused() {
    let bs = '\\';
    for l in [
        line(&TUPLE.replace("\"flows\"", &format!("\"fl{bs}u006fws\""))),
        line(&TUPLE.replace("8.8.8.8", &format!("8.8.8{bs}u002e8"))),
        line(&TUPLE.replace("udp", &format!("ud{bs}u0070"))),
        format!("{{{HEAD},\"re{bs}u0063ords\":[]}}"),
    ] {
        assert!(
            matches!(parse_snapshot(l.as_bytes()), Err(ParseError::Syntax(_))),
            "{l}"
        );
    }
}

#[test]
fn duplicate_keys_are_refused_even_when_escaped_to_hide() {
    let dup_top = format!(r#"{{{HEAD},"records":[],"records":[]}}"#);
    assert_eq!(
        parse_snapshot(dup_top.as_bytes()),
        Err(ParseError::DuplicateKey("records"))
    );
    let dup_flag = format!(r#"{{{HEAD},"table_pressure":true,"records":[]}}"#);
    assert!(
        parse_snapshot(dup_flag.as_bytes()).is_err(),
        "second table_pressure"
    );
    let dup_rec = TUPLE.replace(r#""flows":1"#, r#""flows":1,"flows":99999"#);
    assert!(
        parse_snapshot(line(&dup_rec).as_bytes()).is_err(),
        "duplicate flows in a record"
    );
    let dup_src = TUPLE.replace(
        r#""src":"192.168.8.10""#,
        r#""src":"192.168.8.10","src":"10.9.9.9""#,
    );
    assert!(parse_snapshot(line(&dup_src).as_bytes()).is_err());
    let bs = '\\';
    let hidden = TUPLE.replace(
        r#""flows":1"#,
        &format!(r#""flows":1,"fl{bs}u006fws":99999"#),
    );
    assert!(
        parse_snapshot(line(&hidden).as_bytes()).is_err(),
        "escaped key"
    );
}

#[test]
fn huge_numbers_saturate_and_malformed_numbers_are_errors() {
    let big = "9".repeat(60);
    let r = TUPLE.replace(r#""bytes_up":70"#, &format!(r#""bytes_up":{big}"#));
    let s = parse_snapshot(line(&r).as_bytes()).unwrap();
    assert_eq!(s.records[0].bytes_up, u64::MAX);
    let r = TUPLE.replace(r#""flows":1"#, r#""flows":18446744073709551615"#);
    assert_eq!(
        parse_snapshot(line(&r).as_bytes()).unwrap().records[0].flows,
        u64::MAX
    );
    for bad in [
        "-1", "1.5", "1e3", "01", "+1", "0x10", "\"7\"", "true", "null", "[1]", "",
    ] {
        let r = TUPLE.replace(r#""bytes_down":120"#, &format!(r#""bytes_down":{bad}"#));
        assert!(
            parse_snapshot(line(&r).as_bytes()).is_err(),
            "bytes_down = {bad:?}"
        );
    }
    for bad in ["65536", "-1", "99999999999999999999"] {
        let r = TUPLE.replace(r#""dport":53"#, &format!(r#""dport":{bad}"#));
        assert!(
            parse_snapshot(line(&r).as_bytes()).is_err(),
            "dport = {bad}"
        );
    }
}

#[test]
fn version_must_be_one() {
    for v in ["2", "0", "\"1\"", "1.0", "true"] {
        let l = line("").replace(r#""v":1"#, &format!(r#""v":{v}"#));
        assert!(parse_snapshot(l.as_bytes()).is_err(), "v = {v}");
    }
    let none = line("").replace(r#""v":1,"#, "");
    assert_eq!(
        parse_snapshot(none.as_bytes()),
        Err(ParseError::Missing("v"))
    );
    let norec = r#"{"v":1}"#;
    assert_eq!(
        parse_snapshot(norec.as_bytes()),
        Err(ParseError::Missing("records"))
    );
}

#[test]
fn bad_records_reject_the_whole_snapshot() {
    let bad = [
        TUPLE.replace(r#""src":"192.168.8.10","#, ""),
        TUPLE.replace("192.168.8.10", "not-an-ip"),
        TUPLE.replace("192.168.8.10", "fe80::1%br-lan"),
        TUPLE.replace(r#""dst":"8.8.8.8","#, ""),
        TUPLE.replace(r#""dport":53,"#, ""),
        TUPLE.replace(r#""proto":"udp","#, ""),
        TUPLE.replace(r#""bytes_up":70,"#, ""),
        TUPLE.replace(r#""flows":1,"#, ""),
        TUPLE.replace("192.168.8.10", "192.168.8.10\\n"),
        "[]".to_string(),
        "7".to_string(),
        "null".to_string(),
    ];
    for b in bad {
        assert!(
            parse_snapshot(line(&format!("{TUPLE},{b}")).as_bytes()).is_err(),
            "{b}"
        );
    }
}

#[test]
fn deep_nesting_in_unknown_fields_is_refused_without_overflowing_the_stack() {
    let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
    let l = format!(r#"{{{HEAD},"x":{deep},"records":[]}}"#);
    assert_eq!(parse_snapshot(l.as_bytes()), Err(ParseError::TooDeep));
    let n = MAX_LINE / 2 - 100;
    let bomb = format!(
        r#"{{{HEAD},"x":{}{},"records":[]}}"#,
        "[".repeat(n),
        "]".repeat(n)
    );
    assert!(parse_snapshot(bomb.as_bytes()).is_err());
    let open_only = format!(r#"{{{HEAD},"x":{}"#, "[".repeat(MAX_LINE - 200));
    assert!(parse_snapshot(open_only.as_bytes()).is_err());
    let ok = "[".repeat(MAX_DEPTH - 3) + &"]".repeat(MAX_DEPTH - 3);
    assert!(parse_snapshot(format!(r#"{{{HEAD},"x":{ok},"records":[]}}"#).as_bytes()).is_ok());
}

#[test]
fn too_many_records_are_refused() {
    let tiny = r#"{"src":"10.0.0.1","other":true,"bytes_up":0,"bytes_down":0,"flows":0}"#;
    let many = vec![tiny; MAX_RECORDS + 1].join(",");
    assert_eq!(
        parse_snapshot(line(&many).as_bytes()),
        Err(ParseError::TooManyRecords)
    );
    let at = vec![tiny; MAX_RECORDS].join(",");
    assert_eq!(
        parse_snapshot(line(&at).as_bytes()).unwrap().records.len(),
        MAX_RECORDS
    );
}

#[test]
fn ipv6_spellings_normalise_through_ipaddr() {
    let r = TUPLE.replace("192.168.8.10", "FD00:0:0:0:0:0:0:0001");
    let s = parse_snapshot(line(&r).as_bytes()).unwrap();
    assert_eq!(s.records[0].src.to_string(), "fd00::1");
}
