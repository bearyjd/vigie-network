//! `Sources` with injected fake sources and a fake clock, then with real sockets (a fake helper
//! on a unix socket, multicast injected over the host's LAN interface).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::ctparse::{Kind, Record, Snapshot};
use vigie_agent::ctsock::{CtConfig, CtReader, CtShared};
use vigie_agent::mcast::{McConfig, McMsg, McReader, McShared, Pkt};
use vigie_agent::model::{Health, Meta, Proto};
use vigie_agent::window::{Window, SIGHTINGS_ADMIT_PER_WINDOW, SIGHTINGS_PER_MAC_QUOTA};
use vigie_agent::wiring::{flag, Sources, CT_STALE_S, MAX_MC_PER_PUMP};
use vigie_parse::{mdns, ssdp};

const A: &str = "aa:bb:cc:dd:ee:01";
const B: &str = "aa:bb:cc:dd:ee:02";

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(i, m)| ((*i).to_string(), (*m).to_string()))
        .collect()
}

fn rec(src: &str, up: u64, down: u64, flows: u64) -> Record {
    Record {
        src: src.parse().unwrap(),
        kind: Kind::Tuple,
        dst: Some("1.1.1.1".parse().unwrap()),
        dport: Some(443),
        proto: Proto::Tcp,
        bytes_up: up,
        bytes_down: down,
        flows,
    }
}

fn snap(records: Vec<Record>) -> Snapshot {
    Snapshot {
        records,
        ..Snapshot::default()
    }
}

struct Fake {
    ct_tx: SyncSender<Snapshot>,
    ct: Arc<CtShared>,
    mc_tx: SyncSender<McMsg>,
    mc: Arc<McShared>,
    sources: Sources,
}

fn fake(mono: u64) -> Fake {
    let (ct_tx, ct_rx) = sync_channel(8);
    let (mc_tx, mc_rx) = sync_channel(8192);
    let (ct, mc) = (Arc::new(CtShared::default()), Arc::new(McShared::default()));
    ct.connected.store(true, Ordering::Relaxed);
    let sources = Sources::from_parts(Some((ct_rx, ct.clone())), Some((mc_rx, mc.clone())), mono);
    Fake {
        ct_tx,
        ct,
        mc_tx,
        mc,
        sources,
    }
}

fn meta() -> Meta {
    Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    }
}

/// The finished batch as JSON, the way the server would receive it.
fn batch_json(w: &mut Window) -> serde_json::Value {
    let (sections, drops) = w.take_with_drops();
    let b = build_with_drops(&meta(), sections, &Health::default(), BATCH_CAP, &drops);
    serde_json::from_slice(&b.encoded.body(1_760_000_061, 0)).unwrap()
}

#[test]
fn snapshot_rows_and_flags_reach_the_batch_per_mac() {
    let mut f = fake(0);
    let table = map(&[("192.168.8.10", A), ("192.168.8.11", B)]);
    let s = Snapshot {
        table_pressure: true,
        acct_off: true,
        recounted_flows: 7,
        dropped_new_keys: 9,
        ..snap(vec![
            rec("192.168.8.10", 10, 20, 1),
            rec("192.168.8.11", 30, 40, 2),
            rec("192.168.8.99", 5, 5, 1),
        ])
    };
    f.ct_tx.send(s).unwrap();
    let mut w = Window::default();
    f.sources.pump(&mut w, &table, 10);
    f.sources.finish_window(&mut w, 60);
    let j = batch_json(&mut w);
    let rows = j["conntrack"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let a = rows.iter().find(|r| r["mac"] == A).unwrap();
    assert_eq!(
        (&a["bytes_up"], &a["bytes_down"], &a["flows"]),
        (&json!(10), &json!(20), &json!(1))
    );
    assert_eq!(a["dst_ip"], "1.1.1.1");
    let t = &j["truncated"];
    assert_eq!(
        t["source_flags"],
        flag::CT_TABLE_PRESSURE | flag::CT_ACCT_OFF
    );
    assert_eq!(t["ct_recounted"], 7);
    assert_eq!(t["ct_dropped_keys"], 9);
    assert_eq!(
        t["ct_unmapped_bytes"], 10,
        "the unmapped host's bytes are counted, not lost"
    );
    assert_eq!(
        t["ct_unmapped_flows"], 1,
        "and so are its flows (summed over the window's samples)"
    );
    assert!(j["truncated"].as_object().unwrap().len() <= 16);
}

#[test]
fn flags_and_counters_are_per_window() {
    let mut f = fake(0);
    let table = map(&[("192.168.8.10", A)]);
    f.ct_tx
        .send(Snapshot {
            table_pressure: true,
            recounted_flows: 3,
            ..snap(vec![rec("192.168.8.10", 1, 1, 1)])
        })
        .unwrap();
    let mut w = Window::default();
    f.sources.pump(&mut w, &table, 10);
    f.sources.finish_window(&mut w, 60);
    assert_eq!(batch_json(&mut w)["truncated"]["source_flags"], 1);
    f.ct_tx
        .send(snap(vec![rec("192.168.8.10", 1, 1, 1)]))
        .unwrap();
    f.sources.pump(&mut w, &table, 70);
    f.sources.finish_window(&mut w, 120);
    let j = batch_json(&mut w);
    assert!(j["truncated"].get("source_flags").is_none(), "{j}");
    assert!(j["truncated"].get("ct_recounted").is_none());
    assert_eq!(
        j["conntrack"].as_array().unwrap().len(),
        1,
        "rows restart too"
    );
}

#[test]
fn socket_down_is_reported_from_the_connection_state() {
    let mut f = fake(0);
    let mut w = Window::default();
    f.sources.finish_window(&mut w, 60);
    assert!(
        batch_json(&mut w)["truncated"]
            .get("source_flags")
            .is_none(),
        "connected"
    );
    f.ct.connected.store(false, Ordering::Relaxed);
    f.sources.finish_window(&mut w, 120);
    assert_eq!(
        batch_json(&mut w)["truncated"]["source_flags"],
        flag::CT_SOCKET_DOWN
    );
}

#[test]
fn a_connected_but_silent_helper_goes_down_exactly_after_the_stale_limit() {
    let mut f = fake(100);
    let mut w = Window::default();
    f.sources.finish_window(&mut w, 100 + CT_STALE_S);
    assert!(
        w.take_with_drops().1.is_empty(),
        "exactly at the limit is still fine"
    );
    f.sources.finish_window(&mut w, 100 + CT_STALE_S + 1);
    assert_eq!(
        w.take_with_drops().1.get("source_flags"),
        Some(&flag::CT_SOCKET_DOWN)
    );
    // a snapshot resets the clock
    f.ct_tx.send(snap(vec![])).unwrap();
    f.sources.pump(&mut w, &HashMap::new(), 400);
    f.sources.finish_window(&mut w, 400 + CT_STALE_S);
    assert!(w.take_with_drops().1.is_empty());
}

#[test]
fn reader_errors_and_queue_drops_become_a_counter() {
    let mut f = fake(0);
    f.ct.errors.store(3, Ordering::Relaxed);
    f.ct.dropped.store(2, Ordering::Relaxed);
    let mut w = Window::default();
    f.sources.pump(&mut w, &HashMap::new(), 1);
    f.sources.finish_window(&mut w, 2);
    assert_eq!(w.take_with_drops().1.get("ct_errors"), Some(&5));
    f.sources.finish_window(&mut w, 3);
    assert!(
        !w.take_with_drops().1.contains_key("ct_errors"),
        "taken once"
    );
}

fn mdns_msg(ip: &str, name: &str) -> McMsg {
    McMsg {
        src: ip.parse().unwrap(),
        pkt: Pkt::Mdns(mdns::Parsed {
            names: vec![name.to_string()],
            ..mdns::Parsed::default()
        }),
    }
}

fn ssdp_msg(ip: &str, usn: &str) -> McMsg {
    McMsg {
        src: ip.parse().unwrap(),
        pkt: Pkt::Ssdp(ssdp::Parsed {
            method: ssdp::Method::Notify,
            server: None,
            usn: Some(usn.to_string()),
            nt: Some("upnp:rootdevice".into()),
            st: None,
            user_agent: None,
        }),
    }
}

#[test]
fn multicast_is_mapped_by_source_ip_and_unmapped_sources_are_counted() {
    let mut f = fake(0);
    let table = map(&[("192.168.8.10", A), ("fe80::1", B)]);
    f.mc_tx.send(mdns_msg("192.168.8.10", "tv.local")).unwrap();
    f.mc_tx.send(ssdp_msg("fe80::1", "uuid:1")).unwrap();
    f.mc_tx
        .send(mdns_msg("192.168.8.77", "stranger.local"))
        .unwrap();
    f.mc.dropped.store(4, Ordering::Relaxed);
    let mut w = Window::default();
    f.sources.pump(&mut w, &table, 1);
    f.sources.finish_window(&mut w, 2);
    let j = batch_json(&mut w);
    let s = j["sightings"].as_array().unwrap();
    assert_eq!(s.len(), 2);
    assert!(s
        .iter()
        .any(|x| x["mac"] == A && x["kind"] == "mdns" && x["name"] == "tv.local"));
    assert!(s.iter().any(|x| x["mac"] == B && x["kind"] == "ssdp"));
    assert_eq!(j["truncated"]["mcast_unmapped"], 1);
    assert_eq!(j["truncated"]["mcast_dropped"], 4);
}

#[test]
fn one_chatty_source_is_held_to_its_quota_through_the_whole_path() {
    let mut f = fake(0);
    let table = map(&[("192.168.8.10", A), ("192.168.8.11", B)]);
    let n = SIGHTINGS_PER_MAC_QUOTA + 30;
    for i in 0..n {
        f.mc_tx
            .send(mdns_msg("192.168.8.10", &format!("h{i}.local")))
            .unwrap();
    }
    f.mc_tx
        .send(mdns_msg("192.168.8.11", "quiet.local"))
        .unwrap();
    let mut w = Window::default();
    for _ in 0..4 {
        f.sources.pump(&mut w, &table, 1);
    }
    f.sources.finish_window(&mut w, 2);
    let j = batch_json(&mut w);
    let s = j["sightings"].as_array().unwrap();
    assert_eq!(
        s.iter().filter(|x| x["mac"] == A).count(),
        SIGHTINGS_PER_MAC_QUOTA
    );
    assert_eq!(
        s.iter().filter(|x| x["mac"] == B).count(),
        1,
        "others unaffected"
    );
    assert_eq!(j["truncated"]["sightings_dropped"], 30);
}

#[test]
fn the_window_sightings_cap_holds_when_many_sources_flood() {
    let mut f = fake(0);
    let macs = 100usize;
    let per = 50usize; // 100 x 50 = 5000 > 4096, each under the per-device quota
    let table: HashMap<String, String> = (0..macs)
        .map(|m| {
            (
                format!("10.1.{}.{}", m / 200, m % 200 + 1),
                format!("02:00:00:00:00:{m:02x}"),
            )
        })
        .collect();
    let mut w = Window::default();
    for m in 0..macs {
        for i in 0..per {
            let ip = format!("10.1.{}.{}", m / 200, m % 200 + 1);
            f.mc_tx
                .send(ssdp_msg(&ip, &format!("uuid:{m}-{i}")))
                .unwrap();
        }
    }
    for _ in 0..(macs * per / MAX_MC_PER_PUMP + 2) {
        f.sources.pump(&mut w, &table, 1);
    }
    f.sources.finish_window(&mut w, 2);
    let (sections, drops) = w.take_with_drops();
    assert_eq!(sections.sightings.len(), SIGHTINGS_ADMIT_PER_WINDOW);
    assert_eq!(
        drops.get("sightings_dropped"),
        Some(&((macs * per - SIGHTINGS_ADMIT_PER_WINDOW) as u64))
    );
}

#[test]
fn one_pump_handles_a_bounded_number_of_packets() {
    let mut f = fake(0);
    let table = map(&[("192.168.8.10", A)]);
    let total = MAX_MC_PER_PUMP + 100;
    for i in 0..total {
        f.mc_tx
            .send(mdns_msg("192.168.8.10", &format!("n{i}")))
            .unwrap();
    }
    let mut w = Window::default();
    f.sources.pump(&mut w, &table, 1);
    let (s, drops) = w.take_with_drops();
    assert_eq!(s.sightings.len(), SIGHTINGS_PER_MAC_QUOTA);
    assert_eq!(
        drops.get("sightings_dropped"),
        Some(&((MAX_MC_PER_PUMP - SIGHTINGS_PER_MAC_QUOTA) as u64)),
        "exactly one pump's worth was handled"
    );
    // the remaining 100 are still queued (the taken window starts with a fresh quota)
    f.sources.pump(&mut w, &table, 1);
    let (s, drops) = w.take_with_drops();
    assert_eq!(s.sightings.len(), SIGHTINGS_PER_MAC_QUOTA);
    assert_eq!(
        drops.get("sightings_dropped"),
        Some(&(100 - SIGHTINGS_PER_MAC_QUOTA as u64))
    );
}

#[test]
fn a_multicast_bind_failure_is_a_flag_and_a_startup_failure_too() {
    let mut f = fake(0);
    f.mc.bind_failed.store(true, Ordering::Relaxed);
    let mut w = Window::default();
    f.sources.finish_window(&mut w, 2);
    assert_eq!(
        w.take_with_drops().1.get("source_flags"),
        Some(&flag::MULTICAST_BIND_FAILED)
    );
}

#[test]
fn without_any_source_the_batch_carries_no_source_keys() {
    let mut s = Sources::inert();
    let mut w = Window::default();
    s.pump(&mut w, &HashMap::new(), 1);
    s.finish_window(&mut w, 2);
    assert!(w.take_with_drops().1.is_empty());
}

// ---- real sockets -------------------------------------------------------------------------

/// Both real multicast tests hear each other (same group, same host): one at a time.
static MULTICAST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-wiring-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

#[test]
fn a_fake_helper_on_a_real_socket_ends_up_in_the_batch() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let d = tmpdir("helper");
    let p = d.join("c.sock");
    let l = UnixListener::bind(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    let ct = CtReader::spawn(CtConfig::new(p.clone(), vec![0, me])).unwrap();
    let line = concat!(
        r#"{"v":1,"seq":1,"ts":1,"interval_s":60,"acct_off":true,"recounted_flows":2,"#,
        r#""dropped_new_keys":0,"table_pressure":true,"records":["#,
        r#"{"src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120,"flows":1},"#,
        r#"{"src":"fd00::5","other":true,"bytes_up":5,"bytes_down":6,"flows":3},"#,
        r#"{"src":"0.0.0.0","other_global":true,"bytes_up":100,"bytes_down":100,"flows":9}]}"#
    );
    let shared = ct.shared.clone();
    let (mut conn, _) = l.accept().unwrap();
    writeln!(conn, "{line}").unwrap();
    let mut sources = Sources::from_readers(Some(ct), None, 0);
    let table = map(&[("192.168.8.10", A), ("fd00::5", B)]);
    let end = Instant::now() + Duration::from_secs(10);
    while shared.received.load(Ordering::Relaxed) == 0 && Instant::now() < end {
        thread::sleep(Duration::from_millis(10));
    }
    let mut w = Window::default();
    sources.pump(&mut w, &table, 5);
    sources.finish_window(&mut w, 30);
    let j = batch_json(&mut w);
    let rows = j["conntrack"].as_array().unwrap();
    let a = rows.iter().find(|r| r["mac"] == A).expect("A's row");
    assert_eq!(
        (&a["dst_ip"], &a["dst_port"], &a["proto"]),
        (&json!("8.8.8.8"), &json!(53), &json!("udp"))
    );
    let b = rows
        .iter()
        .find(|r| r["mac"] == B)
        .expect("B's other bucket");
    assert!(b["dst_ip"].is_null() && b["proto"] == "other");
    let t = &j["truncated"];
    assert_eq!(
        t["source_flags"],
        flag::CT_TABLE_PRESSURE | flag::CT_ACCT_OFF
    );
    assert_eq!(
        (&t["ct_recounted"], &t["ct_unmapped_bytes"]),
        (&json!(2), &json!(200))
    );
    assert!(t.get("ct_errors").is_none());
}

// ---- multicast over the host's LAN interface ------------------------------------------------

/// The host's outbound IPv4 address (no packet is sent), or None when there is no route.
fn host_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

fn mdns_query(name: &str) -> Vec<u8> {
    let mut p = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.extend_from_slice(&[0, 0, 12, 0, 1]);
    p
}

fn sender(ip: Ipv4Addr) -> UdpSocket {
    let s = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    s.set_multicast_if_v4(&ip).unwrap();
    s.set_multicast_ttl_v4(255).unwrap();
    s.set_multicast_loop_v4(true).unwrap();
    s.bind(&std::net::SocketAddr::new(IpAddr::V4(ip), 0).into())
        .unwrap();
    s.into()
}

#[test]
fn injected_multicast_lands_as_sightings() {
    let _serial = MULTICAST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(ip) = host_ip() else {
        eprintln!("SKIP: no non-loopback IPv4 route; multicast injection not exercised");
        return;
    };
    let reader = McReader::spawn(McConfig {
        lan: ip,
        prefix: 24,
        iface: "none".into(),
        include_own: true,
    })
    .unwrap();
    let up = Instant::now() + Duration::from_secs(5);
    while reader.shared.sockets.load(Ordering::Relaxed) == 0 && Instant::now() < up {
        thread::sleep(Duration::from_millis(20));
    }
    if reader.shared.sockets.load(Ordering::Relaxed) == 0 {
        eprintln!(
            "SKIP: cannot join the mDNS group on {ip} here; multicast injection not exercised"
        );
        return;
    }
    let mut sources = Sources::from_readers(None, Some(reader), 0);
    let table = map(&[(&ip.to_string(), A)]);
    let tx = sender(ip);
    tx.send_to(&mdns_query("_vigie-probe._tcp.local"), "224.0.0.251:5353")
        .unwrap();
    let notify = |usn: &str| {
        format!("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: {usn}\r\nSERVER: Vigie-Inject/1.0\r\n\r\n")
    };
    for i in 0..5 {
        tx.send_to(
            notify(&format!("uuid:flood-{i}")).as_bytes(),
            "239.255.255.250:1900",
        )
        .unwrap();
    }
    let mut w = Window::default();
    let end = Instant::now() + Duration::from_secs(10);
    let mut got = (false, 0usize);
    while Instant::now() < end {
        sources.pump(&mut w, &table, 1);
        let (s, _) = w.take_with_drops();
        // put them back by counting: we only need to know that both kinds arrived
        got.0 |= s
            .sightings
            .iter()
            .any(|x| x.service.as_deref() == Some("_vigie-probe._tcp.local"));
        got.1 += s
            .sightings
            .iter()
            .filter(|x| {
                x.name
                    .as_deref()
                    .is_some_and(|n| n.starts_with("uuid:flood-"))
            })
            .count();
        if got.0 && got.1 >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(got.0, "the mDNS query was not seen as a sighting of {A}");
    assert!(got.1 >= 1, "no SSDP sighting arrived");
}

#[test]
fn injected_flood_cannot_exceed_the_per_device_quota() {
    let _serial = MULTICAST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(ip) = host_ip() else {
        eprintln!("SKIP: no non-loopback IPv4 route; multicast injection not exercised");
        return;
    };
    let reader = McReader::spawn(McConfig {
        lan: ip,
        prefix: 24,
        iface: "none".into(),
        include_own: true,
    })
    .unwrap();
    let up = Instant::now() + Duration::from_secs(5);
    while reader.shared.sockets.load(Ordering::Relaxed) == 0 && Instant::now() < up {
        thread::sleep(Duration::from_millis(20));
    }
    if reader.shared.sockets.load(Ordering::Relaxed) == 0 {
        eprintln!("SKIP: cannot join the SSDP group on {ip} here");
        return;
    }
    let shared = reader.shared.clone();
    let mut sources = Sources::from_readers(None, Some(reader), 0);
    let table = map(&[(&ip.to_string(), A)]);
    let tx = sender(ip);
    // an unparseable datagram is counted as dropped, never delivered
    tx.send_to(b"\xff\xfe not ssdp", "239.255.255.250:1900")
        .unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while shared.dropped.load(Ordering::Relaxed) == 0 && Instant::now() < end {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        shared.dropped.load(Ordering::Relaxed) >= 1,
        "garbage not counted"
    );
    let total = SIGHTINGS_PER_MAC_QUOTA + 60;
    for i in 0..total {
        let p = format!("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:quota-{i}\r\nSERVER: Vigie-Inject/1.0\r\n\r\n");
        tx.send_to(p.as_bytes(), "239.255.255.250:1900").unwrap();
    }
    let mut w = Window::default();
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end && shared.accepted.load(Ordering::Relaxed) < total as u64 {
        sources.pump(&mut w, &table, 1);
        thread::sleep(Duration::from_millis(20));
    }
    sources.pump(&mut w, &table, 1);
    let accepted = shared.accepted.load(Ordering::Relaxed) as usize;
    let (s, drops) = w.take_with_drops();
    let mine = s.sightings.iter().filter(|x| x.mac == A).count();
    assert!(
        mine <= SIGHTINGS_PER_MAC_QUOTA,
        "{mine} sightings for one device"
    );
    if accepted >= SIGHTINGS_PER_MAC_QUOTA + 10 {
        assert_eq!(mine, SIGHTINGS_PER_MAC_QUOTA);
        assert!(
            drops.get("sightings_dropped").copied().unwrap_or(0) >= 10,
            "{drops:?}"
        );
    } else {
        eprintln!("NOTE: only {accepted}/{total} datagrams arrived; quota boundary not reached");
    }
}
