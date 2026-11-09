//! The FAILED/INCOMPLETE set of the latest neighbor read reaches the attribution in `Sources`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;

use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::ctparse::{Kind, Record, Snapshot};
use vigie_agent::ctsock::CtShared;
use vigie_agent::model::{Health, Meta, Proto};
use vigie_agent::neigh::NeighTable;
use vigie_agent::ownaddr::OwnAddrs;
use vigie_agent::window::Window;
use vigie_agent::wiring::Sources;

const A: &str = "aa:bb:cc:dd:ee:01";
const ULA: &str = "fd00::10";

fn flow() -> Snapshot {
    Snapshot {
        records: vec![Record {
            src: ULA.parse().unwrap(),
            kind: Kind::Tuple,
            dst: Some("1.1.1.1".parse().unwrap()),
            dport: Some(443),
            proto: Proto::Tcp,
            bytes_up: 10,
            bytes_down: 20,
            flows: 1,
        }],
        ..Snapshot::default()
    }
}

fn no_own() -> Option<HashSet<std::net::IpAddr>> {
    Some(HashSet::new())
}

fn setup() -> (Sources, SyncSender<Snapshot>, Window) {
    let (tx, rx) = sync_channel(8);
    let shared = Arc::new(CtShared::default());
    shared.connected.store(true, Ordering::Relaxed);
    let s = Sources::from_parts(Some((rx, shared)), None, 0)
        .with_own_addrs(OwnAddrs::new(Ipv4Addr::new(192, 168, 8, 1), no_own));
    (s, tx, Window::default())
}

fn truncated(w: &mut Window) -> BTreeMap<String, u64> {
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    };
    let (sections, drops) = w.take_with_drops();
    build_with_drops(&meta, sections, &Health::default(), BATCH_CAP, &drops).truncated
}

fn table(failed: &[&str]) -> NeighTable {
    NeighTable {
        neighbors: Vec::new(),
        failed: failed.iter().map(|s| (*s).to_string()).collect(),
    }
}

#[test]
fn a_failed_entry_in_the_latest_read_blocks_the_remembered_mapping() {
    let (mut s, tx, mut w) = setup();
    let mapped: HashMap<String, String> = [(ULA.to_string(), A.to_string())].into();
    tx.send(flow()).unwrap();
    s.pump(&mut w, &mapped, 10); // remembered
    tx.send(flow()).unwrap();
    // the refreshed table has no entry and reports the address FAILED
    s.pump_refreshing(&mut w, &HashMap::new(), Some(&mut || table(&[ULA])), 20);
    s.finish_window(&mut w, 60);
    let t = truncated(&mut w);
    assert_eq!(t.get("ct_lan_unmapped_bytes"), Some(&30), "{t:?}");
    assert_eq!(t.get("ct_lan_unmapped_flows"), Some(&1));
}

#[test]
fn without_a_failed_entry_the_same_refresh_still_attributes_from_memory() {
    let (mut s, tx, mut w) = setup();
    let mapped: HashMap<String, String> = [(ULA.to_string(), A.to_string())].into();
    tx.send(flow()).unwrap();
    s.pump(&mut w, &mapped, 10);
    tx.send(flow()).unwrap();
    s.pump_refreshing(&mut w, &HashMap::new(), Some(&mut || table(&[])), 20);
    s.finish_window(&mut w, 60);
    assert!(truncated(&mut w).is_empty());
}

#[test]
fn a_failed_set_from_the_agents_own_refresh_blocks_it_too() {
    let (mut s, tx, mut w) = setup();
    let mapped: HashMap<String, String> = [(ULA.to_string(), A.to_string())].into();
    tx.send(flow()).unwrap();
    s.pump(&mut w, &mapped, 10);
    s.note_refresh(15, [ULA.to_string()].into());
    tx.send(flow()).unwrap();
    s.pump(&mut w, &HashMap::new(), 20);
    s.finish_window(&mut w, 60);
    assert_eq!(truncated(&mut w).get("ct_lan_unmapped_bytes"), Some(&30));
}
