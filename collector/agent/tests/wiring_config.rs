//! Config keys added for the data sources: defaults and validation.

use vigie_agent::config::parse_config;

fn base() -> String {
    format!(
        "server_url=https://vigie.example.lan:8443/v1/batch\ncollector_id=router-1\nkey_id=k1\n\
         pin1={}\npin2={}\n",
        "0".repeat(64),
        "1".repeat(64)
    )
}

#[test]
fn defaults_match_the_router_layout() {
    let c = parse_config(&base()).unwrap();
    assert_eq!(
        c.conntrack_socket.to_str(),
        Some("/tmp/vigie/conntrack.sock")
    );
    assert_eq!(c.lan_addr.to_string(), "192.168.8.1");
    assert_eq!((c.lan_prefix, c.lan_iface.as_str()), (24, "br-lan"));
}

#[test]
fn the_source_options_can_be_set() {
    let t = format!(
        "{}conntrack_socket=/run/x.sock\nlan_addr=10.1.2.3\nlan_prefix=16\nlan_iface=br0\n",
        base()
    );
    let c = parse_config(&t).unwrap();
    assert_eq!(c.conntrack_socket.to_str(), Some("/run/x.sock"));
    assert_eq!(c.lan_addr.to_string(), "10.1.2.3");
    assert_eq!((c.lan_prefix, c.lan_iface.as_str()), (16, "br0"));
}

#[test]
fn bad_source_options_are_startup_errors() {
    for bad in [
        "lan_addr=not-an-ip",
        "lan_addr=::1",
        "lan_prefix=7",
        "lan_prefix=31",
        "lan_prefix=abc",
        "lan_prefix=",
        "lan_iface=../lo",
        "lan_iface=a/b",
        "lan_iface=waytoolonginterfacename",
        "conntrack_socket=",
    ] {
        assert!(
            parse_config(&format!("{}{bad}\n", base())).is_err(),
            "{bad}"
        );
    }
    let dup = format!("{}lan_prefix=24\nlan_prefix=16\n", base());
    assert!(parse_config(&dup).is_err(), "duplicates stay errors");
}
