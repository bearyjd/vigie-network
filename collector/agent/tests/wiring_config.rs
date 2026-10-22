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
fn dropin_defaults_equal_the_old_constants_and_can_be_overridden() {
    use vigie_agent::dropin::{check_dropin, dropin_content, DropinState, DROPIN_PATH, LOG_DIR};
    assert_eq!(
        (DROPIN_PATH, LOG_DIR),
        ("/tmp/dnsmasq.d/vigie.conf", "/tmp/vigie")
    );
    let c = parse_config(&base()).unwrap();
    assert_eq!(c.dropin_path.to_str(), Some(DROPIN_PATH));
    assert_eq!(c.log_dir.to_str(), Some(LOG_DIR));

    let t = format!("{}dropin_path=/run/d.conf\nlog_dir=/run/vl\n", base());
    let o = parse_config(&t).unwrap();
    assert_eq!(o.dropin_path.to_str(), Some("/run/d.conf"));
    assert_eq!(o.log_dir.to_str(), Some("/run/vl"));
    // the check follows the configured directory
    let content = dropin_content("/run/vl");
    let dir = |c: &vigie_agent::config::Config| c.log_dir.to_string_lossy().into_owned();
    assert_eq!(check_dropin(Some(&content), &dir(&o)), DropinState::Ok);
    assert_eq!(check_dropin(Some(&content), &dir(&c)), DropinState::Differs);

    for bad in ["dropin_path=", "log_dir="] {
        assert!(
            parse_config(&format!("{}{bad}\n", base())).is_err(),
            "{bad}"
        );
    }
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

#[test]
fn dropin_path_and_log_dir_must_be_clean_absolute_paths() {
    for bad in [
        "log_dir=relative/dir",
        "dropin_path=relative.conf",
        "log_dir=/run/../etc",
        "dropin_path=/run/../etc/x.conf",
        "log_dir=/run/vl/",
        "dropin_path=/run/d.conf/",
        "log_dir=/",
        "log_dir=/run/v\0l",
        "dropin_path=/run/d\0.conf",
    ] {
        assert!(
            parse_config(&format!("{}{bad}\n", base())).is_err(),
            "{bad:?}"
        );
    }
    let ok = format!("{}dropin_path=/run/d..x.conf\nlog_dir=/run/vl\n", base());
    assert!(
        parse_config(&ok).is_ok(),
        "`..` inside a name is not a component"
    );
}

#[test]
fn dnsmasq_log_must_be_under_log_dir_unless_explicitly_allowed() {
    // default follows log_dir (the root scripts write the drop-in's log-facility there)
    let c = parse_config(&format!("{}log_dir=/run/vl\n", base())).unwrap();
    assert_eq!(c.dnsmasq_log.to_str(), Some("/run/vl/dnsmasq.log"));
    let same = format!(
        "{}log_dir=/run/vl\ndnsmasq_log=/run/vl/dnsmasq.log\n",
        base()
    );
    assert!(parse_config(&same).is_ok());
    for bad in [
        "dnsmasq_log=/var/log/other.log",
        "log_dir=/run/vl\ndnsmasq_log=/tmp/vigie/dnsmasq.log",
        "dnsmasq_log=/tmp/vigie/other.log",
    ] {
        assert!(
            parse_config(&format!("{}{bad}\n", base())).is_err(),
            "{bad}"
        );
    }
    let custom = format!(
        "{}dnsmasq_log=/var/log/other.log\nallow_custom_log_path=1\n",
        base()
    );
    let c = parse_config(&custom).unwrap();
    assert_eq!(c.dnsmasq_log.to_str(), Some("/var/log/other.log"));
    for bad in [
        "allow_custom_log_path=yes",
        "allow_custom_log_path=",
        "allow_custom_log_path=2",
    ] {
        let t = format!("{}dnsmasq_log=/var/log/other.log\n{bad}\n", base());
        assert!(parse_config(&t).is_err(), "{bad}");
    }
    let off = format!(
        "{}dnsmasq_log=/var/log/other.log\nallow_custom_log_path=0\n",
        base()
    );
    assert!(parse_config(&off).is_err());
}
