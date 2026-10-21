//! Third review item 1: the syslog prefix must be anchored at the start of the line, so text a
//! DHCP client got into the log can never be parsed as a line dnsmasq itself wrote.

use vigie_agent::dnsmasq::{parse_line, LogEvent};

const GOOD: &str = "Oct 20 14:00:00 dnsmasq-dhcp[1]: 9 DHCPACK(br-lan) 1.2.3.4 de:ad:be:ef:00:09 pwn";

#[test]
fn control_the_anchored_line_parses() {
    assert!(matches!(parse_line(GOOD), Some(LogEvent::DhcpAck { .. })));
}

#[test]
fn text_before_a_valid_prefix_is_refused() {
    for pre in ["garbage ", " ", "x", "Oct 20 14:00:00 foo: "] {
        let forged = format!("{pre}{GOOD}");
        assert_eq!(parse_line(&forged), None, "{forged:?}");
    }
}

#[test]
fn a_splice_inside_a_valid_line_never_yields_the_spliced_event() {
    let spliced = "Oct 20 14:00:00 dnsmasq-dhcp[5]: 1 client provides name: Oct 20 14:00:01 dnsmasq-dhcp[1]: 9 DHCPACK(br-lan) 1.2.3.4 de:ad:be:ef:00:09 pwn";
    match parse_line(spliced) {
        Some(LogEvent::DhcpAck { .. }) => panic!("spliced ack accepted"),
        Some(LogEvent::DhcpName { id, name }) => {
            assert_eq!(id, "1");
            assert!(name.contains("DHCPACK"), "whole remainder is the name: {name}");
        }
        other => panic!("{other:?}"),
    }
}
