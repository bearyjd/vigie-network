//! Turn parsed mDNS / SSDP packets (reused `vigie-parse`) into schema sightings for a MAC.
//! The MAC comes from the packet's source IP via the neighbor table; the caller does that join.

use vigie_parse::{mdns, ssdp};

use crate::model::{Sighting, SightingKind};

/// Most sightings produced from one packet (a hostile packet cannot flood the window).
pub const MAX_PER_PACKET: usize = 8;

pub fn from_mdns(mac: &str, p: &mdns::Parsed) -> Vec<Sighting> {
    let name = p.names.first().map(String::as_str);
    let mut out: Vec<Sighting> = p
        .services
        .iter()
        .filter_map(|s| Sighting::new(mac, SightingKind::Mdns, name, Some(s), None))
        .take(MAX_PER_PACKET)
        .collect();
    if out.is_empty() {
        out.extend(
            p.names
                .iter()
                .take(MAX_PER_PACKET)
                .filter_map(|n| Sighting::new(mac, SightingKind::Mdns, Some(n), None, None)),
        );
    }
    out
}

pub fn from_ssdp(mac: &str, p: &ssdp::Parsed) -> Option<Sighting> {
    let service = p.nt.as_deref().or(p.st.as_deref());
    let ua = p.user_agent.as_deref().or(p.server.as_deref());
    if service.is_none() && ua.is_none() && p.usn.is_none() {
        return None;
    }
    Sighting::new(mac, SightingKind::Ssdp, p.usn.as_deref(), service, ua)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "aa:bb:cc:dd:ee:01";

    #[test]
    fn mdns_services_become_sightings_with_the_first_name() {
        let p = mdns::Parsed {
            names: vec!["Living Room._airplay._tcp.local".into(), "tv.local".into()],
            services: vec!["_airplay._tcp.local".into(), "_raop._tcp.local".into()],
            ..mdns::Parsed::default()
        };
        let s = from_mdns(MAC, &p);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].service.as_deref(), Some("_airplay._tcp.local"));
        assert_eq!(
            s[0].name.as_deref(),
            Some("Living Room._airplay._tcp.local")
        );
        assert_eq!(s[0].kind, SightingKind::Mdns);
    }

    #[test]
    fn mdns_names_only_and_per_packet_cap() {
        let p = mdns::Parsed {
            names: (0..20).map(|i| format!("h{i}.local")).collect(),
            ..mdns::Parsed::default()
        };
        assert_eq!(from_mdns(MAC, &p).len(), MAX_PER_PACKET);
        assert!(from_mdns("bad", &p).is_empty());
    }

    #[test]
    fn ssdp_maps_usn_service_and_agent() {
        let p = ssdp::Parsed {
            method: ssdp::Method::Notify,
            server: Some("Linux UPnP/1.0".into()),
            usn: Some("uuid:abc::upnp:rootdevice".into()),
            nt: Some("upnp:rootdevice".into()),
            st: None,
            user_agent: None,
        };
        let s = from_ssdp(MAC, &p).unwrap();
        assert_eq!(s.name.as_deref(), Some("uuid:abc::upnp:rootdevice"));
        assert_eq!(s.service.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(s.ua.as_deref(), Some("Linux UPnP/1.0"));
        let empty = ssdp::Parsed {
            method: ssdp::Method::Notify,
            server: None,
            usn: None,
            nt: None,
            st: None,
            user_agent: None,
        };
        assert!(from_ssdp(MAC, &empty).is_none());
    }
}
