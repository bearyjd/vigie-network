//! Reading the dnsmasq log: tail polling, DHCP assembly and DNS correlation into the window.

use vigie_agent::dnsmasq::{parse_line_pid, LogEvent};
use vigie_agent::model::Lease;
use vigie_agent::neigh::pairing_changed;

use super::Agent;

impl Agent {
    pub(super) fn poll_log(&mut self, now: u64) {
        match self.tail.poll_with_gaps() {
            Ok(lines) => {
                for line in &lines {
                    // `None`: bytes were lost here, so nothing may attach across it.
                    let Some(line) = line else {
                        self.dhcp.lose_context();
                        continue;
                    };
                    match parse_line_pid(line) {
                        Some((pid, ev)) => {
                            self.dns.feed(&ev, now);
                            self.on_dhcp(pid, &ev);
                        }
                        // Anything unparsed sits between packet lines: no attaching across it.
                        None => {
                            let done = self.dhcp.break_context();
                            self.on_leases(done);
                        }
                    }
                }
            }
            // Unknown what was missed (a pending gap is applied only on the next poll): an
            // unfinished block must not be closed by this poll, it is dropped unpublished.
            Err(e) => {
                eprintln!("dnsmasq log: {e}");
                self.dhcp.lose_context();
            }
        }
        let done = self.dhcp.end_poll();
        self.on_leases(done);
        for q in self.dns.take_ready(&self.ip_to_mac) {
            self.window.add_dns(q);
        }
        for (kind, n) in self
            .dns
            .take_counts()
            .into_iter()
            .chain(self.tail.take_counts())
        {
            self.window.note_drops(&kind, n);
        }
    }

    fn on_dhcp(&mut self, pid: u64, ev: &LogEvent) {
        let leases = self.dhcp.feed_pid(pid, ev);
        self.on_leases(leases);
    }

    fn on_leases(&mut self, leases: Vec<Lease>) {
        for lease in leases {
            self.on_lease(lease);
        }
    }

    pub(super) fn on_lease(&mut self, lease: Lease) {
        let new_mac = self
            .urgent
            .on_lease(&lease.mac, super::started_ms(self.started));
        // The lease states the pairing now: a table that disagrees (address moved to this MAC,
        // or not seen yet) is stale and would bill this device's traffic to the old owner.
        let moved = pairing_changed(&self.ip_to_mac, &lease.ip, &lease.mac);
        self.window.add_lease(lease);
        // A new device always refreshes (its first queries must be attributed and its neighbor
        // entry rides along); a changed pairing refreshes at most once per `REFRESH_MIN_S`.
        if new_mac || (moved && self.sources.refresh_due(self.mono)) {
            self.refresh_neighbors();
        }
        if new_mac {
            self.push_identity();
        }
    }
}
