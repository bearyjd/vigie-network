# Endpoint connection events from Snitchwatch hosts (research, 2026-10-26)

Status: proposal for owner review. Nothing built. Full design and source
evidence: Snitchwatch repo,
`docs/superpowers/specs/2026-10-26-vigie-endpoint-events.md`.

## Idea

Vigie sees the LAN from the router. A computer running Snitchwatch (OpenSnitch
underneath) knows, for each outbound connection, the program and the firewall
decision. OpenSnitch's built-in `remote` logger can already send those
decisions as JSON lines. It sends them over loopback to a local rsyslog, which
forwards an allowlisted subset to Vigie over TLS syslog (RFC 5425). No bespoke
protocol, and no Snitchwatch code in the path.

The main value is an external check on the endpoint firewall. Vigie compares
what the router saw from that computer with what OpenSnitch reported, and
raises:

- **likely unreported traffic**: conntrack flows from the host with no matching
  endpoint event within a tolerance. Causes include a VM, a container in its own
  network namespace, a stopped daemon, or a bypass;
- **endpoint guard quiet**: router traffic from the host, but no endpoint
  events for N minutes.

It also enables per-program attribution on that host's device page and in its
upload-baseline incidents.

## What Vigie would need

1. **A new source kind,** "endpoint event (OpenSnitch)", with provenance like
   the router sources. Each event arrives as one JSON object per TLS syslog
   message from rsyslog's `omfwd`.
   - **The input.** Open: a TLS syslog listener service on the server, mutual
     TLS or a pinned client certificate per host, versus a relay that turns
     these events into a new record kind in the signed batch
     (`api/batch.schema.json`).
2. **Host identity.** A configured host id from the shipper, joined to the
   device inventory. It is never inferred from the event's IP alone.
3. **The join.** Protocol, source port, destination IP and port, and time
   against conntrack summaries, with a tolerance.
   - Known exclusions: DNS, the daemon's own traffic, `nolog` rules, inbound.
   - OpenSnitch drops events under load, so incidents need a rate or minimum
     count and must say "likely".
4. **Fields received:**
   - time, protocol, src/dst IP and port, `dst_host`;
   - `process_path`, uid;
   - action and rule name. `"<nil>"` means the daemon's default action.
   - Never the environment, arguments, cwd or process tree; the sender drops
     them.
5. **Boundary.** Vigie only observes. The endpoint firewall stays the sole
   enforcer on that host, consistent with the control-app boundary in
   `docs/roadmap.md`.

## Open questions

- Shipper and input format (above).
- Retention for endpoint events (they name programs, so treat them like DNS
  logs).
- Tolerances, measured on real traffic before choosing numbers.
