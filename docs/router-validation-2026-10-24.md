# Router field validation — 2026-10-24

Status: **ten-minute real-router collection, authenticated inventory and verified closure passed**.
This follows the earlier [container validation closure](deployment-validation-2026-10-24.md).
The earlier access failure remains part of that historical record. The operator subsequently
loaded the documented encrypted administrator identity into its existing local SSH agent.
No credentials, household names, addresses, MACs, DNS names or service-instance values appear here.

## Scope and current boundary

The authorized work uses isolated tmpfs staging and temporary processes on the GL-XE3000.
It does not install an init service, create a persistent user, enable DNS logging, restart dnsmasq,
change firewall policy or integrate Couvre-feu. Root performs the protected conntrack read; the
collector must run as an isolated unprivileged numeric UID/GID, without `--allow-root`.
The reviewed ten-minute collector run completed with exit 0. Its stop/finally handler returned 0 and the reverse tunnel closed. Independent closure checks are recorded below.

Read-only preflight confirmed aarch64, OpenWrt 21.02, the LAN bridge, 222,844 KiB available RAM (217.6 MiB),
237,432 KiB free tmpfs (231.9 MiB), the existing avahi process and about 1304 conntrack entries. These are
point-in-time observations, not resource-soak results. `su`/`setpriv` were unavailable and BusyBox
`start-stop-daemon` rejected an unregistered numeric UID; the pilot therefore uses a temporary numeric-UID launcher rather than modifying the account database.

## Built artifacts

Private provenance records the static `aarch64-unknown-linux-musl` binaries built from `2e1d44d`:

| Binary | Bytes | SHA-256 |
|---|---:|---|
| vigie-collector |1,307,016|`417e7cf295a9f06414e301b940774e315403447dff30cbda5591d37b68c7f4b5`|
| vigie-conntrack |427,928|`99b5031bbdd38c111c623fde4a6b6373c55378b20d5dec83f529df1fec267a7a`|
| net-spike |384,464|`cc4b051cb10ed88b3627003ab10c1f943d0beb974f48fbf2b49c1aebc0f47860`|

The private provenance also checks that the collector source matches main `404748c`.
The fresh server namespace uses the already verified container image
`3eb429f3aabc5572131d965bf5c64fd108052d80c716342aaa85323bbf990505`.

## Observed router probes

The 60-second net-spike probe received real multicast traffic:

| Measurement | Observed |
|---|---:|
| mDNS IPv4 packets |47|
| mDNS IPv6 packets |41|
| SSDP packets |30|
| Read errors / parse errors |0 /0|
| Own packets / off-link packets |0 /1|
| Distinct mDNS names / services |36 /8|
| Distinct SSDP server strings / NT-ST values |2 /4|
| net-spike RSS / high-water RSS |444 /452 KiB|

IPv6 mDNS and SSDP sockets reported joined. This establishes receipt and parsing of the observed
traffic while the existing multicast service was present; it does not establish every client
protocol or prove unchanged end-to-end discovery behavior.

The conntrack helper's real `--once` read emitted 254 aggregate records, reported byte accounting
on, and skipped 0 lines. Aggregate records are not equivalent to the kernel table's flow count.
This validates the observed sample, not every possible protocol/firmware format. No rule or
sysctl was changed to obtain it. The memory numbers above belong to net-spike, not the collector
or helper daemon.

## Fresh collector-to-server pilot — ten-minute result

A separate project, `vigie_router_20261024`, was started with three healthy services, fresh named volumes, a fresh HMAC
key, a separate API certificate, and two distinct actual ingest SPKI pins. Its initial database
had 0 accepted batches and 0 devices. No synthetic container-pilot data or credentials were reused.
Ingest and API published only on host loopback; the SSH reverse forward was also bound to
router loopback, with strict host-key verification and agent forwarding disabled.

The rendered collector configuration reads the actual lease file and neighbor table, and targets
the root helper's isolated socket. DNS logging remains unchanged: the private log and
the drop-in path are intentionally absent, so `dns_log_quiet` is expected true. A valid-looking fake
drop-in must not be used to imply real DNS capture. Live DNS/DHCP fingerprints remain unverified.

The final `final-10m` read-only capture, after the ten-minute process run completed, records the following. The nine accepted batches include the initial health-only clock-sync probe, which contained no source observations:

| Measurement | Final observed result |
|---|---:|
| Accepted batches / last sequence |9 /9|
| Parse failures / dropped batches / pipeline backlog |0 /0 /0|
| Authenticated API status |200|
| Inventory identities / distinct MAC observations |41 /41|
| API type `unknown` |41|
| Raw lease / neighbor / flow rows |26 /80 /3175|
| Raw sightings: mDNS / SSDP |240 /68|
| Raw DNS rows |0|
| Observations with DHCP option 55 / option 60 |0 /0|
| Latest collector health RSS / maximum health sample |1704 /1760 KiB|
| Latest spool size / source flags |0 /0|
| Latest `dns_log_quiet` |true|

These are 41 inventory identities based on 41 MAC observations, not a measured count of unique
physical devices. Every reported type remains `unknown`; the run does not establish classification
accuracy. Service-context buckets contain 59 casting-service rows and 214 other service rows, not
numbers of devices or trusted identities. Household service-instance strings remain private.

Conntrack attribution also has an explicit evidence gap: the sampled batches report
520 unmapped flow observations and 379,085 unmapped bytes. These counters sum observations across
helper snapshots; they are not distinct flows or a dropped-batch count. Source flags remain 0 and
no batch was dropped. The initial empty clock-sync probe had no source rows; its default DNS-health
value is not evidence of DNS logging. The regular data window reports `dns_log_quiet=true`, matching
the intentionally unchanged DNS logging configuration.

Nine paired `/proc` samples from minutes 1–9 show collector RSS peaking at 1756 KiB, helper RSS at 1080 KiB, and simultaneous combined RSS at 2804 KiB. Individual peaks need not coincide. The separate collector health samples peak at 1760 KiB. Over a counter interval with approximately 413.75 seconds between artifact modification timestamps (an approximate capture interval), collector and helper CPU averaged 0.182% and 0.148% of one logical CPU respectively. This uses aggregate CPU tick deltas normalized for the two logical CPUs, without assuming `CLK_TCK`; it is not a full 600-second mean or a long-soak result.

Multicast announcements alone do not authorize a trusted identity or enforcement action.

## Router closure

Independent closure checks found no owned pilot process or reverse-forward listener. Six selected configuration-file hashes were unchanged, as were the existing avahi and dnsmasq PIDs. A post-run DNS query returned rcode 0 with two answers in approximately 23.32 ms. This is a point-in-time DNS continuity check, not DNS-log coverage or proof of every client discovery path. The independent watchdog completed its actual 600-second deadline and stopped both collector and conntrack helper. Router evidence was archived privately; the isolated `/tmp/vigie-validation-20261024` artifacts remain retained until reboot or operator cleanup, with credentials revoked and no persistent account or service installed.

## Private evidence and remaining gates

Evidence is retained under `.omc/runtime-validation/20261024-router/`: binary provenance,
read-only preflight, real net-spike/conntrack output, aggregate `probe-summary.json`, and server
readiness. Household-bearing raw output and API responses remain private; only aggregates belong
in this report. Server capture helpers perform read-only SQL and authenticated API requests,
retain private snapshots, and print aggregate counts, service buckets and health metrics only.

The bounded live collection run completed. No persistent install, procd behavior, DNS-log
ownership/reload behavior, certificate rotation, host reboot, 48-hour soak, classification accuracy
or Couvre-feu integration is claimed. The finalizer exited 0: all three owned containers are exited, both loopback ports are released, and the three named volumes, five secrets and one project network remain retained with private evidence. Both temporary ingest/API credentials were revoked (each operation reported one revocation). Unrelated resources were unchanged and the pre-existing `dev` container remains running. No resources were deleted. This closure is specific to the router pilot, separate from the earlier synthetic container shutdown.
