# NextDNS operator report

Vigie can add third-party threat-feed context to a recent router DNS observation. Run the report
manually for an investigation from an operator environment with read access to the ingest inventory
database and raw DNS shards. Select the Vigie router collector that produced those records. The
pipeline and API services make no provider requests in normal operation.

Before running the report, verify that the NextDNS log device ID was used exclusively for queries
forwarded from the selected LAN device and collector throughout the requested window. A shared
router identifier, a missing provider device ID or a device ID also used by roaming clients cannot
establish this binding. Use the existing deployment and configuration to verify it.

Store the NextDNS API key in a private file readable only by its owner. NextDNS documents an account
API key that can also authenticate API operations that change settings or delete logs. Run the
command as the database file owner because SQLite can create WAL companion files beside a database
on a writable mount. Use a consistent local copy or a read-only mount where available.
[NextDNS API documentation](https://nextdns.github.io/api/)

```bash
python -m vigie_pipeline.nextdns_cli \
  --raw-dir "$RAW_DIR" --inventory "$INGEST_INVENTORY_PATH" \
  --key-file "$NEXTDNS_KEY_PATH" --profile "$NEXTDNS_PROFILE_ID" \
  --device "$NEXTDNS_DEVICE_ID" --collector "$VIGIE_COLLECTOR_ID" --mac "$LAN_DEVICE_MAC" \
  --confirm-exclusive-binding --from "$UTC_START" --to "$UTC_END"
```

Use UTC timestamps in `YYYY-MM-DDTHH:MM:SSZ` format. Select at most one hour within the trailing
seven days. Leave at least five minutes and four seconds after the retention boundary, and end
at least ten minutes and four seconds before running the report. Verify that NextDNS logged the
requested interval, including the four-second margins. The API can return only the records it
still has. The command
checks accepted batches and retained DNS rows, and exits without a report if it detects missing
or degraded local data or cannot finish reading the provider pages. It needs ingest records
that distinguish an explicitly reported DNS health field from a default value. Older records
without that provenance are insufficient. An empty report means the command found no attributable
threat-feed matches among the available observations.

The report requests raw logs across the selected profile for the time window, including entries
for other device IDs. Local DNS names are used only in memory for matching. A match requires
one observed router query and one provider event with the same
normalized name, timestamps within two seconds and the exact configured local MAC and provider
device ID. Both timestamps must be inside the requested window. Other events with the same
name and a nearby timestamp can make the match ambiguous,
including non-security events. The router timestamps queries when it reads the dnsmasq log.
Poll lag and clock skew can put related events outside the two-second match window. Treat the
result as context for an observed query and the DNS decision reported by NextDNS.

The report accepts a blocked verdict with the exact `threat-intelligence-feeds` reason ID. NextDNS
documents structured reason IDs, and this ID appears in a public example of a NextDNS log CSV.
The public Logs API example does not enumerate security IDs. JSON support for this reason has
been tested with synthetic transport. [NextDNS Logs API](https://nextdns.github.io/api/#logs)
· [Public log excerpt](https://help.nextdns.io/t/h7yz86r/threat-intelligence-block)

Output is local JSON with observed MAC addresses and third-party reason counts for the selected
period. `provider_coverage` is `unverified`. Query names, provider device details and credentials
stay out of the report. Store the
output as private investigation material if you need to retain it. A DNS query records an
observation and cannot establish that a connection occurred.
