# Monitoring field status — 2026-10-25

Source for the five-area monitoring build is merged through `fad5d01` (PR12), including the
reviewed collector shutdown and DNS-probe fixes. The owned server deployment is running;
router installation, DNS logging and signed parsed-DNS delivery have passed their checkpoints.
Actual collector privilege checks passed. The LAN configuration correction is applied and a
post-correction parsed-DNS observation has source flags 0. A backlog of 1 was normal pipeline
handoff; a controlled drain reached 0. The processing-age acceptance contract is merged and its API-only image update is deployed
and independently verified, including the additive field and null-at-zero behavior. Full acceptance and
soak readiness are not claimed. The real 48-hour run has
**not started**.

This is a dated installation/readiness report, not a production-acceptance or detection-accuracy
claim. The earlier [container validation](deployment-validation-2026-10-24.md) and
[ten-minute router pilot](router-validation-2026-10-24.md) retain their original scope and results.

## Source and field evidence

| Area | Merged source | Measured field status |
|---|---|---|
| Device characterization | Versioned, expiring same-MAC service evidence; qualitative strength, conflicts/unknown and human-override precedence | Classification accuracy and household role coverage remain unmeasured |
| DNS and source coverage | Retryable deployment recovery, typed observation/probe windows, authenticated coverage API, strict bounded direct-answer DNS probe | LAN correction applied; fresh signed parsed-DNS window has source flags 0. Earlier flags-8 history is retained; controlled drain reached backlog 0; processing-age API update deployed and verified; normal handoff remains distinct from a stall |
| Persistent deployment | Rootless units, dependency recovery, fixed router logfs and privilege transition, bounded collector shutdown | Three owned server roles and router collection are running; actual collector privileges and server restart checkpoints passed; bounded outage, drop-in repair and reconciled helper respawn passed; natural rotation/cold boot remain pending |
| Long-duration testing | Durable real-clock monitor with missing-data, clock/gap, resource and source-quality gates | No real 48-hour run has started; no pass is claimed from fixture clocks or short probes |
| Baselines and incidents | Collector-scoped hourly measurements, versioned pooled references, fixed and qualified learned upload incidents, bounded read APIs | Last snapshot: 31 identities all typed unknown, first three inspected activity records learning, zero incidents. No mature field baseline, labeled accuracy result or monitoring UI is claimed |

Each source change passed independent adversarial review and hosted CI on its reviewed head
before merge. PR12 passed both hosted CI gates on reviewed head `8ff9d70`; its server gate
reported 1428 passed, one expected failure and 95.21% coverage, with 46 native acceptance
checks. Source tests establish their stated contracts; deployment and history-dependent
acceptance require the field observations below.

The live server namespace has three rootless roles, three named data volumes and five secrets.
Checks exercised the role-specific mount matrix, read-only root filesystems, UID/GID 10001,
capability removal, no-new-privileges, resource limits, TLS and authenticated read/write scopes.
Unrelated workloads were preserved. Controlled API and pipeline restarts passed on the same
pinned image. An initial API check ran before readiness and failed; its evidence was retained,
and the settled TLS/health check subsequently passed. This does not establish host cold-boot or
restore behavior.

The API-only processing-age deployment completed in 2.82 seconds. Its new field/null-at-zero
contract and actual UID/GID 10001, zero capabilities, NNP 1 and role constraints were independently
corroborated. All 85 other containers in the 86-container host inventory were unchanged; ingest
and pipeline retained their previous image, whose relevant application code is byte-identical.
Only the API role changed. This does not imply a whole-stack image replacement.

The router checkpoint installed sixteen reviewed files and the dedicated UID/GID 20061 account.
Its journal contains twenty-three ordered prepared/verified step pairs. Installed file hashes,
owners, modes and single-link state matched the bound manifest. Independently derived account
state hashes confirmed only the three intended rows were appended, with foreign rows and
account metadata preserved. Failed attempts and reconciliation evidence were retained.

The public static privilege helper passed a separate harmless procd/kernel proof for the
dedicated IDs, empty supplementary groups, zero capability masks, NNP 1 and zero core limits.
The installed helper also ran the collector's config/key check successfully. After activation,
the actual collector wrapper/child passed its dedicated-ID, group, capability, NNP and core-limit
kernel checks. The conntrack helper remains a separate root service; it is not covered by the
collector's unprivileged-process claim. The post-configuration restart passed renewed kernel
checks, independently corroborated in review. A controlled stop proved the wrapper and Rust child gone. An auxiliary UID-absence check
used an unsupported firmware process-tool option and failed; its stderr was retained. A subsequent
read-only scan of 124 processes found only two legitimate active PIDs in the checked scope.
The repaired portable UID scan and a new controlled stop/restart now passed, followed by renewed
kernel checks. The earlier failed check remains in the evidence and is not retroactively treated
as a successful UID-absence proof. Six owned boot links and a 127-byte root-owned mode-0600 cron job were installed and
independently verified. A new root cron daemon was started with only that owned five-minute job.
First cron execution and cold-boot behavior remain untested.

The owned 20 MiB tmpfs passed its exact mount/ownership/flag checks. A capacity probe, performed
before DNS writers existed, reached genuine ENOSPC at the expected size, verified the owned
file's bytes and identity, removed only that file and confirmed the empty guarded mount.
This does not yet establish DNS behavior while logging is full, log reopen/rotation recovery,
or reboot recreation. The owned filesystem cap does not bound dnsmasq's possible system-logger
fallback allocations outside that filesystem.

Only the scoped Tower DHCP reservation/name tail has been applied, with compare-before-write:
1854 existing bytes were preserved and 185 owned bytes appended. Initial controlled external
DNS continuity samples were positive for approximately 200 seconds before logging activation;
that evidence measures resolver responses. Subsequent authenticated coverage confirmed a positive
parsed-DNS observation window. After the configuration correction, a fresh full signed window at
sequence 2 confirmed parsed DNS at 02:18:02 UTC and source flags 0. The latest checked backlog
was 1 during the normal 30-second pipeline handoff; a controlled 90-second drain reached 0.
An inventory snapshot contained 31
observed identities, all typed unknown, and zero incidents; the first three inspected activity
records were learning. Identity count is not physical-device uniqueness, and an
empty incident snapshot is not evidence of benign traffic or detector accuracy.

The private collector configuration omitted the explicit LAN settings and inherited a builtin
network default that did not match this router. Source flags 8 exposed the resulting multicast
gap. The reviewed correction preserved the 378-byte original configuration prefix and appended
the three explicit verified [LAN settings](deploy.md#collector-lan-scope), producing 430 bytes.
Fresh unflagged delivery does not relabel the earlier windows: flagged history is retained as
degraded evidence and is not silently reset to pass acceptance. No private endpoint, MAC,
credential or household inventory is published here.

The runtime metrics key is **not installed**. The proposed append was blocked before execution;
explicit owner approval remains pending. Expiry arming and the strict 48-hour monitor have not run.

The additive oldest-pending-receipt API field and greater-than-180-second processing-age stall
gate are merged in PR12; the raw backlog count is preserved. The API image (`fcdd` hash prefix) is now deployed and verified; ingest and pipeline were
preserved. The durable runner uses schema 2 and the processing-age contract; its version-2
service is staged only, not running. A transient
handoff count and a stalled pipeline must not be presented as the same failure.

A bounded 125-second ingest outage passed its scoped recovery checkpoint: nine of nine DNS
observations across two fault windows remained positive, buffered batches stayed in the owned
RAM spool, dropped batches remained zero, backlog drained to zero and the collector boot identity
remained stable. Recovery used the same ingest image. An initial readiness check failed before
the service settled; that result was retained and subsequent readiness passed. This proves the
bounded tested outage, not arbitrary-duration buffering, cold boot or restore.

The controlled owned drop-in repair completed in 0.79 seconds. Exact restored-file and applied-marker
checks passed, followed by 144 positive control DNS queries, fresh signed parsed-DNS delivery,
source flags 0, backlog 0 and zero drops. The continuity recorder was explicitly stopped with its
stop event retained. The natural log size was about 4.4 MiB, below the 8 MiB rotation threshold;
no forced fill or rotation was performed. Natural rotation/reopen and cold boot remain untested.

One service-scoped helper TERM RPC caused procd to respawn the root helper with a new process
start and socket inode, while the collector wrapper/Rust process identities stayed unchanged.
The original proof rejected procd's successful empty acknowledgement because it expected `{}`;
its prepared/failed record and stderr remain intact. A separately approved **read-only** reconciliation
used the old baseline and unchanged functional guards, without sending a second signal. It reached
reconciled state after a fresh full signed post-fault window, source flags 0, zero drops, drain to
zero, stable collector boot and positive external/local DNS checks. A future acknowledgement fix
has fixture evidence but was not used to repeat the fault.

The helper fault interval is **partial conntrack evidence**: newly primed cumulative counters avoid
replaying old traffic, but the interruption can undercount traffic without raising source flags.
Flags 0 and zero reported drops do not prove a gap-free interval or zero activity. The
[roadmap](roadmap.md#execution-stages) records a transport-gap/sequence-reset quality-latch
hardening seam; this report does not claim that latch is implemented.

A read-only NextDNS assessment succeeded and confirmed available query/device metadata. Provider
history has not been ingested into Vigie. A future adapter belongs to the richer context stage:
keep provider provenance, request raw events, expose pagination/gaps, avoid duplicate counts and
require explicit timestamped attribution. Cloud history must not train the router-local baseline
or automatically merge identities. Couvre-feu policy/enforcement remains separate.

Credential files used for the authorized assessment were normalized to private permissions and
excluded from version control; no credential or provider household data is published. This does
not authorize the separate pending runtime metrics-key installation. The local read-only GUI
proposal is a draft for M1b, not implemented or approved for implementation.

## Remaining measured gates

1. Complete remaining scoped boot/first-cron proofs, preserving the
   already-recorded degraded windows and all failure evidence.
2. Complete natural-threshold rotation/reopen proof, retain the completed drop-in repair,
   bounded-outage and read-only-reconciled helper evidence, and verify
   final healthy source/resource state. Cold-boot/reboot behavior needs its own reviewed test;
   installation and simulated manager tests do not establish it.
3. Obtain the required owner approval before installing the read-only runtime meter credential.
   Arm expiry and begin the strict real-clock monitor only after its preconditions pass.
   Report the actual 172800-second result, sample gaps,
   quality and resource evidence using the [acceptance contract](../deploy/persistent/README.md#strict-real-clock-monitor).
4. Accumulate qualifying field history for learned references. UI, incident feedback and a labeled
   seven-day pilot follow their [roadmap stages](roadmap.md#execution-stages); a 48-hour resource
   run cannot establish fourteen-date baseline maturity or detection accuracy.

The next checkpoint is credential authorization and the remaining operational proofs;
update this report only from
captured results, keeping pending items distinct from completed evidence.
