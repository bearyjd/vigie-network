# Deployment validation — 2026-10-24

Recorded outcome: **local synthetic container checks passed; router validation blocked**.
This report records the isolated 2026-10-24 pilot and the defects/repairs observed against baseline
`2e1d44d`. Approval and integration status belong to the PR and Git history. Synthetic traffic and
localhost success do not establish router compatibility, production placement, real DHCP/DNS input
formats, firmware behavior or a 48-hour resource soak. No secrets or client identifiers are included.

## Environment and isolation

- Host: actual Podman 5.8.7, rootless networking through pasta; podman-compose 1.6.
- One existing development container was left untouched.
- Source baseline: `2e1d44d588e34d286eab18c5ad8859787d9636db`.
- Initial baseline image: `61e202833ba563c37f8df377ed7788929e7fd43f31e18d27dd7b2f9549e1dc7a`.
- Fixed candidate tag: `localhost/vigie-server:validation-20261024-fixed2`.
- Fixed candidate image: `3eb429f3aabc5572131d965bf5c64fd108052d80c716342aaa85323bbf990505`.
- Fresh fixed project: `vigie_validation_20261024_fixed2`; bindings only on
  `127.0.0.1:18443` (ingest) and `127.0.0.1:18444` (API).
- Three fresh named volumes: project prefix plus `_vigie-raw`, `_vigie-inv`, `_vigie-overrides`.
- Actual inspect evidence confirms read-only root filesystem, UID/GID `10001:10001`, dropped
  capabilities, no-new-privileges, 512 MiB memory limit, one CPU and 256 process limit.
- No production server location or LAN exposure is selected by this pilot.

## Actual image mount issue and candidate repair

The real baseline ingest container acquired an anonymous writable `/overrides` volume from the image's
`VOLUME` declaration. Compose did not explicitly mount that path for ingest, but image metadata added it.
The directory was empty and separate from the trusted overrides named volume: no trusted-data exposure
was observed. It nevertheless violated the documented ownership/mount matrix.
[Podman documents image-volume handling](https://docs.podman.io/en/latest/markdown/podman-run.1.html#image-volume-anonymous-tmpfs-ignore);
the actual captured mount list, rather than that default alone, establishes this pilot finding.

The minimal candidate removes the image `VOLUME` declaration; Compose remains responsible for mounts.
Owned directories and the unprivileged runtime user are preserved. A new read-only checker,
`deploy/tests/check_image_mounts.py`, validates captured real `podman inspect` JSON.
The failing baseline was recorded before the fix; the fixed image then passed all three service checks.

| Service | Actual fixed named mounts | Writable |
|---|---|---|
| ingest | `/raw`, `/inv` | both |
| pipeline | `/raw`, `/inv`, `/overrides` | `/inv` only |
| API | `/inv`, `/overrides` | `/overrides` only |

The final restart summary records all three services healthy after each individual restart;
earlier startup inspect captures may still show health checks starting.
The checker also verifies exact volume names, mount modes, read-only rootfs and runtime user.
The broader hardening assertions above come from actual inspect evidence, not a claim that this checker
covers every runtime field.

## Supported secret mapping for this pilot

podman-compose 1.6 did not support the attempted top-level external secret `name` alias as intended.
The working mapping uses the **actual prefixed Podman secret name as the top-level key and service
`source`**, then an explicit service `target` to preserve the application's expected filename:

```yaml
secrets:
  vigie_validation_20261024_vigie_tls_cert:
    external: true
services:
  ingest:
    secrets:
      - source: vigie_validation_20261024_vigie_tls_cert
        target: vigie_tls_cert
        uid: "10001"
        gid: "10001"
        mode: "0400"
```

The certificate appears at `/run/secrets/vigie_tls_cert`; apply the same source/target pattern to
`vigie_tls_key`, `vigie_api_tls_cert`, `vigie_api_tls_key` and `collector_key_k1`.
All actual secret objects use the `vigie_validation_20261024_` prefix. Secret values are absent here.
This is a tested pilot mapping for this provider version, not a statement that every Compose provider
handles aliases and targets identically.

## Validation evidence so far

Evidence is retained privately in the main workspace under
`.omc/runtime-validation/20261024-container/`; it is not published with this report.

| Check | Evidence | Result |
|---|---|---|
| Baseline image build | `build.log` | built on real host |
| Baseline actual mount boundary | `ingest-created-inspect.json`, `mount-boundary-red.log` | failed: extra anonymous `/overrides` |
| Candidate image builds | fixed and fixed2 build captures | built on real host |
| Final actual mount boundaries | `fixed2-*-inspect.json`, `mount-boundary-final-green.log` | three services passed |
| Fresh volume bootstrap / service health | `fixed2-restart-summary.json` | all three healthy after each individual restart |
| Synthetic authenticated ingest → pipeline → API | `fixed2-functional-summary.json` | four signed batches accepted; seven synthetic devices; API health 200, unauthenticated inventory 401 |
| Human override / subsequent pipeline pass | `fixed2-functional-summary.json` | authenticated versioned PATCH 200; label/group preserved |
| Allowed/forbidden writes | `fixed2-runtime-boundaries-summary.json` | 7 allowed writes; 8 forbidden writes refused with EROFS |
| New database/sidecar and secret modes | `fixed2-boundary-*.json` | scanned database/WAL/SHM files 0600; secrets 0400; UID/GID 10001 |
| Each service restarted individually | `fixed2-restart-summary.json` | after each: all healthy; API token and human override persisted |

A second real deployment defect was found: fresh `inventory.db` had mode 0644 inside its 0700
parent directory. No exposure outside that parent was observed; the mode violated the private-file
contract. The entrypoint now sets `umask 077`; behavioral tests first reported 112 pass / 2 fail,
then 114 pass / 0 fail. A rebuilt image and entirely fresh fixed2 volumes verified the modes above.
This affects future file creation only: existing files are not automatically chmodded. The earlier
pilot's 0644 file is retained as evidence. These checks cover synthetic data and individual process
restarts, not host reboot, restoration, real traffic, load or long-duration stability.

## Router access and remaining field gates

This section records the earlier container-pilot closure state. Subsequent authorized router
access and probe results are recorded separately in the [router field validation follow-up](router-validation-2026-10-24.md); the earlier closure is not retroactively rewritten.

- Gateway `192.168.1.1` answered a DNS probe with response code 0; its configuration was unchanged.
- SSH rejected the default RSA and Ed25519 identities and the explicitly tried existing
  couvre-feu-admin identity. Public-key authorization remains pending.
- Fresh statically linked ARM64 collector, conntrack helper and net-spike binaries were built from
  source `2e1d44d`; hashes, sizes and target are recorded in
  `.omc/runtime-validation/20261024-router/provenance.json`.
- These new binaries have **not** run on the router. No router files, accounts, services,
  dnsmasq/firewall configuration or logging setup were changed.
- D2 dnsmasq coexistence permission remains unanswered. No logging-on script, init installation,
  firewall operation or dnsmasq restart is authorized by these results. D1–D6 remain existing gates.
- After access is supplied, use a separately controlled tmpfs pilot and verify multicast coexistence,
  real parser formats, permissions, resource use and rollback before persistent installation.

## Retained resources and cleanup

At closure, all seven owned validation containers were nonrunning: the original probe remained
created and six fixed/fixed2 service containers were exited; none was paused or restarting.
Loopback ports 18443/18444 were released. The unrelated development container remained running.
`retained-resources.json` records eight prefixed named volumes, five prefixed secrets, three
project networks and the original empty anonymous probe volume, all retained alongside the images
and private evidence. No volume deletion, prune or unrelated workload changes were performed.
Do not remove volumes or use `down -v` as part of validation closure.

A later approved cleanup must name the pilot project/resources, stop only its exact containers,
retain or back up required evidence, and revoke only its collector/API credentials. Volume deletion
requires its own explicit decision. Router rollback is presently unnecessary because it was not changed.
