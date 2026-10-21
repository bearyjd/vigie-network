"""Human-readable ground-truth notes: one per profile (or `profile:variant`) in every manifest."""

from __future__ import annotations

NOTES: dict[str, str] = {
    "baseline": "Benign home LAN of seven archetypes; no anomalies. The false-positive control.",
    "rolling_mac": "A phone takes a fresh private MAC every roll_interval_s with no overlap; the "
    "pipeline should keep them as separate devices until a human approves a rule.",
    "hostname_spoof:hostname_only": "Attacker copies the victim's hostname and mDNS name but NOT "
    "DHCP options 55/60 (naive spoof). Hostname never counts alone.",
    "hostname_spoof:full_fingerprint": "Attacker copies opt55, opt60, hostname AND mDNS name of "
    "the target. Behavior (laptop) still differs from the phone it impersonates.",
    "mac_clone:naive": "Models only the NAIVE clone: the attacker takes the victim's MAC but keeps "
    "its own DHCP fingerprint, so a fingerprint change on an existing MAC is visible.",
    "mac_clone:same_fingerprint": "Sophisticated clone: same MAC AND same opt55/opt60/hostname/"
    "mDNS as the victim; only behavior (ports/domains) differs. No fingerprint change is visible: "
    "only behavioral demotion can detect it.",
    "ip_flap": "One IP alternates between two MACs in the neighbor table (ARP-spoof signal).",
    "doh_user": "A laptop sends large 443 traffic to DoH resolvers (documentation addresses listed "
    "in doh_resolvers) and no DNS queries reach the router.",
    "replay": "replay_identical: the same batch re-sent byte for byte; the server answers 200 "
    "duplicate. replay_header_ts_bumped: same body, ORIGINAL signature, but X-Vigie-Sent-Ts bumped "
    "in the header only; the attacker does not hold the key and cannot re-sign, so the server "
    "answers 401 signature mismatch. It is not a re-signed replay.",
    "out_of_order": "Two adjacent batches arrive swapped; the late one is refused with 409 "
    "seq_regression.",
    "stale_ts": "A batch whose sent_ts is an hour old is refused with 400 sent_ts_out_of_range.",
    "flood": "One window carries more raw flows than the batch cap; PRP section 4 truncation "
    "order applies and byte/flow totals survive in the per-MAC `other` bucket.",
    "rolling_overlap_veto": "PRP section 8 overlap veto with a 10 min grace window. Case "
    "legit_rolling: a rolling phone briefly holds two MACs (overlap shorter than grace; same "
    "device). Case sustained_two_devices: two devices with the same signature are both active "
    "for longer than the grace window; the newer MAC must be detached to its own device.",
    "rolling_fingerprint_copy:victim_away": "PRP section 8 accepted-risk scenario: an attacker "
    "copies a rolling device's opt55, opt60 and hostname and connects after the victim has left "
    "the LAN. No overlap exists, so only behavioral demotion can fire.",
    "rolling_fingerprint_copy:victim_present": "As victim_away, but the attacker connects while "
    "the victim is still on the LAN: the two are active together for longer than the grace window, "
    "so the overlap veto can fire.",
}
