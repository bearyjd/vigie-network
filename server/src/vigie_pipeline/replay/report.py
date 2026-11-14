"""Per-detector evaluation report. Counts are integers; a ratio with no evidence is "unknown",
never zero. Abstentions are reported apart from verdicts and are never misses or negatives.

Hour level: a verdict is an hour where the detector actually evaluated (fired or quiet). TP/FP/FN/TN
use only owner labels normal and anomalous on such hours. precision = TP/(TP+FP), recall =
TP/(TP+FN). `ignore` labels are tallied and excluded from every denominator.

Alert level (the notification budget): an episode is one engine incident (consecutive firing hours).
It is true if any of its hours is labelled anomalous, else false if any is labelled normal, else
unlabelled. False episodes are therefore a lower bound while unlabelled episodes exist.
"""

from __future__ import annotations

from collections import Counter

from vigie_pipeline.replay.labels import Label
from vigie_pipeline.replay.runner import ABSTAINED, DETECTORS, FIRED, Outcome

UNKNOWN = "unknown"
BUDGET_PER_NETWORK_DAY = 1  # roadmap M1: at most 1 unwanted notification per network per day
PLACES = 6


def _ratio(numerator: int, denominator: int):
    return UNKNOWN if denominator == 0 else round(numerator / denominator, PLACES)


def _episodes(fired: list[Outcome], labelled: dict) -> dict:
    marks: dict = {}
    for o in fired:
        verdict = labelled.get((o.device, o.hour))
        if verdict in ("normal", "anomalous"):
            marks.setdefault((o.device, o.episode), set()).add(verdict)
        else:
            marks.setdefault((o.device, o.episode), set())
    true = sum(1 for v in marks.values() if "anomalous" in v)
    false = sum(1 for v in marks.values() if v == {"normal"})
    return {
        "episodes": len(marks),
        "true_episodes": true,
        "false_episodes": false,
        "unlabelled_episodes": len(marks) - true - false,
    }


def _detector(rows: list[Outcome], labelled: dict) -> dict:
    verdicts = Counter()
    abstained = Counter()
    ab_labels = Counter()
    labelled_hours = with_verdict = ignored = unlabelled_alert_hours = 0
    for o in rows:
        label = labelled.get((o.device, o.hour))
        if label == "ignore":
            ignored += 1
        if label in ("normal", "anomalous"):
            labelled_hours += 1
        if o.status == ABSTAINED:
            abstained[o.reason] += 1
            if label in ("normal", "anomalous"):
                ab_labels[label] += 1
            continue
        if label in ("normal", "anomalous"):
            with_verdict += 1
            fired = o.status == FIRED
            verdicts[
                ("tp" if fired else "fn") if label == "anomalous" else ("fp" if fired else "tn")
            ] += 1
        elif o.status == FIRED and label is None:
            unlabelled_alert_hours += 1
    evidence = [o for o in rows if o.status != ABSTAINED]
    fired_rows = [o for o in evidence if o.status == FIRED]
    alerts = _episodes(fired_rows, labelled)
    return {
        "verdicts": {k: verdicts[k] for k in ("tp", "fp", "fn", "tn")},
        "precision": _ratio(verdicts["tp"], verdicts["tp"] + verdicts["fp"]),
        "recall": _ratio(verdicts["tp"], verdicts["tp"] + verdicts["fn"]),
        "abstained": {
            "total": sum(abstained.values()),
            "by_reason": dict(sorted(abstained.items())),
            "labelled_anomalous": ab_labels["anomalous"],
            "labelled_normal": ab_labels["normal"],
        },
        "ignored_labels": ignored,
        "unlabelled_alert_hours": unlabelled_alert_hours,
        "coverage": {
            "evidence_hours": len(evidence),
            "universe_hours": len(rows),
            "fraction": _ratio(len(evidence), len(rows)),
            "labelled_hours": labelled_hours,
            "labelled_with_verdict": with_verdict,
        },
        "alerts": alerts,
        **_budget(evidence, alerts["false_episodes"]),
    }


def _budget(evidence: list[Outcome], false_episodes: int) -> dict:
    device_days = len(evidence) / 24
    network_days = len({o.hour // 86400 for o in evidence})
    per_network = UNKNOWN if not evidence else round(false_episodes / network_days, PLACES)
    return {
        "false_alerts_per_device_day": UNKNOWN
        if not evidence
        else round(false_episodes / device_days, PLACES),
        "false_alerts_per_network_day": per_network,
        "budget_per_network_day": BUDGET_PER_NETWORK_DAY,
        "within_budget": UNKNOWN if not evidence else per_network <= BUDGET_PER_NETWORK_DAY,
    }


def build_report(
    outcomes: list[Outcome] | tuple[Outcome, ...],
    labels: list[Label] | tuple[Label, ...],
    algorithm: str,
    config_version: str,
) -> dict:
    "Deterministic, JSON-safe report; independent of the order of outcomes and labels."
    labelled = {(x.device, x.hour): x.verdict for x in labels}
    devices = {o.device for o in outcomes}
    kinds = Counter(x.verdict for x in labels)
    ordered = sorted(outcomes, key=lambda o: (o.device, o.hour, o.detector))
    names = sorted({o.detector for o in ordered} | set(DETECTORS))
    return {
        "policy": {"algorithm": algorithm, "config_version": config_version},
        "labels": {
            "total": len(labels),
            "normal": kinds["normal"],
            "anomalous": kinds["anomalous"],
            "ignore": kinds["ignore"],
            "unknown_device": sum(1 for x in labels if x.device not in devices),
        },
        "detectors": {
            name: _detector([o for o in ordered if o.detector == name], labelled) for name in names
        },
    }
