"""Per-detector evaluation report. Counts are integers; a ratio with no evidence is "unknown",
never zero. `labels.normal/anomalous/ignore` count label records, so a detector-scoped label and an
unscoped one for the same hour count twice. Abstentions are reported apart from verdicts and are
never misses or negatives.

Hour level: a verdict is an hour where the detector actually evaluated (fired or quiet). TP/FP/FN/TN
use only owner labels normal and anomalous on such hours. precision = TP/(TP+FP). Recall is
reported both ways: `recall` = TP/(TP+FN) over evaluated hours only, and `recall_all_labelled` =
TP/(TP+FN+abstained anomalous hours), which counts a hour the detector could not judge as a miss.
`ignore` labels are tallied and excluded from every denominator. A label may be scoped to one
detector; it then overrides an unscoped label for that detector.

Event level: an anomalous event is a run of consecutive anomalous-labelled hours of one device. It
is detected when the detector fired on any hour of it; `event_recall` divides by events with at
least one evaluated hour, `event_recall_all_labelled` by every event.

Alert level (the notification budget): an episode is one engine incident (consecutive firing hours).
It is true if any of its hours is labelled anomalous, else false if any is labelled normal, else
unlabelled; an episode whose labelled hours are all `ignore` is `ignored_episodes` (not
unlabelled). False episodes are therefore a lower bound while unlabelled episodes exist, so
`within_budget` is `false` only when that lower bound already exceeds the budget, `unknown` while
unlabelled episodes exist and the bound does not, and `true` only with every episode labelled. The
top-level `budget` sums false episodes across detectors (each is a separate notification source).
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


def _labelled(labels, detector: str) -> dict:
    "(device, hour) -> verdict for one detector: a scoped label beats an unscoped one."
    found: dict = {}
    for x in sorted(labels, key=lambda x: x.detector is not None):
        if x.detector in (None, detector):
            found[(x.device, x.hour)] = x.verdict
    return found


def _events(rows: list[Outcome], labelled: dict) -> dict:
    "Runs of consecutive anomalous hours per device; detected when the detector fired in the run."
    status = {(o.device, o.hour): o.status for o in rows}
    known = {o.device for o in rows}  # labels for other devices are only tallied as unknown_device
    hours = sorted(k for k, v in labelled.items() if v == "anomalous" and k[0] in known)
    runs: list[list] = []
    for device, hour in hours:
        if runs and runs[-1][0] == device and runs[-1][-1] == hour - 3600:
            runs[-1].append(hour)
        else:
            runs.append([device, hour])
    evaluated = detected = 0
    for run in runs:
        states = [status.get((run[0], h)) for h in run[1:]]
        evaluated += any(x in (FIRED, "quiet") for x in states)
        detected += FIRED in states
    return {
        "anomalous_events": len(runs),
        "evaluated_events": evaluated,
        "detected_events": detected,
        "event_recall": _ratio(detected, evaluated),
        "event_recall_all_labelled": _ratio(detected, len(runs)),
    }


def _episodes(fired: list[Outcome], labelled: dict) -> dict:
    marks: dict = {}
    for o in fired:
        verdict = labelled.get((o.device, o.hour))
        marks.setdefault((o.device, o.episode), set())
        if verdict in ("normal", "anomalous", "ignore"):
            marks[(o.device, o.episode)].add(verdict)
    judged = {k: v - {"ignore"} for k, v in marks.items()}
    true = sum(1 for v in judged.values() if "anomalous" in v)
    false = sum(1 for v in judged.values() if v == {"normal"})
    # all labelled hours are `ignore`: neither true nor false, and not waiting for a label either
    ignored = sum(1 for k, v in judged.items() if not v and marks[k])
    return {
        "episodes": len(marks),
        "true_episodes": true,
        "false_episodes": false,
        "ignored_episodes": ignored,
        "unlabelled_episodes": len(marks) - true - false - ignored,
    }


def _evidence(rows, labelled: dict) -> list[Outcome]:
    "Hours the detector judged, minus owner-ignored hours: `ignore` leaves every denominator."
    return [
        o for o in rows if o.status != ABSTAINED and labelled.get((o.device, o.hour)) != "ignore"
    ]


def _detector(rows: list[Outcome], labelled: dict) -> dict:
    "labelled: (device, hour) -> verdict as seen by this detector."
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
    evidence = _evidence(rows, labelled)
    fired_rows = [o for o in rows if o.status == FIRED]  # ignored hours still shape an episode
    alerts = _episodes(fired_rows, labelled)
    universe = len(rows) - ignored
    return {
        "verdicts": {k: verdicts[k] for k in ("tp", "fp", "fn", "tn")},
        "precision": _ratio(verdicts["tp"], verdicts["tp"] + verdicts["fp"]),
        "recall": _ratio(verdicts["tp"], verdicts["tp"] + verdicts["fn"]),
        "recall_all_labelled": _ratio(
            verdicts["tp"], verdicts["tp"] + verdicts["fn"] + ab_labels["anomalous"]
        ),
        **_events(rows, labelled),
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
            "universe_hours": universe,
            "fraction": _ratio(len(evidence), universe),
            "labelled_hours": labelled_hours,
            "labelled_with_verdict": with_verdict,
        },
        "alerts": alerts,
        **_budget(evidence, alerts["false_episodes"], alerts["unlabelled_episodes"]),
    }


def _within(rate, unlabelled: int):
    if rate == UNKNOWN:
        return UNKNOWN
    if rate > BUDGET_PER_NETWORK_DAY:
        return False  # a lower bound already over budget
    return UNKNOWN if unlabelled else True


def _budget(evidence: list[Outcome], false_episodes: int, unlabelled: int) -> dict:
    device_days = len(evidence) / 24
    network_days = len({o.hour // 86400 for o in evidence})
    per_network = UNKNOWN if not evidence else round(false_episodes / network_days, PLACES)
    return {
        "false_alerts_per_device_day": UNKNOWN
        if not evidence
        else round(false_episodes / device_days, PLACES),
        "false_alerts_per_network_day": per_network,
        "budget_per_network_day": BUDGET_PER_NETWORK_DAY,
        "within_budget": _within(per_network, unlabelled),
    }


def _combined(detectors: dict, outcomes, labelled_by: dict) -> dict:
    "One notification budget for the whole network: false episodes of every detector add up."
    evidence = [
        o
        for name in labelled_by
        for o in _evidence([x for x in outcomes if x.detector == name], labelled_by[name])
    ]
    false = sum(d["alerts"]["false_episodes"] for d in detectors.values())
    unlabelled = sum(d["alerts"]["unlabelled_episodes"] for d in detectors.values())
    days = len({o.hour // 86400 for o in evidence})
    rate = UNKNOWN if not evidence else round(false / days, PLACES)
    return {
        "false_episodes": false,
        "unlabelled_episodes": unlabelled,
        "false_alerts_per_network_day": rate,
        "budget_per_network_day": BUDGET_PER_NETWORK_DAY,
        "within_budget": _within(rate, unlabelled),
    }


def build_report(
    outcomes: list[Outcome] | tuple[Outcome, ...],
    labels: list[Label] | tuple[Label, ...],
    algorithm: str,
    config_version: str,
) -> dict:
    "Deterministic, JSON-safe report; independent of the order of outcomes and labels."
    devices = {o.device for o in outcomes}
    kinds = Counter(x.verdict for x in labels)
    names = sorted({o.detector for o in outcomes} | set(DETECTORS))
    labelled_by = {name: _labelled(labels, name) for name in names}
    detectors = {
        name: _detector([o for o in outcomes if o.detector == name], labelled_by[name])
        for name in names
    }
    return {
        "policy": {"algorithm": algorithm, "config_version": config_version},
        "labels": {
            "total": len(labels),
            "normal": kinds["normal"],
            "anomalous": kinds["anomalous"],
            "ignore": kinds["ignore"],
            "unknown_device": sum(1 for x in labels if x.device not in devices),
        },
        "detectors": detectors,
        "budget": _combined(detectors, outcomes, labelled_by),
    }
