"""Metric arithmetic of the replay report, on hand-built outcomes with hand-computed answers."""

import json

from vigie_pipeline.replay.labels import Label
from vigie_pipeline.replay.report import BUDGET_PER_NETWORK_DAY, UNKNOWN, build_report
from vigie_pipeline.replay.runner import Outcome

DET = "upload_deviation"
H0 = 3600 * 400_000  # a UTC day boundary is not required for these tests


def out(i, status, reason=None, episode=None, device="d", detector=DET):
    return Outcome(device, H0 + i * 3600, detector, status, reason, episode)


def lab(i, verdict, device="d"):
    return Label(device, H0 + i * 3600, verdict)


def det(outcomes, labels, name=DET):
    return build_report(outcomes, labels, "algo", "v1")["detectors"][name]


def test_confusion_counts_and_denominators():
    outcomes = [
        out(0, "fired", episode="e1"),  # anomalous: TP
        out(1, "fired", episode="e2"),  # anomalous: TP
        out(2, "quiet"),  # anomalous: FN
        out(3, "fired", episode="e3"),  # normal: FP
        out(4, "quiet"),  # normal: TN
        out(5, "quiet"),  # normal: TN
        out(6, "quiet"),  # normal: TN
    ]
    labels = [lab(0, "anomalous"), lab(1, "anomalous"), lab(2, "anomalous")]
    labels += [lab(3, "normal"), lab(4, "normal"), lab(5, "normal"), lab(6, "normal")]
    r = det(outcomes, labels)
    assert r["verdicts"] == {"tp": 2, "fp": 1, "fn": 1, "tn": 3}
    assert r["precision"] == round(2 / 3, 6)  # tp / (tp + fp), not / labelled
    assert r["recall"] == round(2 / 3, 6)  # tp / (tp + fn), not / hours


def test_precision_and_recall_differ_when_denominators_differ():
    outcomes = [out(0, "fired", episode="a"), out(1, "quiet"), out(2, "quiet"), out(3, "quiet")]
    labels = [lab(0, "anomalous"), lab(1, "anomalous"), lab(2, "anomalous"), lab(3, "anomalous")]
    r = det(outcomes, labels)
    assert (r["precision"], r["recall"]) == (1.0, 0.25)


def test_abstentions_are_separate_and_never_false_negatives_or_negatives():
    outcomes = [
        out(0, "abstained", "learning"),
        out(1, "abstained", "learning"),
        out(2, "abstained", "no_sample"),
        out(3, "abstained", "clock_gap"),
        out(4, "fired", episode="e"),
    ]
    labels = [lab(0, "anomalous"), lab(1, "normal"), lab(2, "anomalous"), lab(4, "anomalous")]
    r = det(outcomes, labels)
    assert r["verdicts"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 0}
    assert r["recall"] == 1.0  # the abstained anomalous hours are not misses
    ab = r["abstained"]
    assert ab["total"] == 4
    assert ab["by_reason"] == {"clock_gap": 1, "learning": 2, "no_sample": 1}
    assert ab["labelled_anomalous"] == 2 and ab["labelled_normal"] == 1


def test_unknown_never_zero_without_evidence():
    outcomes = [out(0, "abstained", "learning"), out(1, "abstained", "no_sample")]
    r = det(outcomes, [lab(0, "anomalous")])
    assert r["precision"] == UNKNOWN and r["recall"] == UNKNOWN
    assert r["coverage"]["fraction"] == 0.0 and r["coverage"]["evidence_hours"] == 0
    assert r["false_alerts_per_device_day"] == UNKNOWN
    assert r["false_alerts_per_network_day"] == UNKNOWN
    assert r["within_budget"] == UNKNOWN
    empty = det([], [])
    assert empty["coverage"]["fraction"] == UNKNOWN
    assert empty["precision"] == UNKNOWN


def test_recall_unknown_without_positive_labels_precision_unknown_without_alerts():
    r = det([out(0, "quiet"), out(1, "fired", episode="e")], [lab(0, "normal")])
    assert r["recall"] == UNKNOWN  # no anomalous label with a verdict
    assert r["precision"] == UNKNOWN  # the only alert is on an unlabelled hour
    r = det([out(0, "quiet")], [lab(0, "anomalous")])
    assert r["precision"] == UNKNOWN and r["recall"] == 0.0  # FN present: recall is a real 0


def test_ignore_is_tallied_but_excluded_everywhere():
    outcomes = [out(0, "fired", episode="e"), out(1, "quiet")]
    r = det(outcomes, [lab(0, "ignore"), lab(1, "ignore")])
    assert r["verdicts"] == {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    assert r["ignored_labels"] == 2
    assert r["alerts"]["unlabelled_episodes"] == 1 and r["alerts"]["false_episodes"] == 0


def test_unlabelled_alert_hours_are_counted_apart():
    r = det([out(0, "fired", episode="e"), out(1, "quiet")], [lab(1, "normal")])
    assert r["unlabelled_alert_hours"] == 1
    assert r["verdicts"]["fp"] == 0


def test_coverage_counts_hours_with_a_verdict():
    outcomes = [out(0, "quiet"), out(1, "fired", episode="e"), out(2, "abstained", "learning")]
    outcomes += [out(3, "abstained", "no_sample")]
    c = det(outcomes, [lab(0, "normal"), lab(2, "normal")])["coverage"]
    assert (c["evidence_hours"], c["universe_hours"], c["fraction"]) == (2, 4, 0.5)
    assert (c["labelled_hours"], c["labelled_with_verdict"]) == (2, 1)


def test_episodes_classified_by_their_labelled_hours():
    outcomes = [
        out(0, "fired", episode="true"),
        out(1, "fired", episode="true"),  # one episode over two hours
        out(2, "fired", episode="false"),
        out(3, "fired", episode="mixed"),
        out(4, "fired", episode="mixed"),
        out(5, "fired", episode="unl"),
    ]
    labels = [lab(0, "anomalous"), lab(1, "normal"), lab(2, "normal")]
    labels += [lab(3, "normal"), lab(4, "anomalous")]
    a = det(outcomes, labels)["alerts"]
    assert a == {"episodes": 4, "true_episodes": 2, "false_episodes": 1, "unlabelled_episodes": 1}


def test_false_alert_rate_per_device_day_and_network_day_against_budget():
    # 2 devices x 24 hours of evidence on the same UTC day: 2 device-days, 1 network-day
    day = (H0 // 86400 + 1) * 86400
    outcomes = []
    for dev in ("a", "b"):
        for i in range(24):
            outcomes.append(Outcome(dev, day + i * 3600, DET, "quiet"))
    outcomes[0] = Outcome("a", day, DET, "fired", None, "fa")
    outcomes[24] = Outcome("b", day, DET, "fired", None, "fb")
    labels = [Label("a", day, "normal"), Label("b", day, "normal")]
    r = det(outcomes, labels)
    assert r["alerts"]["false_episodes"] == 2
    assert r["false_alerts_per_device_day"] == 1.0  # 2 / (48 / 24)
    assert r["false_alerts_per_network_day"] == 2.0  # 2 / 1 day
    assert r["budget_per_network_day"] == BUDGET_PER_NETWORK_DAY == 1
    assert r["within_budget"] is False
    r = det(outcomes, labels[:1])  # one false episode: exactly on budget
    assert r["false_alerts_per_network_day"] == 1.0 and r["within_budget"] is True


def test_detectors_are_reported_independently_and_report_is_json_safe():
    outcomes = [
        out(0, "fired", episode="e", detector="large_upload"),
        out(0, "abstained", "learning"),
    ]
    rep = build_report(outcomes, [lab(0, "anomalous")], "algo", "v1")
    assert rep["detectors"]["large_upload"]["verdicts"]["tp"] == 1
    assert rep["detectors"][DET]["verdicts"]["tp"] == 0
    assert rep["detectors"][DET]["abstained"]["total"] == 1
    assert rep["policy"] == {"algorithm": "algo", "config_version": "v1"}
    assert json.loads(json.dumps(rep, sort_keys=True)) == rep


def test_labels_for_unknown_devices_are_counted_not_dropped():
    rep = build_report([out(0, "quiet")], [lab(0, "normal"), lab(0, "normal", "zz")], "a", "v")
    assert rep["labels"] == {
        "total": 2,
        "normal": 2,
        "anomalous": 0,
        "ignore": 0,
        "unknown_device": 1,
    }


def test_report_independent_of_outcome_and_label_order():
    outcomes = [out(i, "fired" if i % 3 == 0 else "quiet", episode=f"e{i}") for i in range(9)]
    labels = [lab(i, "anomalous" if i % 2 else "normal") for i in range(9)]
    one = build_report(outcomes, labels, "a", "v")
    two = build_report(outcomes[::-1], labels[::-1], "a", "v")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
