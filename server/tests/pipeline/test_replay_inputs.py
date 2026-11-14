"""Label and series file loaders for the offline replay harness: strict, bounded, path-free."""

import json

import pytest

from vigie_pipeline.replay.errors import ReplayInputError
from vigie_pipeline.replay.labels import MAX_LABELS, MAX_NOTE, load_labels
from vigie_pipeline.replay.series import MAX_SAMPLES_PER_DEVICE, load_series

H = 3600 * 400_000


def lab(device="dev-a", hour=H, verdict="normal", **extra):
    return {"device": device, "hour": hour, "verdict": verdict, **extra}


def labels_doc(*labels, version=1):
    return json.dumps({"version": version, "labels": list(labels)}).encode()


def sample(hour=H, bytes_up=10, qualified_seconds=3600, **extra):
    return {"hour": hour, "bytes_up": bytes_up, "qualified_seconds": qualified_seconds, **extra}


def series_doc(*devices, version=1):
    return json.dumps({"version": version, "devices": list(devices)}).encode()


def dev(name="dev-a", *samples):
    return {"device": name, "samples": list(samples) or [sample()]}


def test_labels_roundtrip_and_sorted_independent_of_input_order():
    a = lab("dev-b", H + 3600, "anomalous", note="backup")
    b = lab("dev-a", H, "ignore")
    c = lab("2001:db8::1", H, "normal")
    one = load_labels(labels_doc(a, b, c))
    two = load_labels(labels_doc(c, a, b))
    assert one == two
    assert [(x.device, x.hour) for x in one] == sorted((x.device, x.hour) for x in one)
    assert {x.verdict for x in one} == {"normal", "anomalous", "ignore"}
    assert next(x for x in one if x.verdict == "anomalous").note == "backup"


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"[]",
        b"not json",
        b'{"version":1,"labels":[],"labels":[]}',  # duplicate key
        b'{"version":1,"labels":[{"device":"d","hour":NaN,"verdict":"normal"}]}',
        labels_doc(version=2),
        labels_doc(lab(verdict="maybe")),
        labels_doc(lab(hour=H + 1)),
        labels_doc(lab(hour=-3600)),
        labels_doc(lab(hour=True)),
        labels_doc(lab(hour=float(H))),
        labels_doc(lab(device="")),
        labels_doc(lab(device="has space")),
        labels_doc(lab(device="/home/x")),
        labels_doc(lab(device="a" * 65)),
        labels_doc(lab(note="x" * (MAX_NOTE + 1))),
        labels_doc(lab(note="line\nbreak")),
        labels_doc(lab(note=5)),
        labels_doc(lab(extra_key=1)),
        labels_doc(lab(), lab()),  # duplicate (device, hour)
        labels_doc({"device": "d", "hour": H}),
    ],
)
def test_labels_reject_bad_input_with_fixed_message(bad):
    with pytest.raises(ReplayInputError) as err:
        load_labels(bad)
    assert str(err.value).startswith("labels: ")
    assert "/home" not in str(err.value) and "has space" not in str(err.value)


def test_labels_size_and_count_caps():
    many = [lab(hour=H + i * 3600) for i in range(MAX_LABELS + 1)]
    with pytest.raises(ReplayInputError):
        load_labels(labels_doc(*many))
    with pytest.raises(ReplayInputError):
        load_labels(b" " * (4 << 20) + b"{}")
    assert len(load_labels(labels_doc(*many[:MAX_LABELS]))) == MAX_LABELS


def test_series_roundtrip_sorted_and_order_independent():
    s1 = sample(H), sample(H + 3600, 20, 3500, degraded=True)
    one = load_series(series_doc(dev("dev-b", *s1), dev("2001:db8::2")))
    two = load_series(series_doc(dev("2001:db8::2"), dev("dev-b", *reversed(s1))))
    assert one == two
    assert [d.device for d in one] == sorted(d.device for d in one)
    assert [s.hour for s in one[1].samples] == [H, H + 3600]
    assert one[1].samples[1].degraded is True and one[1].samples[0].degraded is False


@pytest.mark.parametrize(
    "bad",
    [
        series_doc(version=3),
        series_doc(dev(), dev()),  # duplicate device
        series_doc(dev("d", sample(), sample())),  # duplicate hour
        series_doc(dev("d", sample(hour=H + 5))),
        series_doc(dev("d", sample(bytes_up=-1))),
        series_doc(dev("d", sample(bytes_up=2**50 + 1))),
        series_doc(dev("d", sample(bytes_up=1.5))),
        series_doc(dev("d", sample(bytes_up=True))),
        series_doc(dev("d", sample(qualified_seconds=3601))),
        series_doc(dev("d", sample(qualified_seconds=-1))),
        series_doc(dev("d", sample(degraded="yes"))),
        series_doc(dev("d", sample(surprise=1))),
        series_doc({"device": "d"}),
        series_doc({"device": "d", "samples": [], "x": 1}),
        series_doc(*[dev(f"d{i}") for i in range(21)]),
    ],
)
def test_series_reject_bad_input_with_fixed_message(bad):
    with pytest.raises(ReplayInputError) as err:
        load_series(bad)
    assert str(err.value).startswith("series: ")


def test_series_per_device_sample_cap():
    rows = [sample(H + i * 3600) for i in range(MAX_SAMPLES_PER_DEVICE + 1)]
    with pytest.raises(ReplayInputError):
        load_series(series_doc(dev("d", *rows)))
    assert load_series(series_doc(dev("d", *rows[:MAX_SAMPLES_PER_DEVICE])))
