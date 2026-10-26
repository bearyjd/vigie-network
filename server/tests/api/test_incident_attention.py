import pytest

from vigie_api.incident_decisions import attention

NOW = 1_000


def review(status, until=None):
    return {"status": status, "snooze_until": until}


@pytest.mark.parametrize(
    ("state", "rev", "expected"),
    [
        ("open", None, True),
        ("open", review("acknowledged"), False),
        ("open", review("expected"), False),
        ("open", review("snoozed", NOW + 1), False),
        ("open", review("snoozed", NOW), True),  # now == snooze_until: expired
        ("open", review("snoozed", NOW - 1), True),
        ("resolved", None, False),
        ("superseded", None, False),
        ("resolved", review("snoozed", NOW + 100), False),
        ("superseded", review("acknowledged"), False),
    ],
)
def test_attention_truth_table(state, rev, expected):
    assert attention(state, rev, NOW) is expected
