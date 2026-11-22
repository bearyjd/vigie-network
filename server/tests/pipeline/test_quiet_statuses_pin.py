"""The review statuses that quiet an incident have one pipeline home and mirror the API's."""

from vigie_api import incident_decisions as api
from vigie_pipeline import delivery_plan, new_device_notice, overrides


def test_pipeline_quiet_statuses_are_one_constant_equal_to_the_api_set():
    assert overrides.QUIET_STATUSES == api.QUIET_STATUSES
    assert delivery_plan.QUIET_STATUSES is overrides.QUIET_STATUSES
    assert new_device_notice.QUIET_STATUSES is overrides.QUIET_STATUSES
