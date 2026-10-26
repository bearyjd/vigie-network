"""Incident reads carry the review overlay and derived attention; retention; audit feed."""

import pytest
from api_helpers import NOW, Env, env  # noqa: F401
from incident_helpers import decisions, incident, post, seed_collector, until

OLD = "2026-01-01T00:00:00Z"


def put(e, incident_id, status, snooze=None, version=1, decided_at=OLD, device="d1"):
    e.ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES (?,'c1',?,'line','large_upload',1,?,?,?,'app:test',?,'x')",
        (incident_id, device, status, snooze, version, decided_at),
    )


@pytest.fixture
def e(env: Env) -> Env:  # noqa: F811
    seed_collector(env)
    return env


def test_unreviewed_open_incident_wants_attention(e):
    incident(e, "inc1")
    data = e.get("/incidents/inc1", collector_id="c1").json()["data"]
    assert data["review"] is None and data["attention"] is True


def test_review_and_attention_after_each_decision(e):
    incident(e, "inc1")
    post(e, "inc1", "acknowledge")
    data = e.get("/incidents/inc1", collector_id="c1").json()["data"]
    assert data["review"] == {
        "status": "acknowledged", "snooze_until": None, "version": 1,
        "decided_by": "app", "decided_at": until(0),
    }  # fmt: skip
    assert data["attention"] is False
    post(e, "inc1", "snooze", {"expected_version": 1, "until": until(3600)})
    data = e.get("/incidents/inc1", collector_id="c1").json()["data"]
    assert (data["review"]["snooze_until"], data["attention"]) == (until(3600), False)


def test_expired_snooze_returns_to_attention_and_resolved_incident_never_does(e):
    incident(e, "exp")
    incident(e, "live", lineage="l2")
    incident(e, "done", state="resolved", lineage="l3")
    put(e, "exp", "snoozed", int(NOW) - 1, version=4)
    put(e, "live", "snoozed", int(NOW) + 1)
    put(e, "done", "snoozed", int(NOW) + 999)
    got = {i["id"]: i for i in e.get("/incidents", collector_id="c1").json()["data"]}
    assert got["exp"]["attention"] is True and got["exp"]["review"]["version"] == 4
    assert got["live"]["attention"] is False
    assert got["done"]["attention"] is False and got["done"]["review"]["status"] == "snoozed"


def test_recurrence_has_a_new_id_so_the_decision_does_not_carry_over(e):
    incident(e, "first")
    post(e, "first", "acknowledge")
    e.inv.execute("UPDATE monitoring_incidents SET state='resolved' WHERE id='first'")
    incident(e, "second", episode=1)
    again = e.get("/incidents/second", collector_id="c1").json()["data"]
    assert again["review"] is None and again["attention"] is True
    old = e.get("/incidents/first", collector_id="c1").json()["data"]
    assert old["review"]["status"] == "acknowledged" and old["attention"] is False


def test_list_does_one_decisions_query_per_page(e, monkeypatch):
    import vigie_api.app as app_mod

    for n in range(5):
        incident(e, f"i{n}", lineage=f"l{n}")
    post(e, "i0", "acknowledge")
    seen = []
    real = app_mod.open_overrides

    def traced(path):
        conn = real(path)
        conn.set_trace_callback(seen.append)
        return conn

    monkeypatch.setattr(app_mod, "open_overrides", traced)
    page = e.get("/incidents", collector_id="c1", limit=200).json()["data"]
    assert len(page) == 5
    assert len([q for q in seen if "FROM incident_decisions" in q]) == 1
    seen.clear()
    e.get("/incidents", collector_id="c1", limit=2)
    assert len([q for q in seen if "FROM incident_decisions" in q]) == 1


def test_pruned_incident_decisions_are_invisible(e):
    incident(e, "inc1")
    put(e, "ghost", "acknowledged")
    ids = [i["id"] for i in e.get("/incidents", collector_id="c1").json()["data"]]
    assert ids == ["inc1"]
    assert e.get("/incidents/ghost", collector_id="c1").status_code == 404


def test_state_filter(e):
    incident(e, "a", lineage="1")
    incident(e, "b", state="resolved", lineage="2")
    incident(e, "c", state="superseded", lineage="3")

    def ids(**q):
        return [i["id"] for i in e.get("/incidents", collector_id="c1", **q).json()["data"]]

    assert ids(state="open") == ["a"] and ids(state="resolved") == ["b"]
    assert ids(state="superseded") == ["c"] and ids() == ["a", "b", "c"]
    assert e.get("/incidents", collector_id="c1", state="bogus").status_code == 422
    first = e.get("/incidents", collector_id="c1", state="open", limit=1)
    assert first.json()["page"]["next_cursor"] is None


def test_retention_prunes_only_old_orphans_at_most_100_per_write(e):
    incident(e, "inc1")
    incident(e, "old-live", lineage="l2")
    for n in range(150):
        put(e, f"orphan{n:03d}", "acknowledged", decided_at=OLD)
    put(e, "old-live", "acknowledged", decided_at=OLD)
    put(e, "fresh-orphan", "acknowledged", decided_at=until(-3600))
    assert post(e, "inc1", "acknowledge").status_code == 200
    left = {d["incident_id"] for d in decisions(e)}
    assert len([i for i in left if i.startswith("orphan")]) == 50
    assert {"inc1", "old-live", "fresh-orphan"} <= left
    post(e, "inc1", "mark-expected", {"expected_version": 1})
    assert not [i for i in {d["incident_id"] for d in decisions(e)} if i.startswith("orphan")]


def test_incident_audit_events_have_no_device_id_and_token_events_stay_hidden(e):
    incident(e, "inc1")
    post(e, "inc1", "acknowledge")
    e.ov.execute(
        "INSERT INTO audit_log (id,ts,principal,action,target)"
        " VALUES ('t','x','p','token.create','tok')"
    )
    events = e.get("/events", kind="monitoring.incident.acknowledge").json()["data"]
    assert len(events) == 1
    assert events[0]["device_id"] is None
    assert "inc1" in events[0]["summary"] and "app" in events[0]["summary"]
    assert "app:test" not in events[0]["summary"]
    kinds = {x["kind"] for x in e.get("/events").json()["data"]}
    assert not any(k.startswith("token.") for k in kinds)
    e.ov.execute(
        "INSERT INTO audit_log (id,ts,principal,action,target)"
        " VALUES ('d','x','p','device.patch','d1')"
    )
    assert any(x["device_id"] == "d1" for x in e.get("/events").json()["data"])
