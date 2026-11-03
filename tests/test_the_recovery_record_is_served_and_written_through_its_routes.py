"""The recovery record's routes (SPINE SP-1c): the read AT-7 calls, and the write of a step.

``GET /api/assurance/deployments/<uuid>/recovery-records/`` serves a deployment's
incidents, each with every step oldest first: its conditions with their witnesses, its
gaps, restrictions and release, and its residual uncertainty with the sources of each
item. ``GET``/``POST /api/assurance/findings/<uuid>/recovery-record/`` serves one
incident's steps and records the next ones (:mod:`assurance.recovery_record`).

- Both are tenant-scoped as every deployment and finding read is (``get_object()``, the
  per-user queryset): a deployment or finding the person cannot read is answered exactly
  as one that does not exist, and a page counts its own deployment's incidents only.
- A write is admin-only, as every write to the assurance record is (``_require_admin``).
  The owner's acceptance is the AUTHENTICATED request user's, and only the deployment's
  owner's: a body never names who accepts.
- A step that changes links and no state is a 409 that says why.

On #209's head there are no such routes, so every test here fails there.
"""

from __future__ import annotations

import copy
import uuid
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import status as st
from rest_framework.test import APIClient

from assurance.models import ClaimEvidence, Deployment, Evidence, Finding, RecoveryRecord
from assurance.retest_closure import INCOMPLETE_REPAIR, INCOMPLETE_REPAIR_PATTERNS, record_closure_evidence
from tests.repair_contracts import agree, replay

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
T0, T1 = "2026-11-01T00:00:00.000000Z", "2026-11-02T00:00:00.000000Z"
COVERED = {
    "sources": [{"source": "edr", "kind": "log", "start": T0, "end": T1}],
    "observations": [{"source": "edr", "start": T0, "end": T1, "basis": "observed"}],
}
GAP = {**COVERED, "gaps": [{"kind": "failed_collector", "subject": "edr-west"}]}
COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


def _person(name, role=User.Roles.ADMIN):
    return User.objects.create_user(username=name, password="x", role=role)


def _as(person):
    client = APIClient()
    client.force_authenticate(user=person)
    return client


def _incident(dep, name):
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{name}", finding_type="sql_injection", title=name, severity="critical",
        retest_required=True,
    )


def _tested(finding):
    agree(finding)
    record_closure_evidence(
        finding, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12", document=replay(finding, COMPLETE),
    )


def _step_url(finding):
    return f"/api/assurance/findings/{finding.uuid}/recovery-record/"


def _read_url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/recovery-records/"


def _accept():
    return {"until": (timezone.now() + timedelta(days=30)).isoformat()}


def _stored(finding):
    return list(RecoveryRecord._base_manager.filter(finding=finding).order_by("version").values())


@pytest.fixture
def world():
    """Deployment A, owned by an admin, with an incident whose repair is tested; B, owned
    by someone else, with two incidents; and a viewer who owns a deployment of their own."""
    w = type("World", (), {})()
    w.owner, w.admin, w.other_owner = _person("owner"), _person("admin"), _person("other-owner")
    w.viewer = _person("viewer", role=User.Roles.VIEWER)
    w.a = Deployment.objects.create(name="a", owner=w.owner)
    w.b = Deployment.objects.create(name="b", owner=w.other_owner)
    w.mine = Deployment.objects.create(name="viewers-own", owner=w.viewer)
    w.incident = _incident(w.a, "a-1")
    w.quiet = _incident(w.a, "a-no-record")
    w.b1, w.b2 = _incident(w.b, "b-1"), _incident(w.b, "b-2")
    _tested(w.incident)
    for finding in (w.b1, w.b2):
        assert _as(w.other_owner).post(_step_url(finding), {}, format="json").status_code == 201
    return w


# ------------------------------------------------------------------ the read AT-7 calls


def test_the_deployment_read_serves_each_incident_its_steps_conditions_gaps_and_sources(world):
    posted = _as(world.owner).post(_step_url(world.incident), {"coverage": GAP, "accept": _accept()}, format="json")
    assert posted.status_code == 201, posted.content

    read = _as(world.owner).get(_read_url(world.a))

    assert read.status_code == 200, read.content
    body = read.json()
    assert (body["deployment"], body["incident_count"], body["returned"], body["truncated"]) == (
        str(world.a.uuid), 1, 1, False,
    )
    (incident,) = body["incidents"]
    assert incident["finding"] == str(world.incident.uuid)
    assert [s["version"] for s in incident["steps"]] == [1, 2, 3]
    assert [s["state"] for s in incident["steps"]] == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    held = incident["steps"][-1]
    assert incident["current"] == {"version": 3, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert [c["condition"] for c in held["conditions"]] == ["incident_recorded", "repair_agreed", "repair_tested"]
    assert all(set(c["witness"]) == {"kind", "ref"} for c in held["conditions"])
    assert "coverage:failed_collector:edr-west" in held["gaps"]
    assert held["coverage"]["complete"] is False and held["coverage"]["manifest"]["gaps"][0]["subject"] == "edr-west"
    assert all(item["sources"] for item in held["residual_uncertainty"])
    assert held["accepted_by"] == "owner" and held["recorded_by"] == "owner"
    # The finding's own read serves the same steps.
    one = _as(world.owner).get(_step_url(world.incident)).json()
    assert one["steps"] == incident["steps"] and one["deployment"] == str(world.a.uuid)


def test_a_read_counts_and_serves_its_own_deployments_incidents_only(world):
    _as(world.owner).post(_step_url(world.incident), {}, format="json")
    body = _as(world.admin).get(_read_url(world.a)).json()
    assert body["incident_count"] == 1
    assert [i["finding"] for i in body["incidents"]] == [str(world.incident.uuid)]
    other = _as(world.admin).get(_read_url(world.b)).json()
    assert other["incident_count"] == 2
    assert {i["finding"] for i in other["incidents"]} == {str(world.b1.uuid), str(world.b2.uuid)}


def test_a_cross_deployment_read_is_answered_as_one_that_does_not_exist(world):
    viewer = _as(world.viewer)
    absent = uuid.uuid4()
    for theirs, nobodys in (
        (_read_url(world.b), f"/api/assurance/deployments/{absent}/recovery-records/"),
        (_step_url(world.b1), f"/api/assurance/findings/{absent}/recovery-record/"),
    ):
        refused, missing = viewer.get(theirs), viewer.get(nobodys)
        assert refused.status_code == missing.status_code == 404
        assert refused.json() == missing.json()
    assert viewer.get(_read_url(world.mine)).json()["incident_count"] == 0


# ------------------------------------------------------------------------- the write


def test_a_cross_deployment_write_is_not_found_and_another_deployments_link_is_refused(world):
    absent = f"/api/assurance/findings/{uuid.uuid4()}/recovery-record/"
    before = _stored(world.b1)
    refused, missing = _as(world.viewer).post(_step_url(world.b1), {}, format="json"), _as(world.viewer).post(
        absent, {}, format="json"
    )
    assert refused.status_code == missing.status_code == 404 and refused.json() == missing.json()
    elsewhere = Evidence.objects.create(finding=world.b1, classification="technically_verified")
    linked = _as(world.admin).post(_step_url(world.incident), {"evidence": [str(elsewhere.uuid)]}, format="json")
    assert linked.status_code == 400 and linked.json()["code"] == "unknown_link"
    assert _stored(world.b1) == before and _stored(world.incident) == []


def test_only_the_signed_in_owner_accepts_and_no_body_names_who(world):
    _as(world.owner).post(_step_url(world.incident), {"coverage": COVERED}, format="json")
    for person, body, answer, code in (
        (world.admin, {"accept": _accept()}, 403, "not_the_owner"),
        (world.admin, {"accept": {**_accept(), "by": "owner"}}, 400, None),
        (world.admin, {"accepted_by": "owner"}, 400, "not_posted"),
        (world.owner, {"accept": {"until": "tomorrow"}}, 400, None),
        (world.owner, {"accept": {"until": (timezone.now() - timedelta(days=1)).isoformat()}}, 400, "acceptance_ended"),
    ):
        refused = _as(person).post(_step_url(world.incident), body, format="json")
        assert refused.status_code == answer, (body, refused.content)
        if code:
            assert refused.json()["code"] == code
        assert [s["state"] for s in _stored(world.incident)][-1] == st.REPAIR_TESTED
    accepted = _as(world.owner).post(_step_url(world.incident), {"accept": _accept()}, format="json")
    assert accepted.status_code == 201, accepted.content
    (step,) = accepted.json()["steps"]
    assert (step["state"], step["release"], step["accepted_by"]) == (st.RECOVERY_ACCEPTED, st.PASS, "owner")


def test_no_owner_refuses_acceptance_and_a_write_needs_an_admin(world):
    unowned = Deployment.objects.create(name="unowned")
    finding = _incident(unowned, "u-1")
    refused = _as(world.admin).post(_step_url(finding), {"accept": _accept()}, format="json")
    assert refused.status_code == 403
    assert refused.json() == {"code": "no_owner", "detail": "no owner set for this deployment"}
    own = _incident(world.mine, "mine-1")
    assert _as(world.viewer).post(_step_url(own), {"accept": _accept()}, format="json").status_code == 403
    assert APIClient().post(_step_url(own), {}, format="json").status_code in (401, 403)
    assert _stored(finding) == [] and _stored(own) == []


def test_a_links_only_change_is_a_409_that_says_why_and_history_is_kept(world):
    first = _as(world.admin).post(_step_url(world.quiet), {}, format="json")
    assert first.status_code == 201
    before = _stored(world.quiet)
    evidence = Evidence.objects.create(finding=world.quiet, classification="technically_verified")
    answer = _as(world.admin).post(_step_url(world.quiet), {"evidence": [str(evidence.uuid)]}, format="json")
    assert answer.status_code == 409
    assert answer.json()["code"] == "nothing_moved" and "under_investigation" in answer.json()["detail"]
    assert _stored(world.quiet) == before
    # A step that does move appends, and the steps before it stay exactly as recorded.
    agree(world.quiet)
    moved = _as(world.admin).post(_step_url(world.quiet), {}, format="json")
    assert moved.status_code == 201 and [s["state"] for s in moved.json()["steps"]] == [st.REPAIR_PROPOSED]
    assert _stored(world.quiet)[:1] == before
