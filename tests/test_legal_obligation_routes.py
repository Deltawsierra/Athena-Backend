"""The legal-obligations routes (the owner's freeze exception 22, 14 Oct; ``assurance.legal_api``).

``deployments/<uuid>/legal-obligations/`` lists and records the obligations a deployment is
bound by; ``.../<obligation uuid>/`` reads one, its versions and the decisions on it; and
``.../<obligation uuid>/supersede/`` records its next version. Each rule the brief names is
held here:

- any signed-in role reads, only an admin writes, and another tenant's deployment -- or an
  obligation this deployment is not bound by -- reads as 404;
- the body is strict JSON of at most 64 KiB, and every answer is ``no-store``;
- a change goes through :mod:`assurance.legal`'s one path to the claims: each affected
  current claim moves to review pending, and nothing here ever makes one legally current
  or legally stale -- only a person's materiality decision with a written rationale does;
- the source type (``authority_tier``) is one of the five the model holds;
- the history is append-only and attributed: a change is a new version that supersedes
  the last, which is never rewritten, and each version names who recorded it;
- none of the routes is a stop, each is classified as not one, and a fault in their
  module leaves every stop served.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import resolve
from rest_framework.test import APIClient

from assurance.legal import record_materiality_decision
from assurance.models import AssuranceClaim, ClaimEvent, Deployment, LegalObligation, LegalStatus, MaterialityDecision
from safety import stops

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
REPO = Path(__file__).resolve().parent.parent

#: The source types, as the brief names them, strongest first.
TIERS = ("statute", "regulation", "binding_guidance", "case_law", "advisory")

GDPR = {
    "jurisdiction": "EU",
    "authority_tier": "regulation",
    "source": "GDPR",
    "source_version": "2016/679",
    "operative_date": "2018-05-25",
}
CHANGE = {"source_version": "2016/679 as amended 2026", "operative_date": "2027-01-01"}


def _user(role, name):
    return User.objects.create_user(username=name, password="x", role=role)


@pytest.fixture
def people():
    return {
        "admin": _user("admin", "admin"),
        "analyst": _user("analyst", "analyst"),
        "owner": _user("viewer", "owner"),
        "stranger": _user("viewer", "stranger"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="checkout-assistant", owner=people["owner"])


@pytest.fixture
def elsewhere(people):
    """Another tenant's deployment: the stranger's."""
    return Deployment.objects.create(name="claims-triage", owner=people["stranger"])


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _claim(dep, fingerprint="fp-1", *, status=Status.SUPPORTED, legal_status=None):
    extra = {} if legal_status is None else {"legal_status": legal_status}
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="destinations are inside the approved boundary",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version="pol",
        environment=dep.environment,
        status=status,
        **extra,
    )


def _legal(claim):
    claim.refresh_from_db()
    return claim.legal_status


def _base(dep):
    return f"/api/assurance/deployments/{dep.uuid}/legal-obligations/"


def _detail(dep, obligation):
    return f"{_base(dep)}{getattr(obligation, 'uuid', obligation)}/"


def _supersede(dep, obligation):
    return _detail(dep, obligation) + "supersede/"


def _record(user, dep, **changes):
    return _client(user).post(_base(dep), {**GDPR, **changes}, format="json")


def _recorded(people, dep, **changes) -> LegalObligation:
    response = _record(people["admin"], dep, **changes)
    assert response.status_code == 201, response.content
    return LegalObligation.objects.get(uuid=response.json()["obligation"]["uuid"])


def _last_event(claim):
    return ClaimEvent.objects.filter(claim=claim).order_by("-pk").first()


# ---------------------------------------------------------------------------
# Tenancy and roles
# ---------------------------------------------------------------------------


def test_another_tenants_deployment_reads_as_404(people, deployment, elsewhere):
    """A viewer sees their own deployment and no other: every route on another
    tenant's answers 404, as a deployment that does not exist does, and records
    nothing."""
    obligation = _recorded(people, deployment)
    stranger = _client(people["stranger"])
    assert stranger.get(_base(deployment)).status_code == 404
    assert stranger.get(_detail(deployment, obligation)).status_code == 404
    assert stranger.post(_base(deployment), {**GDPR, "source": "AI Act"}, format="json").status_code == 404
    assert stranger.post(_supersede(deployment, obligation), CHANGE, format="json").status_code == 404
    missing = "00000000-0000-4000-8000-000000000001"
    assert stranger.get(f"/api/assurance/deployments/{missing}/legal-obligations/").status_code == 404
    # Their own deployment reads.
    assert stranger.get(_base(elsewhere)).status_code == 200
    assert LegalObligation.objects.count() == 1
    obligation.refresh_from_db()
    assert obligation.superseded_by_id is None


def test_an_obligation_the_deployment_is_not_bound_by_reads_as_404(people, deployment, elsewhere):
    theirs = _recorded(people, elsewhere)
    admin = _client(people["admin"])
    assert admin.get(_detail(deployment, theirs)).status_code == 404
    assert admin.post(_supersede(deployment, theirs), CHANGE, format="json").status_code == 404
    theirs.refresh_from_db()
    assert theirs.superseded_by_id is None and LegalObligation.objects.count() == 1
    assert admin.get(_base(deployment)).json()["obligations"] == []


def test_every_signed_in_role_reads_and_nobody_else_does(people, deployment):
    obligation = _recorded(people, deployment)
    for who in ("admin", "analyst", "owner"):
        for route in (_base(deployment), _detail(deployment, obligation)):
            assert _client(people[who]).get(route).status_code == 200, (who, route)
    assert _client().get(_base(deployment)).status_code == 401
    assert _client().get(_detail(deployment, obligation)).status_code == 401


def test_only_an_admin_records_or_supersedes(people, deployment):
    """An analyst and the deployment's own viewer read and never write: 403, nothing
    recorded and no claim moved."""
    claim = _claim(deployment)
    for who in ("analyst", "owner"):
        response = _record(people[who], deployment)
        assert response.status_code == 403, (who, response.content)
    assert not LegalObligation.objects.exists()
    assert _legal(claim) == LegalStatus.NOT_ASSESSED

    obligation = _recorded(people, deployment)
    record_materiality_decision(
        claim, obligation, decided_by=people["admin"], material=False, rationale="not material for this system"
    )
    for who in ("analyst", "owner"):
        response = _client(people[who]).post(_supersede(deployment, obligation), CHANGE, format="json")
        assert response.status_code == 403, (who, response.content)
    obligation.refresh_from_db()
    assert obligation.superseded_by_id is None and LegalObligation.objects.count() == 1
    assert _legal(claim) == LegalStatus.CURRENT


# ---------------------------------------------------------------------------
# A change moves the affected claims to review pending, and judges none
# ---------------------------------------------------------------------------


def test_recording_an_obligation_flags_the_deployments_current_claims_for_review(people, deployment, elsewhere):
    unassessed = _claim(deployment, "fp-1")
    current = _claim(deployment, "fp-2", legal_status=LegalStatus.CURRENT)
    stale = _claim(deployment, "fp-3", legal_status=LegalStatus.STALE)
    revoked = _claim(deployment, "fp-4", status=Status.REVOKED)
    theirs = _claim(elsewhere, "fp-5")

    response = _record(people["admin"], deployment, note="the regulator's guidance names this system")

    assert response.status_code == 201, response.content
    review = response.json()["review"]
    assert review["judged"] is False
    assert sorted(review["flagged"]) == sorted([str(unassessed.uuid), str(current.uuid)])
    assert review["flagged_count"] == 2
    assert _legal(unassessed) == LegalStatus.REVIEW_PENDING
    assert _legal(current) == LegalStatus.REVIEW_PENDING
    # A person's stale ruling stands, a withdrawn claim is out of scope, and another
    # deployment's claims are not this obligation's.
    assert _legal(stale) == LegalStatus.STALE
    assert _legal(revoked) == LegalStatus.NOT_ASSESSED
    assert _legal(theirs) == LegalStatus.NOT_ASSESSED
    # The flag the carry replays (assurance.legal._FLAGGED), by nobody, naming who
    # recorded the change.
    event = _last_event(current)
    assert event.note.startswith("Legal axis legally_current -> legal_review_pending: "), event.note
    assert "Recorded by admin through the legal-obligations route." in event.note
    assert "the regulator's guidance names this system" in event.note
    assert event.actor is None
    assert not MaterialityDecision.objects.exists()


def test_superseding_flags_every_bound_deployment_and_carries_its_bindings(people, deployment, elsewhere):
    v1 = _recorded(people, deployment, thresholds={"data_subjects": 5000}, exemptions=["research"])
    v1.deployments.add(elsewhere)
    mine = _claim(deployment, "fp-1", legal_status=LegalStatus.CURRENT)
    theirs = _claim(elsewhere, "fp-2", legal_status=LegalStatus.CURRENT)

    response = _client(people["admin"]).post(_supersede(deployment, v1), CHANGE, format="json")

    assert response.status_code == 201, response.content
    served = response.json()
    v2 = LegalObligation.objects.get(uuid=served["obligation"]["uuid"])
    v1.refresh_from_db()
    assert v1.superseded_by_id == v2.pk
    assert set(v2.deployments.all()) == {deployment, elsewhere}
    assert sorted(served["review"]["bindings_carried_forward"]) == sorted([str(deployment.uuid), str(elsewhere.uuid)])
    assert _legal(mine) == _legal(theirs) == LegalStatus.REVIEW_PENDING
    assert served["review"]["judged"] is False and served["review"]["flagged_count"] == 2
    # A new version of the same obligation: what the body left out is the previous one's.
    assert (v2.jurisdiction, v2.source, v2.authority_tier, v2.thresholds, v2.exemptions) == (
        "EU", "GDPR", "regulation", {"data_subjects": 5000}, ["research"],
    )
    assert (v2.source_version, v2.operative_date) == (CHANGE["source_version"], date(2027, 1, 1))
    assert served["previous"]["current"] is False and served["previous"]["superseded_by"] == str(v2.uuid)
    assert served["obligation"]["current"] is True
    event = _last_event(mine)
    assert event.note.startswith("Legal axis legally_current -> legal_review_pending: "), event.note
    assert "Supersedes EU GDPR v2016/679" in event.note and "Recorded by admin" in event.note


def test_no_change_ever_makes_a_claim_legally_current_or_stale(people, deployment):
    """Only a person's materiality decision with a written rationale moves the legal
    axis to current or stale. A change sends a person's ruling back to the queue and
    never re-makes it; nothing here records a decision."""
    v1 = _recorded(people, deployment)
    claim = _claim(deployment)
    record_materiality_decision(
        claim, v1, decided_by=people["admin"], material=False, rationale="Art. 28 does not reach this processor"
    )
    assert _legal(claim) == LegalStatus.CURRENT

    response = _client(people["admin"]).post(_supersede(deployment, v1), CHANGE, format="json")

    assert response.status_code == 201, response.content
    assert _legal(claim) == LegalStatus.REVIEW_PENDING
    assert MaterialityDecision.objects.count() == 1

    fresh = _claim(deployment, "fp-2")
    _recorded(people, deployment, source="AI Act", source_version="2024/1689", operative_date="2026-08-02")
    assert _legal(fresh) == LegalStatus.REVIEW_PENDING
    assert _legal(claim) == LegalStatus.REVIEW_PENDING
    assert MaterialityDecision.objects.count() == 1
    assert not AssuranceClaim.objects.filter(legal_status__in=[LegalStatus.CURRENT, LegalStatus.STALE]).exists()


def test_no_body_field_reaches_the_legal_axis(people, deployment):
    claim = _claim(deployment)
    for extra in ({"legal_status": "legally_current"}, {"material": False}, {"rationale": "fine"},
                  {"legal_review_status": "reviewed"}, {"deployments": [str(deployment.uuid)]}):
        response = _record(people["admin"], deployment, **extra)
        assert response.status_code == 400, (extra, response.content)
        assert response.json()["code"] == "field_unrecognised"
    assert not LegalObligation.objects.exists()
    assert _legal(claim) == LegalStatus.NOT_ASSESSED

    v1 = _recorded(people, deployment)
    for extra in ({"legal_status": "legally_current"}, {"jurisdiction": "UK"}, {"source": "DPA"}):
        response = _client(people["admin"]).post(_supersede(deployment, v1), {**CHANGE, **extra}, format="json")
        assert response.status_code == 400, (extra, response.content)
        assert response.json()["code"] == "field_unrecognised"
    assert LegalObligation.objects.count() == 1
    assert _legal(claim) == LegalStatus.REVIEW_PENDING


def test_the_route_module_reaches_the_claims_only_through_assurance_legal():
    """The routes never write the legal axis or a decision themselves: the only calls
    into :mod:`assurance.legal` are the trigger and the supersession, and the module
    names no claim, no claim event and no legal status at all."""
    source = (REPO / "assurance" / "legal_api.py").read_text(encoding="utf-8")
    for word in ("legal_status", "LegalStatus", "legally_current", "legally_stale", "record_materiality_decision",
                 "AssuranceClaim", "ClaimEvent"):
        assert word not in source, word
    tree = ast.parse(source)
    into_legal = {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "legal"
    }
    assert into_legal == {"flag_for_materiality_review", "supersede_obligation"}
    on_decisions = {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name) and node.value.value.id == "MaterialityDecision"
    }
    assert on_decisions == {"filter"}


# ---------------------------------------------------------------------------
# What a body may say
# ---------------------------------------------------------------------------


def test_the_source_type_is_one_of_the_five(people, deployment):
    assert tuple(LegalObligation.AuthorityTier.values) == TIERS
    for index, tier in enumerate(TIERS):
        response = _record(people["admin"], deployment, source=f"instrument-{index}", authority_tier=tier)
        assert response.status_code == 201, (tier, response.content)
        assert response.json()["obligation"]["authority_tier"] == tier
    for bad in ("binding", "Statute", "STATUTE", " statute", "", "guidance", None, 3, ["statute"]):
        response = _record(people["admin"], deployment, source="refused", authority_tier=bad)
        assert response.status_code == 400, (bad, response.content)
        assert response.json()["code"] == "authority_tier_unknown"
    unstated = {key: value for key, value in GDPR.items() if key != "authority_tier"}
    response = _client(people["admin"]).post(_base(deployment), {**unstated, "source": "refused"}, format="json")
    assert response.status_code == 400 and response.json()["code"] == "field_missing"
    first = LegalObligation.objects.get(source="instrument-0")
    response = _client(people["admin"]).post(
        _supersede(deployment, first), {**CHANGE, "authority_tier": "binding"}, format="json"
    )
    assert response.status_code == 400 and response.json()["code"] == "authority_tier_unknown"
    assert not LegalObligation.objects.filter(source="refused").exists()
    assert LegalObligation.objects.count() == len(TIERS)


def test_a_body_is_strict_json_of_at_most_64_kib(people, deployment):
    admin = _client(people["admin"])
    route = _base(deployment)

    def post(body, content_type="application/json", to=route):
        return admin.generic("POST", to, body, content_type=content_type)

    duplicate = (
        b'{"jurisdiction": "EU", "jurisdiction": "UK", "authority_tier": "regulation", "source": "GDPR", '
        b'"source_version": "1", "operative_date": "2018-05-25"}'
    )
    assert post(duplicate).status_code == 400
    assert post(json.dumps({**GDPR, "thresholds": {"x": float("nan")}}).encode()).status_code == 400
    assert post(b"[1, 2]").status_code == 400
    assert post(b"not json").status_code == 400
    assert post(b"jurisdiction=EU&source=GDPR", "application/x-www-form-urlencoded").status_code == 415
    assert post(b"").status_code == 400
    assert not LegalObligation.objects.exists()

    def padded(size, **changes):
        empty = json.dumps({**GDPR, **changes, "thresholds": {"padding": ""}}).encode()
        return json.dumps({**GDPR, **changes, "thresholds": {"padding": "a" * (size - len(empty))}}).encode()

    over = padded(64 * 1024 + 1)
    assert len(over) == 64 * 1024 + 1
    assert post(over).status_code == 413
    assert not LegalObligation.objects.exists()
    at_limit = padded(64 * 1024)
    assert len(at_limit) == 64 * 1024
    assert post(at_limit).status_code == 201

    v1 = LegalObligation.objects.get()
    supersede = _supersede(deployment, v1)
    assert post(b'{"source_version": "2", "source_version": "3", "operative_date": "2027-01-01"}', to=supersede).status_code == 400
    assert post(b"source_version=2", "application/x-www-form-urlencoded", to=supersede).status_code == 415
    big = json.dumps({**CHANGE, "note": "a" * (64 * 1024)}).encode()
    assert post(big, to=supersede).status_code == 413
    assert LegalObligation.objects.count() == 1


def test_the_operative_date_is_a_calendar_date(people, deployment):
    for bad in ("2026-13-01", "2026-02-30", "20260801", "2026-8-1", "2026-08-01T00:00:00", "２026-08-01",
                20260801, None, ""):
        response = _record(people["admin"], deployment, operative_date=bad)
        assert response.status_code == 400, (bad, response.content)
        assert response.json() == {
            "code": "field_malformed",
            "detail": "operative_date is a calendar date, YYYY-MM-DD: the date the rule bites",
            "field": "operative_date",
        }
    unstated = {key: value for key, value in GDPR.items() if key != "operative_date"}
    response = _client(people["admin"]).post(_base(deployment), unstated, format="json")
    assert response.status_code == 400 and response.json()["code"] == "field_missing"
    assert not LegalObligation.objects.exists()


def test_every_answer_is_no_store(people, deployment):
    admin = _client(people["admin"])
    obligation = _recorded(people, deployment)
    answers = {
        "recorded": _record(people["admin"], deployment, source="AI Act"),
        "listed": admin.get(_base(deployment)),
        "read": admin.get(_detail(deployment, obligation)),
        "superseded": admin.post(_supersede(deployment, obligation), CHANGE, format="json"),
        "again": admin.post(_supersede(deployment, obligation), CHANGE, format="json"),
        "conflict": _record(people["admin"], deployment),
        "unauthenticated": _client().get(_base(deployment)),
        "forbidden": _record(people["owner"], deployment, source="NIS2"),
        "not found": _client(people["stranger"]).get(_detail(deployment, obligation)),
        "refused": admin.post(_base(deployment), {"unknown": 1}, format="json"),
        "too large": admin.generic("POST", _base(deployment), b"{" + b" " * (64 * 1024) + b"}",
                                   content_type="application/json"),
        "form": admin.generic("POST", _base(deployment), b"a=1", content_type="application/x-www-form-urlencoded"),
        "not allowed": admin.put(_detail(deployment, obligation), CHANGE, format="json"),
    }
    expected = {"recorded": 201, "listed": 200, "read": 200, "superseded": 201, "again": 200, "conflict": 409,
                "unauthenticated": 401, "forbidden": 403, "not found": 404, "refused": 400, "too large": 413,
                "form": 415, "not allowed": 405}
    assert {name: answer.status_code for name, answer in answers.items()} == expected
    for name, answer in answers.items():
        assert answer["Cache-Control"] == "no-store", name


# ---------------------------------------------------------------------------
# Append-only and attributed
# ---------------------------------------------------------------------------

_FIELDS = ("jurisdiction", "authority_tier", "source", "source_version", "operative_date", "thresholds",
           "exemptions", "legal_review_status", "recorded_by_id", "recorded_by_username", "created_at")


def _as_stored(obligation):
    return LegalObligation.objects.filter(pk=obligation.pk).values(*_FIELDS).get()


def test_a_change_supersedes_and_never_rewrites(people, deployment):
    admin = _client(people["admin"])
    v1 = _recorded(people, deployment, thresholds={"data_subjects": 5000}, exemptions=["research"])
    before = _as_stored(v1)

    first = admin.post(_supersede(deployment, v1), {**CHANGE, "thresholds": {"data_subjects": 10000}}, format="json")

    assert first.status_code == 201, first.content
    v2 = LegalObligation.objects.get(uuid=first.json()["obligation"]["uuid"])
    assert _as_stored(v1) == before
    assert v2.thresholds == {"data_subjects": 10000}
    # A version is never edited or deleted over the API.
    for method in ("put", "patch", "delete"):
        response = getattr(admin, method)(_detail(deployment, v1), {"source_version": "9"}, format="json")
        assert response.status_code == 405, method
    assert _as_stored(v1) == before and LegalObligation.objects.count() == 2

    # The same request again returns the version it recorded and sends nothing back to
    # review: a ruling made since stands.
    claim = _claim(deployment)
    record_materiality_decision(claim, v2, decided_by=people["admin"], material=False, rationale="unchanged for us")
    again = admin.post(_supersede(deployment, v1), {**CHANGE, "thresholds": {"data_subjects": 10000}}, format="json")
    assert again.status_code == 200, again.content
    assert again.json()["created"] is False and again.json()["obligation"]["uuid"] == str(v2.uuid)
    assert again.json()["review"]["flagged_count"] == 0
    assert _legal(claim) == LegalStatus.CURRENT
    assert LegalObligation.objects.count() == 2

    # A version has one successor: another change to it is refused, naming the current one.
    other = admin.post(_supersede(deployment, v1), {"source_version": "3", "operative_date": "2028-01-01"},
                       format="json")
    assert other.status_code == 409, other.content
    assert other.json()["code"] == "obligation_superseded" and other.json()["current"] == str(v2.uuid)
    taken = admin.post(_supersede(deployment, v2), {"source_version": "2016/679", "operative_date": "2028-01-01"},
                       format="json")
    assert taken.status_code == 409 and taken.json()["code"] == "obligation_version_taken"
    third = admin.post(_supersede(deployment, v2), {"source_version": "3", "operative_date": "2028-01-01"},
                       format="json")
    assert third.status_code == 201, third.content
    assert _as_stored(v1) == before

    history = admin.get(_detail(deployment, v2)).json()["history"]
    assert history["truncated"] is False
    versions = history["versions"]
    assert [v["source_version"] for v in versions] == ["2016/679", CHANGE["source_version"], "3"]
    assert [v["superseded_by"] for v in versions] == [str(v2.uuid), third.json()["obligation"]["uuid"], None]
    assert {v["recorded_by"] for v in versions} == {"admin"}
    assert all(v["binds_this_deployment"] for v in versions)


def test_a_second_record_of_one_instrument_is_refused(people, deployment, elsewhere):
    """A version is recorded once, and a deployment bound by a current version of an
    instrument takes a new one only by superseding it -- never a second record beside it."""
    v1 = _recorded(people, deployment)
    again = _record(people["admin"], deployment)
    assert again.status_code == 409 and again.json()["code"] == "obligation_version_taken"
    assert again.json()["obligation"] == str(v1.uuid)
    beside = _record(people["admin"], deployment, source_version="2", operative_date="2027-01-01")
    assert beside.status_code == 409 and beside.json()["code"] == "obligation_recorded_here"
    assert beside.json()["supersede"] == _supersede(deployment, v1)
    there = _record(people["admin"], elsewhere)
    assert there.status_code == 409 and there.json()["code"] == "obligation_version_taken"
    assert LegalObligation.objects.count() == 1


def test_each_version_names_who_recorded_it(people, deployment):
    obligation = _recorded(people, deployment)
    assert (obligation.recorded_by, obligation.recorded_by_username) == (people["admin"], "admin")
    legacy = LegalObligation.objects.create(
        jurisdiction="UK", authority_tier="statute", source="DPA", source_version="2018",
        operative_date=date(2018, 5, 23),
    )
    legacy.deployments.add(deployment)
    listed = {o["uuid"]: o for o in _client(people["owner"]).get(_base(deployment)).json()["obligations"]}
    assert listed[str(obligation.uuid)]["recorded_by"] == "admin"
    # Recorded before the route, by nobody named: said as nobody, never as a person.
    assert listed[str(legacy.uuid)]["recorded_by"] is None


def test_removing_the_operator_who_recorded_one_is_never_held_back(people, deployment):
    """Removing an operator is a stop: a version they recorded keeps their name and
    never refuses or defers the removal."""
    recorder = _user("admin", "recorder")
    response = _record(recorder, deployment)
    assert response.status_code == 201, response.content
    obligation = LegalObligation.objects.get()
    removed = _client(people["admin"]).delete(f"/api/accounts/users/{recorder.pk}/")
    assert removed.status_code == 204, removed.content
    assert not User.objects.filter(pk=recorder.pk).exists()
    obligation.refresh_from_db()
    assert obligation.recorded_by_id is None and obligation.recorded_by_username == "recorder"
    served = _client(people["admin"]).get(_detail(deployment, obligation)).json()
    assert served["obligation"]["recorded_by"] == "recorder"


# ---------------------------------------------------------------------------
# What a read serves
# ---------------------------------------------------------------------------


def test_the_list_and_the_detail_serve_this_deployments_record(people, deployment, elsewhere):
    older = _recorded(people, deployment, jurisdiction="UK", authority_tier="statute", source="DPA",
                      source_version="2018", operative_date="2018-05-23")
    newer = _recorded(people, deployment, source="AI Act", source_version="2024/1689", operative_date="2026-08-02",
                      thresholds={"risk": "high"}, exemptions=["research"])
    _recorded(people, elsewhere, source="NIS2", source_version="2022/2555", operative_date="2024-10-18")

    listed = _client(people["owner"]).get(_base(deployment)).json()
    assert listed["deployment"] == str(deployment.uuid)
    assert listed["count"] == 2 and listed["truncated"] is False
    assert [o["uuid"] for o in listed["obligations"]] == [str(newer.uuid), str(older.uuid)]
    first = listed["obligations"][0]
    assert first == {
        "uuid": str(newer.uuid),
        "jurisdiction": "EU",
        "authority_tier": "regulation",
        "source": "AI Act",
        "source_version": "2024/1689",
        "operative_date": "2026-08-02",
        "thresholds": {"risk": "high"},
        "exemptions": ["research"],
        "legal_review_status": "unreviewed",
        "current": True,
        "superseded_by": None,
        "recorded_by": "admin",
        "recorded_at": first["recorded_at"],
        "detail": _detail(deployment, newer),
    }
    assert first["recorded_at"] == newer.created_at.isoformat()

    claim = _claim(deployment)
    record_materiality_decision(claim, newer, decided_by=people["admin"], material=True,
                                rationale="the high-risk rules reach this system")
    theirs = _claim(elsewhere, "fp-x")
    MaterialityDecision.objects.create(claim=theirs, obligation=newer, decided_by=people["analyst"],
                                       material=False, rationale="another tenant's ruling")
    detail = _client(people["owner"]).get(_detail(deployment, newer)).json()
    assert detail["obligation"] == first
    assert detail["history"]["versions"] == [{
        "uuid": str(newer.uuid), "source_version": "2024/1689", "operative_date": "2026-08-02",
        "authority_tier": "regulation", "superseded_by": None, "recorded_by": "admin",
        "recorded_at": first["recorded_at"], "binds_this_deployment": True,
    }]
    decisions = detail["materiality_decisions"]
    assert decisions["count"] == 1 and decisions["truncated"] is False
    (decision,) = decisions["decisions"]
    assert {key: decision[key] for key in ("claim", "material", "rationale", "decided_by")} == {
        "claim": str(claim.uuid), "material": True, "rationale": "the high-risk rules reach this system",
        "decided_by": "admin",
    }


# ---------------------------------------------------------------------------
# Not a stop, and nothing on a stop's path
# ---------------------------------------------------------------------------


def test_the_routes_are_classified_as_not_stops():
    """Each route and method is in ``safety.stops.NOT_STOPS`` with its reason and in no
    stop set, and no request on it -- whatever it says -- is judged a stop."""
    deployment = "11111111-2222-4333-8444-555555555555"
    obligation = "00000000-0000-4000-8000-000000000000"
    base = f"/api/assurance/deployments/{deployment}/legal-obligations/"
    expected = {
        base: ("deployment-legal-obligations", {"GET", "POST"}),
        f"{base}{obligation}/": ("deployment-legal-obligation", {"GET"}),
        f"{base}{obligation}/supersede/": ("deployment-legal-obligation-supersede", {"POST"}),
    }
    factory = RequestFactory()
    for route, (name, methods) in expected.items():
        match = resolve(route)
        assert match.view_name == name
        served = {
            method.upper() for method in match.func.cls.http_method_names
            if method not in ("options", "head") and hasattr(match.func.cls, method)
        }
        assert served == methods, name
        assert set(stops.NOT_STOPS[name]) == methods, name
        assert name not in stops.EXEMPT_ROUTES
        for method in methods:
            for body in (b"", b'{"paused": true}', b'{"to_status": "revoked"}', b'{"enabled": false}'):
                request = factory.generic(method, route, body, content_type="application/json")
                assert stops.is_stop(request) is False, (name, method, body)


def test_a_legal_obligations_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the route module raise at
    import, before Django loads, runs ``tests/legal_obligations_fault_cases.py``: Django
    loads, the scan's Stop is answered (202) and saved, ``deliver_owed_stops`` reaches
    its handler, ``manage.py check`` passes, and every other route is served; only the
    three legal-obligations routes are not."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.legal_obligations_broken",
         "-q", "tests/legal_obligations_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]
