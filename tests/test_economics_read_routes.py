"""Economic Exposure: the read routes the dashboard needs (``docs/economics/spec-v1.md``,
section 27.12), on step 6's conventions.

- ``GET deployments/<uuid>/economics/receipts/<receipt id>/`` serves a Financial
  Exposure Receipt's signed DSSE envelope as stored, byte for byte the envelope the
  signer returned, as a download with its SHA-256 in a header; a receipt of another
  tenant is not found, and so is one moved onto a residual run; nothing is signed;
- ``GET deployments/<uuid>/economics/scenarios/`` lists a deployment's scenario
  versions a page at a time, each with its templates and its latest EXPOSURE run's
  status, grade and exclusion from totals: a residual run is never listed;
- the report (``results/``) states the run's valuation date and the normalization
  record of each figure the run converted (none: a run converts nothing), under
  ``mythos.economics.report/v2``; ``may_be_totalled`` reads v2 and v1 alike;
- each route reads its query strictly, is no stop, writes nothing when fired twice
  and answers ``no-store``; a Stop is answered while each is held open mid-read.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from mythos_core import exposure_receipt as core
from mythos_core.outcome import canonical_bytes as core_canonical_bytes
from rest_framework.test import APIClient

from assurance.economics import receipt_service, report, report_api
from assurance.economics.models import (
    FinancialExposureReceipt,
    FinancialScenario,
    FinancialValidityCard,
    ScenarioBuild,
    SimulationResult,
)
from assurance.models import Deployment
from pentest.models import PentestScan
from safety import stops
from tests.test_economics_remediation import proposed
from tests.test_economics_report import AS_OF, QUICK, stored

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
README = REPO / "README.md"
TEMPLATE = {"template_id": "cross_customer_data_exposure", "version": 1}


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


@pytest.fixture
def other_deployment(people):
    return Deployment.objects.create(name="someone-elses", owner=people["other"])


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _base(deployment):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/"


def _simulate(client, deployment, scenario, *, receipt=False):
    body = {"seed": 7, "policy": QUICK, "receipt": receipt}
    return client.post(_base(deployment) + f"scenarios/{scenario.uuid}/simulate/", data=json.dumps(body),
                       content_type="application/json")


def _list(client, deployment, query=""):
    return client.get(_base(deployment) + "scenarios/" + query)


def _receipt_url(deployment, receipt_id):
    return _base(deployment) + f"receipts/{uuid.UUID(receipt_id)}/"


def _signing(monkeypatch):
    """A test keyring of one economics-receipt key, and a signer that keeps a copy of
    every envelope it returns: what the engine would sign, held here to compare."""
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ring = core.receipt_keyring([key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)],
                                other_roles={"engine-outcome": [other]})
    signed = []

    def signer(document):
        envelope = core.sign_receipt(document, key)
        signed.append(copy.deepcopy(envelope))
        return envelope

    monkeypatch.setattr(receipt_service, "engine_keyring", lambda: ring)
    monkeypatch.setattr(receipt_service, "engine_signer", signer)
    return ring, signed


def _receipted(deployment, author, monkeypatch, **stored_kwargs):
    """A stored scenario simulated with a receipt asked for, through the route."""
    ring, signed = _signing(monkeypatch)
    scenario = stored(deployment, author, **stored_kwargs)
    response = _simulate(_client(author), deployment, scenario, receipt=True)
    assert response.status_code == 201, response.content
    assert response.json()["receipt"]["issued"] is True, response.json()["receipt"]
    return scenario, FinancialExposureReceipt.objects.get(scenario=scenario), ring, signed[-1]


def _economics_writes(queries) -> list[str]:
    """Every statement in ``queries`` that writes an economics table."""
    tables = {
        model._meta.db_table
        for model in apps.get_app_config("assurance").get_models()
        if model.__module__ == "assurance.economics.models"
    }
    return [
        query["sql"] for query in queries
        if query["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
        and any(table in query["sql"] for table in tables)
    ]


# ======================================================================
# The receipt's signed bytes
# ======================================================================


def test_a_receipt_is_served_as_its_signed_envelope_exactly_as_stored(deployment, people, monkeypatch):
    scenario, row, ring, envelope = _receipted(deployment, people["analyst"], monkeypatch)
    response = _client(people["owner"]).get(_receipt_url(deployment, row.receipt_id))
    assert response.status_code == 200, response.content
    body = response.content
    # The envelope the signer returned, as stored: the same JSON value, in its one
    # canonical spelling, and nothing else.
    assert json.loads(body) == envelope == row.envelope
    assert body == report.canonical_bytes(envelope)
    # Its payload is exactly the stored document's canonical bytes, and it verifies
    # against the economics-receipt keyring as the engine signed it.
    assert base64.b64decode(json.loads(body)["payload"]) == core_canonical_bytes(row.document)
    card = FinancialValidityCard.objects.get(pk=row.card_id)
    assert core.verify_receipt(json.loads(body), ring, card=card.card).authentic is True
    # A download, never sniffed, never cached, with its SHA-256.
    assert response["Content-Type"] == "application/json"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Content-Disposition"] == (
        f'attachment; filename="financial-exposure-receipt-{row.receipt_id}.json"')
    assert response["X-Content-SHA256"] == "sha256:" + hashlib.sha256(body).hexdigest()
    assert response["Cache-Control"] == "no-store"
    assert scenario.uuid  # the scenario is the deployment's


def test_a_receipt_is_never_signed_again_and_fired_twice_writes_nothing(deployment, people, monkeypatch):
    _, row, _, envelope = _receipted(deployment, people["analyst"], monkeypatch)

    def never(*args, **kwargs):
        raise AssertionError("the receipt route signs nothing and asks no engine")

    monkeypatch.setattr(receipt_service, "engine_signer", never)
    monkeypatch.setattr(receipt_service, "engine_keyring", never)
    monkeypatch.setattr(core, "sign_receipt", never)
    client = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        first = client.get(_receipt_url(deployment, row.receipt_id))
        second = client.get(_receipt_url(deployment, row.receipt_id))
    assert first.status_code == second.status_code == 200
    assert first.content == second.content == report.canonical_bytes(envelope)
    assert first["X-Content-SHA256"] == second["X-Content-SHA256"]
    assert _economics_writes(queries.captured_queries) == []
    assert FinancialExposureReceipt.objects.count() == 1


def test_a_receipt_of_another_tenant_is_not_found(deployment, other_deployment, people, monkeypatch):
    _, mine, _, _ = _receipted(deployment, people["analyst"], monkeypatch)
    _, theirs, _, _ = _receipted(other_deployment, people["admin"], monkeypatch, set_key="q3")
    admin, owner, stranger = _client(people["admin"]), _client(people["owner"]), _client(people["other"])
    # The admin sees both deployments: each receipt is served under its own only.
    assert admin.get(_receipt_url(deployment, mine.receipt_id)).status_code == 200
    assert admin.get(_receipt_url(other_deployment, theirs.receipt_id)).status_code == 200
    for response in (
        admin.get(_receipt_url(deployment, theirs.receipt_id)),  # another tenant's, under this path
        admin.get(_receipt_url(other_deployment, mine.receipt_id)),
        owner.get(_receipt_url(deployment, theirs.receipt_id)),
        stranger.get(_receipt_url(deployment, mine.receipt_id)),  # a deployment the caller cannot see
        admin.get(_receipt_url(deployment, uuid.uuid4().hex)),  # no such receipt
        admin.get(_base(deployment) + f"receipts/{mine.receipt_id}/"),  # the id undashed: no route
    ):
        assert response.status_code == 404, response.content
        assert theirs.envelope["signatures"][0]["sig"].encode() not in response.content
    assert _client().get(_receipt_url(deployment, mine.receipt_id)).status_code == 401
    assert admin.post(_receipt_url(deployment, mine.receipt_id), {}, format="json").status_code == 405


def test_a_residual_runs_receipt_is_never_served(deployment, people, monkeypatch):
    """None exists (the receipt service and the row refuse one), so a receipt moved
    onto a residual run past the append-only checks stands for one: not served."""
    ring, signed = _signing(monkeypatch)
    scenario, _, _ = proposed(deployment, people)
    current = SimulationResult.objects.exposure_runs().get(scenario=scenario)
    residual = SimulationResult.objects.residual_runs().get(scenario=scenario)
    row = receipt_service.issue_receipt(current, keyring=ring).receipt
    assert row is not None
    owner = _client(people["owner"])
    assert owner.get(_receipt_url(deployment, row.receipt_id)).status_code == 200
    FinancialExposureReceipt._base_manager.filter(pk=row.pk).update(simulation=residual)
    response = owner.get(_receipt_url(deployment, row.receipt_id))
    assert response.status_code == 404, response.content
    assert signed[-1]["signatures"][0]["sig"].encode() not in response.content


def test_the_receipt_route_reads_its_query_strictly(deployment, people, monkeypatch):
    _, row, _, _ = _receipted(deployment, people["analyst"], monkeypatch)
    response = _client(people["owner"]).get(_receipt_url(deployment, row.receipt_id) + "?inline=1")
    assert response.status_code == 400 and response.json()["code"] == "field_unrecognised", response.content


# ======================================================================
# The scenario list
# ======================================================================


def _entry(body, scenario):
    (found,) = [entry for entry in body["scenarios"] if entry["uuid"] == str(scenario.uuid)]
    return found


def test_the_list_names_each_versions_latest_exposure_run_and_its_standing(deployment, people):
    analyst = _client(people["analyst"])
    graded = stored(deployment, people["analyst"])
    assert _simulate(analyst, deployment, graded).status_code == 201
    unknown = stored(deployment, people["analyst"], unknown=True, set_key="q2")
    assert _simulate(analyst, deployment, unknown).status_code == 201
    unrun = stored(deployment, people["analyst"], set_key="q3")
    response = _list(_client(people["owner"]), deployment)
    assert response.status_code == 200, response.content
    assert response["Cache-Control"] == "no-store"
    body = response.json()
    assert body["deployment"] == str(deployment.uuid)
    assert (body["count"], body["page"], body["page_size"]) == (3, 1, report_api.SCENARIO_PAGE_SIZE)
    assert [entry["uuid"] for entry in body["scenarios"]] == [str(s.uuid) for s in (graded, unknown, unrun)]
    for scenario in (graded, unknown, unrun):
        entry = _entry(body, scenario)
        assert entry["title"] == scenario.title and entry["templates"] == [TEMPLATE]
        # The banner rule is the report's, as the events route serves it.
        standing = report.standing(scenario)
        assert {key: entry[key] for key in standing} == standing
        events = _client(people["owner"]).get(_base(deployment) + f"scenarios/{scenario.uuid}/events/").json()
        assert {key: events[key] for key in standing} == standing
    result = SimulationResult.objects.get(scenario=graded)
    assert _entry(body, graded)["latest_exposure_run"] == {
        "uuid": str(result.uuid), "status": "completed", "refusal_code": None,
        "recorded_at": result.recorded_at.isoformat(),
    }
    assert _entry(body, graded)["grade"] in report.GRADES_FOR_TOTALS
    assert _entry(body, graded)["excluded_from_totals"] is False and _entry(body, graded)["banner"] is None
    assert _entry(body, unknown)["grade"] == "Unknown" and _entry(body, unknown)["excluded_from_totals"] is True
    assert _entry(body, unknown)["banner"] == report.UNKNOWN_BANNER
    assert _entry(body, unrun)["latest_exposure_run"] is None
    assert _entry(body, unrun)["banner_reason"] == report.NO_RESULT


def test_a_residual_run_is_never_listed_as_exposure(deployment, people):
    scenario, _, _ = proposed(deployment, people)
    current = SimulationResult.objects.exposure_runs().get(scenario=scenario)
    residual = SimulationResult.objects.residual_runs().get(scenario=scenario)
    assert residual.pk > current.pk  # the residual run is the scenario's latest run of all
    response = _list(_client(people["owner"]), deployment)
    assert response.status_code == 200, response.content
    entry = _entry(response.json(), scenario)
    assert entry["latest_exposure_run"]["uuid"] == str(current.uuid)
    assert str(residual.uuid).encode() not in response.content


def test_the_list_is_paginated_and_its_page_size_capped(deployment, people, other_deployment):
    made = [
        FinancialScenario.objects.create(deployment=deployment, title=f"scenario {n}", author=people["analyst"])
        for n in range(report_api.SCENARIO_PAGE_SIZE + 2)
    ]
    FinancialScenario.objects.create(deployment=other_deployment, title="theirs", author=people["admin"])
    owner = _client(people["owner"])
    first = _list(owner, deployment).json()
    total = len(made)
    assert (first["count"], first["page"], first["pages"]) == (total, 1, 2)
    assert [e["uuid"] for e in first["scenarios"]] == [str(s.uuid) for s in made[: report_api.SCENARIO_PAGE_SIZE]]
    assert (first["previous"], first["next"]) == (None, 2)
    second = _list(owner, deployment, "?page=2").json()
    assert [e["uuid"] for e in second["scenarios"]] == [str(s.uuid) for s in made[report_api.SCENARIO_PAGE_SIZE:]]
    assert (second["previous"], second["next"]) == (1, None)
    small = _list(owner, deployment, "?page=3&page_size=5").json()
    assert [e["uuid"] for e in small["scenarios"]] == [str(s.uuid) for s in made[10:15]]
    assert (small["page_size"], small["pages"]) == (5, -(-total // 5))
    past = _list(owner, deployment, "?page=9").json()
    assert past["scenarios"] == [] and past["count"] == total and past["next"] is None
    # The cap: the largest page is served, and one past it refused, never cut short.
    assert _list(owner, deployment, f"?page_size={report_api.SCENARIO_PAGE_SIZE_MAX}").status_code == 200
    over = _list(owner, deployment, f"?page_size={report_api.SCENARIO_PAGE_SIZE_MAX + 1}")
    assert over.status_code == 400 and over.json()["code"] == "field_malformed", over.content
    assert "theirs" not in json.dumps([first, second])


@pytest.mark.parametrize(
    "query, code",
    [
        ("?page=0", "field_malformed"),
        ("?page=-1", "field_malformed"),
        ("?page=+1", "field_malformed"),
        ("?page=01", "field_malformed"),
        ("?page=1.0", "field_malformed"),
        ("?page=", "field_malformed"),
        ("?page=one", "field_malformed"),
        ("?page=%EF%BC%91", "field_malformed"),  # a fullwidth digit one: a digit, but not ASCII
        ("?page=" + "9" * 4301, "field_malformed"),  # past Python's 4300-digit limit: never a 500
        ("?page=1&page=2", "field_malformed"),
        ("?page_size=0", "field_malformed"),
        ("?limit=5", "field_unrecognised"),
        ("?page=1&offset=5", "field_unrecognised"),
    ],
)
def test_the_list_reads_its_query_strictly(deployment, people, query, code):
    response = _list(_client(people["owner"]), deployment, query)
    assert response.status_code == 400 and response.json()["code"] == code, response.content


def test_the_list_keeps_to_the_tenant_and_every_role_reads_it(deployment, other_deployment, people):
    mine = stored(deployment, people["analyst"])
    theirs = stored(other_deployment, people["admin"], set_key="q3")
    owner, stranger, admin = _client(people["owner"]), _client(people["other"]), _client(people["admin"])
    listed = _list(owner, deployment)
    assert listed.status_code == 200
    assert [e["uuid"] for e in listed.json()["scenarios"]] == [str(mine.uuid)]
    assert [e["uuid"] for e in _list(admin, other_deployment).json()["scenarios"]] == [str(theirs.uuid)]
    assert _list(stranger, deployment).status_code == 404
    assert _list(_client(), deployment).status_code == 401
    assert admin.post(_base(deployment) + "scenarios/", {}, format="json").status_code == 405


def test_the_list_fired_twice_is_the_same_bytes_and_writes_nothing(deployment, people):
    scenario = stored(deployment, people["analyst"])
    assert _simulate(_client(people["analyst"]), deployment, scenario).status_code == 201
    owner = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        first, second = _list(owner, deployment), _list(owner, deployment)
    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert _economics_writes(queries.captured_queries) == []


# ======================================================================
# The report: the valuation date and the currency bridge
# ======================================================================


def _report(client, deployment, scenario):
    return client.get(_base(deployment) + f"scenarios/{scenario.uuid}/results/")


def test_the_report_states_its_valuation_date_and_converts_nothing(deployment, people):
    scenario = stored(deployment, people["analyst"])
    assert _simulate(_client(people["analyst"]), deployment, scenario).status_code == 201
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["schema"] == report.REPORT_SCHEMA == "mythos.economics.report/v2"
    assert body["currency_bridge"] == {
        "valuation_date": AS_OF.isoformat(),
        "valuation_date_from": report.VALUATION_FROM_BUILD,
        "reporting_currency": "USD",
        "conversions": [],
        "statement": report.NO_CONVERSION,
    }
    assert report.verifies(body) and report.may_be_totalled(body) is True


def test_a_v1_report_is_still_read_and_no_other_schema_is(deployment, people):
    scenario = stored(deployment, people["analyst"])
    assert _simulate(_client(people["analyst"]), deployment, scenario).status_code == 201
    body = _report(_client(people["owner"]), deployment, scenario).json()
    v1 = {key: value for key, value in body.items() if key != "currency_bridge"}
    v1["schema"] = report.REPORT_SCHEMA_V1
    v1["digest"] = report.digest_of(v1)
    assert report.REPORT_SCHEMAS == ("mythos.economics.report/v1", "mythos.economics.report/v2")
    assert report.may_be_totalled(v1) is True
    for schema in ("mythos.economics.report/v3", "mythos.economics.roi/v1"):
        other = dict(body, schema=schema)
        other["digest"] = report.digest_of(other)
        assert report.may_be_totalled(other) is False, schema


def test_the_valuation_date_is_the_one_the_receipt_signs(deployment, people, monkeypatch):
    scenario, row, _, _ = _receipted(deployment, people["analyst"], monkeypatch)
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["currency_bridge"]["valuation_date"] == row.document["result"]["valuation_date"]


def test_without_a_build_the_valuation_date_is_the_latest_as_of_its_inputs_hold(deployment, people):
    scenario = stored(deployment, people["analyst"])
    assert _simulate(_client(people["analyst"]), deployment, scenario).status_code == 201
    ScenarioBuild._base_manager.filter(scenario=scenario).delete()
    body = _report(_client(people["owner"]), deployment, scenario).json()
    bridge = body["currency_bridge"]
    assert (bridge["valuation_date"], bridge["valuation_date_from"]) == (AS_OF.isoformat(), report.VALUATION_FROM_INPUTS)
    # Inputs that no longer give their digest are not read for it.
    result = SimulationResult.objects.get(scenario=scenario)
    inputs = json.loads(json.dumps(result.inputs))
    inputs["events"][0]["components"][0]["as_of"] = "2099-01-01"
    SimulationResult._base_manager.filter(pk=result.pk).update(inputs=inputs)
    bridge = _report(_client(people["owner"]), deployment, scenario).json()["currency_bridge"]
    assert bridge["valuation_date"] is None and bridge["valuation_date_from"] is None
    assert bridge["not_reported"].startswith(report.STORED_ROW_UNVERIFIED)


# ======================================================================
# Safety
# ======================================================================


def test_no_read_route_here_is_a_stop():
    for name in ("deployment-economics-scenarios", "deployment-economics-receipt"):
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES
        assert set(stops.NOT_STOPS[name]) == {"GET"}, name


#: The reads, each held open where it reads: the list while it composes an entry, the
#: receipt and the report while they put their bytes together.
_HELD = {
    "scenarios": ("scenario_entry", lambda deployment, scenario, receipt_id: _base(deployment) + "scenarios/"),
    "receipt": ("canonical_bytes", lambda deployment, scenario, receipt_id: _receipt_url(deployment, receipt_id)),
    "results": ("build_report",
                lambda deployment, scenario, receipt_id: _base(deployment) + f"scenarios/{scenario.uuid}/results/"),
}


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("read", sorted(_HELD))
def test_a_stop_is_answered_while_a_read_is_held_open(read, monkeypatch):
    """SAFETY. ``transaction=True`` IS THE TEST: under the ordinary fixture every test
    runs inside an atomic block. The read is held open mid-read on another thread, and
    the scan's Stop is sent meanwhile: it is answered (202) and saved while the read is
    still held, and the read held no transaction. Every transaction here takes the
    database's write lock, so a read holding one would have kept the Stop waiting
    until it let go; this bounds no wall clock."""
    analyst = User.objects.create_user(username="ann", password="x", role="analyst")
    deployment = Deployment.objects.create(name="probe")
    _signing(monkeypatch)
    scenario = stored(deployment, analyst)
    assert _simulate(_client(analyst), deployment, scenario, receipt=True).status_code == 201
    receipt_id = FinancialExposureReceipt.objects.get().receipt_id
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True, status=PentestScan.STATUS_PENDING
    )
    name, url = _HELD[read]
    real = getattr(report, name)
    inside, release = threading.Event(), threading.Event()
    seen = {}

    def held(*args, **kwargs):
        if not inside.is_set():
            seen["atomic"] = connection.in_atomic_block
            inside.set()
            release.wait(timeout=30)
        return real(*args, **kwargs)

    monkeypatch.setattr(report, name, held)
    out = {}

    def reading():
        try:
            out["status"] = _client(analyst).get(url(deployment, scenario, receipt_id)).status_code
        except Exception as exc:  # noqa: BLE001 - reported by the assertion below
            out["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=reading)
    thread.start()
    try:
        assert inside.wait(timeout=30), f"the read never reached {name}: {out}"
        stop = _client(analyst).post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")
        still_held = thread.is_alive() and not release.is_set()
    finally:
        release.set()
        thread.join(timeout=60)
    assert stop.status_code == 202, stop.content
    assert stop.json()["stop_saved"] is True
    assert still_held, "the Stop was answered only once the read had let go"
    assert seen["atomic"] is False, "the read held a transaction while it read"
    scan.refresh_from_db()
    assert scan.stop_requested_at is not None
    assert out == {"status": 200}, out


# ======================================================================
# The spec and the README
# ======================================================================


SPEC_PHRASES = (
    "### 27.12 The read routes the dashboard needs",
    "`deployment-economics-scenarios`",
    "`deployment-economics-receipt`",
    "`mythos.economics.report/v2`",
    "`currency_bridge`",
    "`X-Content-SHA256`",
    "`report_api.SCENARIO_PAGE_SIZE_MAX`",
    "no normalization record is stored",
)


def test_the_spec_and_the_readme_state_the_read_routes():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    readme = README.read_text(encoding="utf-8")
    for phrase in ("economics/receipts/<receipt id>/", "economics/scenarios/?page=", "`mythos.economics.report/v2`"):
        assert phrase in readme, phrase
