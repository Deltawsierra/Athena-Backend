"""Economic Exposure: the deployment's economic-exposure report as JSON,
``mythos.economics.exposure-report/v1`` (roadmap AT-6b; ``docs/economics/spec-v1.md``, section 38.3).

- ``GET .../exposure-report/?output=json`` serves the same document the HTML and the PDF
  render, as canonical JSON with its own digest, ``no-store`` and ``nosniff``;
- its schema is fixed, key by key: every figure as the typed measure it already is, the
  assumptions as inputs as stated (never measures), the rule, the period and the basis,
  the input digest of the run shown, every gap;
- no amount changed: each measure is the one the HTML shows, and each input is as recorded;
- it never says clean, resolved, secure or safe, and every word meets the persona lint;
- the route is the same route: deployment-scoped, read-only, the same operation class.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from mythos_core import measures
from mythos_core.persona import lint

from assurance.economics import exposure_measures as em
from assurance.economics import exposure_report, report
from assurance.economics.engine import remediation as er
from assurance.models import Deployment
from safety import degraded, stops
from tests.test_every_exposure_figure_says_its_kind import _insured
from tests.test_economics_exposure_report import _client, _url

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
#: The words the JSON never says: none of them, in any of their forms, anywhere in it.
REASSURANCE = re.compile(r"\b(clean(?:ed|ly)?|resolve[ds]?|secured?|safe(?:ly)?)\b", re.IGNORECASE)
#: The schema, key by key.
TOP = ("schema", "deployment", "title", "status", "scenario", "input_digest", "rule", "period", "basis", "kinds",
       "measures", "assumptions", "not_measured", "digest")
SCENARIO = {"uuid", "title", "simulation"}
FIGURE = {"section", "label", "shown", "kind", "why", "measure"}
MEASURE = {"kind", "amount", "currency", "period", "cumulative", "basis", "source"}
INPUT = ("name", "unit", "currency", "low", "base", "high", "source_type", "evidence_ref", "effective_date",
         "withheld")


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


def _json(client, deployment):
    response = client.get(_url(deployment, "?output=json"))
    assert response.status_code == 200, response.content
    return response, json.loads(response.content)


def _strings(value):
    if isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)
    elif isinstance(value, str):
        yield value


def _holds_the_schema(body: dict) -> None:
    """``body`` is a ``mythos.economics.exposure-report/v1`` document, key by key and type by type."""
    assert tuple(exposure_report.json_document({"scenario": None, "measures": [], "assumptions": [],
                                                "not_measured": [], "deployment": "", "title": "",
                                                "status": ""})) == TOP == exposure_report.JSON_FIELDS
    assert set(body) == set(TOP)
    assert body["schema"] == exposure_report.JSON_SCHEMA == "mythos.economics.exposure-report/v1"
    # Named as every format economics serves is: mythos.economics.<thing>/v<n>.
    for name in (exposure_report.JSON_SCHEMA, report.REPORT_SCHEMA, er.ROI_SCHEMA):
        assert re.fullmatch(r"mythos\.economics\.[a-z-]+/v[0-9]+", name), name
    assert UUID.fullmatch(body["deployment"]) and isinstance(body["title"], str) and isinstance(body["status"], str)
    if body["scenario"] is None:
        assert body["input_digest"] is None
    else:
        assert set(body["scenario"]) == SCENARIO and DIGEST.fullmatch(body["input_digest"])
        assert UUID.fullmatch(body["scenario"]["uuid"]) and UUID.fullmatch(body["scenario"]["simulation"])
    assert (body["rule"], body["period"], body["basis"]) == (em.RULE, em.PERIOD_RULE, em.BASIS_RULE)
    assert set(body["kinds"]) == {entry["kind"] for entry in body["measures"]}
    for kind, means in body["kinds"].items():
        assert means == em.KIND_MEANS.get(kind, exposure_report.UNKNOWN_MEANS)
    for entry in body["measures"]:
        assert set(entry) == FIGURE and entry["kind"] in (*measures.MEASURE_KINDS, em.UNKNOWN)
        if entry["measure"] is None:
            assert isinstance(entry["why"], str) and entry["why"]
            continue
        held = entry["measure"]
        assert entry["why"] is None and set(held) == MEASURE and held["kind"] == entry["kind"]
        assert entry["shown"] == f"{held['currency']} {held['amount']}"
        assert set(held["period"]) == {"start", "end"} and isinstance(held["cumulative"], bool)
        assert set(held["basis"]) == {"snapshot_id", "content_hash"} and DIGEST.fullmatch(held["basis"]["content_hash"])
        assert isinstance(held["source"], str) and held["source"]
    assert set(body["assumptions"]) == {"statement", "inputs"} and body["assumptions"]["statement"] == em.ASSUMPTIONS_ARE
    for entry in body["assumptions"]["inputs"]:
        assert tuple(entry) == INPUT or set(entry) == set(INPUT)
    assert all(isinstance(gap, str) for gap in body["not_measured"])
    assert body["digest"] == report.digest_of({key: value for key, value in body.items() if key != "digest"})


# ======================================================================
# The schema, and the same report
# ======================================================================


def test_the_json_holds_its_schema_and_is_the_report_the_html_shows(deployment, people):
    _, result = _insured(deployment, people)
    response, body = _json(_client(people["owner"]), deployment)
    _holds_the_schema(body)
    assert response["Content-Type"] == "application/json"
    assert response["Cache-Control"] == "no-store" and response["X-Content-Type-Options"] == "nosniff"
    served = exposure_report.document(deployment)
    assert body["measures"] == served["measures"] and body["not_measured"] == served["not_measured"]
    assert body["status"] == served["status"] and body["title"] == served["title"]
    assert body["input_digest"] == result.input_digest and body["scenario"]["simulation"] == str(result.uuid)
    assert body["deployment"] == str(deployment.uuid)
    # Every figure is the typed measure it is, and the amount the HTML shows.
    rows = {label: value for _, section in served["sections"] for label, value in section}
    for entry in body["measures"]:
        assert rows[entry["label"]] == entry["shown"]
        assert entry["kind"] == measures.MODELED_EXPOSURE and entry["measure"]["period"] == {
            "start": "2026-10-06", "end": "2026-10-06"}
        assert entry["measure"]["basis"] == {"snapshot_id": f"simulation-inputs:{result.uuid}",
                                             "content_hash": result.input_digest}
    assert len(body["measures"]) == 10 and body["kinds"] == {
        measures.MODELED_EXPOSURE: em.KIND_MEANS[measures.MODELED_EXPOSURE]}


def test_the_assumptions_are_inputs_as_stated_never_measures(deployment, people):
    _, result = _insured(deployment, people)
    _, body = _json(_client(people["owner"]), deployment)
    parameters = report.build_report(result)["parameters"]
    inputs = body["assumptions"]["inputs"]
    assert [entry["name"] for entry in inputs] == sorted(parameters)
    for entry in inputs:
        stated = parameters[entry["name"]]
        assert entry == {key: entry["name"] if key == "name" else stated.get(key) for key in INPUT}
    unit_cost = next(entry for entry in inputs if entry["name"] == "notification_unit_cost")
    assert (unit_cost["low"], unit_cost["base"], unit_cost["high"], unit_cost["currency"]) == (
        "2.375", "2.375", "2.375", "USD")
    names = {entry["name"] for entry in inputs}
    assert not [entry for entry in body["measures"] if entry["label"] in names]
    assert not [gap for gap in body["not_measured"] for name in names if name in gap]


def test_with_no_figure_shown_the_schema_still_holds(deployment, people):
    _, body = _json(_client(people["owner"]), deployment)
    _holds_the_schema(body)
    assert body["scenario"] is None and body["input_digest"] is None and body["measures"] == []
    assert body["assumptions"]["inputs"] == [] and body["status"] == "AUDIT_INCOMPLETE"
    assert body["not_measured"][0] == exposure_report.NONE_SELECTED


# ======================================================================
# Its words
# ======================================================================


def test_the_json_never_says_clean_resolved_secure_or_safe(deployment, people):
    for before in (False, True):
        if before:
            _insured(deployment, people)
        _, body = _json(_client(people["owner"]), deployment)
        said = [text for text in _strings(body) if REASSURANCE.search(text)]
        assert said == []
        for text in _strings(body):
            assert lint.lint(text).ok, text
    for word in ("clean", "Resolved", "secure", "safe", "safely"):
        assert REASSURANCE.search(f"the figure is {word}")
    assert not REASSURANCE.search("insurance security unresolved")


# ======================================================================
# The same route
# ======================================================================


def test_the_json_is_the_same_bytes_writes_nothing_and_another_tenant_gets_nothing(deployment, people):
    _insured(deployment, people)
    client = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        first, second = client.get(_url(deployment, "?output=json")), client.get(_url(deployment, "?output=json"))
    assert first.status_code == second.status_code == 200 and first.content == second.content
    assert first.content == report.canonical_bytes(json.loads(first.content))
    writes = [q["sql"] for q in queries.captured_queries
              if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE"))]
    assert writes == []
    assert _client(people["other"]).get(_url(deployment, "?output=json")).status_code == 404
    assert _client().get(_url(deployment, "?output=json")).status_code in (401, 403)
    assert client.get(_url(deployment, "?output=xml")).status_code == 400
    assert client.get(_url(deployment, "?output=json&output=html")).status_code == 400
    # The route's operation class and its place among the routes that are no stop are unchanged.
    assert degraded.ROUTES["deployment-economics-exposure-report"] == {"GET": degraded.ASSESSMENT}
    assert set(stops.NOT_STOPS["deployment-economics-exposure-report"]) == {"GET"}


def test_the_readme_and_the_spec_state_the_json_format():
    readme = " ".join((REPO / "README.md").read_text(encoding="utf-8").split())
    spec = " ".join((REPO / "docs/economics/spec-v1.md").read_text(encoding="utf-8").split())
    assert "**The report as JSON** (`?output=json`; `mythos.economics.exposure-report/v1`" in readme
    assert "### 38.3 The report as JSON (AT-6b)" in spec and em.ASSUMPTIONS_ARE in spec
