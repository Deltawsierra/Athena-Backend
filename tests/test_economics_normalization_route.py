"""Economic Exposure: the normalization route (MVP step 12; ``docs/economics/spec-v1.md``,
section 12.9).

``GET deployments/<uuid>/economics/normalization/?<query>`` answers one amount
normalized for a run of the deployment as of its valuation date: the engine's record
(section 12.6) with its conflicts, its fallbacks past the primary and its downgrades,
over the source versions a run of THAT deployment may use on that date
(``normalization_service.normalize_for``, section 12.8), never another deployment's. On
step 6's conventions: tenant-scoped, its query read strictly, answered ``no-store``,
canonical bytes, the same bytes fired twice and nothing written, no stop, and a Stop
answered while it is held open mid-read.

Every figure is SYNTHETIC / ILLUSTRATIVE: Minotaur-Engine #79's cases 18 to 20.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from assurance.economics import health_api, normalization_service, snapshots
from assurance.economics.engine.money import Money
from assurance.models import Deployment
from pentest.models import PentestScan
from safety import stops
from tests.test_economics_disagreement import (
    CPI,
    DAY,
    ECB,
    ECB_PRIMARY,
    H10,
    H10_PRIMARY,
    _normalized,
    _posted,
    _register,
    key_fields,
)
from tests.test_economics_read_routes import _economics_writes

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
README = REPO / "README.md"

#: Minotaur-Engine #79's disagreement cases: EUR 400,000 on 30 September 2026, in USD that
#: day, indexed by the test CPI.
QUERY = {
    "amount": "400000",
    "currency": "EUR",
    "event_date": "2026-09-30",
    "valuation_date": "2026-09-30",
    "base_currency": "USD",
    "reporting_currency": "USD",
    "providers": "ECB,FRB-H10",
    "index_series_id": CPI.series_id,
    "index_geography": CPI.geography,
    "index_category": CPI.category,
    "index_base": CPI.base,
}


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def staging(people):
    return Deployment.objects.create(name="payments-staging", environment="staging", owner=people["owner"])


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _url(deployment, **changed):
    query = {**QUERY, **changed}
    query = {key: value for key, value in query.items() if value is not None}
    return f"/api/assurance/deployments/{deployment.uuid}/economics/normalization/?{urlencode(query)}"


def _get(client, deployment, **changed):
    return client.get(_url(deployment, **changed))


def _record(answer) -> dict:
    assert answer.status_code == 200, answer.content
    return json.loads(answer.content)["normalization"]


# ======================================================================
# What it answers
# ======================================================================


@pytest.mark.parametrize(
    "h10_value, providers, display, conflict",
    [
        ("1.1310", "ECB,FRB-H10", "449200.00 USD", (ECB, "1.123", H10, "1.131", ECB_PRIMARY)),
        ("1.128615", "ECB,FRB-H10", "449200.00 USD", None),
        ("1.1310", "FRB-H10,ECB", "452400.00 USD", (H10, "1.131", ECB, "1.123", H10_PRIMARY)),
    ],
)
def test_the_keys_disagreement_cases_through_the_route(staging, people, h10_value, providers, display, conflict):
    """Minotaur-Engine #79's cases 18 to 20 over HTTP: the primary is the policy's, the
    conflict is listed with both sources, and the record is the service's own, byte for
    byte."""
    _posted(h10_value)
    answer = _get(_client(people["owner"]), staging, providers=providers)
    record = _record(answer)
    assert record["status"] == "normalized" and record["display"] == display
    assert record["chain"][0]["provider"] == providers.split(",")[0]
    if conflict is None:
        assert record["conflicts"] == [] and record["confidence_downgrades"] == []
    else:
        (found,) = record["conflicts"]
        assert key_fields(found) == dict(zip(
            ("pair", "date", "primary", "primary_value", "secondary", "secondary_value", "relative_difference"),
            ("EUR/USD", "2026-09-30", *conflict)))
        assert record["confidence_downgrades"] == ["source_disagreement"]
    expected = _normalized(staging, tuple(providers.split(","))).as_dict()
    assert json.loads(health_api.canonical_bytes(expected)) == record
    assert json.loads(answer.content)["deployment"] == str(staging.uuid)


def test_a_primary_the_gate_refuses_is_named_as_a_fallback(people):
    """A production deployment, the ECB's version unverified: H.10's rate is used, and
    the record says so -- the route reads only what a run of THIS deployment may use."""
    production = Deployment.objects.create(name="payments-prod", environment="production", owner=people["owner"])
    _posted("1.1310", ecb_tier="unverified")
    record = _record(_get(_client(people["owner"]), production))
    assert record["display"] == "452400.00 USD"
    assert record["primary_unavailable"] == [{"step": "event_fx", "primary": "ECB", "used": "FRB-H10"}]
    assert record["confidence_downgrades"] == ["primary_unavailable"] and record["conflicts"] == []


def test_a_normalization_the_books_cannot_make_is_answered_unavailable(staging, people):
    """No source quotes EUR/USD on 30 September: the normalization is unavailable,
    naming its reason, and that record is the answer (200), never a number."""
    _register("minotaur-test-fx-and-index", "MINOTAUR-TEST-REF", points=[("2026-09", "325.500", "2026-09-30")])
    record = _record(_get(_client(people["owner"]), staging, providers="ECB"))
    assert record["status"] == "unavailable" and record["value"] is None and record["display"] is None
    assert record["unavailable"]["reason"] == "rate_missing"


def test_the_rest_of_the_policy_is_read_from_the_query(staging, people):
    """Minotaur-Engine #79's weekend cases: an event on Saturday 26 September under the
    default rule takes Friday's rate; with the rule off and a missing rate unavailable,
    it is refused ``rate_missing``."""
    _register(ECB, "ECB", fx_rates=[("EUR", "USD", "2026-09-25", "1.1150"), ("EUR", "USD", "2026-09-30", "1.1230")])
    _register("minotaur-test-fx-and-index", "MINOTAUR-TEST-REF", points=[("2026-09", "325.500", "2026-09-30")])
    owner = _client(people["owner"])
    saturday = {"amount": "500000", "event_date": "2026-09-26", "providers": "ECB"}
    taken = _record(_get(owner, staging, **saturday))
    assert taken["status"] == "normalized" and taken["chain"][0]["rule"] == "last_official_rate"
    assert taken["display"] == "557500.00 USD" and taken["chain"][0]["rate_date"] == "2026-09-25"
    off = _record(_get(owner, staging, **saturday, weekend_holiday_rule="none", missing_rate="unavailable"))
    assert off["status"] == "unavailable" and off["unavailable"]["reason"] == "rate_missing"
    assert off["policy"]["fx"]["weekend_holiday_rule"] == "none"
    limits = _record(_get(owner, staging, **saturday, freshness_days="0", max_interpolation_gap_days="3",
                          rate_types="mid,reference", index_max_lag_months="1"))
    assert limits["policy"]["fx"]["freshness_days"] == 0 and limits["policy"]["index_max_lag_months"] == 1
    assert limits["policy"]["fx"]["rate_types"] == ["mid", "reference"]


# ======================================================================
# Tenancy and access
# ======================================================================


def test_the_route_keeps_to_the_tenant(staging, people):
    """The owner reads their own deployment; another's is 404 whether or not it exists;
    no account, 401; every role reads; and another deployment's own source is never in
    this one's books -- it is in that deployment's, which lists the conflict."""
    other = Deployment.objects.create(name="another-bank", environment="staging", owner=people["other"])
    _posted("1.1240")
    _register("own-bank-rates", "OWN-BANK", fx_rates=[("EUR", "USD", "2026-09-30", "1.2000")], deployment=other)
    owner = _client(people["owner"])
    mine = _record(_get(owner, staging))
    assert mine["conflicts"] == [] and mine["confidence_downgrades"] == []
    assert _get(owner, other).status_code == 404
    assert _get(owner, Deployment(name="never-saved")).status_code == 404
    assert _get(_client(), staging).status_code == 401
    for role in ("admin", "analyst"):
        assert _get(_client(people[role]), staging).status_code == 200, role
    theirs = _record(_get(_client(people["other"]), other))
    assert [c["secondary"] for c in theirs["conflicts"]] == ["own-bank-rates"]
    assert "own-bank-rates" not in json.dumps(mine) and "OWN-BANK" not in json.dumps(mine)


# ======================================================================
# The query, read strictly
# ======================================================================


@pytest.mark.parametrize(
    "changed, code",
    [
        ({"as_of": "2026-09-30"}, "field_unrecognised"),
        ({"index_currency": "USD"}, "field_unrecognised"),
        ({"amount": None}, "field_missing"),
        ({"providers": None}, "field_missing"),
        ({"index_base": None}, "field_missing"),
        ({"event_date": "2026-9-30"}, "field_malformed"),
        ({"valuation_date": "2026-02-30"}, "field_malformed"),
        ({"providers": "ECB,,FRB-H10"}, "field_malformed"),
        ({"providers": "ECB, FRB-H10"}, "field_malformed"),
        ({"freshness_days": "-1"}, "field_malformed"),
        ({"freshness_days": "07"}, "field_malformed"),
        ({"max_interpolation_gap_days": "12345"}, "field_malformed"),
        ({"index_max_lag_months": "one"}, "field_malformed"),
        ({"amount": "4e5"}, "not_decimal"),
        ({"amount": "400,000"}, "not_decimal"),
        ({"currency": "EURO"}, "currency_unknown"),
        ({"providers": "ECB,ECB"}, "policy_invalid"),
        ({"weekend_holiday_rule": "next_day"}, "policy_invalid"),
        ({"event_date": "2026-10-01"}, "date_inversion"),
    ],
)
def test_the_query_is_read_strictly(staging, people, changed, code):
    _posted("1.1310")
    answer = _get(_client(people["owner"]), staging, **changed)
    assert answer.status_code == 400, answer.content
    assert answer.json()["code"] == code, answer.json()


def test_a_key_given_twice_is_malformed(staging, people):
    url = _url(staging) + "&providers=ECB"
    answer = _client(people["owner"]).get(url)
    assert answer.status_code == 400 and answer.json()["code"] == "field_malformed"


def test_only_get_is_served(staging, people):
    admin = _client(people["admin"])
    base = f"/api/assurance/deployments/{staging.uuid}/economics/normalization/"
    assert admin.post(base, {}, format="json").status_code == 405
    assert admin.put(base, {}, format="json").status_code == 405
    assert admin.delete(base).status_code == 405


# ======================================================================
# Step 6's conventions: canonical, no-store, fired twice, writes nothing
# ======================================================================


def test_it_is_canonical_no_store_and_the_same_bytes_fired_twice_writing_nothing(staging, people):
    _posted("1.1310")
    owner = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        first, second = _get(owner, staging), _get(owner, staging)
    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    body = json.loads(first.content)
    assert first.content == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert first["Cache-Control"] == "no-store" and first["Content-Type"] == "application/json"
    assert _economics_writes(queries.captured_queries) == []
    assert not any(q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
                   for q in queries.captured_queries)


def test_the_route_reads_what_the_service_reads_and_nothing_else(staging, people, monkeypatch):
    """The view asks the service, with the deployment the caller may see: the books are
    the service's, never built here."""
    seen = []
    real = normalization_service.normalize_for

    def spy(deployment, native, **kwargs):
        seen.append((deployment.pk, native, kwargs["event_date"], kwargs["valuation_date"]))
        return real(deployment, native, **kwargs)

    monkeypatch.setattr(normalization_service, "normalize_for", spy)
    _posted("1.1310")
    _record(_get(_client(people["owner"]), staging))
    from decimal import Decimal

    assert seen == [(staging.pk, Money(Decimal("400000"), "EUR"), DAY, DAY)]


# ======================================================================
# Safety
# ======================================================================


def test_the_route_is_not_a_stop():
    name = "deployment-economics-normalization"
    assert name in stops.NOT_STOPS and set(stops.NOT_STOPS[name]) == {"GET"}
    assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES


@pytest.mark.django_db(transaction=True)
def test_a_stop_is_answered_while_the_normalization_is_held_open(monkeypatch):
    """SAFETY. ``transaction=True`` IS THE TEST: under the ordinary fixture every test
    runs inside an atomic block. The normalization is held open mid-read -- its rates
    read, its index not yet -- on another thread, and the scan's Stop is sent meanwhile:
    it is answered (202) and saved while the read is still held, and the read held no
    transaction."""
    analyst = User.objects.create_user(username="ann", password="x", role="analyst")
    deployment = Deployment.objects.create(name="probe", environment="staging")
    _posted("1.1310")
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True, status=PentestScan.STATUS_PENDING
    )
    real = snapshots.index_book
    inside, release = threading.Event(), threading.Event()
    seen = {}

    def held(*args, **kwargs):
        if not inside.is_set():
            seen["atomic"] = connection.in_atomic_block
            inside.set()
            release.wait(timeout=30)
        return real(*args, **kwargs)

    monkeypatch.setattr(snapshots, "index_book", held)
    out = {}

    def reading():
        try:
            out["status"] = _client(analyst).get(_url(deployment)).status_code
        except Exception as exc:  # noqa: BLE001 - reported by the assertion below
            out["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=reading)
    thread.start()
    try:
        assert inside.wait(timeout=30), f"the read never reached index_book: {out}"
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
    "### 12.9 The normalization route (MVP step 12)",
    "`deployment-economics-normalization`",
    "`GET /api/assurance/deployments/<uuid>/economics/normalization/?<query>`",
    "`health_api.NORMALIZATION_REQUIRED`",
    "`health_api.NORMALIZATION_OPTIONAL`",
    "`Cache-Control: no-store`",
)


def test_the_spec_and_the_readme_state_the_route():
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    for key in (*health_api.NORMALIZATION_REQUIRED, *health_api.NORMALIZATION_OPTIONAL):
        assert f"`{key}`" in text, key
    readme = " ".join(README.read_text(encoding="utf-8").split())
    assert "economics/normalization/" in readme
