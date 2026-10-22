"""A finding's ``narrative`` reaches every reader of the scan whole.

An engine may put one additive key on a real finding row of its answer,
``result.results[i].narrative``: a string, the finding told in plain words. This service
does not read it, write it or render it. ``PentestScan.engine_response`` keeps the
engine's answer as the engine wrote it ("Django does not interpret or reshape engine
results", ``PentestScanSerializer``), and GET scan detail serves that field.

Nothing here changes that. These tests hold it: a finding that carries ``narrative``
is stored, answered by the launch and served by GET scan detail unchanged -- the key,
its string byte for byte, and every other key of the row -- and a finding that carries
none gains none. A later tightening of a serializer or of the stored copy (an
allow-list of finding keys, say) would drop the key quietly, since nothing else reads it
here; these fail instead.

The launch is driven for real: a loopback engine answers the real client, the view
stores what it read, and the URL stack serves it back, the way
``test_a_scan_target_s_login_is_said_nowhere`` drives its own.

The one thing the stored copy does to a string is withhold a scan target's login from
it (``pentest.views._without_target_login``), as it does from every string in the
answer. A narrative that does not quote the login is untouched by that.
"""

from __future__ import annotations

import json
import secrets
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone
from rest_framework.renderers import JSONRenderer
from rest_framework.test import APIClient

from pentest.models import Engagement, PentestScan
from pentest.serializers import PentestScanSerializer
from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    Recorder,
    no_environment_proxy,  # noqa: F401 - a fixture
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("no_environment_proxy")]

JSON_ANSWER = {"Content-Type": "application/json"}
TARGET = "https://offline.invalid/"
RUN_ID = "run-narrative-1"

#: What an engine says in a finding's words. Quotes, a dash, an angle bracket, an
#: ampersand, a percent sign and a blank line: all of it must come back as it left.
NARRATIVE = (
    "The sign-in form builds its question to the database out of what is typed into it, "
    "and a crafted entry changed the answer it gave.\n\n"
    "What this could mean: a stranger reading other people's records.\n"
    "What was not tested: the reset flow, the API behind the form, anything after sign-in.\n"
    "Wording that must survive: “quoted”, it’s, <b>tags</b> & 100% — done."
)

#: A real finding that carries a narrative, with nested evidence beside it.
TOLD = {
    "type": "sql_injection",
    "title": "SQL injection in the sign-in form",
    "severity": "high",
    "tier": "confirmed",
    "url": "https://offline.invalid/signin",
    "evidence": {"request": "POST /signin", "markers": ["syntax error", "unterminated quote"]},
    "narrative": NARRATIVE,
}

#: A real finding the engine told no story about (the engine's flag is off, or its
#: renderer declined): it must gain no ``narrative`` on the way.
UNTOLD = {
    "type": "missing_header",
    "title": "No clickjacking protection",
    "severity": "low",
    "tier": "likely",
    "url": "https://offline.invalid/",
    "evidence": {"header": "X-Frame-Options", "present": False},
}

#: A row about the run, not about the customer's system: never narrated, never touched.
INTERNAL = {"type": "timing", "internal": True, "elapsed_ms": 812}

ROWS = [TOLD, UNTOLD, INTERNAL]


def _password() -> str:
    return f"cnrytgt{secrets.token_hex(10)}"


def _launch_and_read(monkeypatch, rows, target=TARGET):
    """Launch a scan at a loopback engine that finishes its run with ``rows`` as its
    results, then read it back: ``(the launch's answer, GET scan detail's, the stored scan)``."""

    def engine_answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/scan"):
            accepted = {"run_id": RUN_ID, "status_url": f"/api/scans/{RUN_ID}"}
            return 202, JSON_ANSWER, json.dumps(accepted).encode()
        if path == f"/api/scans/{RUN_ID}":
            finished = {"run_id": RUN_ID, "state": "completed", "done": True, "result": {"results": rows}}
            return 200, JSON_ANSWER, json.dumps(finished).encode()
        return 404, {}, b"{}"

    user = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    now = timezone.now()
    engagement = Engagement.objects.create(
        created_by=user, name="Client Q3", status="running", scope_hosts=["offline.invalid"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )
    monkeypatch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    monkeypatch.setattr("pentest.views.render_scan_pdf_bytes", lambda scan, context=None: b"%PDF-1.4 report")
    monkeypatch.setattr("pentest.views.save_pdf_to_scan", lambda scan, pdf: None)

    client = APIClient()
    client.force_authenticate(user=user)
    engine = Recorder(answer=engine_answer)
    try:
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnryenginekey"):
            launched = client.post(
                "/api/pentest/scan/",
                {"url": target, "consent": True, "engagement_id": engagement.pk},
                format="json",
            )
            assert launched.status_code == 200, launched.content
            scan_id = launched.json()["scan_id"]
            detail = client.get(f"/api/pentest/scans/{scan_id}/")
    finally:
        engine.close()

    assert detail.status_code == 200, detail.content
    return launched.json(), detail.json(), PentestScan.objects.get(uuid=scan_id)


# ---------------------------------------------------------------------------
# Stored, answered and served: whole
# ---------------------------------------------------------------------------


def test_a_finding_s_narrative_is_stored_and_served_by_scan_detail_whole(monkeypatch):
    launched, detail, scan = _launch_and_read(monkeypatch, ROWS)

    assert scan.status == PentestScan.STATUS_COMPLETED, scan.status
    # What the database kept, row for row: every key of every row, the narrative's
    # string byte for byte.
    assert scan.engine_response == {"results": ROWS}, scan.engine_response
    # What GET scan detail serves is what was stored, as JSON on the wire.
    served = detail["engine_response"]["results"]
    assert served == ROWS, served
    assert served[0]["narrative"] == NARRATIVE, "the narrative did not reach scan detail whole"
    # And what the launch answered is what the engine wrote.
    assert launched["result"]["results"] == ROWS, launched["result"]


def test_a_finding_without_a_narrative_gains_none_on_the_way(monkeypatch):
    launched, detail, scan = _launch_and_read(monkeypatch, ROWS)

    for kept in (scan.engine_response["results"], detail["engine_response"]["results"], launched["result"]["results"]):
        assert "narrative" not in kept[1], "a finding the engine told no story about gained a narrative"
        assert "narrative" not in kept[2], "a row about the run gained a narrative"


class _Serializer(PentestScanSerializer):
    """``PentestScanSerializer`` as it is defined, in a form DRF will build.

    The class itself cannot be built as it stands: it declares ``engagement`` and its
    ``Meta.fields`` leaves it out, which DRF refuses (``The field 'engagement' was declared
    ... but has not been included in the 'fields' option``) whenever its fields are read.
    No view uses it -- GET scan detail builds its answer by hand
    (``pentest.views.detail_pentest_scan``, tested above) -- so nothing has noticed. A
    subclass is exempt from that check for the fields it inherits, and lists the same
    ``Meta.fields``, so this serializes exactly what the class says it does, ``engine_response``
    included. It is not a fix: the class is left as it is."""


def test_the_scan_serializer_serializes_a_finding_s_narrative_whole():
    user = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    scan = PentestScan.objects.create(
        user=user, target_url=TARGET, consent=True, status=PentestScan.STATUS_COMPLETED,
        engine_response={"results": ROWS},
    )
    scan.refresh_from_db()  # what the database kept, not what was assigned

    data = _Serializer(scan).data
    assert data["engine_response"] == {"results": ROWS}, data["engine_response"]
    on_the_wire = json.loads(JSONRenderer().render(data))
    assert on_the_wire["engine_response"]["results"][0]["narrative"] == NARRATIVE
    assert on_the_wire["engine_response"] == {"results": ROWS}


# ---------------------------------------------------------------------------
# The one thing the stored copy does to a string
# ---------------------------------------------------------------------------


def test_a_narrative_is_kept_whole_beside_the_withholding_of_a_target_s_login(monkeypatch):
    """The stored copy withholds a target's login from every string in the answer and
    changes nothing else: a narrative that does not quote the login is kept whole, and
    one that does keeps its key and its shape with only the login withheld."""
    password = _password()
    target = f"https://scanner:{password}@offline.invalid/"
    quoting = dict(TOLD, title="Reflected sign-in", narrative=f"{NARRATIVE} The scanner reached {target}.")

    _launched, detail, scan = _launch_and_read(monkeypatch, [TOLD, quoting], target=target)

    for kept in (scan.engine_response["results"], detail["engine_response"]["results"]):
        assert kept[0] == TOLD, kept[0]
        assert set(kept[1]) == set(quoting), "the row lost a key to the withholding of the login"
        assert password not in json.dumps(kept), "the login was said"
        assert kept[1]["narrative"] == f"{NARRATIVE} The scanner reached https://[withheld]@offline.invalid/."
