"""A scan target's login -- the ``user:password@`` a caller put in its URL -- is
said nowhere: not where the scan is shown (``pentest.models.target_shown``), and
not in a refusal the engine quotes the launch back in.

The scan keeps the URL it was launched with, since a reconcile sends that launch
again unchanged. What it says -- its error, its answers -- is withheld from: the
client withholds the login from every error a call carrying a target raises
(``cyberengine_client._saying_none_of``, and ``safety.outbound`` from a failed
send's text), and the scan withholds it from every text it stores or answers
(``PentestScan.said``). The engine's answer itself is read as the engine wrote it:
a login a tenant chose must not be able to rewrite the run id a Stop names.
"""

from __future__ import annotations

import json
import secrets
import traceback

import pytest

from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    Recorder,
    _closed_base,
    no_environment_proxy,  # noqa: F401 - a fixture
)


def _password() -> str:
    return f"cnrytgt{secrets.token_hex(10)}"


def _everything_said(exc: BaseException) -> str:
    """What an exception says: its traceback and text, and every cause's and context's."""
    return "".join(traceback.format_exception(exc)) + repr(exc.args)


# ---------------------------------------------------------------------------
# target_shown and logins_in read the userinfo up to the authority's LAST @
# ---------------------------------------------------------------------------

_SHOWN = [
    ("https://scanner:p@ss@host.example/path", "https://[withheld]@host.example/path"),
    ("https://scanner:p@ss@host.example:8443/a?b=c@d#e@f", "https://[withheld]@host.example:8443/a?b=c@d#e@f"),
    ("https://a@b@c@host.example/", "https://[withheld]@host.example/"),
    ("https://host.example/path?email=a@b.example", "https://host.example/path?email=a@b.example"),
    ("https://host.example/p@th", "https://host.example/p@th"),
    ("https://scanner:pw@host.example", "https://[withheld]@host.example"),  # pragma: allowlist secret
    ("https://host.example/", "https://host.example/"),
]


@pytest.mark.parametrize(("url", "shown"), _SHOWN)
def test_target_shown_withholds_the_userinfo_up_to_the_authority_s_last_at(url, shown):
    from pentest.models import target_shown

    assert target_shown(url) == shown


def test_a_password_with_an_at_in_it_is_withheld_whole():
    """``p@ss``: the part after the FIRST ``@`` is ``ss@host``, and a reading that
    stopped there would show ``ss`` -- the password's tail -- as the host's login."""
    from pentest.models import target_shown
    from safety import outbound

    url = "https://scanner:p@ss-cnry@host.example/x"
    shown = target_shown(url)
    assert "ss-cnry" not in shown and "p@ss" not in shown and shown.endswith("@host.example/x"), shown
    assert outbound.logins_in(url) == ("scanner:p@ss-cnry", "p@ss-cnry")


def test_logins_in_gives_the_userinfo_and_password_as_written_and_decoded():
    from safety import outbound

    assert outbound.logins_in("https://scanner:p%40ss@host.example/") == (  # pragma: allowlist secret
        "scanner:p%40ss", "scanner:p@ss", "p%40ss", "p@ss"
    )
    assert outbound.logins_in("https://host.example/a@b") == ()
    assert outbound.logins_in(None) == ()


# ---------------------------------------------------------------------------
# A refusal quoting the launch back says no login
# ---------------------------------------------------------------------------


def _echo(method, path, headers, body):
    """An engine refusing whatever it is sent with a page quoting the request back."""
    page = {"detail": "upstream error", "request": {"path": path, "body": body.decode("utf-8", "replace")}}
    return 500, {"Content-Type": "application/json"}, json.dumps(page).encode()


def test_a_launch_refused_with_a_page_quoting_it_back_says_no_login(no_environment_proxy):  # noqa: F811
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

    password = _password()
    target = f"https://scanner:{password}@offline.invalid/"
    engine = Recorder(answer=_echo)
    try:
        with pytest.raises(EngineError) as raised:
            CyberEngineClient(engine.base, "cnryenginekey").run_scan(target, idempotency_key="k-1")
    finally:
        engine.close()
    assert password.encode() in engine.bodies[0], "the launch did not carry the target's login"
    said = _everything_said(raised.value)
    assert "upstream error" in said, said
    assert password not in said and f"scanner:{password}" not in said, said


def test_an_llm_scan_refused_with_a_page_quoting_it_back_says_no_login(no_environment_proxy):  # noqa: F811
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

    password = _password()
    engine = Recorder(answer=_echo)
    try:
        with pytest.raises(EngineError) as raised:
            CyberEngineClient(engine.base, "cnryenginekey").run_llm_scan(
                {"base_url": f"https://bot:{password}@llm.invalid/v1", "adapter": "openai_style"}
            )
    finally:
        engine.close()
    said = _everything_said(raised.value)
    assert "upstream error" in said and password not in said, said


def test_a_failed_send_says_none_of_what_it_is_asked_to_withhold(no_environment_proxy):  # noqa: F811
    """``safety.outbound`` withholds the values a call site names from a failed
    send's text: here the port, which the text names."""
    import requests

    from safety import outbound

    base = _closed_base()
    port = base.rsplit(":", 1)[1]
    with pytest.raises(requests.RequestException) as raised:
        outbound.post(base + "/api/scan", json={}, timeout=2, engine=True, also_withhold=(port,))
    assert port not in _everything_said(raised.value)


@pytest.mark.django_db
def test_every_text_a_scan_stores_says_no_login():
    from django.contrib.auth import get_user_model

    from pentest.models import PentestScan

    password = _password()
    user = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    scan = PentestScan.objects.create(
        user=user, target_url=f"https://scanner:{password}@offline.invalid/", consent=True,
        status=PentestScan.STATUS_PENDING,
    )
    scan.mark_unknown(f"no answer to https://scanner:{password}@offline.invalid/")
    scan.refresh_from_db()
    assert password not in scan.error_message and "[withheld]" in scan.error_message
    scan.mark_failed(f'Engine error: 500: {{"target": "https://scanner:{password}@offline.invalid/"}}')
    scan.refresh_from_db()
    assert password not in scan.error_message and "[withheld]" in scan.error_message
    assert scan.target_url == f"https://scanner:{password}@offline.invalid/", "the launch URL is kept as it was"


def test_a_target_s_login_never_rewrites_the_run_a_stop_names(no_environment_proxy):  # noqa: F811
    """The SAFETY RULE: the login is withheld from what is said, never from what is
    read. A target whose password is the run's own id still names that run, so its
    Stop reaches it."""
    from ai_engine.services.cyberengine_client import CyberEngineClient
    from tests.test_a_lost_launch_answer_reads_unknown import ACCEPTED, COMPLETED

    run_id = "run-cnry-1"

    def engine_answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/scan"):
            return 202, {"Content-Type": "application/json"}, json.dumps(dict(ACCEPTED, run_id=run_id)).encode()
        if path == f"/api/scans/{run_id}":
            return 200, {"Content-Type": "application/json"}, json.dumps(dict(COMPLETED, run_id=run_id)).encode()
        return 404, {}, b"{}"

    named = []
    engine = Recorder(answer=engine_answer)
    try:
        CyberEngineClient(engine.base, "cnryenginekey").run_scan(
            f"https://scanner:{run_id}@offline.invalid/", idempotency_key="k-2", on_run=named.append
        )
    finally:
        engine.close()
    assert named == [run_id]


@pytest.mark.django_db
def test_an_answer_quoting_the_login_is_withheld_from_scan_detail(no_environment_proxy, monkeypatch):  # noqa: F811
    """A target's login the engine quotes back in its 2xx answer is withheld from the
    copy GET scan detail serves (``engine_response``), run over AFTER the run id has
    been read from the launch answer -- so the run id is read correctly and the Stop
    path is unchanged. The engine's answer itself is read as the engine wrote it; only
    the copy kept for a reader is cleaned of the login."""
    from datetime import timedelta

    from django.contrib.auth import get_user_model
    from django.test import override_settings
    from django.utils import timezone
    from rest_framework.test import APIClient

    from pentest.models import Engagement, PentestScan

    password = _password()
    target = f"https://scanner:{password}@offline.invalid/"
    run_id = "run-detail-cnry"

    def engine_answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/scan"):
            return 202, {"Content-Type": "application/json"}, json.dumps(
                {"run_id": run_id, "status_url": f"/api/scans/{run_id}"}
            ).encode()
        if path == f"/api/scans/{run_id}":
            # The engine's finding quotes the target back, login and all.
            return 200, {"Content-Type": "application/json"}, json.dumps({
                "run_id": run_id, "state": "completed", "done": True,
                "result": {"results": [
                    {"type": "finding", "title": "reflected credentials", "severity": "high",
                     "evidence": f"the scanner reached {target}"},
                ]},
            }).encode()
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
            scan_id = launched.json()["scan_id"]
            detail = client.get(f"/api/pentest/scans/{scan_id}/")
    finally:
        engine.close()

    assert launched.status_code == 200, launched.content
    assert any(password.encode() in sent for sent in engine.bodies), "the launch did not carry the target's login"
    assert ("POST", "/api/scan") in [(m, p) for m, p, _h in engine.seen], engine.seen
    scan = PentestScan.objects.get(uuid=scan_id)
    # The run id was read from the launch answer and kept on the scan.
    assert scan.engine_run_id == run_id, scan.engine_run_id
    assert scan.status == PentestScan.STATUS_COMPLETED, scan.status
    # GET scan detail carries the answer, its finding's shape kept, the login withheld.
    assert detail.status_code == 200, detail.content
    body = detail.content.decode()
    assert password not in body and f"scanner:{password}" not in body, body
    served = detail.json()["engine_response"]
    assert served["results"][0]["title"] == "reflected credentials"
    assert password not in json.dumps(served) and "[withheld]" in json.dumps(served), served
