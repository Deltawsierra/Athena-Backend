"""No credential a scan's target carries is ever shown (AB-TARGET-REDACT).

A scan keeps the URL it was launched with: the engine needs it to reach the target,
and a reconcile sends that launch again unchanged. Every form of it that is SHOWN
withholds what could be a credential (``pentest.models.target_shown``):

* the userinfo, as ``[withheld]`` (as before);
* every query value and every ``;param`` value, as ``•••``, each name kept -- every
  value, not those whose names look like keys: a list of names always misses one;
* the fragment, as ``#•••``;
* and a target that cannot be read is shown as ``•••``, never as given.

What a scan SAYS -- its errors, the engine's answer kept for a reader -- says the
target as shown, each ``name=value`` as ``name=•••``, and withholds the login and
each value said alone (``pentest.models.target_said``).

The tripwire plants a distinct key in the userinfo, the query, a ``;param`` and the
fragment of a standard scan and of an LLM scan, has the engine quote the target
back (whole, and each key on its own) in its answer and in a refusal, and then walks
every shown site the inventory found: every API answer (the launch, the reconcile,
detail, list, the refusals), both report renderers (ReportLab, and the Mythos HTML
renderer through a weasyprint stub), the stored PDF, the unused HTML template, the
e-mail (subject, body, attachment), the admin changelist and change form, every log
record, ``str(scan)``, and every row of every model but the scan's own
``target_url``. Each key is searched for in every encoding (``tests.canary_search``,
a PDF's streams inflated first). The engine still receives the real URL, key and
all.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import logging
import re
import secrets
import sys
import types
import zlib
from datetime import timedelta
from pathlib import Path

import pytest

from tests.canary_search import Needles, search
from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    Recorder,
    no_environment_proxy,  # noqa: F401 - a fixture
)

ROOT = Path(__file__).resolve().parent.parent
PLACES = ("login", "query", "param", "fragment")
SHOWN = "•••"

_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)


def _pdf_texts(data: bytes) -> list[str]:
    """The PDF whole, and every stream in it decoded: Flate, and ASCII85 then Flate
    (reportlab's ``[/ASCII85Decode /FlateDecode]``), as the sink harness reads one."""
    texts = [data.decode("latin-1")]
    for match in _STREAM.finditer(data):
        raw = match.group(1).strip()
        candidates = [raw]
        with contextlib.suppress(Exception):
            candidates.append(base64.a85decode(raw if raw.startswith(b"<~") else b"<~" + raw, adobe=True))
        for candidate in candidates:
            for window in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                with contextlib.suppress(zlib.error):
                    texts.append(zlib.decompress(candidate, window).decode("latin-1"))
                    break
    return texts


# ---------------------------------------------------------------------------
# target_shown: what a shown target withholds
# ---------------------------------------------------------------------------

_SHOWN = [
    ("https://host.example/path?api_key=sk-1&page=2", f"https://host.example/path?api_key={SHOWN}&page={SHOWN}"),
    ("https://host.example/p;jsessionid=abc/q;v=1;w=2", f"https://host.example/p;jsessionid={SHOWN}/q;v={SHOWN};w={SHOWN}"),
    ("https://host.example/#access_token=abc", f"https://host.example/#{SHOWN}"),
    ("https://host.example/?SECRETONITSOWN", f"https://host.example/?{SHOWN}"),
    ("https://host.example/p;SECRETONITSOWN", f"https://host.example/p;{SHOWN}"),
    ("https://host.example/?a=&b", f"https://host.example/?a=&{SHOWN}"),
    ("https://host.example/?", "https://host.example/?"),
    ("https://host.example/#", "https://host.example/#"),
    ("https://host.example/p#f?x=1", f"https://host.example/p#{SHOWN}"),
    ("https://u:pw@host.example:8443/a;b=c?d=e#f",  # pragma: allowlist secret
     f"https://[withheld]@host.example:8443/a;b={SHOWN}?d={SHOWN}#{SHOWN}"),
    ("https://host.example/path", "https://host.example/path"),
    ("https://host.example", "https://host.example"),
]


@pytest.mark.parametrize(("url", "shown"), _SHOWN)
def test_a_shown_target_withholds_every_query_param_and_fragment_value(url, shown):
    from pentest.models import target_shown

    assert target_shown(url) == shown


class _Unprintable:
    def __str__(self):
        raise RuntimeError("cnryunprintable")


@pytest.mark.parametrize(
    "url",
    [
        "host.example/?api_key=cnrybare0001",  # no scheme
        "host.example/p;cnrybare0001",
        "u:cnrybare0001@host.example",
        "http://[::1/?api_key=cnrybare0001",  # urlsplit refuses it
        "https://host.example;api_key=cnrybare0001/",  # a host that carries parameters
        "https://host.example=cnrybare0001/",
        _Unprintable(),
    ],
)
def test_a_target_that_cannot_be_read_is_shown_withheld_whole(url):
    from pentest.models import target_shown

    assert target_shown(url) == SHOWN


@pytest.mark.parametrize("url", [None, "", 12, b"https://host.example/?k=cnrybytes0001"])
def test_target_shown_never_raises_and_never_shows_a_value(url):
    from pentest.models import target_shown

    shown = target_shown(url)
    assert isinstance(shown, str) and "cnrybytes0001" not in shown


def test_what_a_scan_says_withholds_every_credential_its_target_carries():
    from pentest.models import target_said, target_shown

    keys = {place: f"cnry{place}{secrets.token_hex(6)}" for place in PLACES}
    target = (
        f"https://scanner:{keys['login']}@host.example/a;sid={keys['param']}/b"
        f"?api_key={keys['query']}&level=critical#{keys['fragment']}"
    )
    text = (
        f"refused {target}; quoted api_key={keys['query']} and sid={keys['param']}; "
        f"bare {keys['query']} {keys['param']} {keys['fragment']} {keys['login']}; "
        f"encoded api_key%3D{keys['query']}"
    )
    said = target_said(text, target)
    for place, key in keys.items():
        assert key not in said, (place, said)
    assert target_shown(target) in said and f"api_key={SHOWN}" in said and f"sid={SHOWN}" in said, said
    # A plain word a value happens to be is not withheld on its own: the words a scan's
    # record is read by (a severity, a row's type) are left as they are.
    assert target_said("severity critical", target) == "severity critical"
    assert target_said(None, target) is None and target_said({"a": 1}, target) == {"a": 1}
    assert target_said("nothing to withhold", "") == "nothing to withhold"


def test_a_value_that_is_a_word_the_record_is_read_by_never_rewrites_the_verdict():
    """The SAFETY of the verdict: a tenant's ``?level=critical`` (or a ``;param`` of
    ``scan_incomplete``) must not withhold the severity or the marker a verdict is
    read from, in the copy of the answer kept for a reader."""
    from django.contrib.auth import get_user_model

    from pentest.models import PentestScan
    from pentest.views import _without_target_login

    scan = PentestScan(
        user=get_user_model()(username="x"),
        target_url="https://host.example/a;m=scan_incomplete?level=critical&x=informational",
    )
    answer = {"results": [{"type": "finding", "severity": "critical", "title": "t"},
                          {"type": "scan_incomplete", "internal": True}]}
    kept = _without_target_login(scan, answer)
    assert kept == answer
    assert PentestScan.derive_verdict(kept) is None  # still read as an incomplete run


# ---------------------------------------------------------------------------
# The tripwire: a key planted in every place, walked through every shown site
# ---------------------------------------------------------------------------


def _keys() -> dict[str, str]:
    return {place: f"cnry{place}{secrets.token_hex(10)}" for place in PLACES}


def _standard_target(keys) -> str:
    return (
        f"https://scanner:{keys['login']}@offline.invalid/app;jsessionid={keys['param']}/login"
        f"?api_key={keys['query']}&page=2#{keys['fragment']}"
    )


def _llm_target(keys) -> str:
    return (
        f"https://bot:{keys['login']}@llm.invalid/v1;session={keys['param']}/chat"
        f"?api_key={keys['query']}#{keys['fragment']}"
    )


def _echoes(target, keys) -> list[dict]:
    """Findings that quote the target back whole and each key on its own."""
    return [
        {"type": "finding", "title": "reflected target", "severity": "high",
         "evidence": f"the scanner reached {target}", "location": target, "details": f"GET {target}"},
        {"type": "finding", "title": "keys in the clear", "severity": "medium",
         "evidence": " ".join(f"{place} {key}" for place, key in keys.items()),
         "details": " ".join(keys.values())},
    ]


class _Weasy:
    """A weasyprint stub: the Mythos renderer's HTML is kept, and its PDF is a stub."""

    def __init__(self):
        self.docs: list[str] = []
        stub = types.ModuleType("weasyprint")
        docs = self.docs

        class HTML:
            def __init__(self, string=None, base_url=None):
                docs.append(string)

            def write_pdf(self):
                return b"%PDF-1.4 stub"

        stub.HTML = HTML
        self.module = stub


@pytest.fixture
def world(no_environment_proxy, monkeypatch, tmp_path, settings, caplog, mailoutbox, db):  # noqa: F811 - mailoutbox: the locmem backend
    from django.contrib.auth import get_user_model
    from django.utils import timezone

    from pentest.models import Engagement

    settings.MEDIA_ROOT = str(tmp_path / "media")
    caplog.set_level(logging.DEBUG)
    # The test-only allowlist: the scope guard lets these hosts through, and logs it.
    monkeypatch.setenv("ATHENA_PENTEST_TEST_TARGETS", "offline.invalid,llm.invalid")
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    User = get_user_model()
    analyst = User.objects.create_user(username="analyst", password=None, role="analyst")
    now = timezone.now()
    engagement = Engagement.objects.create(
        created_by=analyst, name="Client Q3", status="running", scope_hosts=["offline.invalid", "llm.invalid"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )
    admin = User.objects.create_superuser(username="root", email="root@example.com", password=None)
    return types.SimpleNamespace(analyst=analyst, admin=admin, engagement=engagement, caplog=caplog)


def _outbox() -> list:
    """What was mailed (the locmem backend's outbox, read when it is needed: the list
    is replaced as mail is sent)."""
    from django.core import mail

    return list(mail.outbox)


def _api(user):
    from rest_framework.test import APIClient

    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _with_engine(answer, run):
    from django.test import override_settings

    engine = Recorder(answer=answer)
    try:
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnryenginekey"):
            return engine, run()
    finally:
        engine.close()


def _shown_sites(world, scan) -> dict[str, object]:
    """Every site that shows ``scan``, by name."""
    from django.template import Context, Template
    from django.test import Client
    from django.urls import reverse

    from pentest.models import PentestScan
    from pentest.utils import render_scan_pdf_bytes

    scan.refresh_from_db()
    api = _api(world.analyst)
    sites: dict[str, object] = {
        "api.detail": api.get(f"/api/pentest/scans/{scan.uuid}/").content,
        "api.list": api.get("/api/pentest/scans/").content,
        "str(scan)": str(scan),
        "error_message": scan.error_message or "",
        "engine_response": scan.engine_response,
        "template.scan_report": Template(
            (ROOT / "pentest" / "templates" / "scan_report.html").read_text(encoding="utf-8")
        ).render(Context({"scan": scan})),
    }
    if scan.status == PentestScan.STATUS_COMPLETED:
        sites["api.pdf"] = _pdf_texts(api.get(f"/api/pentest/scans/{scan.uuid}/pdf/").content)
        sites["report.reportlab"] = _pdf_texts(render_scan_pdf_bytes(scan))
        sites["report.mythos"] = _mythos_html(scan, {"client": "Client Q3"})
        if scan.pdf_file:
            with scan.pdf_file.open("rb") as stored:
                sites["media.pdf"] = _pdf_texts(stored.read())
    admin = Client()
    admin.force_login(world.admin)
    for name, url in (("admin.changelist", reverse("admin:pentest_pentestscan_changelist")),
                      ("admin.change", reverse("admin:pentest_pentestscan_change", args=[scan.pk]))):
        page = admin.get(url)
        assert page.status_code == 200, (name, page.status_code)
        sites[name] = page.content
    # The walk is not vacuous: each site that names the target shows it, as shown.
    host = scan.target_shown.split("@")[-1].split("/")[0]
    for name in ("api.detail", "api.list", "str(scan)", "template.scan_report", "admin.changelist",
                 "admin.change", "report.mythos", "report.reportlab", "api.pdf", "media.pdf"):
        if name in sites:
            seen = sites[name]
            text = seen.decode("utf-8", "replace") if isinstance(seen, bytes) else "".join(map(str, seen)) \
                if isinstance(seen, list) else str(seen)
            assert host in text, (name, host)
    return sites


def _mythos_html(scan, context) -> list[str]:
    """The Mythos renderer's HTML for ``scan``, through a weasyprint stub; the module
    imported for it is taken out again, so no later test renders through the stub."""
    weasy = _Weasy()
    name = "pentest.report_mythos"
    before_module, before_weasy = sys.modules.get(name), sys.modules.get("weasyprint")
    sys.modules["weasyprint"] = weasy.module
    sys.modules.pop(name, None)
    try:
        importlib.import_module(name).render_scan_pdf_bytes_html(scan, context=context)
    finally:
        sys.modules.pop(name, None)
        sys.modules.pop("weasyprint", None)
        if before_module is not None:
            sys.modules[name] = before_module
        if before_weasy is not None:
            sys.modules["weasyprint"] = before_weasy
    return weasy.docs


def _everything_else(world) -> dict[str, object]:
    """The log, the e-mail, and every row of every model but the scan's ``target_url``."""
    from django.apps import apps

    from pentest.models import PentestScan

    sites: dict[str, object] = {
        "log": world.caplog.text + "".join(
            f"{record.getMessage()} {record.exc_text or ''}" for record in world.caplog.records
        ),
    }
    for i, message in enumerate(_outbox()):
        sites[f"mail[{i}].subject"] = message.subject
        sites[f"mail[{i}].body"] = message.body
        sites[f"mail[{i}].message"] = message.message().as_string()
        for j, (_name, content, _type) in enumerate(message.attachments):
            sites[f"mail[{i}].attachment[{j}]"] = _pdf_texts(content)
    for model in apps.get_models():
        rows = model.objects.values()
        if model is PentestScan:
            rows = rows.values(*[f.attname for f in model._meta.concrete_fields if f.attname != "target_url"])
        sites[f"db.{model._meta.label}"] = [dict(row) for row in rows]
    return sites


def _found(sites: dict[str, object], keys: dict[str, str]) -> list[tuple[str, str, str, str]]:
    needles = Needles(keys)
    hits = []
    for site, document in sites.items():
        if isinstance(document, (bytes, bytearray)):
            document = bytes(document).decode("utf-8", "replace")
        for origin, form, _digest, context in search(json.loads(json.dumps(document, default=repr)), needles):
            hits.append((site, origin, form, context))
    return hits


def _engine_payloads(engine, path) -> list[dict]:
    return [
        json.loads(body) for (method, seen, _h), body in zip(engine.seen, engine.bodies)
        if (method, seen) == ("POST", path)
    ]


def _standard_engine(target, keys, run_id):
    def answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/scan"):
            return 202, {"Content-Type": "application/json"}, json.dumps(
                {"run_id": run_id, "status_url": f"/api/scans/{run_id}", "target": target}
            ).encode()
        if path == f"/api/scans/{run_id}":
            return 200, {"Content-Type": "application/json"}, json.dumps({
                "run_id": run_id, "state": "completed", "done": True,
                "result": {"target": target, "results": _echoes(target, keys)},
            }).encode()
        return 404, {}, b"{}"

    return answer


def _quoting_refusal(method, path, headers, body):
    """An engine refusing whatever it is sent with a page quoting the request back."""
    page = {"detail": "upstream error", "request": {"path": path, "body": body.decode("utf-8", "replace")}}
    return 500, {"Content-Type": "application/json"}, json.dumps(page).encode()


def _assert_shown_nowhere(sites, keys):
    hits = _found(sites, keys)
    assert hits == [], "\n".join(f"{site}: {origin} as {form}: {context}" for site, origin, form, context in hits)


def test_a_standard_scan_shows_no_key_its_target_carries(world):
    from pentest.models import PentestScan

    keys = _keys()
    target = _standard_target(keys)
    run_id = f"run-{secrets.token_hex(4)}"
    api = _api(world.analyst)

    def launch():
        return api.post(
            "/api/pentest/scan/",
            {"url": target, "consent": True, "engagement_id": world.engagement.pk,
             "recipient_email": "client@example.com"},
            format="json",
        )

    engine, launched = _with_engine(_standard_engine(target, keys, run_id), launch)
    assert launched.status_code == 200, launched.content
    scan = PentestScan.objects.get(uuid=launched.json()["scan_id"])
    assert scan.status == PentestScan.STATUS_COMPLETED and scan.engine_run_id == run_id
    assert len(_outbox()) == 1 and "offline.invalid" in _outbox()[0].subject, "the report was not mailed"
    # The engine was sent the URL the scan was launched with, every key in it.
    assert [payload["target"] for payload in _engine_payloads(engine, "/api/scan")] == [target]
    assert scan.target_url == target, "the launch URL is kept as it was"

    sites = {"api.launch": launched.content, **_shown_sites(world, scan), **_everything_else(world)}
    assert "allowlist" in sites["log"], "the scope guard's log line was not walked"
    _assert_shown_nowhere(sites, keys)


def test_a_standard_scan_the_engine_refuses_quoting_its_target_shows_no_key(world):
    from pentest.models import PentestScan

    keys = _keys()
    target = _standard_target(keys)
    api = _api(world.analyst)
    engine, launched = _with_engine(_quoting_refusal, lambda: api.post(
        "/api/pentest/scan/", {"url": target, "consent": True, "engagement_id": world.engagement.pk},
        format="json",
    ))
    assert launched.status_code == 502, launched.content
    assert [payload["target"] for payload in _engine_payloads(engine, "/api/scan")] == [target]
    scan = PentestScan.objects.get(uuid=launched.json()["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED and "upstream error" in scan.error_message
    _assert_shown_nowhere({"api.launch": launched.content, **_shown_sites(world, scan), **_everything_else(world)}, keys)


def test_a_reconciled_scan_shows_no_key_its_target_carries(world):
    """A launch whose answer was lost, sent again by the reconcile: the reconcile's
    answer is the copy kept for a reader, and the engine is sent the URL unchanged."""
    import uuid

    from pentest.models import PentestScan

    keys = _keys()
    target = _standard_target(keys)
    run_id = f"run-{secrets.token_hex(4)}"
    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(), user=world.analyst, engagement=world.engagement, target_url=target,
        consent=True, status=PentestScan.STATUS_UNKNOWN,
    )
    admin_api = _api(world.admin)
    engine, reconciled = _with_engine(
        _standard_engine(target, keys, run_id),
        lambda: admin_api.post(f"/api/pentest/scans/{scan.uuid}/reconcile/", {}, format="json"),
    )
    assert reconciled.status_code == 200, reconciled.content
    assert [payload["target"] for payload in _engine_payloads(engine, "/api/scan")] == [target]
    _assert_shown_nowhere(
        {"api.reconcile": reconciled.content, **_shown_sites(world, scan), **_everything_else(world)}, keys
    )


def test_a_failed_mailing_quoting_the_target_shows_no_key(world, monkeypatch):
    from pentest.models import PentestScan

    keys = _keys()
    target = _standard_target(keys)

    def refuse(scan, pdf_bytes, recipient_email, from_email=None):
        raise RuntimeError(f"the relay refused a report about {scan.target_url}")

    monkeypatch.setattr("pentest.views.send_pentest_scan_email", refuse)
    api = _api(world.analyst)
    engine, launched = _with_engine(_standard_engine(target, keys, "run-mail"), lambda: api.post(
        "/api/pentest/scan/",
        {"url": target, "consent": True, "engagement_id": world.engagement.pk, "recipient_email": "c@example.com"},
        format="json",
    ))
    assert [payload["target"] for payload in _engine_payloads(engine, "/api/scan")] == [target]
    scan = PentestScan.objects.get(uuid=launched.json()["scan_id"])
    assert scan.error_message.startswith("Email failed: the relay refused"), scan.error_message
    _assert_shown_nowhere({"api.launch": launched.content, **_shown_sites(world, scan), **_everything_else(world)}, keys)


def _llm_engine(target, keys):
    def answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/llm-scan"):
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"target": target, "base_url": target, "results": _echoes(target, keys)}
            ).encode()
        return 404, {}, b"{}"

    return answer


def _launch_llm(world, target, **extra):
    api = _api(world.analyst)
    return lambda: api.post(
        "/api/pentest/llm-scan/",
        {"base_url": target, "consent": True, "engagement_id": world.engagement.pk, "adapter": "openai_style",
         "model": "m-1", "attacks": [], "max_turns": 2, **extra},
        format="json",
    )


def test_an_llm_scan_shows_no_key_its_target_carries(world):
    from pentest.models import PentestScan

    keys = _keys()
    target = _llm_target(keys)
    engine, launched = _with_engine(_llm_engine(target, keys), _launch_llm(world, target, recipient_email="c@example.com"))
    assert launched.status_code == 200, launched.content
    scan = PentestScan.objects.get(uuid=launched.json()["scan_id"])
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert len(_outbox()) == 1 and "llm.invalid" in _outbox()[0].subject, "the report was not mailed"
    # The engine was sent the endpoint as given, every key in it.
    assert [payload["base_url"] for payload in _engine_payloads(engine, "/api/llm-scan")] == [target]
    sites = {"api.launch": launched.content, **_shown_sites(world, scan), **_everything_else(world)}
    assert "allowlist" in sites["log"], "the scope guard's log line was not walked"
    _assert_shown_nowhere(sites, keys)


@pytest.mark.parametrize("how", ["refused", "error"])
def test_an_llm_scan_the_engine_refuses_quoting_its_target_shows_no_key(world, how):
    from pentest.models import PentestScan

    keys = _keys()
    target = _llm_target(keys)

    def said_error(method, path, headers, body):
        # A 200 that refuses, quoting the target and its key back (engine_refused).
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"error": f"policy refused {target} (api_key {keys['query']})", "results": []}
        ).encode()

    engine, launched = _with_engine(_quoting_refusal if how == "refused" else said_error, _launch_llm(world, target))
    assert launched.status_code == 502, launched.content
    assert [payload["base_url"] for payload in _engine_payloads(engine, "/api/llm-scan")] == [target]
    scan = PentestScan.objects.get(uuid=launched.json()["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED
    _assert_shown_nowhere({"api.launch": launched.content, **_shown_sites(world, scan), **_everything_else(world)}, keys)


def test_a_caller_s_report_target_is_shown_as_the_scan_s(world):
    """The Mythos renderer takes a caller's ``context["target"]`` over the scan's: it is
    shown the same way."""
    from pentest.models import PentestScan

    keys = _keys()
    target = _standard_target(keys)
    scan = PentestScan.objects.create(
        user=world.analyst, target_url="https://plain.example/", consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response={"results": []},
    )
    _assert_shown_nowhere({"report.mythos": _mythos_html(scan, {"target": target})}, keys)
    assert "Acme Payments API" in "".join(_mythos_html(scan, {"target": "Acme Payments API"}))
