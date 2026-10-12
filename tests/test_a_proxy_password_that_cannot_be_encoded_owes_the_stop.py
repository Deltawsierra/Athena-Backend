"""A proxy password that ``requests`` cannot encode, and one owed scan's delivery
raising, both keep a Stop owed and sent again -- never a 500 out of the stop route,
and never the other owed scans held back.

- A non-latin-1 password in ``HTTP_PROXY``'s userinfo makes ``requests`` raise
  ``UnicodeEncodeError`` -- not a ``RequestException`` -- while it builds the proxy's
  ``Proxy-Authorization`` header, before anything is sent. ``safety.outbound`` now
  treats a failure to prepare or send as a failed send: it is quieted, withheld, and
  raised as a ``RequestException`` the engine client reads as unreachable, so the
  Stop route answers 202 (owed, retried), never 500, and the password is said
  nowhere.
- ``deliver_owed_stops`` delivers every other owed scan even when one scan's delivery
  raises: it logs the class alone, keeps that scan owed, and carries on.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging

import pytest

from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    Recorder,
    _proxy_environment,
)

#: The userinfo as it stands in HTTP_PROXY (percent-encoded) and as requests decodes
#: it before trying to encode it latin-1 and raising. The euro sign is outside latin-1.
_ENCODED_PW = "cnry%E2%82%ACpw"
_DECODED_PW = "cnry€pw"


@pytest.mark.django_db
def test_a_non_latin1_proxy_password_owes_the_stop_and_never_500s(monkeypatch, caplog):
    from django.contrib.auth import get_user_model
    from django.test import override_settings
    from rest_framework.test import APIClient

    from pentest.models import PentestScan

    proxy_url = f"http://egress:{_ENCODED_PW}@127.0.0.1:1"
    # The engine is reached through the proxy (NO_PROXY empty), so building the proxy's
    # auth from the password that will not encode fails before anything is sent.
    _proxy_environment(monkeypatch, proxy_url, no_proxy="")

    analyst = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True,
        status=PentestScan.STATUS_PENDING, engine_run_id="run-1",
    )
    client = APIClient(raise_request_exception=False)
    client.force_authenticate(user=analyst)
    with caplog.at_level(logging.DEBUG), override_settings(
        CYBERENGINE_URL="http://engine.invalid:8000", CYBERENGINE_OPERATOR_KEY="cnrystopkey"
    ):
        answer = client.post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")

    assert answer.status_code == 202, answer.content  # owed, retried -- never 500
    scan.refresh_from_db()
    assert scan.stop_delivered_at is None, scan.stop_detail
    text = answer.content.decode("utf-8", "replace") + caplog.text + (scan.stop_detail or "")
    for form in (_DECODED_PW, _ENCODED_PW, f"egress:{_DECODED_PW}", f"egress:{_ENCODED_PW}"):
        assert form not in text, f"the proxy password was said: {form!r}"


def _engine_stopping_any_run():
    """An engine that records the stop of whatever run it is asked about."""
    def answer(method, path, headers, body):
        if method == "POST" and path.startswith("/api/scans/") and path.endswith("/abort"):
            run_id = path.removeprefix("/api/scans/").removesuffix("/abort")
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"run_id": run_id, "state": "aborted", "recorded": True, "reason": "operator stop"}
            ).encode()
        return 404, {}, b"{}"
    return answer


@pytest.mark.django_db
def test_one_owed_scans_delivery_raising_does_not_hold_back_the_others(monkeypatch):
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.test import override_settings
    from django.utils import timezone

    from pentest.management.commands import deliver_owed_stops as command
    from pentest.models import PentestScan

    analyst = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    first, second = (
        PentestScan.objects.create(
            user=analyst, target_url="https://offline.invalid/", consent=True,
            status=PentestScan.STATUS_PENDING, engine_run_id=run_id,
        )
        for run_id in ("run-first", "run-second")
    )
    for scan in (first, second):
        PentestScan.objects.filter(pk=scan.pk).update(stop_requested_at=timezone.now(), stop_delivered_at=None)

    secret = "cnryraise" + "0123456789ab"  # pragma: allowlist secret
    real = command.deliver_owed_stop

    def flaky(scan, client):
        if scan.pk == first.pk:
            raise RuntimeError(f"a delivery broke, quoting {secret}")
        return real(scan, client)

    monkeypatch.setattr(command, "deliver_owed_stop", flaky)

    engine = Recorder(answer=_engine_stopping_any_run())
    out, err = io.StringIO(), io.StringIO()
    try:
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            # The command exits non-zero while any Stop is still owed (the first stays
            # owed); at the base the first's raise escapes and the second is never reached.
            with contextlib.suppress(Exception):
                call_command("deliver_owed_stops", stdout=out, stderr=err)
    finally:
        engine.close()

    first.refresh_from_db()
    second.refresh_from_db()
    assert second.stop_delivered_at is not None, "the second owed Stop was held back by the first's raise"
    assert first.stop_delivered_at is None, "the first scan should stay owed"
    assert secret not in (out.getvalue() + err.getvalue()), "the raising delivery's text was written out"
