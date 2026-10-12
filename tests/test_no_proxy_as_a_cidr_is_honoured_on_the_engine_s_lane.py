"""``NO_PROXY`` is honoured on the engine's lane the way ``requests`` honours it:
an entry that is a CIDR block bypasses the proxy for every IP inside it, and a bare
suffix for every host that ends with it (``safety.outbound._proxies_for``, now
``requests.utils.should_bypass_proxies``).

The review's case: an engine on ``127.0.0.1`` named by ``NO_PROXY=127.0.0.0/8`` while
``HTTP_PROXY`` points at a proxy that cannot carry it. ``urllib``'s ``proxy_bypass``
matched a CIDR against neither the address nor the host, so the engine was dialled
through the proxy all the same -- the proxy answered 502, the Stop failed, and it
stayed owed. Now the block is honoured, the engine is reached directly, and the Stop
is delivered.
"""

from __future__ import annotations

import contextlib
import io

import pytest

from safety import outbound
from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    _ABORT,
    Recorder,
    _proxy_environment,
    _stops_at,
)


# --------------------------------------------------------------------------- #
# The bypass decision alone, no network: a CIDR block and a bare suffix, read
# the way requests reads them.
# --------------------------------------------------------------------------- #

_PROXIES = {"http": "http://egress.invalid:3128", "https": "http://egress.invalid:3128"}

_BYPASS_CASES = [
    # NO_PROXY, url, whether the proxy is bypassed (so _proxies_for returns {}).
    ("10.0.0.0/8", "http://10.1.2.3/x", True),
    ("10.0.0.0/8", "http://10.255.255.254:8000/scan", True),
    ("10.0.0.0/8", "http://11.1.2.3/x", False),
    ("ine.corp.test", "http://machine.corp.test/x", True),
    ("ine.corp.test", "http://machine.corp.test:8443/api/scan", True),
    ("ine.corp.test", "http://other.test/x", False),
]


@pytest.mark.parametrize(("no_proxy", "url", "bypassed"), _BYPASS_CASES)
def test_the_bypass_decision_matches_requests_for_a_cidr_and_a_suffix(no_proxy, url, bypassed, monkeypatch):
    for variable in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(variable, no_proxy)
    decided = outbound._proxies_for(url, dict(_PROXIES))
    assert decided == ({} if bypassed else dict(_PROXIES)), (no_proxy, url, decided)


# --------------------------------------------------------------------------- #
# The review's case, through deliver_owed_stops.
# --------------------------------------------------------------------------- #


def _proxy_that_cannot_carry_the_engine():
    """A proxy that answers 502 to everything: if the engine is dialled through it, the
    Stop fails. It must never be dialled -- NO_PROXY names the engine's block."""
    return Recorder(answer=lambda method, path, headers, body: (502, {"Content-Type": "application/json"}, b"{}"))


@pytest.mark.django_db
def test_a_stop_to_an_engine_in_a_no_proxy_block_is_delivered_directly(monkeypatch):
    """HTTP_PROXY points at a 502 proxy; NO_PROXY=127.0.0.0/8 names the engine's block;
    the engine is on 127.0.0.1. The owed Stop is delivered directly -- never through the
    proxy -- and ``deliver_owed_stops`` clears it."""
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.core.management.base import CommandError
    from django.test import override_settings
    from django.utils import timezone

    from pentest.models import PentestScan

    engine = Recorder(answer=_stops_at(_ABORT))  # the engine on 127.0.0.1, answering the abort
    proxy = _proxy_that_cannot_carry_the_engine()
    _proxy_environment(monkeypatch, proxy.base, no_proxy="127.0.0.0/8")

    analyst = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True,
        status=PentestScan.STATUS_PENDING, engine_run_id="run-1",
    )
    PentestScan.objects.filter(pk=scan.pk).update(stop_requested_at=timezone.now(), stop_delivered_at=None)
    try:
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            # At the base the block is not honoured, the proxy 502s the Stop, and it stays
            # owed so the command exits non-zero; the delivery assert below is the real check.
            with contextlib.suppress(CommandError):
                call_command("deliver_owed_stops", stdout=io.StringIO(), stderr=io.StringIO())
    finally:
        engine.close()
        proxy.close()

    scan.refresh_from_db()
    assert scan.stop_delivered_at is not None, scan.stop_detail
    assert proxy.seen == [], f"the Stop went through the proxy, which NO_PROXY named off: {proxy.seen}"
    assert [p for _m, p, _h in engine.seen] == [_ABORT], engine.seen
