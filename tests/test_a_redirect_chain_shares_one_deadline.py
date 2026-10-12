"""The engine's lane follows a redirect up to ``ENGINE_REDIRECT_HOPS`` times, and the
whole chain shares ONE deadline -- the call's timeout as a total, each hop given the
time left (``safety.outbound._send``, ``_chain_deadline``).

Each hop used to get the full timeout of its own, so a Stop through three hops could
take four times the connect-plus-read (~252 s at the default ``(3.05, 60)``). Now the
chain finishes, or fails and leaves the Stop owed, within one call's budget. This is
tested on a fake clock a redirecting engine advances each hop, with no wall-clock
sleeps: the engine client (a real Stop) and a bare ``outbound.post`` on the engine's
lane -- which is exactly what the defender gateway also calls -- are both held to it.
"""

from __future__ import annotations

import pytest
import requests

from ai_engine.services import cyberengine_client as cec
from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError
from safety import outbound
from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    _ABORT,
    _STOPPED,
    Recorder,
    no_environment_proxy,  # noqa: F401 - a fixture
)

#: A short budget so the whole chain is a few fake seconds. ENGINE_TIMEOUT is
#: (connect, read); _chain_deadline sums them, so the chain's budget is 5.0.
_TIMEOUT = (1.0, 4.0)
_BUDGET = sum(_TIMEOUT)


class Clock:
    """A fake monotonic clock a test advances by hand. The engine's redirecting server
    advances it each hop, so a chain's cost is deterministic and needs no real sleep."""

    def __init__(self, start=10_000.0):
        self.now = start

    def monotonic(self):
        return self.now

    def advance(self, dt):
        self.now += dt


def _redirecting_engine(clock, per_hop, hops=3):
    """An engine whose abort route redirects ``hops`` times on its own host (same host,
    307, a path each time) before it answers the Stop, advancing ``clock`` each request
    so a hop 'takes' ``per_hop`` of the shared budget. The final hop answers _STOPPED."""
    chain = [_ABORT, *[f"{_ABORT}/{n}" for n in range(1, hops + 1)]]
    nxt = {here: chain[i + 1] for i, here in enumerate(chain[:-1])}

    def answer(method, path, headers, body):
        clock.advance(per_hop)
        if path in nxt:
            return 307, {"Location": nxt[path]}, b""
        return _STOPPED  # the end of the chain: the engine records the stop

    return answer


@pytest.mark.django_db
def test_a_stop_through_a_redirect_chain_finishes_within_one_call_s_budget(no_environment_proxy, monkeypatch):  # noqa: F811
    """Fast redirects: the three-hop chain completes and the Stop lands, the whole chain
    inside one call's budget rather than once per hop."""
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", _TIMEOUT)
    clock = Clock()
    monkeypatch.setattr(outbound, "time", clock, raising=False)
    engine = Recorder(answer=_redirecting_engine(clock, per_hop=0.1))
    start = clock.now
    try:
        said = CyberEngineClient(engine.base, "cnrystopkey").abort_scan("run-1", "operator stop")
    finally:
        engine.close()
    assert said["stopped"] is True, said
    assert len(engine.seen) == 4, engine.seen  # three redirects, then the Stop
    assert clock.now - start <= _BUDGET, clock.now - start


@pytest.mark.django_db
def test_a_redirect_chain_that_overruns_the_shared_deadline_fails_within_it(no_environment_proxy, monkeypatch):  # noqa: F811
    """Slow redirects: each hop eats half the budget, so the shared deadline runs out
    mid-chain. The call fails -- a Stop is then owed and sent again -- and the whole
    chain still fits inside one call's budget, not four hops' worth of it."""
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", _TIMEOUT)
    clock = Clock()
    monkeypatch.setattr(outbound, "time", clock, raising=False)
    engine = Recorder(answer=_redirecting_engine(clock, per_hop=_BUDGET / 2))
    start = clock.now
    try:
        with pytest.raises(EngineError):
            CyberEngineClient(engine.base, "cnrystopkey").abort_scan("run-1", "operator stop")
    finally:
        engine.close()
    # Cut off mid-chain, not run to all four requests.
    assert len(engine.seen) < 4, engine.seen
    assert clock.now - start <= _BUDGET, clock.now - start


def test_the_shared_deadline_is_in_outbound_so_every_engine_lane_call_shares_it(no_environment_proxy, monkeypatch):  # noqa: F811
    """The gateway (``audit.middleware``) and the engine client both reach the engine
    through ``outbound.post(engine=True)``, so the one deadline is enforced there: a
    slow redirect chain raises a timeout within the budget, having sent fewer than the
    full set of hops."""
    clock = Clock()
    monkeypatch.setattr(outbound, "time", clock, raising=False)
    engine = Recorder(answer=_redirecting_engine(clock, per_hop=_BUDGET / 2))
    start = clock.now
    try:
        with pytest.raises(requests.exceptions.RequestException):
            outbound.post(
                f"{engine.base}{_ABORT}", json={}, headers={"X-API-Key": "k"},
                timeout=_TIMEOUT, engine=True,
            )
    finally:
        engine.close()
    assert len(engine.seen) < 4, engine.seen
    assert clock.now - start <= _BUDGET, clock.now - start
