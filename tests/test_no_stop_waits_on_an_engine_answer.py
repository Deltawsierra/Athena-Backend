"""Round 5 (E1/E2): no stop waits on the parsing of an engine answer.

Round 4 put a nesting-depth check in front of every engine answer the client
parses (``cyberengine_client._nesting_depth``): a body nested past any answer
raised RecursionError straight past every reader. The check stripped strings with
the regex ``"(?:[^"\\\\]|\\\\.)*"`` first. On a body cut off inside a string that
carries escaped quotes -- a truncated finding whose evidence is a captured page,
``<a href=\\"...\\">`` -- every escaped quote started a match that ran to the end
and failed: quadratic, and ``re.sub`` held the GIL throughout. The lead measured,
on c59045b:

- the check alone at 4/8/16/32 KB: 86/298/1181/5168 ms; ``run_scan`` on a
  truncated 8/16/32/64 KB answer: 144/504/2086/9035 ms, where ``json.loads``
  rejects each in under 0.4 ms;
- ``GET /api/failsafe/state/`` -- a stop-lane read with a 2 s deadline, which waits
  for the engine on a thread of its own -- answered in 12,716 ms behind a 62 KB
  truncated state answer: its own ``done.wait(2.0)`` could not return while the
  regex held the GIL;
- a contradiction issued 100 ms after another thread of the worker began reading a
  truncated 62 KB answer completed 12,670 ms late (46 ms alone).

The check is now one linear pass -- a character scanner tracking string and escape
state and bracket depth, stopping at the depth limit -- over at most
``MAX_PARSE_BODY`` bytes (a longer answer is unreadable, never scanned or parsed),
and the stop-lane read is bounded by ``MAX_STOP_LANE_BODY``.
"""

from __future__ import annotations

import json
import threading
import time

import pytest
import requests
from django.test import override_settings

from ai_engine.services import cyberengine_client as cec
from ai_engine.services.cyberengine_client import ENGINE_UNREADABLE, CyberEngineClient, EngineError
from assurance.models import AssuranceClaim
from tests.test_every_writer_decides_from_the_row_it_writes import _client, _deployment, _person
from tests.test_spine_evidence_audit import _access_claim, _current

Status = AssuranceClaim.ClaimStatus

KB = 1024
#: What the depth check may cost on any of the adversary's shapes at 64 KB.
BOUND_MS = 50.0


def _captured_page(size):
    """A finding cut off inside its evidence string, a captured page full of escaped
    quotes: the shape the regex went quadratic on (round 5, E1)."""
    captured = '<a href=\\"https://t.example/p\\" class=\\"x\\">' * (size // 44)
    return (
        '{"answer": "status", "run_id": "r-1", "done": true, "state": "completed", '
        '"result": {"findings": [{"evidence": "' + captured
    )


def _state_note(size):
    """The failsafe state answer cut off inside a note of escaped quotes (E2)."""
    return '{"enabled": true, "engine_id": "e1", "state": "running", "note": "' + '<a href=\\"x\\">' * (size // 14)


#: The adversary's worst shapes, each 64 KB, each cut off inside a string.
SHAPES = {
    "a truncated finding whose evidence is a captured page": _captured_page(64 * KB),
    "a truncated failsafe state note of escaped quotes": _state_note(64 * KB),
    "an unterminated string of nothing but escaped quotes": '{"note": "' + '\\"' * (32 * KB),
    "an unterminated string ending in a lone backslash": '{"note": "' + "x" * (64 * KB) + "\\",
}


def _response(status, text, headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp._content = text.encode("utf-8")
    resp.encoding = "utf-8"
    resp.headers["Content-Type"] = "application/json"
    for name, value in (headers or {}).items():
        resp.headers[name] = value
    return resp


def _best_ms(fn, runs=3):
    best = None
    for _ in range(runs):
        started = time.perf_counter()
        fn()
        took = (time.perf_counter() - started) * 1000
        best = took if best is None else min(best, took)
    return best


# ---------------------------------------------------------------------------
# 1. The depth check is one linear pass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_depth_check_takes_under_50_ms_on_every_adversary_shape_at_64_kb(shape):
    body = SHAPES[shape]
    assert len(body) >= 64 * KB

    took = _best_ms(lambda: cec._nesting_depth(body))

    assert took < BOUND_MS, f"the depth check took {took:.1f} ms on {shape}"


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_scan_answer_cut_off_inside_a_string_is_refused_as_unreadable_at_once(shape):
    """E1 end to end: ``run_scan`` on the cut-off answer, which ``json.loads`` rejects
    in well under a millisecond, took 9 s at 64 KB."""
    body = SHAPES[shape]
    engine = CyberEngineClient("http://engine.invalid", "k")
    engine._send_post = lambda path, payload: _response(200, body)

    def launch():
        with pytest.raises(EngineError) as raised:
            engine.run_scan("https://t.example")
        assert raised.value.kind == ENGINE_UNREADABLE

    took = _best_ms(launch)

    assert took < 4 * BOUND_MS, f"run_scan took {took:.1f} ms on {shape}"


def _true_depth(value) -> int:
    if isinstance(value, list):
        return 1 + max((_true_depth(v) for v in value), default=0)
    if isinstance(value, dict):
        return 1 + max((_true_depth(v) for v in value.values()), default=0)
    return 0


@pytest.mark.parametrize("text", [
    '{"a": [1, {"b": "]]]"}]}',
    '["\\"[", [[]]]',
    '{"x": "\\\\"}',
    '{"x": "\\\\\\"[[[["}',
    '[{"k": "{{{{"}, [[["}}}"]]]]',
    '"[[[["',
    "[" + ",".join(["[]"] * 100) + "]",
    "[" * 64 + "]" * 64,
])
def test_the_depth_check_counts_brackets_only_outside_strings_exactly_as_the_parser_nests(text):
    assert cec._nesting_depth(text) == _true_depth(json.loads(text))


def test_the_depth_check_stops_at_the_limit_and_says_it_was_passed():
    assert cec._nesting_depth("[" * 10_000) == cec.MAX_JSON_DEPTH + 1
    assert cec._nesting_depth("[" * 10_000, limit=3) == 4


@pytest.mark.parametrize("depth, readable", [(64, True), (65, False)])
def test_a_body_nested_one_level_past_the_limit_is_unreadable_and_one_at_it_is_read(depth, readable):
    """Killers C1 (no depth check, RecursionError still caught) and C3 (the limit
    raised to 1000): a body nested 65 deep parses without any RecursionError, so only
    the check refuses it."""
    resp = _response(200, "[" * depth + "]" * depth)
    if readable:
        assert cec._json_of(resp) is not None
        return
    with pytest.raises(ValueError, match="nests deeper"):
        cec._json_of(resp)
    engine = CyberEngineClient("http://engine.invalid", "k")
    engine._send_get = lambda path: resp
    with pytest.raises(EngineError) as raised:
        engine.assurance_measured()
    assert raised.value.kind == ENGINE_UNREADABLE


def test_an_answer_longer_than_the_parse_bound_is_unreadable_and_never_scanned(monkeypatch):
    """The bytes the check and the parser look at are bounded: an answer past
    ``MAX_PARSE_BODY`` is refused before either runs."""
    monkeypatch.setattr(cec, "MAX_PARSE_BODY", 4 * KB)
    scanned = []
    real = cec._nesting_depth
    monkeypatch.setattr(cec, "_nesting_depth", lambda text, *a, **k: scanned.append(len(text)) or real(text, *a, **k))
    body = json.dumps({"state": "running", "note": "x" * (8 * KB)})

    with pytest.raises(ValueError, match="past the"):
        cec._json_of(_response(200, body))
    assert scanned == []

    # At the bound it is read as always.
    small = json.dumps({"state": "running"})
    assert cec._json_of(_response(200, small)) == {"state": "running"}
    assert scanned == [len(small)]


# ---------------------------------------------------------------------------
# 2. The stop lane never waits on it
# ---------------------------------------------------------------------------


def _engine_answers(monkeypatch, body):
    monkeypatch.setattr(cec.requests, "get", lambda url, headers=None, timeout=None, **_: _response(200, body))


@pytest.mark.django_db
@override_settings(CYBERENGINE_URL="http://engine.invalid", CYBERENGINE_OPERATOR_KEY="k", FAILSAFE_STATE_ENGINE_SECONDS=2.0)
def test_the_failsafe_state_view_answers_within_its_deadline_behind_a_truncated_64_kb_state_answer(monkeypatch):
    """E2: the view waits for the engine on a thread of its own, at most its 2 s
    deadline. Behind a 62 KB truncated answer it answered in 12.7 s."""
    _engine_answers(monkeypatch, _state_note(64 * KB))
    admin = _client(_person("fs-admin"))

    started = time.perf_counter()
    response = admin.get("/api/failsafe/state/")
    took = time.perf_counter() - started

    assert response.status_code == 200
    assert took < 2.0, f"the stop-lane read took {took:.2f}s behind the engine's answer"
    assert response.json()["engine_state"] is None
    assert response.json()["engine_state_available"] is False


@pytest.mark.django_db
@override_settings(CYBERENGINE_URL="http://engine.invalid", CYBERENGINE_OPERATOR_KEY="k", FAILSAFE_STATE_ENGINE_SECONDS=2.0)
def test_a_failsafe_state_answer_past_the_stop_lane_bound_is_not_read(monkeypatch):
    """The governor's state is three fields: the stop lane parses no more than
    ``MAX_STOP_LANE_BODY`` of it, whatever else the answer carries."""
    _engine_answers(monkeypatch, json.dumps({
        "enabled": True, "engine_id": "e1", "state": "running", "note": "x" * (cec.MAX_STOP_LANE_BODY + 1),
    }))
    with pytest.raises(EngineError) as raised:
        CyberEngineClient.from_settings().failsafe_state()
    assert raised.value.kind == ENGINE_UNREADABLE

    _engine_answers(monkeypatch, json.dumps({"enabled": True, "engine_id": "e1", "state": "running"}))
    assert CyberEngineClient.from_settings().failsafe_state()["state"] == "running"


def _reading_a_truncated_answer_on_another_thread():
    """Another thread of the worker reads a truncated 64 KB scan answer, as E2's did.
    Returns (thread, started event)."""
    engine = CyberEngineClient("http://engine.invalid", "k")
    engine._send_post = lambda path, payload: _response(200, _captured_page(64 * KB))
    started = threading.Event()
    box = {}

    def read():
        started.set()
        try:
            engine.run_scan("https://t.example")
        except EngineError as exc:
            box["kind"] = exc.kind

    thread = threading.Thread(target=read, name="engine-reader", daemon=True)
    return thread, started, box


@pytest.mark.django_db
@override_settings(CYBERENGINE_URL="http://engine.invalid", CYBERENGINE_OPERATOR_KEY="k", FAILSAFE_STATE_ENGINE_SECONDS=2.0)
def test_the_failsafe_state_view_answers_within_its_deadline_while_another_thread_reads_a_truncated_answer(monkeypatch):
    _engine_answers(monkeypatch, json.dumps({"enabled": True, "engine_id": "e1", "state": "running"}))
    admin = _client(_person("fs-admin2"))
    admin.get("/api/failsafe/state/")  # warm
    thread, started, box = _reading_a_truncated_answer_on_another_thread()
    # Timed from the reader's start: the request is issued as soon as it runs (on
    # c59045b even this thread's wait on the start event sat behind the regex).
    began = time.perf_counter()
    thread.start()
    assert started.wait(5)
    response = admin.get("/api/failsafe/state/")
    took = time.perf_counter() - began
    thread.join(60)

    assert response.status_code == 200
    assert took < 2.0, f"the stop-lane read took {took:.2f}s while another thread parsed an engine answer"
    assert response.json()["engine_state"] == "running"
    assert box.get("kind") == ENGINE_UNREADABLE


@pytest.mark.django_db
def test_a_contradiction_issued_while_another_thread_reads_a_truncated_answer_lands_in_its_own_time():
    """E2: a contradiction issued 100 ms after another thread began reading a
    truncated 62 KB answer completed 12,670 ms late (46 ms alone)."""
    dep = _deployment("e2-stop")
    claim = _access_claim(dep)
    person = _client(_person("e2-stopper"))

    def contradict(target, note):
        began = time.perf_counter()
        response = person.post(
            f"/api/assurance/claims/{target.uuid}/transition/", {"to_status": "contradicted", "note": note},
            format="json",
        )
        return response, time.perf_counter() - began

    control = _access_claim(_deployment("e2-alone"))
    contradict(_access_claim(_deployment("e2-warm")), "warm")
    alone_response, alone = contradict(control, "alone")
    assert alone_response.status_code == 200

    thread, started, box = _reading_a_truncated_answer_on_another_thread()
    # Timed from the reader's start, as above.
    began = time.perf_counter()
    thread.start()
    assert started.wait(5)
    response, _own = contradict(claim, "stop")
    took = time.perf_counter() - began
    thread.join(60)

    assert response.status_code == 200, response.content
    assert took < 3 * alone + 0.25, f"the stop took {took * 1000:.0f} ms (alone {alone * 1000:.0f} ms)"
    assert _current(dep).status == Status.CONTRADICTED
    assert box.get("kind") == ENGINE_UNREADABLE
