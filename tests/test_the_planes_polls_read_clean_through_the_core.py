"""The engine poll reads clean through the core's own reader (AB-POLL-CONFORMANCE).

Mythos-Core#87 and #89 (pinned at 1de268c) define what one poll of this control plane
heard. ``mythos_core.failsafe.wire.poll_outcome`` reads an answer's status, its body and
the plane's two headers -- ``X-Failsafe-Unreadable``, how many of its own rows the plane
could not read, and ``X-Failsafe-In-Force``, the kinds of stop in force, a list of
distinct words of a closed set -- and answers one question, ``heard_clean``. Given the
HTTP client's own list of the header lines (``lines``: urllib3's, which
``PollingHTTPChannel.poll_heard`` passes as ``response.raw.headers``), either header sent
on more than one line is two values: unreadable, and the poll is not heard clean. The
core's vectors file says: "A control plane that sets the two headers, and a product that
reads a poll without this core, each hold themselves to the core with one test against
this file." This is this plane's.

1. The poll an engine makes (``/api/failsafe/pending/``) is answered over real HTTP: a
   live, threaded WSGI server (Django's, the one ``LiveServerTestCase`` runs) in front of
   ``config.wsgi.application``, the entry point a server calls, so the header lines the
   engine's client keeps apart are the lines the plane sent. In every state -- nothing in
   force; each of pause, stand_down and terminate; every two at once and all three; a
   stop whose row cannot be read; a page with starts on it; a poll without the token --
   the answer is read by ``poll_outcome`` with those lines, and: ``heard_clean``,
   ``in_force`` (strongest first) and ``unreadable`` are the state's; neither header is
   ever on more than one line; the in-force value is the core's own words, strongest
   first, exactly as the core gives them back; the count is always sent.
2. The vectors file's ``answers`` and ``lines`` cases, through the plane's own writers:
   ``failsafe.views._page_headers`` for the count, and the poll itself for the in-force
   value, over every set of stops it can name. Where a case says something the plane
   can mean, what the plane writes for it reads exactly as the case expects; where a
   case is a value the core cannot read, the plane never writes it.

Found on the way, and failing on master: a ready stop whose row could not be loaded at
all was counted in X-Failsafe-Unreadable and left out of X-Failsafe-In-Force, so a
terminate in force whose row could not be read was named nowhere an engine reads.
"""

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
import requests
import urllib3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.utils import timezone
from requests.structures import CaseInsensitiveDict

from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, _admin, _client_for, _wsgi_module
from tests.test_no_control_holds_back_a_stop import configure, rates  # noqa: F401 - fixtures, used by name

VECTORS = Path(__file__).resolve().parent / "vectors" / "poll-outcome-v1.json"
#: Byte for byte Mythos-Core's tests/vectors/poll-outcome-v1.json at the pin (1de268c).
VECTOR_SHA256 = "10d8bba14eab53f154975c65510f3f2c1c8ed950ae5ebb390ac73cb2e3d48ee8"
POLL = "/api/failsafe/pending/"
ENGINE = "conform-1"
U = "X-Failsafe-Unreadable"
F = "X-Failsafe-In-Force"
#: Every set of stops the poll can name, each signed weakest first here, so the order
#: the plane names them in is never the order they were made in.
STATES = [
    (),
    ("pause",),
    ("stand_down",),
    ("terminate",),
    ("pause", "stand_down"),
    ("pause", "terminate"),
    ("stand_down", "terminate"),
    ("pause", "stand_down", "terminate"),
]

pytestmark = pytest.mark.django_db(transaction=True)


def _wire():
    from mythos_core.failsafe import wire

    return wire


def _vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _strongest_first(stops) -> tuple:
    """The stops in the core's order, strongest first (wire.IN_FORCE_ORDER)."""
    return tuple(word for word in _wire().IN_FORCE_ORDER if word in stops)


def _said(outcome) -> dict:
    """An outcome in the vectors file's words."""
    return {
        "ended": outcome.ended,
        "status": outcome.status,
        "commands": len(outcome.commands),
        "unreadable": outcome.unreadable,
        "skipped": outcome.skipped,
        "in_force": list(outcome.in_force),
        "in_force_unreadable": outcome.in_force_unreadable,
        "truncated": outcome.truncated,
        "heard_clean": outcome.heard_clean,
    }


# ------------------------------------------------------------------------------- the plane


@pytest.fixture()
def keys(settings):
    made = {f"op{n}": Ed25519PrivateKey.generate() for n in range(2)}
    settings.FAILSAFE_OPERATOR_KEYS = {name: key.public_key().public_bytes_raw().hex() for name, key in made.items()}
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    return made


#: How far the plane's clock is ahead of the real one, in seconds.
_AHEAD = [0.0]


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Each draft one second after the one before it (_signed), so no two commands are
    drafted in one tick of a clock that ties: which came first is never luck."""
    real = timezone.now
    _AHEAD[0] = 0.0
    monkeypatch.setattr(timezone, "now", lambda: real() + timedelta(seconds=_AHEAD[0]))


@pytest.fixture()
def operator():
    return _client_for(_admin())


@pytest.fixture()
def plane(request, settings, monkeypatch):
    """The plane over real HTTP: Django's live server thread (a threaded WSGI server)
    serving ``config.wsgi.application``, with a handler built under this test's settings
    (``rates``: the poll token, the gateway answering at once) behind its wrapper, as
    tests/test_no_control_holds_back_a_stop.py serves the stops. An in-memory database is
    shared with the server thread, as LiveServerTestCase shares it."""
    from django.core.handlers.wsgi import WSGIHandler
    from django.db import connections
    from django.test.testcases import LiveServerThread

    request.getfixturevalue("rates")
    wsgi = _wsgi_module()
    monkeypatch.setattr(wsgi, "_application", WSGIHandler())
    # The wrapper starts the owed-dispatch sweeper on a request: not a thread to leave running.
    monkeypatch.setattr("assurance.dispatch.ensure_owed_sweeper", lambda: None)
    settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, "127.0.0.1"]
    shared = {conn.alias: conn for conn in connections.all() if conn.vendor == "sqlite" and conn.is_in_memory_db()}
    for conn in shared.values():
        conn.inc_thread_sharing()
    server = LiveServerThread("127.0.0.1", lambda _django: wsgi.application, connections_override=shared, port=0)
    server.daemon = True
    server.start()
    try:
        assert server.is_ready.wait(timeout=30), "the live server did not start"
        if server.error:
            raise server.error
        yield f"http://127.0.0.1:{server.port}"
    finally:
        server.terminate()
        for conn in shared.values():
            conn.dec_thread_sharing()


def _signed(operator, action, keys, engine=ENGINE):
    """Draft ``action`` and sign it into force through the API, as operators do."""
    _AHEAD[0] += 1.0
    drafted = operator.post("/api/failsafe/commands/", {"action": action, "engine_id": engine, "reason": ""},
                            format="json")
    assert drafted.status_code in (200, 201), drafted.content
    for name, key in keys.items():
        sig = key.sign(bytes.fromhex(drafted.data["signing_bytes"])).hex()
        answer = operator.post(f"/api/failsafe/commands/{drafted.data['uuid']}/signatures/",
                               {"key_id": name, "sig": sig}, format="json")
        assert answer.status_code == 200, answer.content
        if answer.data["status"] == "ready":
            return drafted.data
    raise AssertionError(f"{action} was not made ready: {answer.data}")


def _poll(plane, engine=ENGINE, token=POLL_TOKEN):
    """One poll as an engine's client makes it, over the wire, and what the core's own
    reader hears in it: the status, the body (from a 200 only, as the channel reads it),
    the joined headers and the client's own list of the lines, kept apart."""
    session = requests.Session()
    session.trust_env = False  # the loopback server itself, never a proxy from the environment
    try:
        response = session.get(plane + POLL, params={"engine_id": engine},
                               headers={"X-Failsafe-Poll-Token": token} if token else {}, timeout=30)
    finally:
        session.close()
    if "Content-Length" in response.headers:
        assert int(response.headers["Content-Length"]) == len(response.content), "the body arrived cut"
    body = response.text if response.status_code == 200 else ""
    outcome = _wire().poll_outcome(response.status_code, body, response.headers, truncated=False,
                                   lines=response.raw.headers)
    return response, outcome


def _holds(response, outcome, *, in_force, unreadable):
    """What every 200 the poll answers holds, read through the core."""
    wire = _wire()
    lines = response.raw.headers
    assert isinstance(lines, urllib3.HTTPHeaderDict), type(lines)
    for name in (U, F):
        assert len(lines.getlist(name)) <= 1, f"{name} was sent on {len(lines.getlist(name))} lines"
    # The count is always sent, on one line, as plain digits: "0" when there was none.
    assert lines.getlist(U) == [str(unreadable)], lines.getlist(U)
    sent = lines.getlist(F)
    if in_force:
        (value,) = sent
        words = [word.strip(" \t") for word in value.split(",")]
        assert set(words) <= wire.IN_FORCE_WORDS, f"{value!r} is not in the core's words"
        # Strongest first, one comma and a space between: exactly what the core gives back.
        assert value == ", ".join(outcome.in_force), value
    else:
        assert sent == [], f"nothing is in force and the poll says {sent}"
    assert (outcome.ended, outcome.status, outcome.truncated) == (wire.POLL_HEARD, 200, False)
    assert outcome.in_force == in_force and outcome.in_force_unreadable is False
    assert outcome.unreadable == unreadable
    # Every command served is read as one by the core: nothing skipped.
    assert outcome.skipped == 0 and len(outcome.commands) == len(response.json())
    assert [command.nonce for command in outcome.commands] == [doc["nonce"] for doc in response.json()]
    assert outcome.heard_clean is (unreadable == 0)


# ----------------------------------------------------------------- 1. every state, on the wire


@pytest.mark.parametrize("stops", STATES, ids=["nothing"] + ["+".join(state) for state in STATES[1:]])
def test_every_state_s_answer_reads_clean_through_the_core(stops, plane, keys, operator):
    """Nothing in force, each stop, every two at once and all three: heard clean, each
    stop named strongest first and served strongest first, nothing unreadable."""
    signed = {action: _signed(operator, action, keys) for action in stops}
    response, outcome = _poll(plane)
    assert response.status_code == 200, response.content[:300]
    expected = _strongest_first(stops)
    _holds(response, outcome, in_force=expected, unreadable=0)
    assert outcome.heard_clean is True
    assert [command.nonce for command in outcome.commands] == [signed[action]["nonce"] for action in expected]
    # Another engine's poll hears none of it, and is heard clean too.
    response, outcome = _poll(plane, "conform-another")
    _holds(response, outcome, in_force=(), unreadable=0)


@pytest.mark.parametrize("how", ["its_signatures_are_not_signatures", "it_cannot_be_loaded"])
def test_a_stop_whose_row_cannot_be_read_is_counted_and_still_named_in_force(how, plane, keys, operator, monkeypatch):
    """A ready terminate whose row the plane cannot read, beside a readable pause: the
    terminate is not served (it cannot be), it is counted, and it is still named in
    force, so the core reads the poll as not heard clean and the list of stops whole,
    never short. Unreadable is caution: a stop's row that cannot be read is a stop."""
    from failsafe.models import FailsafeCommand

    terminate = _signed(operator, "terminate", keys)
    pause = _signed(operator, "pause", keys)
    if how == "its_signatures_are_not_signatures":
        FailsafeCommand.objects.filter(uuid=terminate["uuid"]).update(signatures=[1])
    else:
        broken = FailsafeCommand.objects.get(uuid=terminate["uuid"]).pk
        real = FailsafeCommand.from_db.__func__

        def from_db(cls, db, names, values):
            if values[list(names).index("id")] == broken:
                raise ValueError("the stored row does not decode")
            return real(cls, db, names, values)

        monkeypatch.setattr(FailsafeCommand, "from_db", classmethod(from_db))
    response, outcome = _poll(plane)
    assert response.status_code == 200, response.content[:300]
    _holds(response, outcome, in_force=("terminate", "pause"), unreadable=1)
    assert outcome.heard_clean is False
    assert [command.nonce for command in outcome.commands] == [pause["nonce"]]


def test_a_page_with_starts_on_it_reads_clean_and_names_only_the_stops_in_force(plane, keys, operator):
    """A pause a later resume lifted, a stand-down in force, and a resume signed after
    the stand-down (a resume never lifts one): the stand-down and the later resume are
    served and read, the resume drafted before the stand-down is held back, and only
    the stand-down is named in force."""
    _signed(operator, "pause", keys)
    held = _signed(operator, "resume", keys)
    stand_down = _signed(operator, "stand_down", keys)
    later = _signed(operator, "resume", keys)
    response, outcome = _poll(plane)
    assert response.status_code == 200, response.content[:300]
    _holds(response, outcome, in_force=("stand_down",), unreadable=0)
    assert outcome.heard_clean is True
    assert [command.nonce for command in outcome.commands] == [stand_down["nonce"], later["nonce"]]
    assert held["nonce"] not in {command.nonce for command in outcome.commands}
    assert [str(command.action) for command in outcome.commands] == ["stand_down", "resume"]


def test_a_poll_without_the_token_is_refused_and_never_heard_clean(plane, keys, operator):
    _signed(operator, "terminate", keys)
    response, outcome = _poll(plane, token=None)
    assert response.status_code == 401
    assert (outcome.ended, outcome.status, outcome.commands, outcome.heard_clean) == ("refused", 401, (), False)
    assert response.raw.headers.getlist(U) == [] and response.raw.headers.getlist(F) == []


# --------------------------------------------------- 2. the vectors, through the plane's writers


def test_the_vectors_are_the_cores_at_the_pin_and_name_the_planes_headers():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == VECTOR_SHA256
    from failsafe import views

    v, wire = _vectors(), _wire()
    assert v["schema"] == "mythos.poll-outcome-vectors/v1"
    assert v["headers"] == {"unreadable": U, "in_force": F}
    assert (views.UNREADABLE_HEADER, views.IN_FORCE_HEADER) == (wire.UNREADABLE_HEADER, wire.IN_FORCE_HEADER) == (U, F)
    assert tuple(v["in_force_order"]) == views.POLL_STOP_ORDER == wire.IN_FORCE_ORDER
    assert len(v["answers"]) == 85 and len(v["lines"]) == 13


def _most_rows_one_poll_reads() -> int:
    """The largest count the poll can send: one page reads at most POLL_STOP_LIMIT stops
    and POLL_START_LIMIT starts, and each row it cannot read is one of them."""
    from failsafe import views

    return views.POLL_STOP_LIMIT + views.POLL_START_LIMIT


def _the_plane_writes_count(value) -> bool:
    """Whether the plane's writer writes ``value`` as X-Failsafe-Unreadable for a count
    the poll can have: the one count it could be is the one ``value`` names in plain
    digits."""
    from failsafe import views

    if not (value.isascii() and value.isdigit()) or int(value) > _most_rows_one_poll_reads():
        return False
    return views._page_headers(False, None, None, int(value))[U] == value


def test_the_vectors_read_through_the_planes_own_writers_as_the_core_reads_them(plane, keys, operator):
    """Every ``answers`` and ``lines`` case, case by case. The plane's writers are
    ``_page_headers`` for the count and the poll itself for the in-force value: each of
    the eight sets of stops is signed for an engine of its own and polled over the wire,
    so ``written`` is every in-force value the plane can send. A case the plane can mean
    is written by the plane and read by the core exactly as the case expects; a case
    the core cannot read is one the plane never writes."""
    from failsafe import views

    wire = _wire()
    written = {}
    for n, stops in enumerate(STATES):
        engine = f"conform-set-{n}"
        for action in stops:
            _signed(operator, action, keys, engine)
        response, outcome = _poll(plane, engine)
        _holds(response, outcome, in_force=_strongest_first(stops), unreadable=0)
        written[frozenset(stops)] = response.raw.headers.getlist(F)
    v = _vectors()
    for case in [*v["answers"], *v["lines"]]:
        expect = case["expect"]
        sent = case["lines"] if "lines" in case else list(case["headers"].items())
        counts = [value for name, value in sent if name.lower() == U.lower()]
        kinds = [value for name, value in sent if name.lower() == F.lower()]
        if expect["unreadable"] is None:
            assert len(counts) > 1 or not _the_plane_writes_count(counts[0]), case["why"]
        if expect["in_force_unreadable"]:
            assert len(kinds) > 1 or [kinds[0]] not in written.values(), case["why"]
        if expect["unreadable"] is None or expect["in_force_unreadable"]:
            continue
        kept = urllib3.HTTPHeaderDict()
        for name, value in views._page_headers(False, None, None, expect["unreadable"]).items():
            kept.add(name, value)
        for value in written[frozenset(expect["in_force"])]:
            kept.add(F, value)
        outcome = wire.poll_outcome(
            case["status"], case["body"], CaseInsensitiveDict(kept), truncated=case["truncated"], lines=kept
        )
        assert _said(outcome) == expect, (case["why"], dict(kept))
    # And every count the plane can write, beside every set of stops, reads back as itself.
    most = _most_rows_one_poll_reads()
    assert len(str(most)) < v["count_digits"], most
    for count in (0, 1, 2, 9, 10, most - 1, most):
        for stops, lines in written.items():
            kept = urllib3.HTTPHeaderDict()
            for name, value in views._page_headers(False, None, None, count).items():
                kept.add(name, value)
            for value in lines:
                kept.add(F, value)
            outcome = wire.poll_outcome(200, "[]", CaseInsensitiveDict(kept), lines=kept)
            assert (outcome.unreadable, outcome.in_force, outcome.in_force_unreadable) == (
                count, _strongest_first(stops), False), (count, dict(kept))
            assert outcome.heard_clean is (count == 0)
