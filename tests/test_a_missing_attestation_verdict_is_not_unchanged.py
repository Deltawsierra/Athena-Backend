"""A route answer with no verdict is not a route that is unchanged (#334).

The preflight gate asks the engine to measure each serving route before a scan.
It read each answer's verdict as ``str(route.get("verdict") or "")`` and then
treated the empty string as no objection. So an answer with no verdict, or a
null one, made the route read UNCHANGED -- "1 serving route(s) match their
baseline" -- and the gate read ``ok``: the scan went ahead as though the route
had been measured and found unchanged, when nothing had said so. That is the
gate failing open on the one input it cannot read.

A word the gate did not know already read review, but its reason said "drift":
a moved route, which is not what happened either. And an answer that was not an
object crashed the gate with an AttributeError.

Now each of those is a route the engine answered for without a verdict this
gate can read. It is never unchanged: the gate reads ``review``, and its reason
says the verdict was missing -- not "drift" (a moved route) and not "coverage"
(a route nobody could measure), because each calls for different work. Under
observe the reason says the gate refuses nothing in that mode. Nothing here is
on any stop path.

The answers are athena-engine's own (tests/fixtures/engine_launch/, recorded
from the real engine at #71's f4610ae and at main 5779e99). Neither engine sends
a 2xx attestation answer without a measured verdict -- #71 refuses to -- so the
malformed answers are "derived": the recorded answer with the verdict field
changed, which is what a proxy, a truncated write, or a future engine would
hand this gate.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest import mock

import pytest

from ai_engine.services import preflight

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "engine_launch"
PR71 = "pr71-f4610ae"
MAIN = "main-5779e99"


def recorded(where: str, scenario: str = "attest-unchanged") -> dict:
    """The engine's recorded answer to `POST /api/attestation/check`."""
    fx = json.loads((FIXTURES / where / f"{scenario}.json").read_text())
    return next(one["body"] for one in fx["exchanges"]
                if one["request"]["path"] == "/api/attestation/check"
                and not one["note"].startswith("setup"))


def _dep(*names):
    dep = mock.Mock()
    assets = []
    for name in names:
        asset = mock.Mock(identifier=f"https://{name}.example/v1/chat")
        asset.name = name
        assets.append(asset)
    dep.assets.all.return_value = assets
    return dep


def attest(answers, *names):
    """`_attest_routes` over routes `names`, the engine answering `answers` in turn."""
    client = mock.Mock()
    client.attestation_check.side_effect = list(answers)
    with mock.patch("assurance.served_route.serves_inference", return_value=True):
        return client, preflight._attest_routes(client, _dep(*(names or ("gateway",))))


def _without_verdict(answer):
    answer = copy.deepcopy(answer)
    del answer["verdict"]
    return answer


def _with(recorded_answer, **fields):
    changed = copy.deepcopy(recorded_answer)
    changed.update(fields)
    return changed


# Each derived answer, and the words the gate must use about it.
DERIVED = [
    ("no verdict", _without_verdict, "carried no verdict"),
    ("null verdict", lambda a: _with(a, verdict=None), "carried a null verdict"),
    ("empty verdict", lambda a: _with(a, verdict=""), "does not know"),
    ("unknown word", lambda a: _with(a, verdict="probably_fine"), "does not know ('probably_fine')"),
    ("a number", lambda a: _with(a, verdict=1), "is not a word"),
    ("a list", lambda a: _with(a, verdict=["unchanged"]), "is not a word"),
    ("an object", lambda a: _with(a, verdict={"verdict": "unchanged"}), "is not a word"),
    # #71's `answer` says which shape this is; a status is not a verdict, even
    # one that carries the word.
    ("answer status", lambda a: _with(a, answer="status"), "was answer 'status', not a verdict"),
    ("answer null", lambda a: _with(a, answer=None), "was answer None, not a verdict"),
]


def test_the_recorded_answers_are_unchanged_as_recorded():
    """The negative control: the same answers, unmodified, read unchanged. A gate
    that read everything as review would pass every test below."""
    for where in (PR71, MAIN):
        _, report = attest([recorded(where)])
        assert report["verdict"] == "unchanged", where
        assert not report.get("verdict_missing")
        verdict, detail = preflight._decide(_report(report))
        assert verdict == "ok", (where, detail)


@pytest.mark.parametrize("where", [PR71, MAIN])
@pytest.mark.parametrize("label, derive, why", DERIVED)
def test_an_answer_with_no_readable_verdict_is_review_never_unchanged(where, label, derive, why):
    client, report = attest([derive(recorded(where))])

    assert report["verdict"] == "review", label
    assert report["verdict_missing"] == [{"name": "gateway", "why": mock.ANY}]
    assert why in report["verdict_missing"][0]["why"], report["verdict_missing"]
    assert "match their baseline" not in report["detail"]
    assert "nothing was established" in report["detail"]
    # Asked once, and not again: a missing verdict is read, not retried.
    assert client.attestation_check.call_count == 1


@pytest.mark.parametrize("answer", [None, [], "unchanged", 0, ["verdict", "unchanged"]])
def test_an_answer_that_is_not_an_object_is_review_and_does_not_crash_the_gate(answer):
    _, report = attest([answer])

    assert report["verdict"] == "review"
    assert report["verdict_missing"] == [{"name": "gateway", "why": "carried a null verdict"}]
    # Kept, as what it was, under the route it answered for.
    assert report["routes"][0]["engine_answer"] == answer
    assert "was not an object" in report["routes"][0]["detail"]


def test_one_route_without_a_verdict_holds_a_gate_whose_other_routes_are_unchanged():
    real = recorded(PR71)
    _, report = attest([real, _without_verdict(real)], "a", "b")

    assert report["verdict"] == "review"
    assert [m["name"] for m in report["verdict_missing"]] == ["b"]


def test_a_blocking_list_still_blocks_even_without_a_verdict():
    """A missing verdict never softens what the answer does say."""
    _, report = attest([_with(_without_verdict(recorded(MAIN)), blocking=["issuer"])])
    assert report["verdict"] == "blocked"


# ---------------------------------------------------------------------------
# What the gate says, and does, about it
# ---------------------------------------------------------------------------


def _report(attestation, mode=None):
    report = {
        "assurance": {"verdict": "unchanged", "detail": "ok"},
        "extensions": {"review": {"verdict": "ok", "detail": "ok"}},
        "unattributed": {"effects": []},
        "attestation": attestation,
    }
    if mode:
        report["mode"] = mode
    return report


@pytest.mark.parametrize("mode", ["enforce", "observe"])
@pytest.mark.parametrize("label, derive, why", DERIVED)
def test_the_reason_says_the_verdict_was_missing_not_moved_and_not_coverage(mode, label, derive, why):
    _, attestation = attest([derive(recorded(PR71))])

    verdict, detail = preflight._decide(_report(attestation, mode))

    assert verdict == "review", label
    assert "route attestation (missing verdict)" in detail
    assert "gateway" in detail
    assert "(drift)" not in detail
    assert "(coverage)" not in detail
    if mode == "observe":
        assert "observe mode: this is reported, and nothing is refused in this mode" in detail
    else:
        assert "the gate reads review, never ok" in detail
        assert "observe mode" not in detail


def test_a_missing_verdict_beside_a_moved_route_says_both():
    real = recorded(PR71)
    moved = recorded(PR71, "attest-no-baseline")
    _, attestation = attest([moved, _without_verdict(real)], "a", "b")

    verdict, detail = preflight._decide(_report(attestation, "enforce"))

    assert verdict == "review"
    assert "route attestation (missing verdict): 1 route(s)" in detail
    assert "b: carried no verdict" in detail
    assert "route attestation (drift)" in detail


def test_an_aggregate_verdict_the_gate_does_not_know_is_missing_not_drift():
    """The attestation section itself is external data on the stored report."""
    for word in ("", "probably_fine"):
        verdict, detail = preflight._decide(_report({"verdict": word, "detail": "x"}, "enforce"))
        assert verdict == "review", word
        assert "missing verdict" in detail
        assert "(drift)" not in detail


@pytest.mark.parametrize("mode, setting", [("enforce", "enforce"), ("observe", "observe")])
def test_the_gate_end_to_end_reads_review_under_either_mode_and_raises_nothing(settings, mode, setting):
    """Through `preflight.check`: the engine's other gates answer clean, and the one
    route answers without a verdict. Under enforce the report reads review -- never
    ok -- and the scan is not refused on it (review never is); under observe the
    report says so."""
    settings.CYBERENGINE_ASSURANCE_MODE = setting
    client = mock.Mock()
    client.assurance_check.return_value = {"verdict": "unchanged", "detail": "ok"}
    client.extension_review.return_value = {"review": {"verdict": "ok", "detail": "ok"}}
    client.unattributed_effects.return_value = {"effects": []}
    client.attestation_check.return_value = _without_verdict(recorded(PR71))
    preflight.clear_cache()
    try:
        with mock.patch.object(preflight, "deployment_for_routes", return_value=_dep("gateway")), \
                mock.patch("assurance.served_route.serves_inference", return_value=True):
            report = preflight.check(client, force=True)
    finally:
        preflight.clear_cache()

    assert report["mode"] == mode
    assert report["verdict"] == "review"
    assert "route attestation (missing verdict)" in report["detail"]
    assert report["attestation"]["verdict_missing"] == [{"name": "gateway", "why": "carried no verdict"}]


def test_nothing_on_a_stop_path_reaches_the_preflight_gate():
    """The gate is asked on the way to STARTING a scan, and nowhere else: no stop,
    pause, stand-down, revoke or failsafe route can wait on it, whatever it reads."""
    import re

    root = Path(preflight.__file__).resolve().parents[2]
    imports = re.compile(r"^\s*(from|import)\s.*\bpreflight\b", re.MULTILINE)
    importers = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if "tests" not in path.parts and ".venv" not in path.parts
        and path.name != "preflight.py"
        and imports.search(path.read_text(encoding="utf-8", errors="replace"))
    )
    assert importers == [
        "pentest/management/commands/approve_deployment.py",
        "pentest/views.py",
    ]
