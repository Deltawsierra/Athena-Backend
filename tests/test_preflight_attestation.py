"""Route attestation in the scan gate: what a changed endpoint does to a scan.

`attestation_check` existed on the client and nothing called it. `preflight.check`
asked the assurance gate, the extension gate and the audit query, and never asked
whether the route it was about to scan is still the route the baseline describes.
A control reachable only from its own definition is a control that is not running.

The shape of the answer is the engine's, not this module's. `/api/attestation/check`
already separates blocking certificate facts from advisory behavioural ones, and
already folds the behavioural half so it can raise a verdict to review and never
to blocked -- "a changed fingerprint has four explanations and only one of them is
a substituted model". A second opinion from this side would duplicate that rule or
quietly contradict it, so the gate trusts it.

What the gate adds is the part the engine cannot know: which routes this
deployment serves, and that a route it could not measure must never read like one
it measured and found unchanged.
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.contrib.auth import get_user_model

from ai_engine.services import preflight
from ai_engine.services.cyberengine_client import EngineError
from assurance.models import Asset, Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="owner"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(name="mythos-platform"):
    return Deployment.objects.create(name=name, owner=_user())


def _serving(dep, *, name="gateway", identifier="https://llm.example/v1/chat", **kw):
    return Asset.objects.create(
        deployment=dep,
        kind=kw.pop("kind", Asset.Kind.GATEWAY),
        name=name,
        identifier=identifier,
        metadata=kw.pop("metadata", {"model": "gpt-4o"}),
        **kw,
    )


def _client(answer=None, raises=None):
    client = mock.Mock()
    if raises is not None:
        client.attestation_check.side_effect = raises
    else:
        client.attestation_check.return_value = answer
    return client


def _unchanged(name="gateway"):
    return {
        "name": name,
        "verdict": "unchanged",
        "detail": "matches baseline",
        "blocking": [],
        "advisory": [],
    }


# ---------------------------------------------------------------------------
# Which routes get measured
# ---------------------------------------------------------------------------


def test_a_serving_asset_with_a_url_is_measured():
    dep = _deployment()
    _serving(dep)
    client = _client(_unchanged())

    report = preflight._attest_routes(client, dep)

    client.attestation_check.assert_called_once_with(
        "gateway", "https://llm.example/v1/chat", tenant_id=None
    )
    assert report["verdict"] == "unchanged"


def test_an_asset_that_serves_nothing_is_not_measured():
    """A scanner tool is not an inference route, and probing it would spend a
    round trip to learn nothing."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.TOOL,
        name="port-scanner",
        identifier="https://tool.example/scan",
        metadata={},
    )
    client = _client(_unchanged())

    report = preflight._attest_routes(client, dep)

    assert client.attestation_check.called is False
    assert report["routes"] == []


def test_a_serving_asset_with_no_url_is_unmeasurable_not_skipped():
    """The coverage hole this gate must not hide. An asset that serves inference
    but carries an ARN or a tool name has no endpoint to probe, and dropping it
    would let a gate that measured one of two routes report what a gate that
    measured both reports."""
    dep = _deployment()
    _serving(dep, name="bedrock", identifier="arn:aws:bedrock:us-east-1::model/x")
    client = _client(_unchanged())

    report = preflight._attest_routes(client, dep)

    assert client.attestation_check.called is False
    assert report["verdict"] == "unobservable"
    assert report["not_measured_count"] == 1
    assert report["unmeasurable"][0]["name"] == "bedrock"
    assert "no endpoint to measure" in report["unmeasurable"][0]["why"]


def test_a_deployment_that_serves_nothing_reads_unchanged():
    """A real negative over an enumerable set: we hold the inventory and it
    contains no serving route. That is a true answer, and distinct from not
    holding an inventory at all."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="t", identifier="t", metadata={}
    )

    report = preflight._attest_routes(_client(_unchanged()), dep)

    assert report["verdict"] == "unchanged"
    assert "serves no inference route" in report["detail"]


def test_no_deployment_record_is_unobservable_not_clean():
    """An inventory we do not hold is not an inventory of no routes."""
    report = preflight._attestation_for(None, _client(_unchanged()), None)

    assert report["verdict"] == "unobservable"
    assert "no deployment record" in report["detail"]
    # Not 0. We hold no inventory, so we do not know how many routes exist, and
    # a zero here would be read as "nothing was left unmeasured".
    assert report["not_measured_count"] is None


def test_an_unknown_route_count_never_reads_as_zero_unmeasured():
    """The reason an operator reads must not turn "we do not know" into "none".

    `_attestation_for(None, ...)` is the real producer of this state: there is no
    deployment row, so there is no route count. If the reason rendered that as
    "0 not measured" it would say the opposite of what happened -- the same
    silent zero the whole gate exists to stop."""
    detail = preflight._decide(
        _report(preflight._attestation_for(None, _client(_unchanged()), None))
    )[1]

    assert "an unknown number not measured" in detail
    assert "0 not measured" not in detail


def test_a_malformed_count_from_the_engine_is_unknown_not_zero():
    """The attestation section is external data. A count that is not an integer
    is a count we do not have, and must not be coerced into a reassuring zero."""
    for bogus in ("many", -0.0, [], True):
        detail = preflight._decide(
            _report(
                {
                    "verdict": "unobservable",
                    "detail": "x",
                    "routes": [],
                    "not_measured_count": bogus,
                }
            )
        )[1]
        assert "an unknown number not measured" in detail, bogus


# ---------------------------------------------------------------------------
# The worst route decides, and unmeasured is not good
# ---------------------------------------------------------------------------


def test_a_blocking_route_blocks_the_report():
    dep = _deployment()
    _serving(dep)
    client = _client(
        {
            "name": "gateway",
            "verdict": "blocked",
            "detail": "issuer changed",
            "blocking": ["issuer"],
            "advisory": [],
        }
    )

    assert preflight._attest_routes(client, dep)["verdict"] == "blocked"


def test_a_blocking_list_blocks_even_if_the_verdict_word_does_not():
    """Belt and braces on external data: the engine names what it considers
    blocking, and a reply that lists blocking facts under a softer verdict is not
    one this gate rounds down."""
    dep = _deployment()
    _serving(dep)
    client = _client(
        {
            "name": "gateway",
            "verdict": "review",
            "detail": "hm",
            "blocking": ["names"],
            "advisory": [],
        }
    )

    assert preflight._attest_routes(client, dep)["verdict"] == "blocked"


def test_an_unobservable_route_beats_a_review():
    """Not being able to look ranks worse than having looked and wanting a second
    opinion, because only one of them produced a measurement."""
    dep = _deployment()
    _serving(dep, name="a", identifier="https://a.example/")
    _serving(dep, name="b", identifier="https://b.example/")
    client = mock.Mock()
    client.attestation_check.side_effect = [
        {
            "name": "a",
            "verdict": "review",
            "detail": "x",
            "blocking": [],
            "advisory": [],
        },
        {
            "name": "b",
            "verdict": "unobservable",
            "detail": "tls handshake failed",
            "blocking": [],
            "advisory": [],
        },
    ]

    assert preflight._attest_routes(client, dep)["verdict"] == "unobservable"


def test_a_blocked_route_beats_an_unobservable_one():
    dep = _deployment()
    _serving(dep, name="a", identifier="https://a.example/")
    _serving(dep, name="b", identifier="https://b.example/")
    client = mock.Mock()
    client.attestation_check.side_effect = [
        {
            "name": "a",
            "verdict": "unobservable",
            "detail": "x",
            "blocking": [],
            "advisory": [],
        },
        {
            "name": "b",
            "verdict": "blocked",
            "detail": "issuer changed",
            "blocking": ["issuer"],
            "advisory": [],
        },
    ]

    assert preflight._attest_routes(client, dep)["verdict"] == "blocked"


def test_an_engine_that_cannot_be_asked_is_unobservable_not_unchanged():
    """The egress allowlist refusing a host lands here. "We were not allowed to
    look" must never read as "we looked and it was fine"."""
    dep = _deployment()
    _serving(dep)
    client = _client(raises=EngineError("host not on the engine allowlist"))

    report = preflight._attest_routes(client, dep)

    assert report["verdict"] == "unobservable"
    assert report["routes"][0]["verdict"] == "unobservable"
    assert "allowlist" in report["routes"][0]["detail"]


def test_a_verdict_this_module_does_not_recognise_is_not_a_pass():
    """The engine's replies are external data, and an unknown word must not widen
    the gate."""
    dep = _deployment()
    _serving(dep)
    client = _client(
        {
            "name": "gateway",
            "verdict": "probably_fine",
            "detail": "?",
            "blocking": [],
            "advisory": [],
        }
    )

    assert preflight._attest_routes(client, dep)["verdict"] == "review"


def test_the_route_cap_is_reported_rather_than_silently_shortening_the_answer():
    """A gate that quietly measured eight of twenty routes would report what a
    gate that measured all twenty reports."""
    dep = _deployment()
    for i in range(preflight.MAX_ATTESTED_ROUTES + 3):
        _serving(dep, name=f"r{i}", identifier=f"https://r{i}.example/")
    client = _client(_unchanged())

    report = preflight._attest_routes(client, dep)

    assert client.attestation_check.call_count == preflight.MAX_ATTESTED_ROUTES
    assert report["verdict"] == "unobservable"
    assert len(report["truncated"]) == 3
    assert "were not measured" in report["detail"]


# ---------------------------------------------------------------------------
# What it does to the scan gate
# ---------------------------------------------------------------------------


def _report(attestation):
    return {
        "assurance": {"verdict": "unchanged", "detail": "ok"},
        "extensions": {"verdict": "ok", "detail": "ok"},
        "unattributed": {"effects": []},
        "attestation": attestation,
    }


def test_a_blocked_route_blocks_the_scan():
    """The whole point of option B: a route whose certificate identity moved
    under us is a different endpoint, and a scan of a different endpoint is not
    the scan that was asked for."""
    verdict, detail = preflight._decide(
        _report({"verdict": "blocked", "detail": "issuer changed on gateway"})
    )

    assert verdict == "blocked"
    assert "route attestation" in detail
    assert "issuer changed" in detail


def test_an_unobservable_route_is_review_and_never_blocks():
    """Not being able to look is a coverage gap, not evidence of drift. Blocking
    on it would make the first deployment with an un-probeable route unable to
    scan at all, which is how a gate gets switched off."""
    verdict, detail = preflight._decide(
        _report(
            {
                "verdict": "unobservable",
                "detail": "1 route carries no endpoint",
                "routes": [{"name": "a"}],
                "not_measured_count": 1,
            }
        )
    )

    assert verdict == "review"
    assert "coverage" in detail
    assert "1 route(s) measured, 1 not measured" in detail


def test_the_three_review_states_are_told_apart_in_the_detail():
    """A coverage gap, a moved baseline and an unparseable reply are three
    different facts that call for three different actions. An earlier version
    appended the same generic text for all three, so two of the branches were
    decoration -- a mutation deleting either changed nothing, which is how it was
    found."""
    coverage = preflight._decide(
        _report(
            {
                "verdict": "unobservable",
                "detail": "x",
                "routes": [],
                "not_measured_count": 2,
            }
        )
    )[1]
    drift = preflight._decide(_report({"verdict": "review", "detail": "x"}))[1]
    unreadable = preflight._decide(_report("not a dict"))[1]

    assert "coverage" in coverage
    assert "drift" in drift
    assert "was not a report" in unreadable
    # No two of them read the same.
    assert len({coverage, drift, unreadable}) == 3


def test_a_review_route_is_review():
    verdict, detail = preflight._decide(
        _report({"verdict": "review", "detail": "no baseline recorded yet"})
    )
    assert verdict == "review"
    assert "drift" in detail
    assert "no baseline recorded yet" in detail


def test_unchanged_routes_leave_the_gate_ok():
    verdict, detail = preflight._decide(
        _report({"verdict": "unchanged", "detail": "2 serving route(s) match"})
    )
    assert verdict == "ok"
    assert "route attestation" not in detail


def test_an_attestation_answer_that_is_not_a_report_is_not_a_pass():
    verdict, detail = preflight._decide(_report("yes"))
    assert verdict == "review"
    assert "was not a report" in detail
    # Named as an engine/contract problem, not as a fact about the routes: a
    # reply nobody can parse establishes nothing either way.
    assert "nothing was established" in detail


def test_a_missing_attestation_section_is_not_a_pass():
    """A report assembled without ever asking must not read like one that asked
    and heard nothing wrong."""
    report = _report(None)
    report.pop("attestation")

    verdict, detail = preflight._decide(report)

    assert verdict == "review"
    assert "route attestation" in detail


def test_the_assurance_gate_still_outranks_attestation():
    """A blocked assurance gate is reported as the assurance gate. Attestation is
    an addition to the gate, not a replacement for what it already refused on."""
    report = _report({"verdict": "blocked", "detail": "issuer changed"})
    report["assurance"] = {"verdict": "blocked", "detail": "components changed"}

    verdict, detail = preflight._decide(report)

    assert verdict == "blocked"
    assert "assurance gate" in detail


def test_the_attestation_section_is_made_storable_before_the_report_is_kept():
    """The report is persisted on the scan row, and the attestation section holds
    the engine's raw measurements -- external data. Left out of the _jsonable
    pass, a reply carrying anything non-JSON would fail to store the verdict that
    governed the scan. Enumerated rather than spot-checked: every section the
    report carries has to be in that roster."""
    import inspect

    source = inspect.getsource(preflight.check)
    roster = next(line for line in source.splitlines() if "for section in (" in line)
    for section in ("assurance", "extensions", "unattributed", "attestation"):
        assert f'"{section}"' in roster, section


def test_the_behavioural_half_is_never_re_decided_here():
    """The engine folds behaviour so it can raise to review and never to blocked.
    This gate reads the engine's verdict; it does not look at the behavioural
    fingerprint and form a second opinion, which would either duplicate that rule
    or contradict it."""
    import inspect

    source = inspect.getsource(preflight._attest_verdict)
    assert "behaviour" not in source
    assert "fingerprint" not in source
