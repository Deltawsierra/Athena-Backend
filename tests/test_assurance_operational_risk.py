"""Athena — Operational-risk register (Phase 3.9).

Proves the operational-risk register is a narrow, honest, REUSE-ONLY read of four
operational-risk classes — unbounded-loop/retry-storm, denial-of-wallet/cost-
runaway, token-storm, and provider-outage/no-fallback — derived only from the
stored asset/provider graph and the deployment's ingested findings.

Above all it proves the honesty invariants that are the point of the module:

- A class with a **real signal** in the graph derives an honest ordinal risk band
  and cites the signal: provider-outage from the model-provider dependency graph
  (single provider → high, multiple → moderate), retry-storm from the autonomous
  ``agent`` assets, and any class from a direct ingested finding that names it.
- A class with **no basis** reads honestly ``unmapped`` (``risk`` is ``None``,
  ``observed`` is ``False``) — never a fabricated ``0``/``0%``, and never "no
  risk"/"safe"/"secure". It is correct and expected that denial-of-wallet and
  token-storm read ``unmapped`` on a graph with no budget/token-cap signal.
- The overall roll-up is weakest-honest: a real high risk drives it, unmapped
  classes are surfaced as gaps, and a deployment with nothing observed rolls up to
  ``unmapped``, never to a clean band.
- The output is deterministic and None-safe, and the API read is open to any
  operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Asset, Deployment, Finding, Provider
from assurance.operational_risk import (
    CLASS_DENIAL_OF_WALLET,
    CLASS_PROVIDER_OUTAGE,
    CLASS_RETRY_STORM,
    CLASS_TOKEN_STORM,
    RISK_ELEVATED,
    RISK_HIGH,
    RISK_MODERATE,
    STATUS_OBSERVED,
    STATUS_UNMAPPED,
    assess_operational_risk,
)
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name, kind=Provider.Kind.MODEL_PROVIDER):
    return Provider.objects.create(name=name, kind=kind)


def _asset(dep, *, kind, name, classification=Asset.Classification.KNOWN, provider=None, identifier=None):
    return Asset.objects.create(
        deployment=dep,
        kind=kind,
        name=name,
        identifier=identifier or name,
        classification=classification,
        provider=provider,
    )


def _finding(dep, *, finding_type, severity="high", status=Finding.Status.OPEN, n="1"):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{finding_type}-{n}",
        finding_type=finding_type,
        title=f"{finding_type} #{n}",
        severity=severity,
        status=status,
    )


def _classes_by_key(result):
    return {c["key"]: c for c in result["classes"]}


def _walk_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _walk_strings(item)
    elif isinstance(obj, str):
        yield obj


# ---------------------------------------------------------------------------
# provider-outage / no-fallback — the class with a real structural basis
# ---------------------------------------------------------------------------


def test_single_model_provider_reads_high_no_fallback_and_cites_it():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("only-llm")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_PROVIDER_OUTAGE]
    assert cls["observed"] is True
    assert cls["status"] == STATUS_OBSERVED
    # A single model provider is a single point of failure — an honest high.
    assert cls["risk"] == RISK_HIGH
    assert "structural" in cls["basis"]
    # The provider is cited as the signal.
    provider_sigs = [s for s in cls["signals"] if s["source"] == "provider"]
    assert provider_sigs and provider_sigs[0]["provider_name"] == "only-llm"


def test_two_model_providers_soften_to_moderate_never_a_clean_pass():
    dep = Deployment.objects.create(name="d", owner=_user())
    a = _provider("llm-a")
    b = _provider("llm-b")
    _asset(dep, kind=Asset.Kind.MODEL, name="m-a", provider=a, identifier="a")
    _asset(dep, kind=Asset.Kind.MODEL, name="m-b", provider=b, identifier="b")

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_PROVIDER_OUTAGE]
    assert cls["observed"] is True
    # An alternative provider exists in the graph — moderate, but NOT clear/none.
    assert cls["risk"] == RISK_MODERATE
    assert cls["risk"] is not None
    assert len([s for s in cls["signals"] if s["source"] == "provider"]) == 2


def test_no_provider_dependency_is_unmapped_not_no_risk():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A deployment with assets but no provider dependency at all.
    _asset(dep, kind=Asset.Kind.API, name="app")

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_PROVIDER_OUTAGE]
    assert cls["observed"] is False
    assert cls["status"] == STATUS_UNMAPPED
    # Absence of a provider dependency is unmapped, never a fabricated 0 / no risk.
    assert cls["risk"] is None


# ---------------------------------------------------------------------------
# unbounded-loop / retry-storm — real structural basis (autonomous agents)
# ---------------------------------------------------------------------------


def test_autonomous_agent_surface_reads_elevated_bound_unmapped():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", classification=Asset.Classification.KNOWN)

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_RETRY_STORM]
    assert cls["observed"] is True
    # A managed autonomous-loop surface with no evidenced bound → elevated.
    assert cls["risk"] == RISK_ELEVATED
    assert any(s["source"] == "asset" and s["kind"] == Asset.Kind.AGENT for s in cls["signals"])
    # The bound is explicitly named as an engine execution-layer signal, not read here.
    assert "execution-layer" in cls["runtime_signal"].lower()


def test_shadow_agent_raises_retry_storm_to_high():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="rogue", classification=Asset.Classification.UNMANAGED)

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_RETRY_STORM]
    # A shadow (unmanaged) agent raises the band one step, mirroring the capability map.
    assert cls["risk"] == RISK_HIGH


def test_no_agent_and_no_finding_is_unmapped():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="m")

    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_RETRY_STORM]
    assert cls["observed"] is False
    assert cls["status"] == STATUS_UNMAPPED
    assert cls["risk"] is None


# ---------------------------------------------------------------------------
# denial-of-wallet & token-storm — finding-derived; unmapped by default
# ---------------------------------------------------------------------------


def test_unbounded_consumption_finding_signals_both_cost_classes():
    dep = Deployment.objects.create(name="d", owner=_user())
    # OWASP LLM10 "Unbounded Consumption" — the real engine finding type that spans
    # denial-of-wallet and token exhaustion.
    _finding(dep, finding_type="unbounded_consumption", severity="high")

    by_key = _classes_by_key(assess_operational_risk(dep))
    dow = by_key[CLASS_DENIAL_OF_WALLET]
    tok = by_key[CLASS_TOKEN_STORM]
    for cls in (dow, tok):
        assert cls["observed"] is True
        assert cls["status"] == STATUS_OBSERVED
        assert cls["risk"] == RISK_HIGH
        assert cls["active_finding_count"] == 1
        assert "finding" in cls["basis"]
        assert any(s["source"] == "finding" for s in cls["signals"])


def test_cost_classes_are_unmapped_with_no_budget_or_token_signal():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A metered model provider exists (cost-exposure surface), but the graph records
    # NO budget, rate-limit, spend, or token cap — those are runtime controls.
    p = _provider("llm")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)

    by_key = _classes_by_key(assess_operational_risk(dep))
    for key in (CLASS_DENIAL_OF_WALLET, CLASS_TOKEN_STORM):
        cls = by_key[key]
        # Correct and expected: no basis → unmapped, never a fabricated 0 / no risk.
        assert cls["observed"] is False
        assert cls["status"] == STATUS_UNMAPPED
        assert cls["risk"] is None
        # The cost-exposure surface is noted honestly as context, not as a risk band.
        assert cls["notes"]


def test_resolved_finding_is_not_live_operational_risk():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(
        dep,
        finding_type="unbounded_consumption",
        severity="critical",
        status=Finding.Status.CLOSED,
    )
    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_TOKEN_STORM]
    # A verified-closed finding is no longer active exposure → back to unmapped.
    assert cls["observed"] is False
    assert cls["risk"] is None
    assert cls["active_finding_count"] == 0


def test_finding_severity_sets_the_band():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, finding_type="denial_of_wallet", severity="medium")
    cls = _classes_by_key(assess_operational_risk(dep))[CLASS_DENIAL_OF_WALLET]
    # A medium-severity direct finding bands at elevated, not high.
    assert cls["risk"] == RISK_ELEVATED


# ---------------------------------------------------------------------------
# Roll-up honesty
# ---------------------------------------------------------------------------


def test_overall_is_weakest_honest_high_drives_it_unmapped_are_gaps():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One real high class (single provider), the rest unmapped.
    p = _provider("only-llm")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)

    result = assess_operational_risk(dep)
    assert result["overall"]["status"] == STATUS_OBSERVED
    # A real high risk drives the roll-up.
    assert result["overall"]["risk"] == RISK_HIGH
    # The unmapped classes are surfaced as remaining gaps, not counted as a pass.
    assert result["overall"]["unmapped_classes"] >= 1
    assert result["summary"]["unmapped"]  # non-empty list of gap keys
    # The most concerning class leads the sorted list.
    assert result["classes"][0]["risk"] == RISK_HIGH


def test_empty_deployment_every_class_unmapped_and_overall_unmapped():
    dep = Deployment.objects.create(name="empty", owner=_user("e"))
    result = assess_operational_risk(dep)

    # Every one of the four classes reads unmapped — no basis anywhere.
    assert len(result["classes"]) == 4
    for cls in result["classes"]:
        assert cls["observed"] is False
        assert cls["status"] == STATUS_UNMAPPED
        assert cls["risk"] is None
    # Nothing observed → overall is honestly unmapped, never a clean band or 0.
    assert result["overall"]["status"] == STATUS_UNMAPPED
    assert result["overall"]["risk"] is None
    assert result["summary"]["observed_classes"] == 0
    assert result["summary"]["unmapped_classes"] == 4
    assert result["summary"]["worst_risk"] is None


def test_no_class_ever_reads_no_risk_safe_secure_or_a_fake_zero():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A mix: observed provider-outage + unmapped cost classes.
    p = _provider("only-llm")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)
    result = assess_operational_risk(dep)

    # An unmapped class NEVER carries a fabricated numeric/zero risk.
    for cls in result["classes"]:
        if cls["status"] == STATUS_UNMAPPED:
            assert cls["risk"] is None
            assert cls["risk"] != 0
            assert cls["observed"] is False
        else:
            # An observed class carries an ordinal band, floored at moderate.
            assert cls["risk"] in {RISK_HIGH, RISK_ELEVATED, RISK_MODERATE}
    # The overall risk is None or an ordinal band — never a number.
    assert result["overall"]["risk"] in {None, RISK_HIGH, RISK_ELEVATED, RISK_MODERATE}

    # No output string dishonestly reads the deployment as clean/secure.
    forbidden = ("no risk", "risk-free", "0%", "is secure", "fully secure", "is safe", "all clear", "healthy")
    for text in _walk_strings(result):
        low = text.lower()
        for phrase in forbidden:
            assert phrase not in low, f"dishonest phrase {phrase!r} in {text!r}"


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("llm")
    _asset(dep, kind=Asset.Kind.AGENT, name="agent")
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    _finding(dep, finding_type="unbounded_consumption", severity="high")
    assert assess_operational_risk(dep) == assess_operational_risk(dep)


def test_none_safe_missing_finding_type_and_provider():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A finding with an empty finding_type and an asset with no provider — nothing
    # should raise, and nothing should read as clean.
    _finding(dep, finding_type="", severity="low")
    _asset(dep, kind=Asset.Kind.TOOL, name="t", provider=None)
    result = assess_operational_risk(dep)
    assert set(result) >= {"system", "classes", "summary", "overall"}
    assert len(result["classes"]) == 4


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_operational_risk_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    p = _provider("only-llm")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "operational_risk"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/operational-risk/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    # The documented return keys are present.
    assert set(resp.data) >= {"system", "classes", "summary", "overall"}
    assert len(resp.data["classes"]) == 4
    # Provider-outage reads a real high from the single-provider graph.
    by_key = {c["key"]: c for c in resp.data["classes"]}
    assert by_key[CLASS_PROVIDER_OUTAGE]["risk"] == RISK_HIGH
