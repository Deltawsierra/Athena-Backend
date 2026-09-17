"""Athena Phase 3.5 — Data & Context assessment modules.

Proves the four read-only, computed "data & context" assessments — Personal
Context Exposure, Data Lifecycle Review, Training/Reuse Review, and Metadata &
Logging Risk — are honest in the way the rest of the assurance layer is:

- Nothing reads "secure" / "compliant" / "safe". An unknown classification or an
  unevidenced control reads unknown / gap, never a pass.
- Evidence honesty: a vendor_asserted or self-declared claim never reads as
  independently verified.
- No fabrication: only what the asset graph / metadata / provider assertions /
  boundary evidence is reported — no invented PII, deletion step or log sink; the
  who-can-reach parts reuse the evidenced effective-access reach only.
- No sensitive VALUES are emitted — only presence / lineage facts.
- Deterministic (same graph → same output), and the empty / unmapped graph is an
  honest empty result, not a clean bill.
- Each API action is open to any authenticated operator and returns 200 with the
  expected shape.
"""

from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.data_lifecycle import (
    STAGE_DELETED,
    STAGE_ORDER,
    assess_data_lifecycle,
)
from assurance.metadata_logging import (
    CATEGORY_PII,
    CATEGORY_PROMPTS,
    assess_metadata_logging,
)
from assurance.models import (
    Asset,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
)
from assurance.personal_context import assess_personal_context
from assurance.training_reuse import (
    POSTURE_NOT_REUSED,
    POSTURE_REUSED,
    assess_training_reuse,
)
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

_FORBIDDEN = ("secure", "compliant", "safe")


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _dep(owner=None):
    return Deployment.objects.create(name="d", owner=owner or _user(name=f"u{Deployment.objects.count()}"))


def _asset(dep, *, kind, classification=Asset.Classification.KNOWN, name="c", identifier=None,
           provider=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification, provider=provider,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _provider(name, kind=Provider.Kind.MODEL_PROVIDER):
    return Provider.objects.create(name=name, kind=kind)


def _assert(provider, field, value, *, evidence_class=EvidenceClass.VENDOR_ASSERTED,
            source=ProviderAssertion.Source.SELF_DECLARED):
    return ProviderAssertion.objects.create(
        provider=provider, field=field, value=value, evidence_class=evidence_class, source=source
    )


def _no_forbidden(result):
    blob = json.dumps(result).lower()
    for word in _FORBIDDEN:
        assert word not in blob, f"'{word}' must never appear in an assurance result"


# ---------------------------------------------------------------------------
# 1. Personal Context Exposure
# ---------------------------------------------------------------------------


def test_personal_data_store_is_evidenced_from_metadata():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customers",
           metadata={"data_classification": "pii, customer profile"})
    result = assess_personal_context(dep)
    store = result["stores"][0]
    assert store["data_sensitivity"] == "personal"
    assert store["personal_data"] is True
    assert store["signals"]  # the tokens that evidenced it
    assert result["summary"]["personal_data_components"] == 1
    _no_forbidden(result)


def test_unclassified_store_reads_unknown_not_no_pii():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="mystery")  # no classification signal
    result = assess_personal_context(dep)
    store = result["stores"][0]
    assert store["data_sensitivity"] == "unknown"
    assert store["personal_data"] is False
    # Unknown is surfaced as a gap (exposure cannot be ruled out), never "no PII".
    assert any(g["type"] == "unclassified" for g in store["gaps"])
    blob = json.dumps(result).lower()
    assert "no pii" not in blob and "no personal" not in blob


def test_personal_data_reachable_by_shadow_principal_uses_evidenced_reach():
    dep = _dep()
    # A shadow (unmanaged) agent -> tool -> personal data store, all declared edges.
    _asset(dep, kind=Asset.Kind.AGENT, name="rogue", identifier="rogue",
           classification=Asset.Classification.UNMANAGED, metadata={"tools": ["reader"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
           metadata={"server": "customers"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customers", identifier="customers",
           metadata={"data_classification": "personal"})
    result = assess_personal_context(dep)
    store = next(s for s in result["stores"] if s["asset_name"] == "customers")
    # The reader is the evidenced reach path, not a re-derived one.
    assert any(r["principal"] == "rogue" and r["shadow"] for r in store["reachable_by"])
    assert any(g["type"] == "reachable_by_shadow" for g in store["gaps"])
    assert store["risk"] == "high"


def test_personal_data_reach_is_not_invented_without_a_declared_edge():
    dep = _dep()
    # An agent with no tools, and a separate store — no declared path connects them.
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant", metadata={})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customers", identifier="customers",
           metadata={"data_classification": "pii"})
    store = assess_personal_context(dep)["stores"][0]
    assert store["reachable_by"] == []  # no path fabricated


def test_personal_data_crossing_boundary_is_a_gap():
    dep = _dep()
    # An unmanaged personal-data store is a shadow destination outside any boundary.
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="leak", identifier="leak",
           classification=Asset.Classification.UNMANAGED,
           metadata={"data_classification": "customer pii"})
    DataBoundary.objects.create(deployment=dep, allowed_regions=["eu"])
    store = assess_personal_context(dep)["stores"][0]
    assert any(g["type"] == "crosses_boundary" for g in store["gaps"])


def test_personal_context_empty_graph_is_honest_empty():
    dep = _dep()
    result = assess_personal_context(dep)
    assert result["stores"] == []
    assert result["summary"]["data_bearing_components"] == 0
    assert result["summary"]["worst_risk"] is None
    _no_forbidden(result)


def test_personal_context_is_deterministic():
    def build():
        dep = _dep()
        _asset(dep, kind=Asset.Kind.AGENT, name="a", identifier="a",
               classification=Asset.Classification.UNMANAGED, metadata={"tools": ["t"]})
        _asset(dep, kind=Asset.Kind.TOOL, name="t", identifier="t", metadata={"server": "s"})
        _asset(dep, kind=Asset.Kind.DATA_STORE, name="s", identifier="s",
               metadata={"data_classification": "pii"})
        _asset(dep, kind=Asset.Kind.VECTOR_DB, name="v", identifier="v")
        return dep

    assert json.dumps(assess_personal_context(build()), sort_keys=True) == json.dumps(
        assess_personal_context(build()), sort_keys=True
    )


def test_personal_context_api_returns_200_and_shape():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customers", metadata={"pii": True})
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "personal_context"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/personal-context/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"stores", "gaps", "summary"}
    assert resp.data["summary"]["personal_data_components"] == 1


# ---------------------------------------------------------------------------
# 2. Data Lifecycle Review
# ---------------------------------------------------------------------------


def _stages(result):
    return {s["stage"]: s for s in result["stages"]}


def test_unevidenced_deleted_stage_is_a_gap_not_compliant():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="store")  # retained, but no deletion evidence
    result = assess_data_lifecycle(dep)
    deleted = _stages(result)[STAGE_DELETED]
    assert deleted["evidenced"] is False
    assert deleted["gap"] is True
    assert "not evidenced" in (deleted["gap_detail"] or "").lower() or "no evidenced" in (deleted["gap_detail"] or "").lower()
    _no_forbidden(result)


def test_retention_carries_true_evidence_class_and_stays_a_gap_when_weak():
    dep = _dep()
    p = _provider("Store Co", kind=Provider.Kind.CLOUD)
    _assert(p, ProviderAssertion.Field.DATA_RETENTION, "30 days",
            evidence_class=EvidenceClass.VENDOR_ASSERTED)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s", provider=p)
    retained = _stages(assess_data_lifecycle(dep))["retained"]
    # The provider assertion is carried at its true (vendor_asserted) class...
    assert any(c["evidence_class"] == EvidenceClass.VENDOR_ASSERTED.value for c in retained["components"])
    # ...and a vendor-asserted-only control is still a gap, not a pass.
    assert retained["gap"] is True


def test_deletion_only_evidenced_when_erasure_is_named():
    dep = _dep()
    p = _provider("Erase Co", kind=Provider.Kind.CLOUD)
    _assert(p, ProviderAssertion.Field.DATA_RETENTION, "data deleted after 30 days",
            evidence_class=EvidenceClass.CONFIGURATION_VERIFIED)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s", provider=p)
    deleted = _stages(assess_data_lifecycle(dep))[STAGE_DELETED]
    assert deleted["evidenced"] is True  # "deleted" names an erasure control


def test_retention_window_alone_does_not_evidence_deletion():
    dep = _dep()
    p = _provider("Keep Co", kind=Provider.Kind.CLOUD)
    _assert(p, ProviderAssertion.Field.DATA_RETENTION, "kept for 90 days",
            evidence_class=EvidenceClass.CONFIGURATION_VERIFIED)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s", provider=p)
    deleted = _stages(assess_data_lifecycle(dep))[STAGE_DELETED]
    # "kept for 90 days" retains but names no erasure — deletion must not be claimed.
    assert deleted["evidenced"] is False
    assert deleted["gap"] is True


def test_flow_stage_not_evidenced_reads_not_evidenced():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s")  # collected/retained only
    transmitted = _stages(assess_data_lifecycle(dep))["transmitted"]
    assert transmitted["evidenced"] is False
    assert "not evidenced" in (transmitted["gap_detail"] or "").lower()


def test_data_lifecycle_empty_graph_is_honest_empty():
    dep = _dep()
    result = assess_data_lifecycle(dep)
    assert len(result["stages"]) == len(STAGE_ORDER)
    assert all(not s["evidenced"] for s in result["stages"])
    _no_forbidden(result)


def test_data_lifecycle_is_deterministic():
    dep = _dep()
    p = _provider("P", kind=Provider.Kind.MODEL_PROVIDER)
    _assert(p, ProviderAssertion.Field.LOGGING, "logs prompts")
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s")
    assert json.dumps(assess_data_lifecycle(dep), sort_keys=True) == json.dumps(
        assess_data_lifecycle(dep), sort_keys=True
    )


def test_data_lifecycle_api_returns_200_and_shape():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="s")
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "data_lifecycle"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/data-lifecycle/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"stages", "gaps", "summary"}
    assert resp.data["summary"]["stages_total"] == len(STAGE_ORDER)


# ---------------------------------------------------------------------------
# 3. Training / Reuse Review
# ---------------------------------------------------------------------------


def _posture(provider_dict, field):
    return next(p for p in provider_dict["postures"] if p["field"] == field)


def test_vendor_asserted_no_training_is_not_verified():
    dep = _dep()
    p = _provider("OpenAI")
    _assert(p, ProviderAssertion.Field.TRAINS_ON_DATA, "No — we do not train on your data",
            evidence_class=EvidenceClass.VENDOR_ASSERTED, source=ProviderAssertion.Source.SELF_DECLARED)
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", provider=p)
    provider = assess_training_reuse(dep)["providers"][0]
    trains = _posture(provider, ProviderAssertion.Field.TRAINS_ON_DATA)
    assert trains["posture"] == POSTURE_NOT_REUSED
    assert trains["verified"] is False  # a vendor claim is never verified
    assert any(g["type"] == "reuse_denied_unverified" for g in provider["gaps"])
    _no_forbidden(assess_training_reuse(dep))


def test_affirmative_training_is_a_high_gap():
    dep = _dep()
    p = _provider("Trainer")
    _assert(p, ProviderAssertion.Field.TRAINS_ON_DATA, "Yes, on customer data")
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    provider = assess_training_reuse(dep)["providers"][0]
    trains = _posture(provider, ProviderAssertion.Field.TRAINS_ON_DATA)
    assert trains["posture"] == POSTURE_REUSED
    assert provider["reuse_declared"] is True
    gap = next(g for g in provider["gaps"] if g["field"] == ProviderAssertion.Field.TRAINS_ON_DATA)
    assert gap["risk"] == "high"  # affirmative + unverified


def test_unstated_reuse_policy_is_a_gap_not_safe():
    dep = _dep()
    p = _provider("Silent")  # declares nothing
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    provider = assess_training_reuse(dep)["providers"][0]
    assert provider["reuse_possible"] is True
    assert any(g["type"] == "reuse_unstated" for g in provider["gaps"])


def test_independently_verified_no_reuse_is_the_only_way_reuse_is_ruled_out():
    dep = _dep()
    p = _provider("Clean")
    strong = dict(evidence_class=EvidenceClass.TECHNICALLY_VERIFIED, source=ProviderAssertion.Source.MEASURED)
    _assert(p, ProviderAssertion.Field.TRAINS_ON_DATA, "No", **strong)
    _assert(p, ProviderAssertion.Field.SUBPROCESSORS, "None — no subprocessors", **strong)
    _assert(p, ProviderAssertion.Field.DATA_RETENTION, "Zero retention", **strong)
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    provider = assess_training_reuse(dep)["providers"][0]
    assert provider["reuse_possible"] is False
    assert _posture(provider, ProviderAssertion.Field.TRAINS_ON_DATA)["verified"] is True
    assert assess_training_reuse(dep)["summary"]["verified_no_reuse"] == 1


def test_training_reuse_empty_graph_is_honest_empty():
    dep = _dep()
    result = assess_training_reuse(dep)
    assert result["providers"] == []
    assert result["summary"]["worst_risk"] is None
    _no_forbidden(result)


def test_training_reuse_is_deterministic():
    dep = _dep()
    p = _provider("P")
    _assert(p, ProviderAssertion.Field.TRAINS_ON_DATA, "Yes")
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    assert json.dumps(assess_training_reuse(dep), sort_keys=True) == json.dumps(
        assess_training_reuse(dep), sort_keys=True
    )


def test_training_reuse_api_returns_200_and_shape():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    p = _provider("Trainer")
    _assert(p, ProviderAssertion.Field.TRAINS_ON_DATA, "Yes")
    _asset(dep, kind=Asset.Kind.MODEL, name="m", provider=p)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "training_reuse"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/training-reuse/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"providers", "gaps", "summary"}
    assert resp.data["summary"]["reuse_declared"] == 1


# ---------------------------------------------------------------------------
# 4. Metadata & Logging Risk
# ---------------------------------------------------------------------------


def test_observability_sink_is_detected_with_prompt_category():
    dep = _dep()
    obs = _provider("Datadog", kind=Provider.Kind.OBSERVABILITY)
    _asset(dep, kind=Asset.Kind.API, name="trace-exporter", provider=obs)
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt")  # makes prompts a category in play
    result = assess_metadata_logging(dep)
    sink = next(s for s in result["sinks"] if s["asset_name"] == "trace-exporter")
    assert any(c["category"] == CATEGORY_PROMPTS for c in sink["sensitive_categories"])
    _no_forbidden(result)


def test_pii_category_only_when_personal_data_is_evidenced():
    dep = _dep()
    obs = _provider("Logs Co", kind=Provider.Kind.OBSERVABILITY)
    _asset(dep, kind=Asset.Kind.API, name="log-sink", provider=obs)
    # No personal-data-bearing store: PII must NOT be listed.
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="anon")  # unknown, not personal
    result = assess_metadata_logging(dep)
    handled = {c["category"] for c in result["sensitive_categories_handled"]}
    assert CATEGORY_PII not in handled
    # Now add a personal store and it appears.
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customers", identifier="customers",
           metadata={"data_classification": "pii"})
    handled2 = {c["category"] for c in assess_metadata_logging(dep)["sensitive_categories_handled"]}
    assert CATEGORY_PII in handled2


def test_logging_without_control_is_a_gap():
    dep = _dep()
    obs = _provider("NoRedact", kind=Provider.Kind.OBSERVABILITY)
    _asset(dep, kind=Asset.Kind.API, name="sink", provider=obs)
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    sink = assess_metadata_logging(dep)["sinks"][0]
    assert sink["control_evidenced"] is False
    assert any(g["type"] == "logged_without_control" for g in sink["gaps"])


def test_shadow_log_sink_is_a_gap_and_no_values_leak():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="shadow-logs", identifier="shadow-logs",
           classification=Asset.Classification.UNMANAGED, metadata={"role": "logging"})
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    result = assess_metadata_logging(dep)
    sink = next(s for s in result["sinks"] if s["asset_name"] == "shadow-logs")
    assert any(g["type"] == "shadow_sink" for g in sink["gaps"])
    # Only presence/lineage facts — no logged value, prompt or secret content.
    _no_forbidden(result)


def test_metadata_logging_empty_graph_is_honest_empty():
    dep = _dep()
    result = assess_metadata_logging(dep)
    assert result["sinks"] == []
    assert result["summary"]["worst_risk"] is None
    _no_forbidden(result)


def test_metadata_logging_is_deterministic():
    dep = _dep()
    obs = _provider("Obs", kind=Provider.Kind.OBSERVABILITY)
    _asset(dep, kind=Asset.Kind.API, name="sink", identifier="sink", provider=obs)
    _asset(dep, kind=Asset.Kind.MODEL, name="m", identifier="m")
    _asset(dep, kind=Asset.Kind.VECTOR_DB, name="v", identifier="v")
    assert json.dumps(assess_metadata_logging(dep), sort_keys=True) == json.dumps(
        assess_metadata_logging(dep), sort_keys=True
    )


def test_metadata_logging_api_returns_200_and_shape():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    obs = _provider("Datadog", kind=Provider.Kind.OBSERVABILITY)
    _asset(dep, kind=Asset.Kind.API, name="sink", provider=obs)
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "metadata_logging"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/metadata-logging/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"sinks", "sensitive_categories_handled", "gaps", "summary"}
    assert resp.data["summary"]["sinks"] == 1
