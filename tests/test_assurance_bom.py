"""Athena Phase 1.7 — AI-BOM (AI supply-chain bill of materials).

Proves the BOM aggregates the asset graph and provider profiles into one
exportable artifact honestly: every component is listed with its provider and
salient facts; each provider fact carries its evidence class and the profile's
weakest link is surfaced; an unmanaged component is flagged as shadow supply
chain; the digest is deterministic over stable content (not the timestamp) so a
recipient can verify it, and it changes when the inventory changes; and the API
read is open to any operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import bom
from assurance.bom import build_ai_bom
from assurance.models import Asset, Deployment, EvidenceClass, Provider, ProviderAssertion
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name, kind=Provider.Kind.MODEL_PROVIDER, region="", **assertions):
    p = Provider.objects.create(name=name, kind=kind, region=region)
    for field, (value, ev) in assertions.items():
        ProviderAssertion.objects.create(provider=p, field=field, value=value, evidence_class=ev)
    return p


def _asset(dep, *, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN, name="c", identifier=None, provider=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification, provider=provider,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def test_bom_lists_components_with_their_facts_and_provider():
    dep = Deployment.objects.create(name="acme", owner=_user())
    prov = _provider("OpenAI")
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt-x", provider=prov,
           metadata={"model": "gpt-x", "version": "2026-01", "base_url": "https://api.openai.com"})

    result = build_ai_bom(dep)
    assert result["format"] == bom.BOM_FORMAT and result["version"] == bom.BOM_VERSION
    comp = result["components"][0]
    assert comp["name"] == "gpt-x"
    assert comp["provider_name"] == "OpenAI"
    assert comp["facts"]["version"] == "2026-01"
    assert result["summary"]["component_count"] == 1
    assert result["summary"]["provider_count"] == 1


def test_provider_facts_are_evidence_graded_and_the_weakest_is_surfaced():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "OpenAI",
        data_retention=("30 days", EvidenceClass.TECHNICALLY_VERIFIED),
        trains_on_data=("No", EvidenceClass.VENDOR_ASSERTED),
    )
    _asset(dep, provider=prov, name="m")

    entry = build_ai_bom(dep)["providers"][0]
    fields = {f["field"]: f for f in entry["declared_facts"]}
    assert fields["data_retention"]["evidence_class"] == EvidenceClass.TECHNICALLY_VERIFIED
    # The weakest fact (vendor_asserted) is the profile's honest headline.
    assert entry["weakest_evidence"] == EvidenceClass.VENDOR_ASSERTED
    assert entry["declared_field_count"] == 2


def test_an_unmanaged_component_is_flagged_as_shadow_supply_chain():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MCP_SERVER, name="rogue",
           classification=Asset.Classification.UNMANAGED, identifier="mcp://rogue")
    result = build_ai_bom(dep)
    assert result["summary"]["shadow_components"] == 1
    assert result["components"][0]["shadow"] is True


def test_summary_tallies_components_by_kind_and_classification():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    _asset(dep, kind=Asset.Kind.TOOL, name="t", classification=Asset.Classification.APPROVED)
    _asset(dep, kind=Asset.Kind.TOOL, name="t2")
    summary = build_ai_bom(dep)["summary"]
    assert summary["components_by_kind"]["tool"] == 2
    assert summary["components_by_kind"]["model"] == 1
    assert summary["components_by_classification"]["approved"] == 1


def test_digest_is_deterministic_over_stable_content_not_the_timestamp():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider("OpenAI", data_retention=("30 days", EvidenceClass.VENDOR_ASSERTED))
    _asset(dep, provider=prov, name="m")

    a = build_ai_bom(dep)
    b = build_ai_bom(dep)
    # Same DB state → identical digest, even though generated_at differs.
    assert a["receipt"]["digest"] == b["receipt"]["digest"]
    assert a["receipt"]["algorithm"] == "sha256"


def test_digest_changes_when_the_inventory_changes():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    before = build_ai_bom(dep)["receipt"]["digest"]
    _asset(dep, kind=Asset.Kind.TOOL, name="t", identifier="t")
    after = build_ai_bom(dep)["receipt"]["digest"]
    assert before != after


def test_empty_deployment_is_an_honest_empty_bom():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = build_ai_bom(dep)
    assert result["components"] == []
    assert result["providers"] == []
    assert result["summary"]["weakest_evidence"] is None
    # Even an empty BOM has a stable, recomputable digest.
    assert len(result["receipt"]["digest"]) == 64


def test_ai_bom_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.MODEL, name="m")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "ai_bom"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/ai-bom/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["component_count"] == 1
    assert resp.data["deployment"]["name"] == "d"
