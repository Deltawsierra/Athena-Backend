"""Athena — Third-Party Vendor Assurance.

Proves the vendor assessment is an honest, computed layer over the deployment's
providers and their graded assertions: each vendor's assertions are carried at
their true evidence strength; a ``vendor_asserted`` or ``self_declared`` assertion
reads as vendor-asserted and never as independently evidenced; a vendor is never
presented as secure — only an ordinal posture band derived from its weakest
evidence, raised when an unmanaged component depends on it; provider-less and
unmanaged dependencies are surfaced as gaps rather than dropped; the output is
deterministic; and the API read is open to any operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.capability import RISK_BASELINE, RISK_ELEVATED, RISK_HIGH
from assurance.models import (
    Asset,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
)
from assurance.vendor import assess_vendors
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER, **assertions):
    p = Provider.objects.create(name=name, kind=kind)
    for field, spec in assertions.items():
        value, ev = spec[0], spec[1]
        source = spec[2] if len(spec) > 2 else ProviderAssertion.Source.SELF_DECLARED
        ProviderAssertion.objects.create(
            provider=p, field=field, value=value, evidence_class=ev, source=source
        )
    return p


def _asset(dep, *, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN,
           name="c", provider=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification, provider=provider,
        name=name, identifier=name,
    )


def _vendors_by_name(result):
    return {v["provider_name"]: v for v in result["vendors"]}


def test_vendor_lists_assertions_and_dependent_assets():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "OpenAI",
        region=("us-east-1", EvidenceClass.CONTRACTUALLY_STATED, ProviderAssertion.Source.CONTRACT),
        trains_on_data=("No", EvidenceClass.VENDOR_ASSERTED, ProviderAssertion.Source.SELF_DECLARED),
    )
    _asset(dep, name="gpt-x", provider=prov)

    result = assess_vendors(dep)
    v = _vendors_by_name(result)["OpenAI"]
    fields = {a["field"]: a for a in v["assertions"]}
    assert set(fields) == {"region", "trains_on_data"}
    assert v["summary"]["dependent_asset_count"] == 1
    assert v["dependent_assets"][0]["asset_name"] == "gpt-x"
    assert v["dependent_assets"][0]["managed"] is True


def test_vendor_asserted_never_reads_as_independently_evidenced():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "Vend",
        # A vendor-asserted, self-declared claim: the weakest kind of evidence.
        trains_on_data=("No", EvidenceClass.VENDOR_ASSERTED, ProviderAssertion.Source.SELF_DECLARED),
    )
    _asset(dep, provider=prov, name="m")

    v = _vendors_by_name(assess_vendors(dep))["Vend"]
    a = v["assertions"][0]
    assert a["evidence_class"] == EvidenceClass.VENDOR_ASSERTED
    assert a["independently_evidenced"] is False
    assert a["gap"] is True
    assert v["summary"]["vendor_asserted"] == 1
    assert v["summary"]["independently_evidenced"] == 0


def test_self_declared_source_is_a_gap_even_if_labelled_strong():
    # A self-declared source is the vendor's own word — never independent, even if
    # someone labelled it with a strong evidence class.
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "Vend",
        region=("us-east-1", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.SELF_DECLARED),
    )
    _asset(dep, provider=prov, name="m")

    v = _vendors_by_name(assess_vendors(dep))["Vend"]
    a = v["assertions"][0]
    assert a["independently_evidenced"] is False
    assert a["gap"] is True


def test_independently_evidenced_assertion_is_recognised():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "Vend",
        region=("eu-west-1", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.MEASURED),
    )
    _asset(dep, provider=prov, name="m")

    v = _vendors_by_name(assess_vendors(dep))["Vend"]
    a = v["assertions"][0]
    assert a["independently_evidenced"] is True
    assert a["gap"] is False
    assert v["summary"]["independently_evidenced"] == 1


def test_posture_band_reflects_weakest_evidence_and_is_never_secure():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One strongly-evidenced fact, one bare vendor claim: the weakest link sets it.
    prov = _provider(
        "Vend",
        region=("eu-west-1", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.MEASURED),
        trains_on_data=("No", EvidenceClass.VENDOR_ASSERTED, ProviderAssertion.Source.SELF_DECLARED),
    )
    _asset(dep, provider=prov, name="m")

    v = _vendors_by_name(assess_vendors(dep))["Vend"]
    assert v["weakest_evidence"] == EvidenceClass.VENDOR_ASSERTED
    # Vendor-asserted weakest → elevated band. Never a "secure"/"compliant" string.
    assert v["posture_band"] == RISK_ELEVATED
    assert v["posture_band"] in {RISK_HIGH, RISK_ELEVATED, RISK_BASELINE}


def test_vendor_with_no_profile_is_high_band_and_a_gap():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider("Silent")  # no assertions
    _asset(dep, provider=prov, name="m")

    v = _vendors_by_name(assess_vendors(dep))["Silent"]
    assert v["weakest_evidence"] is None
    assert v["posture_band"] == RISK_HIGH
    assert v["summary"]["assertion_count"] == 0
    assert any("no assurance profile" in g for g in v["gaps"])


def test_unmanaged_dependency_raises_the_band_and_is_a_gap():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider(
        "Vend",
        region=("eu-west-1", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.MEASURED),
    )
    # An unmanaged (shadow) component depends on this otherwise well-evidenced vendor.
    _asset(dep, provider=prov, name="shadow", classification=Asset.Classification.UNMANAGED)

    v = _vendors_by_name(assess_vendors(dep))["Vend"]
    # Base band would be baseline (technically verified); the unmanaged dependency
    # raises it one step to elevated.
    assert v["posture_band"] == RISK_ELEVATED
    assert v["summary"]["unmanaged_dependencies"] == 1
    assert any("unmanaged dependency" in g for g in v["gaps"])


def test_provider_less_and_unmanaged_dependencies_are_surfaced():
    dep = Deployment.objects.create(name="d", owner=_user())
    prov = _provider("Vend", region=("eu-west-1", EvidenceClass.DOCUMENT_SUPPORTED, ProviderAssertion.Source.VENDOR_DOC))
    _asset(dep, provider=prov, name="m")
    # A component with no vendor behind it at all.
    _asset(dep, name="orphan", provider=None, kind=Asset.Kind.TOOL)
    # A component with no vendor AND unmanaged.
    _asset(dep, name="shadow", provider=None, kind=Asset.Kind.MCP_SERVER,
           classification=Asset.Classification.UNMANAGED)

    result = assess_vendors(dep)
    reasons = {u["asset_name"]: u["reason"] for u in result["ungoverned_dependencies"]}
    assert reasons["orphan"] == "no_provider"
    assert reasons["shadow"] == "no_provider_and_unmanaged"
    assert result["summary"]["provider_less_dependencies"] == 2
    assert result["summary"]["unmanaged_dependencies"] == 1


def test_summary_rolls_up_evidence_strength_and_worst_band():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, name="a", provider=_provider(
        "Strong", region=("eu", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.MEASURED)))
    _asset(dep, name="b", provider=_provider(
        "Weak", kind=Provider.Kind.GATEWAY,
        logging=("abuse only", EvidenceClass.UNKNOWN, ProviderAssertion.Source.SELF_DECLARED)))

    result = assess_vendors(dep)
    s = result["summary"]
    assert s["vendors"] == 2
    assert s["assertions_total"] == 2
    assert s["assertions_by_evidence_strength"][EvidenceClass.TECHNICALLY_VERIFIED] == 1
    assert s["assertions_by_evidence_strength"][EvidenceClass.UNKNOWN] == 1
    assert s["independently_evidenced"] == 1
    assert s["vendor_asserted"] == 1
    # Worst band across vendors is the "Weak" vendor's (unknown evidence → high).
    assert s["worst_posture_band"] == RISK_HIGH
    # Most-concerning vendor leads the list.
    assert result["vendors"][0]["provider_name"] == "Weak"


def test_no_vendor_is_ever_labelled_secure_or_compliant():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, provider=_provider(
        "Vend", region=("eu", EvidenceClass.VENDOR_ASSERTED, ProviderAssertion.Source.SELF_DECLARED)))
    result = assess_vendors(dep)
    v = result["vendors"][0]
    assert "secure" not in v and "compliant" not in v
    assert v["posture_band"] in {RISK_HIGH, RISK_ELEVATED, RISK_BASELINE}


def test_empty_deployment_is_an_honest_empty_view():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_vendors(dep)
    assert result["vendors"] == []
    assert result["ungoverned_dependencies"] == []
    assert result["summary"]["vendors"] == 0
    assert result["summary"]["worst_posture_band"] is None


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, name="a", provider=_provider(
        "Strong", region=("eu", EvidenceClass.TECHNICALLY_VERIFIED, ProviderAssertion.Source.MEASURED)))
    _asset(dep, name="b", provider=_provider("Silent", kind=Provider.Kind.GATEWAY))
    _asset(dep, name="orphan", provider=None)
    assert assess_vendors(dep) == assess_vendors(dep)


def test_vendor_assurance_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, provider=_provider(
        "OpenAI", region=("us-east-1", EvidenceClass.VENDOR_ASSERTED, ProviderAssertion.Source.SELF_DECLARED)))

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "vendor_assurance"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/vendor-assurance/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["vendors"] == 1
    assert resp.data["vendors"][0]["assertions"][0]["independently_evidenced"] is False
