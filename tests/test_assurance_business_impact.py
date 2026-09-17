"""Athena Phase 2.4 — Business-impact mapping.

Proves the business-impact map is an honest, computed layer over findings that
already exist: a finding's type implicates the business-impact *dimensions* it
maps to, weighted by severity; the worst severity and the ordinal exposure band
per dimension are correct and read only the *active* findings; a resolved finding
is listed as historically implicated but does not count as active exposure; a
finding_type implying no dimension is surfaced in ``unmapped`` rather than dropped;
the output is deterministic; and the API read is open to any operator. Every field
is inferred *potential* exposure from type and severity — never a realized loss, a
dollar figure, or a claim the business was harmed.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import business_impact
from assurance.business_impact import (
    BAND_ELEVATED,
    BAND_LOW,
    BAND_MODERATE,
    DIMENSION_CUSTOMER_TRUST,
    DIMENSION_DATA_CONFIDENTIALITY,
    DIMENSION_FINANCIAL,
    DIMENSION_OPERATIONAL,
    DIMENSION_REGULATORY,
    DIMENSION_SAFETY,
    build_business_impact,
)
from assurance.models import Deployment, Finding
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, finding_type, severity="high", *, status=Finding.Status.OPEN, n="1"):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{finding_type}-{n}",
        finding_type=finding_type,
        title=finding_type.replace("_", " ").title(),
        severity=severity,
        status=status,
    )


def _dims_by_key(result):
    return {d["key"]: d for d in result["dimensions"]}


def test_finding_maps_to_expected_dimensions():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high")

    result = build_business_impact(dep)
    dims = _dims_by_key(result)
    # SQLi implicates data confidentiality, regulatory, and customer trust.
    assert set(dims) == {
        DIMENSION_DATA_CONFIDENTIALITY,
        DIMENSION_REGULATORY,
        DIMENSION_CUSTOMER_TRUST,
    }
    conf = dims[DIMENSION_DATA_CONFIDENTIALITY]
    assert conf["label"] == "Data confidentiality"
    assert conf["finding_types"] == ["sql_injection"]
    assert conf["active_finding_count"] == 1
    assert result["summary"]["mapped_finding_types"] == 1
    assert result["summary"]["dimensions_touched"] == 3


def test_mapped_finding_types_are_counted_case_insensitively():
    """Regression: the crosswalk lookup is case-insensitive, but the distinct-type
    count used to store the non-lowercased type. "SQL_Injection" and "sql_injection"
    then double-counted as two mapped types though they map identically. They must
    count as one."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "SQL_Injection", "high", n="upper")
    _finding(dep, "sql_injection", "high", n="lower")

    result = build_business_impact(dep)
    # Both are the same crosswalk type — one distinct mapped finding type, not two.
    assert result["summary"]["mapped_finding_types"] == 1


def test_hinted_crosswalk_entries():
    # The crosswalk entries the roadmap named explicitly.
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "auth_bruteforce", "high", n="a")
    _finding(dep, "excessive_agency", "high", n="b")
    _finding(dep, "command_injection", "high", n="c")
    _finding(dep, "missing_security_header", "high", n="d")

    dims = _dims_by_key(build_business_impact(dep))
    assert set(dims[DIMENSION_CUSTOMER_TRUST]["finding_types"]) >= {"auth_bruteforce"}
    # auth_bruteforce -> customer_trust + operational
    assert "auth_bruteforce" in dims[DIMENSION_OPERATIONAL]["finding_types"]
    # excessive_agency / command_injection -> operational + safety
    assert {"excessive_agency", "command_injection"} <= set(dims[DIMENSION_SAFETY]["finding_types"])
    assert {"excessive_agency", "command_injection"} <= set(dims[DIMENSION_OPERATIONAL]["finding_types"])
    # missing_security_header -> operational only
    assert "missing_security_header" in dims[DIMENSION_OPERATIONAL]["finding_types"]
    for key, dim in dims.items():
        if key != DIMENSION_OPERATIONAL:
            assert "missing_security_header" not in dim["finding_types"]


def test_financial_dimension_is_reserved_for_direct_cost_exposure():
    # ``financial`` is only asserted where the finding type IS direct cost/fraud
    # exposure — not inferred from a data breach, which would read as a loss figure.
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "unbounded_consumption", "high")

    dims = _dims_by_key(build_business_impact(dep))
    assert DIMENSION_FINANCIAL in dims
    assert dims[DIMENSION_FINANCIAL]["finding_types"] == ["unbounded_consumption"]
    assert DIMENSION_OPERATIONAL in dims


def test_worst_severity_and_band_read_only_active_findings():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Two active SQLi on data_confidentiality: low and high -> worst active is high.
    _finding(dep, "sql_injection", "low", n="lo")
    _finding(dep, "sql_injection", "high", n="hi")
    # A resolved critical SQLi must NOT raise the dimension's worst severity or band.
    _finding(dep, "sql_injection", "critical", status=Finding.Status.ACCEPTED, n="cr")

    dims = _dims_by_key(build_business_impact(dep))
    conf = dims[DIMENSION_DATA_CONFIDENTIALITY]
    assert conf["active_finding_count"] == 2
    assert conf["resolved_finding_count"] == 1
    assert conf["worst_severity"] == "high"  # not "critical" — that one is resolved
    assert conf["exposure_band"] == BAND_ELEVATED


def test_exposure_band_derives_from_severity():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A single medium misconfiguration -> operational at the moderate band.
    _finding(dep, "misconfiguration", "medium")
    dims = _dims_by_key(build_business_impact(dep))
    assert dims[DIMENSION_OPERATIONAL]["worst_severity"] == "medium"
    assert dims[DIMENSION_OPERATIONAL]["exposure_band"] == BAND_MODERATE


def test_exposure_band_is_raised_by_a_concentration_of_findings():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Three active low findings on operational -> concentration raises low to moderate.
    for i in range(3):
        _finding(dep, "misconfiguration", "low", n=str(i))
    dims = _dims_by_key(build_business_impact(dep))
    op = dims[DIMENSION_OPERATIONAL]
    assert op["active_finding_count"] == 3
    assert op["worst_severity"] == "low"
    assert op["exposure_band"] == BAND_MODERATE  # raised one step from low


def test_resolved_findings_are_historically_implicated_not_active_exposure():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One resolved (verified-closed) SQLi, nothing active.
    _finding(dep, "sql_injection", "critical", status=Finding.Status.CLOSED, n="c")

    result = build_business_impact(dep)
    conf = _dims_by_key(result)[DIMENSION_DATA_CONFIDENTIALITY]
    # The dimension is still listed (historically implicated)...
    assert conf["resolved_finding_count"] == 1
    # ...but it is NOT active exposure: no active findings, no severity, no band.
    assert conf["active_finding_count"] == 0
    assert conf["worst_severity"] is None
    assert conf["exposure_band"] is None
    assert result["summary"]["active_findings"] == 0
    assert result["summary"]["resolved_findings"] == 1
    assert result["summary"]["dimensions_with_active_exposure"] == 0
    assert result["summary"]["worst_severity"] is None
    assert result["summary"]["worst_exposure_band"] is None


def test_unmapped_finding_type_is_surfaced_not_dropped():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high", n="a")
    _finding(dep, "quantum_teapot_anomaly", "medium", n="b")

    result = build_business_impact(dep)
    unmapped_types = {u["finding_type"] for u in result["unmapped"]}
    assert "quantum_teapot_anomaly" in unmapped_types
    # The unmapped type reaches no dimension.
    for dim in result["dimensions"]:
        assert "quantum_teapot_anomaly" not in dim["finding_types"]
    entry = next(u for u in result["unmapped"] if u["finding_type"] == "quantum_teapot_anomaly")
    assert entry["active_finding_count"] == 1
    assert entry["worst_severity"] == "medium"
    assert result["summary"]["unmapped_finding_types"] == 1
    assert result["summary"]["mapped_finding_types"] == 1


def test_dimensions_are_ordered_worst_exposure_first():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A critical SQLi (elevated across conf/regulatory/trust) plus a low-only
    # operational finding — the elevated dimensions must lead the list.
    _finding(dep, "sql_injection", "critical", n="a")
    _finding(dep, "missing_security_header", "low", n="b")

    result = build_business_impact(dep)
    bands = [d["exposure_band"] for d in result["dimensions"]]
    # No weaker band precedes a stronger one.
    assert bands == sorted(bands, key=lambda b: business_impact._band_rank(b))
    assert result["dimensions"][0]["exposure_band"] == BAND_ELEVATED
    assert result["summary"]["worst_exposure_band"] == BAND_ELEVATED
    assert result["summary"]["worst_severity"] == "critical"


def test_empty_deployment_is_an_honest_empty_map():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = build_business_impact(dep)
    assert result["dimensions"] == []
    assert result["unmapped"] == []
    assert result["summary"]["total_findings"] == 0
    assert result["summary"]["dimensions_touched"] == 0
    assert result["summary"]["worst_severity"] is None
    assert result["summary"]["worst_exposure_band"] is None
    # The curated dimension vocabulary is still reported by size.
    assert result["summary"]["dimensions"] == 6


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high", n="a")
    _finding(dep, "excessive_agency", "medium", n="b")
    _finding(dep, "unbounded_consumption", "low", n="c")
    _finding(dep, "quantum_teapot_anomaly", "low", n="d")
    assert build_business_impact(dep) == build_business_impact(dep)


def test_map_reads_as_potential_exposure_never_a_dollar_amount():
    # No field may read as a quantified financial loss or a currency amount.
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "unbounded_consumption", "high")
    result = build_business_impact(dep)
    dim = result["dimensions"][0]
    forbidden = ("amount", "dollar", "usd", "currency", "cost_estimate", "loss", "arr", "revenue")
    assert not any(k in dim for k in forbidden)
    # The band is an ordinal string, never a number.
    assert dim["exposure_band"] in {BAND_ELEVATED, BAND_MODERATE, BAND_LOW}
    assert not isinstance(dim["exposure_band"], (int, float))


def test_no_per_process_or_owner_attribution_is_invented():
    # The model carries no business-process/owner-of-process field, so the map must
    # not invent per-process or per-owner entries — dimensions only.
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high")
    result = build_business_impact(dep)
    assert set(result) == {"dimensions", "unmapped", "summary"}
    for dim in result["dimensions"]:
        assert not any(k in dim for k in ("process", "business_process", "owner", "owners"))


def test_crosswalk_uses_only_curated_dimensions():
    valid = {
        DIMENSION_FINANCIAL,
        DIMENSION_REGULATORY,
        DIMENSION_CUSTOMER_TRUST,
        DIMENSION_OPERATIONAL,
        DIMENSION_DATA_CONFIDENTIALITY,
        DIMENSION_SAFETY,
    }
    assert len(valid) == 6
    for finding_type, keys in business_impact._FINDING_TYPE_DIMENSIONS.items():
        assert keys, f"{finding_type} maps to no dimension — surface as unmapped, not empty"
        assert set(keys) <= valid


def test_business_impact_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _finding(dep, "sql_injection", "high")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "business_impact"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/business-impact/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["total_findings"] == 1
    keys = {d["key"] for d in resp.data["dimensions"]}
    assert DIMENSION_DATA_CONFIDENTIALITY in keys
