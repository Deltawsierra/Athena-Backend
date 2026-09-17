"""Athena Phase 2.1 — Compliance mapping expansion.

Proves the compliance map is an honest, computed layer over findings that already
exist: a finding lands on the NIST / OWASP / OWASP-LLM / DoD-ZT controls its type
maps to, a finding_type that maps nowhere is surfaced in ``unmapped`` rather than
dropped, only active findings count as open control gaps (a resolved one is listed
as historically touched but is not a gap), the worst severity per control is the
worst among its *active* findings, the engine's own per-finding ``control_mapping``
ids are merged in (OWASP onto the framework, CWE/MITRE into engine references), the
output is deterministic, and the API read is open to any operator. The map is
evidence of gaps, never a certificate that a control passes.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import compliance
from assurance.compliance import (
    FRAMEWORK_DOD_ZT,
    FRAMEWORK_NIST,
    FRAMEWORK_OWASP,
    FRAMEWORK_OWASP_LLM,
    build_compliance_map,
)
from assurance.models import Deployment, Finding
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, finding_type, severity="high", *, status=Finding.Status.OPEN, control_mapping=None, n="1"):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{finding_type}-{n}",
        finding_type=finding_type,
        title=finding_type.replace("_", " ").title(),
        severity=severity,
        status=status,
        control_mapping=control_mapping or {},
    )


def _framework(result, key):
    return next(f for f in result["frameworks"] if f["key"] == key)


def _controls_by_id(framework):
    return {c["control_id"]: c for c in framework["controls"]}


def test_finding_maps_to_expected_controls_across_frameworks():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "critical")

    result = build_compliance_map(dep)
    nist = _controls_by_id(_framework(result, FRAMEWORK_NIST))
    owasp = _controls_by_id(_framework(result, FRAMEWORK_OWASP))
    dod = _controls_by_id(_framework(result, FRAMEWORK_DOD_ZT))

    # SQLi is input validation + vuln scanning in NIST, Injection in OWASP.
    assert "SI-10" in nist and "RA-5" in nist
    assert nist["SI-10"]["name"] == "Information Input Validation"
    assert nist["SI-10"]["family"] == "SI"
    assert nist["SI-10"]["family_name"] == "System and Information Integrity"
    assert "A03:2021" in owasp and owasp["A03:2021"]["name"] == "Injection"
    # DoD Zero Trust pillars are the framework's controls.
    assert "data" in dod and dod["data"]["name"] == "Data"
    # The type is recorded on the control it touched.
    assert nist["SI-10"]["finding_types"] == ["sql_injection"]


def test_prompt_injection_maps_to_the_llm_control():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "prompt_injection", "high")

    llm = _controls_by_id(_framework(build_compliance_map(dep), FRAMEWORK_OWASP_LLM))
    assert "LLM01" in llm
    assert llm["LLM01"]["name"] == "Prompt Injection"
    assert llm["LLM01"]["active_finding_count"] == 1


def test_unmapped_finding_type_is_surfaced_not_dropped():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high", n="a")
    _finding(dep, "quantum_teapot_anomaly", "medium", n="b")

    result = build_compliance_map(dep)
    unmapped_types = {u["finding_type"] for u in result["unmapped"]}
    assert "quantum_teapot_anomaly" in unmapped_types
    # The unmapped type reaches no framework control.
    for framework in result["frameworks"]:
        for control in framework["controls"]:
            assert "quantum_teapot_anomaly" not in control["finding_types"]
    entry = next(u for u in result["unmapped"] if u["finding_type"] == "quantum_teapot_anomaly")
    assert entry["active_finding_count"] == 1
    assert entry["worst_severity"] == "medium"
    assert result["summary"]["unmapped_finding_types"] == 1
    assert result["summary"]["mapped_finding_types"] == 1


def test_resolved_findings_are_historically_touched_not_open_gaps():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One resolved (verified-closed) SQLi, nothing active.
    _finding(dep, "sql_injection", "critical", status=Finding.Status.CLOSED, n="c")

    result = build_compliance_map(dep)
    nist = _controls_by_id(_framework(result, FRAMEWORK_NIST))
    # The control is still listed (historically touched)...
    assert "SI-10" in nist
    assert nist["SI-10"]["resolved_finding_count"] == 1
    # ...but it is NOT an open gap: no active findings, no worst severity.
    assert nist["SI-10"]["active_finding_count"] == 0
    assert nist["SI-10"]["worst_severity"] is None
    assert _framework(result, FRAMEWORK_NIST)["summary"]["controls_with_active_findings"] == 0
    assert result["summary"]["active_findings"] == 0
    assert result["summary"]["resolved_findings"] == 1
    assert result["summary"]["worst_severity"] is None


def test_worst_severity_per_control_is_the_worst_active_finding():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Two active injections on A03: low and high → worst active is high.
    _finding(dep, "sql_injection", "low", n="lo")
    _finding(dep, "xss", "high", n="hi")
    # A resolved critical injection must NOT raise the control's worst severity.
    _finding(dep, "command_injection", "critical", status=Finding.Status.ACCEPTED, n="cr")

    owasp = _controls_by_id(_framework(build_compliance_map(dep), FRAMEWORK_OWASP))
    a03 = owasp["A03:2021"]
    assert a03["active_finding_count"] == 2
    assert a03["resolved_finding_count"] == 1
    assert a03["worst_severity"] == "high"  # not "critical" — that one is resolved
    assert a03["finding_types"] == ["command_injection", "sql_injection", "xss"]


def test_engine_control_mapping_ids_are_merged_in():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A CORS finding maps to A05 statically; the engine also attached A01 and a CWE.
    _finding(
        dep,
        "cors_misconfiguration",
        "high",
        control_mapping={"owasp": ["A01:2021"], "cwe": ["CWE-942"]},
    )

    result = build_compliance_map(dep)
    owasp = _controls_by_id(_framework(result, FRAMEWORK_OWASP))
    # Both the curated (A05) and the engine-attested (A01) OWASP controls are present.
    assert "A05:2021" in owasp
    assert "A01:2021" in owasp
    # The CWE id names no curated framework, so it rides in engine_references.
    refs = {(r["taxonomy"], r["id"]) for r in result["engine_references"]}
    assert ("cwe", "CWE-942") in refs


def test_engine_references_carry_cwe_and_mitre_untouched():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(
        dep,
        "sql_injection",
        "high",
        control_mapping={"mitre": ["T1190"], "cwe": ["CWE-89"]},
        n="a",
    )
    _finding(dep, "sql_injection", "medium", control_mapping={"cwe": ["CWE-89"]}, n="b")

    refs = {(r["taxonomy"], r["id"]): r for r in build_compliance_map(dep)["engine_references"]}
    assert ("mitre", "T1190") in refs
    assert ("cwe", "CWE-89") in refs
    # CWE-89 was carried by two findings.
    assert refs[("cwe", "CWE-89")]["finding_count"] == 2
    assert refs[("cwe", "CWE-89")]["finding_types"] == ["sql_injection"]


def test_engine_owasp_id_outside_catalog_is_surfaced_uncatalogued():
    dep = Deployment.objects.create(name="d", owner=_user())
    # An OWASP-keyed id we do not itemise in the catalog must still be surfaced,
    # flagged as un-catalogued, never silently dropped.
    _finding(dep, "sql_injection", "high", control_mapping={"owasp": ["A99:2021"]})

    owasp = _controls_by_id(_framework(build_compliance_map(dep), FRAMEWORK_OWASP))
    assert "A99:2021" in owasp
    assert owasp["A99:2021"]["catalogued"] is False
    assert owasp["A99:2021"]["name"] is None
    # A real catalogued control reports catalogued True.
    assert owasp["A03:2021"]["catalogued"] is True


def test_framework_rollup_and_overall_summary():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "critical", n="a")  # NIST/OWASP/DoD
    _finding(dep, "prompt_injection", "high", n="b")  # + LLM

    result = build_compliance_map(dep)
    owasp = _framework(result, FRAMEWORK_OWASP)
    assert owasp["summary"]["worst_severity"] == "critical"
    assert owasp["summary"]["controls_with_active_findings"] >= 1
    # Worst active across every framework is the critical.
    assert result["summary"]["worst_severity"] == "critical"
    assert result["summary"]["frameworks"] == 4
    assert result["summary"]["total_findings"] == 2
    # The most-concerning control leads each framework's list.
    assert owasp["controls"][0]["worst_severity"] == "critical"


def test_empty_deployment_is_an_honest_empty_map():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = build_compliance_map(dep)
    assert [f["key"] for f in result["frameworks"]] == [
        FRAMEWORK_NIST,
        FRAMEWORK_OWASP,
        FRAMEWORK_OWASP_LLM,
        FRAMEWORK_DOD_ZT,
    ]
    for framework in result["frameworks"]:
        assert framework["controls"] == []
        assert framework["summary"]["controls_touched"] == 0
        assert framework["summary"]["worst_severity"] is None
    assert result["unmapped"] == []
    assert result["engine_references"] == []
    assert result["summary"]["total_findings"] == 0
    assert result["summary"]["worst_severity"] is None


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high", n="a")
    _finding(dep, "xss", "medium", n="b")
    _finding(dep, "quantum_teapot_anomaly", "low", n="c")
    assert build_compliance_map(dep) == build_compliance_map(dep)


def test_the_map_reads_as_gaps_not_a_compliance_certificate():
    # A touched control must never be phrased as "compliant"/"passed": the field
    # vocabulary is about findings landing on controls (evidence of gaps).
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high")
    control = _framework(build_compliance_map(dep), FRAMEWORK_OWASP)["controls"][0]
    assert "active_finding_count" in control
    assert not any(k in control for k in ("compliant", "passed", "satisfied", "met"))


def test_curated_catalogs_are_present_and_complete():
    # NIST families: the 18 the roadmap names.
    assert set(compliance._NIST_FAMILIES) == {
        "AC", "AU", "AT", "CA", "CM", "CP", "IA", "IR", "MA",
        "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI", "SR",
    }
    assert len(compliance._OWASP_CONTROLS) == 10
    assert len(compliance._OWASP_LLM_CONTROLS) == 10
    assert len(compliance._DOD_ZT_CONTROLS) == 7
    # Every curated NIST control belongs to a catalogued family.
    for control_id in compliance._NIST_CONTROLS:
        family = control_id.split("-", 1)[0]
        assert family in compliance._NIST_FAMILIES


def test_compliance_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _finding(dep, "sql_injection", "high")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "compliance"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/compliance/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["total_findings"] == 1
    owasp = next(f for f in resp.data["frameworks"] if f["key"] == FRAMEWORK_OWASP)
    assert owasp["controls"][0]["control_id"] == "A03:2021"
