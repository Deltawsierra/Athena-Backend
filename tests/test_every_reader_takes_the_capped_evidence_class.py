"""#343, round 2: every reader of a provider assertion takes the capped class.

Round 1 capped the evidence class a claim takes from a provider assertion at what
the assertion's source can prove (``ProviderAssertion.effective_evidence_class``).
The claim derivers read the cap; every other reader still read the raw label. A
self-declared -- or unsourced -- "configuration_verified" fact read as
independently evidenced on the vendor-assurance view, verified on the
training-reuse view, an evidenced logging control with no gap on the
metadata-logging view, and the provider profile's, the vendor posture's and the
executive summary's weakest evidence all read configuration_verified.

There is one accessor, and every reader uses it. The raw label is read only to
echo what was declared -- the assertion's own serializer field, and
``declared_evidence_class`` beside the capped class -- or to fingerprint it. The
last test holds the line: no attribute read of ``evidence_class`` anywhere in the
application code may be a provider assertion's, outside the accessors.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance.models import Asset, DataBoundary, Deployment, EvidenceClass, Provider, ProviderAssertion

pytestmark = pytest.mark.django_db

User = get_user_model()
Source = ProviderAssertion.Source

_FIELDS = (
    ("region", "eu-west-1"),
    ("trains_on_data", "No"),
    ("subprocessors", "none"),
    ("data_retention", "none"),
    ("logging", "PII redaction on all traces"),
)


def _views(source):
    """Every reader of the same five assertions, all labelled configuration_verified."""
    admin = User.objects.create_user(username=f"reader-{source or 'blank'}", password=None, role=User.Roles.ADMIN)
    client = APIClient()
    client.force_authenticate(user=admin)
    dep = Deployment.objects.create(name=f"cap-{source or 'blank'}", owner=admin)
    provider = Provider.objects.create(name=f"Obs Co {source or 'blank'}", kind=Provider.Kind.OBSERVABILITY)
    for field, value in _FIELDS:
        response = client.post(
            "/api/assurance/provider-assertions/",
            {"provider": str(provider.uuid), "field": field, "value": value,
             "evidence_class": "configuration_verified", "source": source},
            format="json",
        )
        assert response.status_code == 201, response.content
    Asset.objects.create(
        deployment=dep, provider=provider, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
        classification=Asset.Classification.APPROVED,
    )
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False
    )
    base = f"/api/assurance/deployments/{dep.uuid}"
    return {
        name: client.get(url).json()
        for name, url in (
            ("vendor", f"{base}/vendor-assurance/"),
            ("training", f"{base}/training-reuse/"),
            ("logging", f"{base}/metadata-logging/"),
            ("lifecycle", f"{base}/data-lifecycle/"),
            ("executive", f"{base}/executive-summary/"),
            ("bom", f"{base}/ai-bom/"),
            ("provider", f"/api/assurance/providers/{provider.uuid}/"),
        )
    }


def _logged_by_provider(lifecycle, name):
    for stage in lifecycle["stages"]:
        for component in stage["components"]:
            if component["name"] == name:
                yield stage["stage"], component["evidence_class"]


@pytest.mark.parametrize("source", [Source.SELF_DECLARED, ""])
def test_a_vendors_word_labelled_configuration_verified_reads_as_the_vendors_word_everywhere(source):
    views = _views(source)
    capped = EvidenceClass.VENDOR_ASSERTED.value

    vendor = views["vendor"]["vendors"][0]
    assert [a["evidence_class"] for a in vendor["assertions"]] == [capped] * 5
    assert [a["declared_evidence_class"] for a in vendor["assertions"]] == ["configuration_verified"] * 5
    assert not any(a["independently_evidenced"] for a in vendor["assertions"])
    assert vendor["weakest_evidence"] == capped
    assert vendor["summary"]["gap_count"] >= 5
    assert views["vendor"]["summary"]["assertions_by_evidence_strength"] == {capped: 5}
    assert views["vendor"]["summary"]["independently_evidenced"] == 0

    training = views["training"]["providers"][0]
    assert [p["verified"] for p in training["postures"]] == [False, False, False]
    assert {p["evidence_class"] for p in training["postures"]} == {capped}

    sink = views["logging"]["sinks"][0]
    assert "control_unverified" in [g["type"] for g in sink["gaps"]]

    provider_name = f"Obs Co {source or 'blank'}"
    assert {cls for _, cls in _logged_by_provider(views["lifecycle"], provider_name)} == {capped}

    assert views["provider"]["profile"]["weakest_evidence"] == capped
    assert {a["effective_evidence_class"] for a in views["provider"]["assertions"]} == {capped}
    assert {a["evidence_class"] for a in views["provider"]["assertions"]} == {"configuration_verified"}

    assert views["executive"]["assessments"]["vendors"]["independently_evidenced"] == 0
    assert views["bom"]["providers"][0]["weakest_evidence"] == capped


def test_a_measured_fact_keeps_its_label_everywhere():
    """The control: an independent measurement is what the label says."""
    views = _views(Source.MEASURED)
    vendor = views["vendor"]["vendors"][0]
    assert all(a["independently_evidenced"] for a in vendor["assertions"])
    assert vendor["weakest_evidence"] == "configuration_verified"
    assert [p["verified"] for p in views["training"]["providers"][0]["postures"]] == [True, True, True]
    assert "control_unverified" not in [g["type"] for g in views["logging"]["sinks"][0]["gaps"]]
    assert views["provider"]["profile"]["weakest_evidence"] == "configuration_verified"


# ---------------------------------------------------------------------------
# The line: no raw read of a provider assertion's label outside its accessors
# ---------------------------------------------------------------------------

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Every ``.evidence_class`` / ``.get_evidence_class_display()`` read in the
#: application code, keyed ``(file, enclosing function, receiver)``, that is NOT a
#: provider assertion's -- with the model it reads. A new read must be classified
#: here: if its receiver can be a ProviderAssertion it must go through
#: ``effective_evidence_class`` (any judgment) or ``declared_evidence_class`` (an
#: echo of the label, or a fingerprint of it) instead.
_NOT_A_PROVIDER_ASSERTION = {
    ("assurance/bundle.py", "_claim_rows", "claim"): "AssuranceClaim",
    ("assurance/claims.py", "_can_verify", "claim"): "AssuranceClaim",
    ("assurance/decision.py", "_decision_from_findings", "f"): "Finding",
    ("assurance/evidence_audit.py", "_intrinsic_reasons", "item"): "ClaimEvidence",
    ("assurance/evidence_audit.py", "audit_of", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "audit_claim", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "evidence_record", "item"): "ClaimEvidence",
    ("assurance/fingerprint.py", "_provider_descriptor", "provider"): "Provider",
    ("assurance/incident.py", "_evidence", "finding"): "Finding",
    ("assurance/posture/base.py", "PostureFinding.as_dict", "self"): "PostureFinding",
    ("assurance/posture/base.py", "_weakest_evidence", "f"): "PostureFinding",
    ("assurance/roi.py", "_evidence_and_findings", "finding"): "Finding",
    ("assurance/unknowns.py", "_derive_finding_unknowns", "finding"): "Finding",
}

#: The accessors themselves: the only place a provider assertion's label is read.
_ACCESSORS = {
    ("assurance/models.py", "ProviderAssertion.effective_evidence_class", "self"),
    ("assurance/models.py", "ProviderAssertion.declared_evidence_class", "self"),
}


def _label_reads():
    """``(file, qualname, receiver, line)`` for every load of ``X.evidence_class``,
    ``X.get_evidence_class_display()`` and ``getattr(X, "evidence_class")`` in the
    application code (tests and migrations aside)."""
    out = []
    for path in sorted(_ROOT.rglob("*.py")):
        rel = path.relative_to(_ROOT).as_posix()
        if rel.startswith(("tests/", ".venv/", "venv/", "node_modules/", "frontend/")) or "/migrations/" in rel:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        stack: list[str] = []

        def visit(node):
            scoped = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            if scoped:
                stack.append(node.name)
            if (
                isinstance(node, ast.Attribute)
                and node.attr in ("evidence_class", "get_evidence_class_display")
                and isinstance(node.ctx, ast.Load)
            ):
                out.append((rel, ".".join(stack), ast.unparse(node.value), node.lineno))
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "evidence_class"
            ):
                out.append((rel, ".".join(stack), ast.unparse(node.args[0]), node.lineno))
            for child in ast.iter_child_nodes(node):
                visit(child)
            if scoped:
                stack.pop()

        visit(tree)
    return out


def test_no_reader_takes_a_provider_assertions_raw_label_outside_its_accessors():
    reads = _label_reads()
    assert reads, "the scan found nothing: it is not looking where the code is"
    unclassified = [
        f"{rel}:{line} in {qual or '<module>'}: {receiver}.evidence_class"
        for rel, qual, receiver, line in reads
        if (rel, qual, receiver) not in _NOT_A_PROVIDER_ASSERTION and (rel, qual, receiver) not in _ACCESSORS
    ]
    assert unclassified == [], (
        "A raw evidence_class read that may be a provider assertion's. Read "
        "effective_evidence_class (a judgment) or declared_evidence_class (an echo "
        "or fingerprint of the label), or add it to _NOT_A_PROVIDER_ASSERTION with "
        "the model it reads:\n" + "\n".join(unclassified)
    )
    # The accessors are what the scan says they are.
    assert {(rel, qual, receiver) for rel, qual, receiver, _ in reads} >= _ACCESSORS


def test_the_declared_label_is_the_label_and_the_effective_class_is_capped():
    assertion = ProviderAssertion(evidence_class=EvidenceClass.CONFIGURATION_VERIFIED, source=Source.SELF_DECLARED)
    assert assertion.declared_evidence_class == EvidenceClass.CONFIGURATION_VERIFIED
    assert assertion.effective_evidence_class == EvidenceClass.VENDOR_ASSERTED
