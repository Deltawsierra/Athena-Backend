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
    ("assurance/claims.py", "_mark_stale", "claim"): "AssuranceClaim",
    ("assurance/claims.py", "_move_reading", "claim"): "AssuranceClaim",
    ("assurance/decision.py", "_decision_from_findings", "f"): "Finding",
    ("assurance/evidence_audit.py", "_intrinsic_reasons", "item"): "ClaimEvidence",
    ("assurance/evidence_audit.py", "audit_of", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "_write_audit", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "_record_unsettled", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "served_audit", "claim"): "AssuranceClaim",
    ("assurance/evidence_audit.py", "evidence_record", "item"): "ClaimEvidence",
    ("assurance/fingerprint.py", "_provider_descriptor", "provider"): "Provider",
    ("assurance/incident.py", "_evidence", "finding"): "Finding",
    ("assurance/invalidation.py", "_mark_row_stale", "claim"): "AssuranceClaim",
    ("assurance/posture/base.py", "PostureFinding.as_dict", "self"): "PostureFinding",
    ("assurance/posture/base.py", "_weakest_evidence", "f"): "PostureFinding",
    ("assurance/roi.py", "_evidence_and_findings", "finding"): "Finding",
    ("assurance/serializers.py", "AssuranceClaimSerializer.get_confidence_basis", "obj"): "AssuranceClaim",
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


# ---------------------------------------------------------------------------
# Round 3: the other ways to reach the raw label
# ---------------------------------------------------------------------------
#
# The attribute scan above caught ``assertion.evidence_class``. Round 3's mutants
# reached the same raw label four other ways and each got past it: the declared
# label used for a judgment (MN3b, ``effective = assertion.declared_evidence_class``
# in training reuse), the instance dict (MN3c, ``a.__dict__["evidence_class"]``),
# a query that returns the column (MN3d, ``values_list("evidence_class")``), and a
# getattr whose name is built at runtime (MN3e, ``getattr(a, "evidence_" + "class")``).

#: Where the declared label is read, and the dict keys it may be read into: an
#: echo beside the effective class, or the fingerprint of the declaration. A read
#: anywhere else -- assigned to a name, compared, returned, passed to a judgment --
#: is a judgment on the vendor's word.
_DECLARED_LABEL_ECHOES = {
    ("assurance/bom.py", "_provider_entry"): {"evidence_class", "evidence_class_label"},
    ("assurance/boundary.py", "_assertion_map"): {"declared_evidence_class"},
    ("assurance/fingerprint.py", "_assertion_descriptor"): {"evidence_class"},
    ("assurance/training_reuse.py", "_posture_dict"): {"declared_evidence_class"},
    ("assurance/vendor.py", "_assertion_dict"): {"declared_evidence_class"},
}

#: Every read of an instance's ``__dict__`` (or ``vars()``) in the application
#: code, by (file, enclosing function): each reads its own model's prior state and
#: never an evidence class. A new one must be added here with what it reads.
_INSTANCE_DICT_READS = {
    ("assurance/models.py", "Deployment.save"): "Deployment",
    ("assurance/signals.py", "_fanout_input_deleting"): "decision inputs",
    ("assurance/signals.py", "_fanout_input_deleted"): "decision inputs",
    ("assurance/signals.py", "_remember_prior_deployment"): "decision inputs",
    ("assurance/signals.py", "_decision_input_saved"): "decision inputs",
    ("assurance/signals.py", "_remember_prior_provider_name"): "Provider",
    ("assurance/signals.py", "_provider_profile_written"): "Provider",
}

#: Every ``getattr``/``hasattr`` whose attribute name is not a literal, by (file,
#: enclosing function, receiver): none can be a provider assertion's label. A new
#: one must be added here with what it reads.
_RUNTIME_NAMED_READS = {
    ("assurance/claims.py", "_adopt", "row"): "AssuranceClaim: the caller's copy brought to the row written",
    ("assurance/claims.py", "_same_reading", "claim"): "AssuranceClaim reading fields",
    ("assurance/connectors/base.py", "Connector.marker_scope", "self.config"): "connector config",
    ("assurance/dispatch.py", "_dispatch_one", "existing"): "dispatch row",
    ("assurance/dispatch.py", "_number_setting", "settings"): "settings",
    ("assurance/dispatch.py", "settings_problems", "settings"): "settings",
    ("assurance/latent.py", "_observe_boundary_allows", "boundary"): "DataBoundary",
    ("assurance/latent.py", "_Evaluation._save", "condition"): "LatentCondition",
    ("assurance/legal.py", "_legal", "LegalStatus"): "LegalStatus choices",
    ("assurance/models.py", "_CredentialBinding.__str__", "self"): "credential binding",
    ("assurance/signals.py", "writes_a_decision_input", "instance"): "decision inputs",
    ("assurance/signals.py", "_follow", "instance"): "decision inputs' foreign keys",
    ("assurance/signals.py", "schedule_decision_refresh", "connection"): "connection state",
    ("assurance/views.py", "_credential_binding_state", "binding"): "credential binding",
    ("failsafe/views.py", "_setting", "settings"): "settings",
    ("pentest/report_mythos.py", "_extract.g", "scan"): "scan record",
    ("safety/stops.py", "is_stop", "request"): "request marker",
}

#: Query and accessor calls that name a column by string. None may name the label.
_NAMING_CALLS = {"values", "values_list", "only", "defer", "order_by", "F", "attrgetter"}


def _app_trees():
    for path in sorted(_ROOT.rglob("*.py")):
        rel = path.relative_to(_ROOT).as_posix()
        if rel.startswith(("tests/", ".venv/", "venv/", "node_modules/", "frontend/")) or "/migrations/" in rel:
            continue
        yield rel, ast.parse(path.read_text(encoding="utf-8"))


def _walk_scoped(tree):
    """``(node, qualname, parents)`` for every node."""
    stack: list[str] = []
    parents: list[ast.AST] = []

    def visit(node):
        scoped = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        if scoped:
            stack.append(node.name)
        yield node, ".".join(stack), tuple(parents)
        parents.append(node)
        for child in ast.iter_child_nodes(node):
            yield from visit(child)
        parents.pop()
        if scoped:
            stack.pop()

    yield from visit(tree)


def _constant_text(node):
    """The string an expression of literals spells ("evidence_" + "class",
    f"{'evidence'}_class"), or None where it is not literals alone."""
    try:
        if isinstance(node, ast.JoinedStr):
            return "".join(_constant_text(v.value if isinstance(v, ast.FormattedValue) else v) for v in node.values)
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = _constant_text(node.left), _constant_text(node.right)
            return left + right if left is not None and right is not None else None
        return None
    return value if isinstance(value, str) else None


def _echo_key(node, parents):
    """The dict key a declared-label read is the value of, through calls and
    attributes only (``EvidenceClass(a.declared_evidence_class).label``); None
    where it is read any other way."""
    child = node
    for parent in reversed(parents):
        if isinstance(parent, ast.Dict):
            for key, value in zip(parent.keys, parent.values, strict=True):
                if value is child and isinstance(key, ast.Constant) and isinstance(key.value, str):
                    return key.value
            return None
        if isinstance(parent, (ast.Call, ast.Attribute)):
            child = parent
            continue
        return None
    return None


def test_the_declared_label_is_read_only_as_an_echo_or_a_fingerprint():
    wrong = []
    seen = set()
    for rel, tree in _app_trees():
        for node, qual, parents in _walk_scoped(tree):
            if isinstance(node, ast.Attribute) and node.attr == "declared_evidence_class" and isinstance(node.ctx, ast.Load):
                if rel == "assurance/models.py":
                    continue
                allowed = _DECLARED_LABEL_ECHOES.get((rel, qual))
                key = _echo_key(node, parents)
                seen.add((rel, qual))
                if allowed is None or key not in allowed:
                    wrong.append(f"{rel}:{node.lineno} in {qual}: declared_evidence_class read as {key!r}")
    assert wrong == [], (
        "The declared label read for something other than an echo or a fingerprint. A judgment reads "
        "effective_evidence_class:\n" + "\n".join(wrong)
    )
    assert seen == set(_DECLARED_LABEL_ECHOES), "an echo listed here is gone: take it off the list"


def test_no_reader_takes_the_label_through_the_instance_dict():
    wrong = []
    for rel, tree in _app_trees():
        for node, qual, parents in _walk_scoped(tree):
            dict_read = (isinstance(node, ast.Attribute) and node.attr == "__dict__") or (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "vars"
            )
            if not dict_read:
                continue
            parent = parents[-1] if parents else None
            keyed = None
            if isinstance(parent, ast.Subscript) and parent.value is node:
                keyed = _constant_text(parent.slice)
            elif isinstance(parent, ast.Attribute) and isinstance(parents[-2], ast.Call) and parents[-2].args:
                keyed = _constant_text(parents[-2].args[0])
            if (keyed and "evidence_class" in keyed) or (rel, qual) not in _INSTANCE_DICT_READS:
                wrong.append(f"{rel}:{node.lineno} in {qual or '<module>'}: {ast.unparse(parent or node)[:80]}")
    assert wrong == [], "An instance-dict read not classified, or of an evidence class:\n" + "\n".join(wrong)


def test_no_query_or_accessor_names_the_label_by_string():
    wrong = []
    for rel, tree in _app_trees():
        for node, qual, _parents in _walk_scoped(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            if name not in _NAMING_CALLS:
                continue
            texts = [_constant_text(a) for a in node.args] + [k.arg for k in node.keywords if k.arg]
            if any(t and ("evidence_class" in t) for t in texts):
                wrong.append(f"{rel}:{node.lineno} in {qual or '<module>'}: {ast.unparse(node)[:100]}")
    assert wrong == [], "A query or accessor naming an evidence class column by string:\n" + "\n".join(wrong)


def test_no_getattr_reaches_the_label_by_a_runtime_name():
    wrong = []
    seen = set()
    for rel, tree in _app_trees():
        for node, qual, _parents in _walk_scoped(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("getattr", "hasattr")
                and len(node.args) >= 2
            ):
                continue
            name = node.args[1]
            if isinstance(name, ast.Constant):
                continue
            receiver = ast.unparse(node.args[0])
            spelled = _constant_text(name)
            if spelled is not None and "evidence_class" in spelled:
                wrong.append(f"{rel}:{node.lineno} in {qual}: getattr({receiver}, {spelled!r})")
            elif (rel, qual, receiver) not in _RUNTIME_NAMED_READS:
                wrong.append(f"{rel}:{node.lineno} in {qual}: getattr({receiver}, {ast.unparse(name)})")
            else:
                seen.add((rel, qual, receiver))
    assert wrong == [], (
        "A getattr whose name is built at runtime, not classified here (or spelling the label):\n" + "\n".join(wrong)
    )
    assert seen == set(_RUNTIME_NAMED_READS), "a runtime-named read listed here is gone: take it off the list"
