"""A drift finding reported a confidence of 0.9. Nothing measured 0.9.

`Finding.confidence` is nullable with no default, and the comment on the field
says why: a number nobody computed is indistinguishable, in every report and
every API response, from a real one a detector measured. Migration 0016 nulled
every invented value the ingest had written and read each row's `raw` payload to
tell the real ones from the defaults.

Two files away, `bom_drift._reconcile_finding` went on writing `confidence=0.9`
into every machine-managed drift finding it created. Every AI-BOM drift on the
platform carried a figure that reads as near-certainty and came from nowhere, and
changing that literal to 0.111 left all 1,274 tests in this repo green.

Drift is a set difference: a declared component that was not observed, or an
observed one that was not declared. It is either right about what it compared or
its inputs were wrong. It has no confidence, and null is the only honest value.

The second half of this file is the gate. A repo-wide source check, run as a
test, because the property it enforces is a property of the source: no numeric
confidence literal may be written anywhere in `assurance/`. That is a different
thing from a test that greps a file as a *proxy* for behaviour -- there is no
behaviour to observe for a defect that has not been written yet, and the one
above is the behavioural test for the path that exists. Both are here because
neither alone would have caught this: the behavioural test cannot see a seventh
deriver added next quarter, and the gate cannot see whether the finding that
reaches the API actually carries null.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from django.contrib.auth import get_user_model

from assurance.bom_drift import record_bom_drift_findings
from assurance.models import Asset, DeclaredComponent, Deployment, Finding
from assurance.serializers import FindingSerializer

pytestmark = pytest.mark.django_db

User = get_user_model()
Kind = Asset.Kind


def _deployment_with_drift() -> Deployment:
    """One declared tool that was observed, and one observed tool nobody declared.

    The same fixture the existing drift tests use, so this measures the path that
    actually runs rather than a shape built to suit the assertion.
    """
    owner = User.objects.create_user(username="analyst", password="x")
    deployment = Deployment.objects.create(name="drifted", owner=owner)
    DeclaredComponent.objects.create(
        deployment=deployment, kind=Kind.TOOL, name="search", identifier="search"
    )
    Asset.objects.create(
        deployment=deployment, kind=Kind.TOOL, name="search", identifier="search"
    )
    Asset.objects.create(
        deployment=deployment, kind=Kind.TOOL, name="shadow", identifier="shadow"
    )
    return deployment


# ---------------------------------------------------------------------------
# The finding itself
# ---------------------------------------------------------------------------


def test_a_drift_finding_carries_no_confidence_at_all():
    """Null, not a small number. A low confidence is still a claim that somebody
    measured something and got a low answer."""
    deployment = _deployment_with_drift()

    record_bom_drift_findings(deployment)

    findings = list(Finding.objects.filter(deployment=deployment))
    assert findings, "no drift finding was created, so this test proves nothing"
    for finding in findings:
        assert finding.confidence is None, (
            f"{finding.finding_type} reports confidence={finding.confidence!r}, "
            "which nothing computed"
        )


def test_the_null_survives_serialization_and_is_not_rendered_as_a_number():
    """The column being null is not the claim. The claim is that no consumer is
    handed a figure -- and a serializer coercing null to 0.0 would put the defect
    back one layer out, where the model's own comment cannot see it."""
    deployment = _deployment_with_drift()
    record_bom_drift_findings(deployment)

    for finding in Finding.objects.filter(deployment=deployment):
        assert FindingSerializer(finding).data["confidence"] is None


def test_refreshing_a_drift_finding_does_not_invent_one_either():
    """`_reconcile_finding` sets confidence only on create, so a second pass is
    the path where a re-introduced default would hide: the first run would look
    correct and the value would appear on the refresh."""
    deployment = _deployment_with_drift()
    record_bom_drift_findings(deployment)
    record_bom_drift_findings(deployment)

    for finding in Finding.objects.filter(deployment=deployment):
        assert finding.confidence is None


def test_a_confidence_a_detector_did_measure_is_still_kept():
    """The control. Without it, "always null" would satisfy every assertion above
    and this repo would have swapped one dishonesty for another: discarding a real
    measurement is as wrong as inventing one."""
    owner = User.objects.create_user(username="measurer", password="x")
    deployment = Deployment.objects.create(name="measured", owner=owner)
    finding = Finding.objects.create(
        deployment=deployment,
        fingerprint="fp-measured",
        finding_type="detector.thing",
        title="a detector actually measured this",
        confidence=0.9,
        raw={"confidence": 0.9},
    )

    finding.refresh_from_db()
    assert finding.confidence == 0.9
    assert FindingSerializer(finding).data["confidence"] == 0.9


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

_ASSURANCE = pathlib.Path(__file__).resolve().parent.parent / "assurance"

#: Paths the gate does not walk, each for a stated reason.
_NOT_WALKED = {
    # Migrations are a record of what the schema and the data USED to be. 0016
    # and 0026 both have to name the numbers they removed in order to remove
    # them, and rewriting history to satisfy a gate would be the dishonest move.
    "migrations",
}


def _confidence_literals(tree: ast.AST) -> list[tuple[int, object]]:
    """Every numeric literal written to something named ``confidence``.

    Covers the three spellings that reach a Finding: a dict entry
    (``{"confidence": 0.9}``), a keyword argument (``confidence=0.9``), and an
    attribute or name assignment (``finding.confidence = 0.9``). A `.get` with a
    numeric fallback (``raw.get("confidence", 0.5)``) counts too -- it is the
    same invention with an extra step, and it is the spelling six of the seven
    live cases across the platform actually use.
    """
    found: list[tuple[int, object]] = []

    def numeric(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, (int, float))

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "confidence" and numeric(value):
                    found.append((value.lineno, value.value))
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "confidence" and numeric(keyword.value):
                    found.append((keyword.value.lineno, keyword.value.value))
            # `something.get("confidence", <number>)`
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "confidence"
                and numeric(node.args[1])
            ):
                found.append((node.args[1].lineno, node.args[1].value))
        elif isinstance(node, ast.Assign) and numeric(node.value):
            for target in node.targets:
                name = getattr(target, "attr", None) or getattr(target, "id", None)
                if name == "confidence":
                    found.append((node.value.lineno, node.value.value))
    return found


def test_nothing_in_assurance_writes_a_confidence_number_of_its_own():
    """The gate. It reads source, and says so.

    This is not a substring assertion standing in for behaviour: it enforces a
    property that *is* about the source, which is that the next deriver somebody
    writes cannot quietly add an eighth invented figure. The behavioural tests
    above cover the path that exists today; this one covers the ones that do not
    exist yet, which no behavioural test can reach.

    A real measurement never appears as a literal here. It arrives from an engine
    payload, is parsed, and is stored -- or it is absent and stays null. If a
    future caller genuinely needs a constant, it needs a reason in a comment and a
    line in this test, not silence.
    """
    offenders: list[str] = []
    for path in sorted(_ASSURANCE.rglob("*.py")):
        if any(part in _NOT_WALKED for part in path.relative_to(_ASSURANCE).parts):
            continue
        for lineno, value in _confidence_literals(ast.parse(path.read_text())):
            offenders.append(f"{path.relative_to(_ASSURANCE.parent)}:{lineno} -> {value!r}")

    assert not offenders, (
        "a confidence value nobody computed is written here:\n  "
        + "\n  ".join(offenders)
        + "\n\nIf it is genuinely measured, read it from the payload. If it is "
        "not, leave it null."
    )


def test_the_gate_can_actually_see_each_spelling():
    """The control for the gate, and the reason it is worth having.

    A source check that matched nothing would pass on every repository forever.
    Each spelling is fed to it directly, so a refactor that silently narrows
    `_confidence_literals` fails here rather than going quiet.
    """
    cases = {
        'x = {"confidence": 0.9}': 0.9,
        "f(confidence=0.5)": 0.5,
        'raw.get("confidence", 0.8)': 0.8,
        "finding.confidence = 1.0": 1.0,
        "confidence = 0": 0,
    }
    for source, expected in cases.items():
        found = _confidence_literals(ast.parse(source))
        assert found, f"the gate does not see {source!r}"
        assert found[0][1] == expected

    # And does not fire on the honest spellings.
    for source in (
        'confidence = raw.get("confidence")',
        'x = {"confidence": None}',
        "f(confidence=parsed)",
        'x = {"cvss_score": 0.9}',
    ):
        assert not _confidence_literals(ast.parse(source)), f"the gate fires on {source!r}"
