"""Economic Exposure: the ROI document says what it nets, and every amount of money in it
says what kind it is (roadmap AT-6b; ``docs/economics/spec-v1.md``, section 28.11).

- every amount of money the ROI document serves (``mythos.economics.roi/v2``) is held as a
  ``mythos_core.measures`` measure, of the core's eight kinds, or says why it is not one;
- no amount changed: every figure is the one ``d5ed249`` (v1) served for the same fixture,
  to the last minor unit;
- the expected reduction is a modelled figure: ``modeled_exposure``, never a booked kind,
  never savings realised;
- the first-year investment is ``remediation_expense`` and says it is an estimate; it never
  adds to a booked expense;
- unlike kinds are never netted: each pair the document compares stands side by side with
  the core's reason they do not add, and no sum or difference of a pair is served;
- a difference of two percentiles keeps its value under a name that says what it is
  (``difference_of_percentiles``; v1's ``reduction``), and is not held as a measure;
- the ROI and the payback are ratios, not measures;
- the module that types them computes nothing.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from mythos_core import measures
from mythos_core.persona import lint

from assurance.economics import exposure_measures as em
from assurance.economics import remediation_service, report, roi_measures
from assurance.economics.engine import remediation as er
from assurance.economics.models import canonical_digest
from assurance.models import Deployment
from tests.test_economics_remediation import _client, _roi, _service_runs, option_body

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
DAY = "2026-10-06"
#: What ``d5ed249`` (``mythos.economics.roi/v1``) served for :func:`_insured_roi`'s
#: fixture, every amount and ratio, read from that commit's own answer. v1 named each
#: ``difference_of_percentiles`` ``reduction``.
BASE = {
    "headline": {
        "current_expected_annual_exposure": "201680.00", "residual_expected_annual_exposure": "101920.00",
        "expected_reduction": "99760.00", "risk_adjusted_roi": "0.4988", "payback": "2.00",
        "first_year_investment": {"low": "200000.00", "base": "200000.00", "high": "200000.00"},
        "p90": ("400000.00", "200000.00", "200000.00"), "p95": ("500000.00", "300000.00", "200000.00"),
    },
    "gross_cash": {
        "current_expected_annual_exposure": "553073.11", "residual_expected_annual_exposure": "279683.20",
        "expected_reduction": "273389.91", "risk_adjusted_roi": "1.3669", "payback": "0.73",
        "p90": ("1120987.56", "675018.35", "445969.21"), "p95": ("1355711.23", "850261.27", "505449.96"),
    },
}


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


def _insured_roi(deployment, people):
    """The repository's own fixture: a stored scenario under an insurance policy (a
    headline of retained cash, gross cash beside it), its option halving the frequency,
    both runs through the services, seed 11, 10,000 draws."""
    scenario, option, current, residual = _service_runs(deployment, people, option_body("0.5"), draws=10_000,
                                                        policy=True)
    return scenario, option, current, residual, remediation_service.roi_document(scenario, residual)


def _typed(roi) -> dict[str, dict]:
    return {f"{entry['section']}.{entry['label']}": entry for entry in roi["measures"]}


def _block(roi, line):
    return roi["figures"] if line == "headline" else roi["figures"]["gross_cash"]


def _strings(value):
    if isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)
    elif isinstance(value, str):
        yield value


# ======================================================================
# Every amount is a measure of its kind, and no amount changed
# ======================================================================


def test_every_amount_is_a_measure_of_its_kind_and_none_changed(deployment, people):
    """Every amount of both lines, held as a measure of the run, the pair of runs or
    the option it rests on, each the figure v1 served to the last minor unit."""
    _, option, current, residual, roi = _insured_roi(deployment, people)
    assert roi["schema"] == er.ROI_SCHEMA == "mythos.economics.roi/v2" and roi["line"] == "retained_cash"
    typed = _typed(roi)
    expected = set()
    for line, base in BASE.items():
        block = _block(roi, line)
        runs = {"current_expected_annual_exposure": current, "residual_expected_annual_exposure": residual,
                "expected_reduction": residual}
        for key, run in runs.items():
            entry = typed[f"{line}.{key}"]
            expected.add(f"{line}.{key}")
            assert block[key] == base[key] == entry["measure"]["amount"] and entry["shown"] == f"USD {base[key]}"
            assert entry["kind"] == entry["measure"]["kind"] == measures.MODELED_EXPOSURE and not entry["estimate"]
            assert entry["measure"]["basis"] == {"snapshot_id": f"simulation-inputs:{run.uuid}",
                                                 "content_hash": run.input_digest}
            assert entry["measure"]["period"] == {"start": DAY, "end": DAY} and entry["measure"]["cumulative"] is False
            schema = er.ROI_SCHEMA if key == "expected_reduction" else report.REPORT_SCHEMA
            assert entry["measure"]["source"] == f"{schema}:{run.uuid}"
        for tail in ("p90", "p95"):
            now, after, difference = base[tail]
            part = block["tail_reduction"][tail]
            assert (part["current"], part["residual"], part["difference_of_percentiles"]) == base[tail]
            for side, value, run in (("current", now, current), ("residual", after, residual)):
                entry = typed[f"{line}.tail_reduction.{tail}.{side}"]
                expected.add(f"{line}.tail_reduction.{tail}.{side}")
                assert entry["measure"]["amount"] == value and entry["kind"] == measures.MODELED_EXPOSURE
                assert entry["measure"]["basis"]["snapshot_id"] == f"simulation-inputs:{run.uuid}"
            gap = typed[f"{line}.tail_reduction.{tail}.difference_of_percentiles"]
            expected.add(f"{line}.tail_reduction.{tail}.difference_of_percentiles")
            assert gap == {"section": line, "label": f"tail_reduction.{tail}.difference_of_percentiles",
                           "shown": f"USD {difference}", "kind": measures.MODELED_EXPOSURE, "measure": None,
                           "why": roi_measures.DIFFERENCE_IS, "estimate": False}
        assert block["risk_adjusted_roi"]["value"] == base["risk_adjusted_roi"]
        assert block["payback"]["value"] == base["payback"]
    for point, value in BASE["headline"]["first_year_investment"].items():
        entry = typed[f"headline.first_year_investment.{point}"]
        expected.add(f"headline.first_year_investment.{point}")
        assert roi["figures"]["first_year_investment"][point] == value == entry["measure"]["amount"]
        assert entry["kind"] == measures.REMEDIATION_EXPENSE and entry["estimate"] is True
        assert entry["measure"]["basis"] == {"snapshot_id": f"remediation-option:{option.uuid}",
                                             "content_hash": option.option_digest}
        assert entry["measure"]["source"] == f"{er.OPTION_SCHEMA}:{option.uuid}"
        assert entry["measure"]["period"] == {"start": DAY, "end": DAY}
    # Every amount, and only amounts: the ROI and the payback are never measures.
    assert set(typed) == expected
    assert not [label for label in typed if "roi" in label or "payback" in label]
    assert {entry["kind"] for entry in roi["measures"]} == {measures.MODELED_EXPOSURE, measures.REMEDIATION_EXPENSE}


def test_the_route_serves_v2_with_its_digest_and_its_measures(deployment, people):
    scenario, _, _, residual, roi = _insured_roi(deployment, people)
    response = _roi(_client(people["owner"]), deployment, scenario, residual.uuid)
    assert response.status_code == 200 and response["Cache-Control"] == "no-store"
    body = json.loads(response.content)
    assert body == json.loads(report.canonical_bytes(roi))
    assert body["schema"] == "mythos.economics.roi/v2" and body["digest"] == report.digest_of(
        {key: value for key, value in body.items() if key != "digest"})
    assert er.ROI_SCHEMAS == ("mythos.economics.roi/v1", "mythos.economics.roi/v2")
    assert er.ROI_SCHEMA_V1 == "mythos.economics.roi/v1"


# ======================================================================
# A modelled difference is never booked
# ======================================================================


def test_the_expected_reduction_is_modelled_never_booked_and_never_savings_realised(deployment, people):
    _, _, current, residual, roi = _insured_roi(deployment, people)
    for line in ("headline", "gross_cash"):
        entry = _typed(roi)[f"{line}.expected_reduction"]
        assert entry["kind"] == measures.MODELED_EXPOSURE and entry["kind"] not in measures.BOOKED_KINDS
    # It rests on the residual run's inputs, which hold the current run's: the pair.
    assert canonical_digest({k: v for k, v in residual.inputs.items() if k != "remediation"}) == current.input_digest
    nets = roi["nets"]["expected_reduction"]
    assert "a modelled figure (modeled_exposure)" in nets and nets.endswith("never booked, and never savings realised")
    # Wherever the document speaks of savings, of anything realised or of anything
    # booked, it is to deny it: each such word sits in a clause that says not or never.
    words = re.compile(r"\b(sav(?:e|ed|es|ing|ings)|reali[sz](?:e|ed|es)|booked)\b", re.IGNORECASE)
    found = 0
    for text in _strings(roi):
        for match in words.finditer(text):
            found += 1
            clause = re.split(r"[.;:]", text[:match.start()])[-1]
            assert re.search(r"\b(not|never)\b", clause), (match.group(0), text)
    assert found >= 4


def test_a_reduction_below_zero_is_not_a_measure_and_says_why():
    run = em.ModelRun("USD", DAY, "simulation-inputs:run-1", "sha256:" + "ab" * 32, "x:run-1")
    runs = roi_measures.Runs(current=run, residual=run, reduction=run,
                             option=em.ModelRun("USD", DAY, "remediation-option:o", "sha256:" + "cd" * 32, "y:o"))
    held = roi_measures.figures_of({"expected_reduction": "-5.00"}, runs)
    assert [(f.label, f.kind, f.measure, f.why, f.shown) for f in held] == [
        ("expected_reduction", measures.MODELED_EXPOSURE, None, roi_measures.NEGATIVE_IS, "USD -5.00")]


# ======================================================================
# Unlike kinds never net: they stand side by side
# ======================================================================


def test_unlike_kinds_are_never_netted_and_stand_side_by_side(deployment, people):
    _, _, _, _, roi = _insured_roi(deployment, people)
    pairs = [(p["line"], p["left"], p["right"], tuple(p["kinds"]), p["do_not_add"]) for p in roi["side_by_side"]]
    modeled, expense = measures.MODELED_EXPOSURE, measures.REMEDIATION_EXPENSE
    expected = []
    for line in ("headline", "gross_cash"):
        expected += [
            (line, f"{line}.current_expected_annual_exposure", f"{line}.residual_expected_annual_exposure",
             (modeled, modeled), "modeled_with_modeled"),
            (line, f"{line}.expected_reduction", "headline.first_year_investment.base", (modeled, expense),
             "modeled_with_booked"),
            (line, f"{line}.tail_reduction.p90.current", f"{line}.tail_reduction.p90.residual", (modeled, modeled),
             "modeled_with_modeled"),
            (line, f"{line}.tail_reduction.p95.current", f"{line}.tail_reduction.p95.residual", (modeled, modeled),
             "modeled_with_modeled"),
        ]
    assert pairs == expected
    assert all(set(p) == {"line", "left", "right", "kinds", "do_not_add", "statement"} for p in roi["side_by_side"])
    # No sum and no difference of a pair of unlike kinds is served anywhere.
    text = report.canonical_bytes(roi).decode()
    for line, base in BASE.items():
        reduction, cost = Decimal(base["expected_reduction"]), Decimal(BASE["headline"]["first_year_investment"]["base"])
        for computed in (reduction + cost, reduction - cost, cost - reduction):
            assert f'"{computed}"' not in text, (line, computed)
    # The core refuses each such pair, and an estimated cost never adds to a booked expense.
    typed = roi_measures.figures_of(roi["figures"], roi_measures.runs_of(
        report.build_report(_current(roi)), report.build_report(_residual(roi)), option=roi["option"]["uuid"],
        option_digest=roi["option"]["digest"], option_currency="USD",
        option_source=f"{er.OPTION_SCHEMA}:{roi['option']['uuid']}", roi_schema=er.ROI_SCHEMA))
    by = {f.label: f for f in typed if f.section == "headline"}
    with pytest.raises(measures.MeasuresDoNotAdd) as refused:
        em.total([by["expected_reduction"], by["first_year_investment.base"]])
    assert refused.value.code == "modeled_with_booked"
    estimate = by["first_year_investment.base"].measure
    booked = measures.Measure(kind=measures.REMEDIATION_EXPENSE, amount=estimate.amount, period=estimate.period,
                              cumulative=False, basis="observed", source="ledger/2026-q4")
    with pytest.raises(measures.MeasuresDoNotAdd) as apart:
        measures.total([estimate, booked])
    assert apart.value.code == "basis_mismatch"


def _current(roi):
    from assurance.economics.models import SimulationResult

    return SimulationResult.objects.get(uuid=roi["current"]["simulation"])


def _residual(roi):
    from assurance.economics.models import SimulationResult

    return SimulationResult.objects.get(uuid=roi["residual"]["simulation"])


def test_a_difference_of_two_percentiles_keeps_its_value_under_a_name_that_says_what_it_is(deployment, people):
    """v1's ``reduction`` is ``difference_of_percentiles``, its value unchanged, never a
    measure; the name ``reduction`` is served nowhere in a tail."""
    _, _, _, _, roi = _insured_roi(deployment, people)
    for line, base in BASE.items():
        tails = _block(roi, line)["tail_reduction"]
        for tail in ("p90", "p95"):
            assert set(tails[tail]) == {"current", "residual", "difference_of_percentiles", "not_reported"}
            assert tails[tail]["difference_of_percentiles"] == base[tail][2]
    assert roi["nets"]["tail_reduction"] == roi_measures.DIFFERENCE_IS
    assert "not a percentile of the reduction" in roi_measures.DIFFERENCE_IS


def test_the_roi_and_the_payback_are_ratios_never_measures(deployment, people):
    _, _, _, _, roi = _insured_roi(deployment, people)
    for key in ("risk_adjusted_roi", "payback"):
        assert roi["nets"][key] == roi_measures.RATIO_IS
        assert all(key not in entry["label"] for entry in roi["measures"])
    assert "two kinds that never add or net" in roi_measures.RATIO_IS


def test_a_document_with_no_figures_has_no_measures_and_says_what_it_would_net(deployment, people):
    scenario, _, _, residual, _ = _insured_roi(deployment, people)
    residual.status = "refused"
    roi = remediation_service.roi_document(scenario, residual)
    assert "not_reported" in roi["figures"] and roi["measures"] == [] and roi["side_by_side"] == []
    assert roi["nets"] == roi_measures.NETS


# ======================================================================
# Nothing is computed, and it is said in words the lint allows
# ======================================================================


def test_the_module_that_types_the_roi_computes_nothing():
    tree = ast.parse(inspect.getsource(roi_measures))
    assert not [node for node in ast.walk(tree) if isinstance(node, (ast.BinOp, ast.AugAssign))]
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not names & {"Decimal", "sum", "fsum", "quantize", "round", "total", "add", "compute"}


def test_what_the_roi_nets_is_said_in_the_readme_the_spec_and_words_the_lint_allows():
    for text in (*roi_measures.NETS.values(), roi_measures.BESIDE_IS, roi_measures.NEGATIVE_IS):
        assert lint.lint(text).ok, text
    readme = " ".join((REPO / "README.md").read_text(encoding="utf-8").split())
    spec = " ".join((REPO / "docs/economics/spec-v1.md").read_text(encoding="utf-8").split())
    assert "**What the ROI says it nets** (`mythos.economics.roi/v2`" in readme
    assert "`difference_of_percentiles`, its value unchanged" in readme and "never savings realised" in readme
    assert "### 28.11 What the ROI nets (AT-6b)" in spec and "`mythos.economics.roi/v2`" in spec
