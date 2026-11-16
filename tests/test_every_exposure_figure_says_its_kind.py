"""Economic Exposure: every money figure of the deployment's economic-exposure report says
what kind of figure it is, and unlike kinds are never added (roadmap AT-6;
``docs/economics/spec-v1.md``, section 38.2).

- every amount the report shows of a run, of a residual run and of the deployment's
  portfolio is held as a ``mythos_core.measures.Measure``: ``modeled_exposure``, its
  money the amount the report prints (to the last minor unit), its period the valuation
  day, its basis the stored inputs of the run that computed it, its source that run's
  report;
- no amount changed: each is the figure ``report.build_report`` and
  ``GET .../economics/portfolio/`` serve, text for text;
- an estimate is never labelled a booked kind; a figure the core refuses, or one with no
  period, is not a measure and says why, its amount still shown and the gap named; a
  figure whose kind cannot be established reads ``unknown``, with the reason, never under
  a default kind;
- an assumption is an input as stated, not a measure: listed with the assumptions, its
  numbers as recorded, under one line that says so, with no kind and no gap;
- a total is the core's to make: two kinds, two currencies and two modelled exposures are
  refused, and the report itself adds nothing; the deployment total is the portfolio's own
  figure, typed, never a sum of the scenarios' own;
- the kinds are the core's eight, each in the core's words, in the code and the README.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import ast
import inspect
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from mythos_core import measures
from mythos_core.persona import lint

from assurance.economics import exposure_measures as em
from assurance.economics import exposure_report, portfolio, report, simulation_service
from assurance.models import Deployment
from tests.economics_review import approve_for_receipt
from tests.test_economics_exposure_report import _client, _member, _page, _portfolio_api, _text, _totalled, _url
from tests.test_economics_portfolio import LARGE
from tests.test_economics_remediation import _service_runs, option_body
from tests.test_economics_report import stored

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
DAY = "2026-10-06"
HASH = "sha256:" + "ab" * 32
RUN = em.ModelRun(currency="USD", valuation_date=DAY, snapshot_id="simulation-inputs:run-1", content_hash=HASH,
                  source="mythos.economics.report/v2:run-1")


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


def _insured(deployment, people):
    """An approved version with an insurance policy (a gross and a net line), run once."""
    scenario = stored(deployment, people["analyst"], set_key="exposure_p", policy=True)
    result = simulation_service.simulate_scenario(scenario, seed=7, draws=10_000).result
    assert result is not None and result.status == "completed"
    approve_for_receipt(scenario)
    return scenario, result


def _figures(served: dict, section: str) -> dict[str, dict]:
    return {entry["label"]: entry for entry in served["measures"] if entry["section"] == section}


def _amount_rows(served: dict, heading: str) -> dict[str, str]:
    """Every row of a section that shows an amount of money of a run: label -> text."""
    labels = [f"{name}{suffix}: {figure}" for name in exposure_report.LINE_LABELS.values()
              for suffix in ("", ", total") for _key, figure in exposure_report.TOTAL_FIGURES]
    severe = [label.replace("Severe but plausible", "Severe but plausible (P95)") for label in labels]
    return {label: value for label, value in dict(served["sections"])[heading]
            if label in labels + severe and value != "not measured"}


def _booked(kind=measures.CONFIRMED_LOSS, amount="10.00", currency="USD", start="2026-01-01", end="2026-03-31"):
    measure = measures.Measure(kind=kind, amount=measures.Money(Decimal(amount), currency),
                               period=measures.Period(start, end), cumulative=False, basis="observed",
                               source="filing/10-Q")
    return em.Figure("Test", f"{kind} {start}", f"{currency} {amount}", kind, measure, None)


# ======================================================================
# Every figure shown is a measure, and no amount changed
# ======================================================================


def test_every_figure_of_a_run_is_a_modeled_exposure_measure_and_no_amount_changed(deployment, people):
    """The exposure section over the repository's own fixture (a gross and a net line):
    each amount row has its measure, the measure's money is the row's text and the run
    report's figure to the last minor unit, and its kind, period, basis and source are
    the run's."""
    _, result = _insured(deployment, people)
    built = report.build_report(result)
    served = exposure_report.document(deployment)
    rows = _amount_rows(served, exposure_report.EXPOSURE_HEADING)
    typed = _figures(served, exposure_report.EXPOSURE_HEADING)
    assert len(rows) == 10 and set(rows) == set(typed)
    keys = dict((figure if key != "severe_plausible" else f"{figure} (P95)", key)
                for key, figure in exposure_report.FIGURE_LABELS)
    names = {name: line for line, name in exposure_report.LINE_LABELS.items()}
    for label, text in rows.items():
        name, _, figure = label.partition(": ")
        stated = built["summary"]["lines"][names[name]][keys[figure]]
        entry = typed[label]
        # No amount changed: the row is the run report's figure, and the measure is the row.
        assert text == f"USD {stated}" == entry["shown"]
        held = entry["measure"]
        assert entry["kind"] == held["kind"] == measures.MODELED_EXPOSURE and entry["why"] is None
        assert (held["currency"], held["amount"]) == ("USD", stated)
        assert Decimal(held["amount"]).as_tuple().exponent == -2
        assert held["period"] == {"start": DAY, "end": DAY} == {
            "start": built["currency_bridge"]["valuation_date"], "end": built["currency_bridge"]["valuation_date"]}
        assert held["cumulative"] is False
        assert held["basis"] == {"snapshot_id": f"simulation-inputs:{result.uuid}",
                                 "content_hash": result.input_digest}
        assert held["source"] == f"{report.REPORT_SCHEMA}:{result.uuid}"
    # The page says it: the line's kind above its figures, and each figure as a measure.
    text = _text(_page(_client(people["owner"]), deployment))
    assert f"Gross exposure (cash, before insurance): kind {em.MODELED}" in text
    eal = "Gross exposure (cash, before insurance): Expected annual loss (EAL)"
    assert (f"Exposure: {eal} modeled_exposure; {rows[eal]}; period {DAY} to {DAY}, for that period alone; rests on "
            f"snapshot simulation-inputs:{result.uuid} ({result.input_digest}); recorded in "
            f"{report.REPORT_SCHEMA}:{result.uuid}") in text
    assert em.RULE in text and em.PERIOD_RULE in text and em.BASIS_RULE in text
    pdf = _client(people["owner"]).get(_url(deployment, "?output=pdf"))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_a_residual_runs_figures_are_measures_of_the_residual_run(deployment, people):
    scenario, _, current, residual = _service_runs(deployment, people, option_body("0.5"), draws=10_000)
    approve_for_receipt(scenario)
    served = exposure_report.document(deployment)
    rows = _amount_rows(served, exposure_report.RESIDUAL_HEADING)
    typed = _figures(served, exposure_report.RESIDUAL_HEADING)
    assert rows and set(rows) == set(typed)
    for label, text in rows.items():
        held = typed[label]["measure"]
        assert typed[label]["shown"] == text == f"USD {held['amount']}"
        assert held["kind"] == measures.MODELED_EXPOSURE
        assert held["basis"]["content_hash"] == residual.input_digest != current.input_digest
        assert held["source"] == f"{report.REPORT_SCHEMA}:{residual.uuid}"
    # The exposure and its residual stand side by side; the core refuses their sum.
    beside = [value for label, value in dict(served["sections"])[exposure_report.MEASURES_HEADING]
              if label == "Side by side, never added"]
    assert any("beside Residual exposure after controls" in value
               and value.endswith("they do not add (modeled_with_modeled)") for value in beside)


def test_the_deployment_total_is_the_portfolios_own_measure_never_a_sum(deployment, people):
    """The total's measures are the portfolio route's figures, text for text, resting on
    the portfolio's own inputs; the report asks the core whether the scenarios' own
    figures add, is refused, and adds nothing."""
    _member(deployment, people["analyst"], "Payment agent")
    _member(deployment, people["analyst"], "Refund agent", amount=LARGE, rate="0.2")
    row = _totalled(deployment)
    api = _portfolio_api(_client(people["owner"]), deployment)
    served = exposure_report.document(deployment)
    rows = _amount_rows(served, exposure_report.TOTAL_HEADING)
    typed = _figures(served, exposure_report.TOTAL_HEADING)
    assert len(rows) == 2 * len(exposure_report.TOTAL_FIGURES) and set(rows) == set(typed)
    keys = dict((figure if key != "severe_plausible" else f"{figure} (P95)", key)
                for key, figure in exposure_report.TOTAL_FIGURES)
    names = {f"{name}, total": line for line, name in exposure_report.LINE_LABELS.items()}
    for label, text in rows.items():
        name, _, figure = label.partition(": ")
        stated = api["summary"]["lines"][names[name]][keys[figure]]
        held = typed[label]["measure"]
        assert text == f"USD {stated}" == typed[label]["shown"] and held["amount"] == stated
        assert held["kind"] == measures.MODELED_EXPOSURE
        assert held["period"] == {"start": api["portfolio"]["valuation_date"], "end": api["portfolio"]["valuation_date"]}
        assert held["basis"] == {"snapshot_id": f"portfolio-inputs:{row.uuid}", "content_hash": row.input_digest}
        assert held["source"] == f"{portfolio.REPORT_SCHEMA}:{row.uuid}"
    # Never a sum of the scenarios' own figures: the P90 is not, and the core refuses one.
    own = [member["own"]["gross_cash"] for member in api["scenarios"]["included"]]
    p90 = typed["Gross exposure (cash, before insurance), total: P90"]["measure"]["amount"]
    assert Decimal(p90) != sum(Decimal(block["p90"]) for block in own)
    total_rows = dict(served["sections"])[exposure_report.TOTAL_HEADING]
    asked = [value for label, value in total_rows if label.endswith("a sum of the scenarios' own figures")]
    assert asked == ["never made: mythos_core.measures refuses it (modeled_with_modeled); the total is the "
                     "portfolio's joint run, as served"] * 2
    joint = em.portfolio_run(api)
    alone = [em.modeled(joint, "Test", f"own {index}", block["expected_annual_loss"])
             for index, block in enumerate(own)]
    with pytest.raises(measures.MeasuresDoNotAdd) as refused:
        em.total(alone)
    assert refused.value.code == "modeled_with_modeled"
    assert lint.lint(_text(_page(_client(people["owner"]), deployment))).ok


# ======================================================================
# Nothing is typed by default
# ======================================================================


def test_an_estimate_is_never_labelled_a_booked_kind(deployment, people):
    _insured(deployment, people)
    _member(deployment, people["analyst"], "Payment agent")
    _totalled(deployment)
    served = exposure_report.document(deployment)
    kinds = {entry["kind"] for entry in served["measures"]}
    assert kinds == {measures.MODELED_EXPOSURE} and not kinds & set(measures.BOOKED_KINDS)
    figure = em.modeled(RUN, "Exposure", "P90", "12.34")
    assert figure.kind == figure.measure.kind == measures.MODELED_EXPOSURE
    # A figure cannot carry one kind and hold a measure of another.
    with pytest.raises(ValueError):
        em.Figure("Exposure", "P90", "USD 12.34", measures.CONFIRMED_LOSS, figure.measure, None)


def test_an_assumption_is_an_input_as_stated_never_a_measure_and_never_a_gap(deployment, people):
    """An assumption's nature is known: an input the model reads, as someone stated it. It
    is not a measure and not ``unknown``: it is listed where the report lists its
    assumptions, its numbers exactly as before, under one line that says what it is, with no
    kind and no gap."""
    _, result = _insured(deployment, people)
    parameters = report.build_report(result)["parameters"]
    served = exposure_report.document(deployment)
    listed = dict(served["sections"])[exposure_report.ASSUMPTIONS_HEADING]
    assert listed[0] == ("What these are", em.ASSUMPTIONS_ARE)
    rows = dict(listed[1:])
    assert set(rows) == set(parameters) and len(listed) == len(parameters) + 1
    # The numbers as recorded, below the minor unit included: the text the report served before.
    for name, entry in parameters.items():
        assert rows[name] == (f"low {entry.get('low')}, base {entry.get('base')}, high {entry.get('high')} "
                              f"{entry.get('currency') or entry.get('unit')}; source {entry.get('source_type')}; "
                              f"evidence {entry.get('evidence_ref') or 'none named'}; effective "
                              f"{entry.get('effective_date')}")
    assert rows["notification_unit_cost"].startswith("low 2.375, base 2.375, high 2.375 USD; ")
    # Never a measure, never a kind, never unknown.
    assert _figures(served, exposure_report.ASSUMPTIONS_HEADING) == {}
    assert {entry["kind"] for entry in served["measures"]} == {measures.MODELED_EXPOSURE}
    kinds = dict(served["sections"])[exposure_report.MEASURES_HEADING]
    assert not [label for label, _ in kinds
                if label == em.UNKNOWN or label.startswith(exposure_report.ASSUMPTIONS_HEADING)]
    # Never a gap: no line under "What is not measured" names an assumption.
    gaps = [value for _, value in dict(served["sections"])["What is not measured"]]
    assert not [gap for gap in gaps for name in parameters if name in gap]
    text = _text(_page(_client(people["owner"]), deployment))
    assert f"What these are {em.ASSUMPTIONS_ARE}" in text


def test_a_figure_whose_kind_is_not_established_reads_unknown_and_is_never_a_measure():
    # Unknown is not a kind of the core, and nothing is a measure of it.
    assert em.UNKNOWN not in measures.MEASURE_KINDS
    measure = em.modeled(RUN, "Exposure", "P90", "12.34").measure
    for kind, held, why in ((em.UNKNOWN, measure, None), (measures.MODELED_EXPOSURE, None, None),
                            (measures.MODELED_EXPOSURE, None, ""), ("an_estimate", None, "because")):
        with pytest.raises(ValueError):
            em.Figure("Assumptions", "x", "USD 1.00", kind, held, why)
    unknown = em.not_established("Assumptions", "x", "low 1, base 2, high 3 USD", "no kind is established")
    assert (unknown.kind, unknown.measure, unknown.why) == (em.UNKNOWN, None, "no kind is established")
    with pytest.raises(measures.MeasureError) as refused:
        em.total([unknown])
    assert refused.value.code == "not_a_measure"


@pytest.mark.parametrize("run, value, why", [
    # An amount that is not at the currency's minor unit: refused, never rounded or padded.
    (RUN, "12.345", "mythos_core.measures refuses it (amount_precision)"),
    (RUN, "12", "mythos_core.measures refuses it (amount_precision)"),
    (RUN, "-1.00", "mythos_core.measures refuses it (amount_malformed)"),
    (RUN, "twelve", "its amount is not a number"),
    (em.ModelRun("XXX", DAY, RUN.snapshot_id, HASH, RUN.source), "1.00",
     "mythos_core.measures refuses it (currency_retired)"),
    (em.ModelRun("ZZZ", DAY, RUN.snapshot_id, HASH, RUN.source), "1.00",
     "mythos_core.measures refuses it (currency_unknown)"),
    # No valuation date: no period, and none is invented.
    (em.ModelRun("USD", None, RUN.snapshot_id, HASH, RUN.source), "1.00", em.NO_PERIOD),
    (em.ModelRun("USD", "06/10/2026", RUN.snapshot_id, HASH, RUN.source), "1.00",
     "mythos_core.measures refuses it (bad_date)"),
    # A missing basis or source is never accepted.
    (em.ModelRun("USD", DAY, RUN.snapshot_id, "", RUN.source), "1.00", "mythos_core.measures refuses it (bad_digest)"),
    (em.ModelRun("USD", DAY, RUN.snapshot_id, "sha256:" + "AB" * 32, RUN.source), "1.00",
     "mythos_core.measures refuses it (bad_digest)"),
    (em.ModelRun("USD", DAY, "", HASH, RUN.source), "1.00", "mythos_core.measures refuses it (bad_identifier)"),
    (em.ModelRun("USD", DAY, RUN.snapshot_id, HASH, ""), "1.00", "mythos_core.measures refuses it (malformed)"),
    (em.ModelRun("USD", DAY, RUN.snapshot_id, HASH, "a report with spaces"), "1.00",
     "mythos_core.measures refuses it (not_a_name)"),
])
def test_a_figure_the_core_will_not_hold_is_not_a_measure_and_says_why(run, value, why):
    figure = em.modeled(run, "Exposure", "P90", value)
    assert figure.measure is None and figure.why == why
    # Its kind is still the model's, never another, and its text is the report's own.
    assert figure.kind == measures.MODELED_EXPOSURE and figure.shown == f"{run.currency} {value}"
    assert em.said(figure) == f"modeled_exposure; not held as a measure: {why}; shown as recorded: {figure.shown}"
    assert lint.lint(em.said(figure)).ok


def test_a_run_with_no_valuation_date_shows_its_amounts_unchanged_and_names_each_gap(deployment, people, monkeypatch):
    """No period is invented: each figure is still shown, to the last minor unit, is not a
    measure, and is named under "What is not measured"."""
    _insured(deployment, people)
    before = _amount_rows(exposure_report.document(deployment), exposure_report.EXPOSURE_HEADING)
    dated = em.scenario_run

    def undated(built):
        run = dated(built)
        return em.ModelRun(run.currency, None, run.snapshot_id, run.content_hash, run.source)

    monkeypatch.setattr(em, "scenario_run", undated)
    served = exposure_report.document(deployment)
    assert _amount_rows(served, exposure_report.EXPOSURE_HEADING) == before
    typed = _figures(served, exposure_report.EXPOSURE_HEADING)
    assert set(typed) == set(before)
    assert all(entry["measure"] is None and entry["why"] == em.NO_PERIOD
               and entry["kind"] == measures.MODELED_EXPOSURE for entry in typed.values())
    gaps = [value for _, value in dict(served["sections"])["What is not measured"]]
    for label in before:
        name, _, figure = label.partition(": ")
        assert f"{name}, {figure}: not held as a measure: {em.NO_PERIOD}" in gaps
    assert served["status"] == "AUDIT_INCOMPLETE"


# ======================================================================
# A total is the core's to make
# ======================================================================


def test_unlike_kinds_two_currencies_and_modelled_figures_never_add():
    loss, expense = _booked(), _booked(measures.REMEDIATION_EXPENSE)
    later = _booked(start="2026-04-01", end="2026-06-30", amount="5.25")
    euros = _booked(currency="EUR", start="2026-04-01", end="2026-06-30")
    modelled, other = em.modeled(RUN, "Exposure", "P90", "12.34"), em.modeled(RUN, "Exposure", "P50", "1.00")
    for figures, code in (
        ((loss, expense), "kind_mismatch"),
        ((loss, euros), "currency_mismatch"),
        ((modelled, loss), "modeled_with_booked"),
        ((modelled, other), "modeled_with_modeled"),
        ((loss, _booked()), "overlapping_periods"),
        ((_booked(measures.FUNDS_FROZEN), _booked(measures.FUNDS_RETURNED)), "kind_mismatch"),
        ((_booked(measures.INSURANCE_PROMISED), _booked(measures.INSURANCE_RECEIVED)), "kind_mismatch"),
    ):
        with pytest.raises(measures.MeasuresDoNotAdd) as refused:
            em.total(figures)
        assert refused.value.code == code == em.why_not_added(figures)
    with pytest.raises(measures.MeasureError) as nothing:
        em.total([])
    assert nothing.value.code == "nothing_to_add"
    # One kind, one currency, one basis, no shared day: the core adds them, exactly.
    summed = em.total([loss, later])
    assert type(summed) is measures.Total and summed.kind == measures.CONFIRMED_LOSS
    assert summed.amount == measures.Money(Decimal("15.25"), "USD") and em.why_not_added([loss, later]) is None


def test_two_figures_set_side_by_side_are_the_cores_and_are_never_summed(deployment, people):
    _insured(deployment, people)
    served = exposure_report.document(deployment)
    typed = _figures(served, exposure_report.EXPOSURE_HEADING)
    gross = typed["Gross exposure (cash, before insurance): Expected annual loss (EAL)"]["shown"]
    net = typed["Net exposure (cash retained after insurance): Expected annual loss (EAL)"]["shown"]
    beside = [value for label, value in dict(served["sections"])[exposure_report.MEASURES_HEADING]
              if label == "Side by side, never added"]
    assert beside == [
        f"Exposure, Gross exposure (cash, before insurance): Expected annual loss (EAL) (modeled_exposure, {gross}) "
        f"beside Exposure, Net exposure (cash retained after insurance): Expected annual loss (EAL) "
        f"(modeled_exposure, {net}): they do not add (modeled_with_modeled)"]
    # Neither the sum nor the difference of the pair is anywhere on the page.
    text = _text(_page(_client(people["owner"]), deployment))
    amounts = [Decimal(gross.split()[1]), Decimal(net.split()[1])]
    for computed in (amounts[0] + amounts[1], amounts[0] - amounts[1]):
        assert f"USD {computed}" not in text
    with pytest.raises(measures.MeasureError) as refused:
        em.beside(em.modeled(RUN, "Exposure", "P90", "1.00"), em.not_established("A", "x", "1 USD", "no kind"))
    assert refused.value.code == "not_a_measure"
    # Where the core would add two figures, the report still adds nothing, and says so.
    said = em.beside(_booked(), _booked(start="2026-04-01", end="2026-06-30"))
    assert said.endswith(f": {em.NOT_SUMMED}") and "15" not in said and "20.00" not in said


def _names(module) -> tuple[set[str], list[ast.Call]]:
    tree = ast.parse(inspect.getsource(module))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    return names, [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def test_the_report_adds_no_amount_itself_and_reads_no_receipt():
    """The report path has no arithmetic on money of its own: no ``Decimal`` and no sum in
    the report, one ``Decimal(...)`` in the measures module (the amount the report prints,
    read as it stands), and one call of the core's ``total``. Neither module imports the
    receipt, its service or anything that writes."""
    arithmetic = {"sum", "fsum", "quantize", "Decimal", "round", "normalize", "scaleb"}
    names, _ = _names(exposure_report)
    assert not names & arithmetic, names & arithmetic
    names, calls = _names(em)
    assert not names & (arithmetic - {"Decimal"}), names & arithmetic
    called = [call.func.id for call in calls if isinstance(call.func, ast.Name)]
    assert called.count("Decimal") == 1
    totals = [call for call in calls if isinstance(call.func, ast.Attribute) and call.func.attr == "total"
              and isinstance(call.func.value, ast.Name) and call.func.value.id == "measures"]
    assert len(totals) == 1
    imported = set()
    for node in ast.walk(ast.parse(inspect.getsource(em))):
        if isinstance(node, ast.ImportFrom):
            imported |= {node.module or ""} | {alias.name for alias in node.names}
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
    assert imported == {"__future__", "annotations", "dataclasses", "dataclass", "decimal", "Decimal",
                        "InvalidOperation", "mythos_core", "measures"}


# ======================================================================
# The kinds are the core's, in the core's words
# ======================================================================


def _core_table() -> dict[str, str]:
    """Each kind's meaning as ``mythos_core.measures``' own docstring tables it."""
    held: dict[str, str] = {}
    kind = None
    for line in (measures.__doc__ or "").splitlines():
        if line.startswith("``") and line.split("``")[1] in measures.MEASURE_KINDS:
            kind = line.split("``")[1]
            held[kind] = line.split("``", 2)[2].strip()
        elif kind is not None and line.startswith(" " * 20) and line.strip():
            held[kind] += " " + line.strip()
        else:
            kind = None
    return held


def test_the_kinds_are_the_cores_eight_each_in_the_cores_words():
    assert tuple(em.KIND_MEANS) == measures.MEASURE_KINDS and len(em.KIND_MEANS) == 8
    table = _core_table()
    if measures.__doc__:  # absent only under python -OO
        assert table == em.KIND_MEANS
    assert em.MODELED == "modeled_exposure: a figure a model computed for a scenario: never booked, and never " \
                         "added to another"
    readme = " ".join((REPO / "README.md").read_text(encoding="utf-8").split())
    spec = " ".join((REPO / "docs/economics/spec-v1.md").read_text(encoding="utf-8").split())
    for kind, means in em.KIND_MEANS.items():
        assert f"`{kind}`: {means}" in readme, kind
        assert lint.lint(f"{kind}: {means}").ok
    assert "kinds are never added" in readme and "### 38.2 Every figure says what kind it is" in spec
    for words in (em.RULE, em.PERIOD_RULE, em.BASIS_RULE, em.ASSUMPTIONS_ARE, em.NO_PERIOD, em.NOT_SUMMED):
        assert lint.lint(words).ok, words
    assert em.RULE in spec and em.PERIOD_RULE in spec and em.BASIS_RULE in spec and em.ASSUMPTIONS_ARE in spec
    # The README says both: the period and the basis of a modelled figure.
    assert "Its period is the valuation day alone" in readme
    assert "Its basis is the stored inputs of the run that computed it, named with that run's input digest" in readme
    assert "An assumption is not a measure" in readme and "An assumption is not a measure" in spec
