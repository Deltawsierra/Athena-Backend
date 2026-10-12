"""Economic Exposure step 6, PR A: the writer of stated distributions and of the
scenario's frequency, and the range test, two-sided for every stated distribution and,
for the frequency, by the rate its count implies (``docs/economics/spec-v1.md``,
sections 19.2, 24.8 and 25.1, decisions 9 and 12 of section 25.10).

- The range test is two-sided. Before, a stated distribution held its row's figures
  from one side only (the base between its P5 and P95, the low and the high inside
  its support), so a gamma whose median lay far below the row's low still fitted. Now
  a continuous one's median lies between the low and the high, and at least
  ``RANGE_MASS_FLOOR`` (one constant) of its mass between them; a refusal names the
  variable and the test it failed; and a fixed row (low = base = high) states no
  continuous distribution (``distribution_on_fixed_row``). The same test at write
  time and at run time.
- The frequency is held to its rate. Its low, base and high are values of its annual
  RATE; a count distribution says how the count varies from year to year given the
  rate, and how uncertain the rate is. So the frequency is held by its exact mean
  between the low and the high (the rate test), its support, round 2's base rule, and
  the rate its count implies from both sides (a negative binomial's Gamma, a
  zero-inflated Poisson's zero or rate); and it may state a fixed rate only as a
  Poisson of that rate. Every other count row holds the count itself, and is held
  from both sides like any figure (review round 1).
- The writer. A parameter-set version (the existing POST) may state each entry's
  distribution and the scenario's frequency; a build may state an effect attribute's,
  the other writer of an event's parameters. Each is recorded on the new version,
  read back, part of its digest, and used by a run. Nothing is written past a refusal,
  a viewer is 403, a body over the limit 413, and the version's transaction only
  inserts.
"""

from __future__ import annotations

import contextlib
import copy
import json
import sys
import types
from datetime import date
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from assurance.economics import builder, simulation_service
from assurance.economics import models as econ_models
from assurance.economics.api import MAX_BODY_BYTES
from assurance.economics.engine import parameter_set as pset
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine.formulas import evaluate
from assurance.economics.engine.money import Money
from assurance.economics.engine.parameters import POINTS, Parameter
from assurance.economics.models import (
    CustomerParameterSet,
    EconomicsRewriteRefused,
    EngineRefused,
    FinancialParameter,
    FinancialScenario,
    SimulationResult,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_scenarios import _entry, full_document

pytestmark = pytest.mark.django_db
User = get_user_model()
SET_KEY = "bank_prod_2026q4"
LABEL = "SYNTHETIC / ILLUSTRATIVE"
SPEC = Path(__file__).resolve().parent.parent / "docs" / "economics" / "spec-v1.md"


def stated(distribution_id, sparse=None, **params) -> dict:
    """A stated distribution in its stored form, its parameters as decimal strings."""
    obj = {"id": distribution_id, "version": 1, "params": {k: str(v) for k, v in params.items()}}
    if sparse is not None:
        obj["sparse"] = sparse
    return obj


# Each figure below was worked out with the engine's own quantiles and CDFs; every
# one of the refused cases passed the one-sided test this step replaces.
#: average_transaction_value 20,000 / 25,000 / 32,000 (money per transfer).
ATV = ("20000", "25000", "32000")
#: Holds the row from both sides: P50 25,000, 88% of its mass in range.
ATV_GOOD = stated("lognormal", mu="10.1266", sigma="0.15")
#: Mean 25,000 (the base), P5 to P95 [0, 128,800]: one-sided, it fitted; its median
#: is 2,593, far below the low of 20,000.
ATV_GAMMA_BELOW_THE_LOW = stated("gamma", shape="0.2", scale="125000")
#: P50 40,000, above the high of 32,000.
ATV_MEDIAN_ABOVE_THE_HIGH = stated("lognormal", mu="10.5966", sigma="1")
#: P50 25,000, in range, but only 18.6% of its mass between 20,000 and 32,000.
ATV_LITTLE_MASS = stated("lognormal", mu="10.1266", sigma="1")
#: transactions_per_day 15,000 / 18,000 / 21,000: P50 17,940, 91% in range.
TPD = ("15000", "18000", "21000")
TPD_GOOD = stated("gamma", shape="100", scale="180")
#: recovery_rate 0.70 / 0.825 / 0.95: P50 0.83, 97% in range.
RR = ("0.70", "0.825", "0.95")
RR_GOOD = stated("beta_binomial_rate", alpha="33", beta="7")
#: The frequency, a rate of 1 / 2 / 4 events a year, Poisson(2): its mean, its rate, 2.
FREQUENCY_GOOD = stated("poisson", rate="2")


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "viewer": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["viewer"])


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _set_url(deployment, versions=True):
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/{SET_KEY}/"
    return base + "versions/" if versions else base


def _post_set(client, deployment, document, raw=False, **extra):
    data = document if raw else json.dumps(document)
    return client.post(_set_url(deployment), data=data, content_type="application/json", **extra)


def _post_build(client, deployment, body):
    url = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/"
    return client.post(url, data=json.dumps(body), content_type="application/json")


def _payment_document(*, atv=ATV, atv_distribution=None, distributions=True, frequency=True,
                      frequency_figures=("1", "2", "4"), frequency_distribution=FREQUENCY_GOOD):
    """The payment agent's three set variables, each a customer's range stating its
    distribution, and the scenario's frequency: SYNTHETIC figures."""
    variables = {
        "transactions_per_day": _entry("count_per_day", *TPD),
        "average_transaction_value": _entry("money_per_unit", *atv),
        "recovery_rate": _entry("ratio", *RR),
    }
    if distributions:
        variables["transactions_per_day"]["distribution"] = TPD_GOOD
        variables["average_transaction_value"]["distribution"] = ATV_GOOD
        variables["recovery_rate"]["distribution"] = RR_GOOD
    if atv_distribution is not None:
        variables["average_transaction_value"]["distribution"] = atv_distribution
    document = {"variables": variables}
    if frequency:
        document["frequency"] = _entry("count", *frequency_figures, source_type="INDUSTRY_BENCHMARK",
                                       evidence_ref=f"{LABEL}: industry loss data",
                                       distribution=frequency_distribution)
    return document


def _point_document(**over):
    """The same three variables as point masses, which a run draws nothing from."""
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.825"),
    }
    for name, entry in over.items():
        variables[name] = entry
    return {"variables": variables}


def _attribute(unit, *figures, **over):
    fields = {"source_type": "EXPERT_ESTIMATE", "evidence_ref": f"{LABEL}: made up", **over}
    return _entry(unit, *figures, **fields)


def _payment_world(deployment):
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                 identifier="agent://payments-agent")
    finding = Finding.objects.create(deployment=deployment, fingerprint="fp-0", finding_type="approval_check_missing",
                                     title="finding 0", severity="high")
    return asset, finding


def _build_body(asset, finding, *, version=1, title="Payment agent: destination changed after approval", **attributes):
    effect_attributes = {
        "success_rate": _attribute("ratio", "0.35"),
        "exploitable_window_hours": _attribute("hours", "1.25"),
        "incident_response_cost": _attribute("money", "165000"),
        "legal_response_cost": _attribute("money", "825000"),
    }
    effect_attributes.update(attributes)
    return {
        "title": title,
        "parameter_set": {"set_key": SET_KEY, "version": version}, "currency": "USD", "as_of": "2026-10-06",
        "effects": [{
            "key": "redirect", "origin": "hypothetical", "effect_type": "funds_transfer_altered",
            "asset": str(asset.uuid), "business_process": "payments", "attributes": effect_attributes,
        }],
        "findings": [{"finding": str(finding.uuid), "effect": "redirect", "role": "prerequisite"}],
    }


def _row(name, unit, figures, source="CUSTOMER_PROVIDED") -> Parameter:
    money = unit.startswith("money")

    def value(text):
        return Money(Decimal(text), "USD") if money else Decimal(text)

    low, base, high = figures
    return Parameter(name=name, unit=unit, source_type=source, low=value(low), base=value(base), high=value(high),
                     evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1))


def _nothing_recorded():
    assert not CustomerParameterSet.objects.exists() and not FinancialParameter.objects.exists()


# ======================================================================
# The two-sided range test (the engine, at run time; the writer below)
# ======================================================================


def _refusal(parameter, distribution, *, frequency=False):
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        if frequency:
            ss.resolve_frequency(parameter, ss.parse_stated(distribution))
        else:
            ss.resolve(parameter, ss.parse_stated(distribution))
    return refused.value


def _one_sided(parameter, distribution) -> bool:
    """The test this step replaces: the base between P5 and P95, and the low and the
    high inside the support."""
    built = ss.build(ss.parse_stated(distribution), parameter.source_type)
    low, base, high = (float(getattr(parameter.at(p), "amount", parameter.at(p))) for p in POINTS)
    lower, upper = ss.support(built)
    return lower <= low and high <= upper and built.ppf(0.05) <= base <= built.ppf(0.95)


def test_a_gamma_whose_median_lies_below_the_low_is_refused():
    """Spec 25, decision 9's open case: one-sided, a gamma whose median lies far below
    the row's low still fitted. Refused, naming the variable and the median test."""
    row = _row("average_transaction_value", "money_per_unit", ATV)
    assert _one_sided(row, ATV_GAMMA_BELOW_THE_LOW)
    refused = _refusal(row, ATV_GAMMA_BELOW_THE_LOW)
    assert refused.code == "distribution_contradicts_range"
    assert refused.detail.startswith("average_transaction_value is 20000 / 25000 / 32000; its gamma fails the median")
    assert "P50 2593" in refused.detail


def test_a_distribution_whose_median_lies_above_the_high_is_refused():
    row = _row("average_transaction_value", "money_per_unit", ATV)
    assert _one_sided(row, ATV_MEDIAN_ABOVE_THE_HIGH)
    refused = _refusal(row, ATV_MEDIAN_ABOVE_THE_HIGH)
    assert refused.code == "distribution_contradicts_range"
    assert "its lognormal fails the median test" in refused.detail and "P50 39998" in refused.detail


def test_one_with_less_than_the_floor_of_its_mass_in_range_is_refused():
    """Its median lies in range, so only the mass test catches it: 18.6% of it lies
    between the low and the high."""
    row = _row("average_transaction_value", "money_per_unit", ATV)
    assert _one_sided(row, ATV_LITTLE_MASS)
    built = ss.build(ss.parse_stated(ATV_LITTLE_MASS), row.source_type)
    assert 20000 <= built.ppf(0.5) <= 32000
    assert ss.mass_between(built, 20000.0, 32000.0) < float(ss.RANGE_MASS_FLOOR)
    refused = _refusal(row, ATV_LITTLE_MASS)
    assert refused.code == "distribution_contradicts_range"
    assert "its lognormal fails the mass test" in refused.detail
    mass = ss.mass_between(built, 20000.0, 32000.0)
    assert f"P(low <= X <= high) {ss.dist.float_text(mass)} (at least 0.5)" in refused.detail


def test_a_fixed_row_states_no_continuous_distribution():
    """low = base = high is a point mass. One-sided, a lognormal on it fitted, and a
    fixed figure was drawn from a range."""
    fixed = _row("legal_retainer", "money", ("250000", "250000", "250000"))
    lognormal = stated("lognormal", mu="12.43", sigma="0.1")
    assert _one_sided(fixed, lognormal)
    refused = _refusal(fixed, lognormal)
    assert refused.code == "distribution_on_fixed_row"
    assert refused.detail == (
        "legal_retainer is 250000 / 250000 / 250000, one figure: a point mass, and it states a lognormal"
    )
    # Without a distribution a fixed row is a point mass, as ever.
    assert ss.resolve(fixed, None).rule == ss.RULE_POINT_MASS


def _frequency(low, base, high):
    return _row(ss.FREQUENCY_PARAMETER, "count", (low, base, high), source="INDUSTRY_BENCHMARK")


def _nb_with_mean(size: str, mean: str) -> dict:
    """A negative binomial of ``size`` whose mean is ``mean``: p = size / (size + mean),
    to 20 places, as a customer's mean and dispersion state it."""
    s, m = Decimal(size), Decimal(mean)
    p = (s / (s + m)).quantize(Decimal("1e-20"))
    return stated("negative_binomial", size=size, probability=format(p, "f"))


def test_a_count_may_state_a_fixed_rate_whose_mean_it_is():
    """A fixed rate, 2 / 2 / 2 events a year, with Poisson(2): the rate is known and
    the count still varies from year to year. Its mean must be that figure: Poisson(3)
    on 2 / 2 / 2 is refused by the rate test, and so is Poisson(0.01) on 0 / 0 / 0. A
    negative binomial of mean 2 is not a known rate (its rate is a Gamma): refused on
    a fixed row (review round 1, MEDIUM-2)."""
    resolved = ss.resolve_frequency(_frequency("2", "2", "2"), ss.parse_stated(stated("poisson", rate="2")))
    assert resolved.rule == ss.RULE_STATED and resolved.drawn
    for figures, rate in ((("2", "2", "2"), "3"), (("0", "0", "0"), "0.01")):
        refused = _refusal(_frequency(*figures), stated("poisson", rate=rate), frequency=True)
        assert refused.code == "distribution_contradicts_range", figures
        assert "values of its rate; its poisson fails the rate test" in refused.detail, refused.detail
    refused = _refusal(_frequency("2", "2", "2"), stated("negative_binomial", size="2", probability="0.5"),
                       frequency=True)
    assert refused.code == "distribution_on_fixed_row"


def test_a_distribution_that_holds_its_row_from_both_sides_is_drawn_from():
    for name, unit, figures, distribution in (
        ("average_transaction_value", "money_per_unit", ATV, ATV_GOOD),
        ("transactions_per_day", "count_per_day", TPD, TPD_GOOD),
        ("recovery_rate", "ratio", RR, RR_GOOD),
    ):
        resolved = ss.resolve(_row(name, unit, figures), ss.parse_stated(distribution))
        assert resolved.rule == ss.RULE_STATED, name
    frequency = _row(ss.FREQUENCY_PARAMETER, "count", ("1", "2", "4"), source="INDUSTRY_BENCHMARK")
    assert ss.resolve_frequency(frequency, ss.parse_stated(FREQUENCY_GOOD)).rule == ss.RULE_STATED


def test_the_step_7b_frequency_fixtures():
    """Two step-7b fixtures. Poisson(4) on a rate of 1 / 2 / 3 contradicts its row: its
    rate, its mean, is 4, above the high; refused, and its test states 2 / 4 / 6.
    Poisson(5) on 4 / 5 / 6 holds it: its rate is 5, though only 49.7% of its yearly
    count falls in 4 to 6, which says nothing about the rate."""
    refused = _refusal(_frequency("1", "2", "3"), stated("poisson", rate="4"), frequency=True)
    assert refused.code == "distribution_contradicts_range" and "fails the rate test" in refused.detail
    assert "mean 4," in refused.detail
    five = ss.parse_stated(stated("poisson", rate="5"))
    assert ss.resolve_frequency(_frequency("4", "5", "6"), five).rule == ss.RULE_STATED
    built = ss.build(five, ss.SourceType.INDUSTRY_BENCHMARK)
    assert ss.mass_between(built, 4.0, 6.0) < float(ss.RANGE_MASS_FLOOR)  # the mass test is not a count's


def test_a_counts_figures_are_its_rate():
    """The frequency is held by its rate, never by its count's spread: a rate of 0.01 /
    0.05 / 0.2 a year with Poisson(0.05) holds (no whole number lies in that range, and
    the median and mass tests refused it); a negative binomial whose mean lies above
    the high is refused by the rate test."""
    rare = ss.resolve_frequency(_frequency("0.01", "0.05", "0.2"), ss.parse_stated(stated("poisson", rate="0.05")))
    assert rare.rule == ss.RULE_STATED
    assert ss.resolve_frequency(_frequency("0", "0.05", "0.2"), ss.parse_stated(stated("poisson", rate="0.05")))
    # size 4, p 0.4: mean 4 x 0.6 / 0.4 = 6, above a high of 4.
    refused = _refusal(_frequency("1", "2", "4"), stated("negative_binomial", size="4", probability="0.4"),
                       frequency=True)
    assert refused.code == "distribution_contradicts_range"
    assert "its negative_binomial fails the rate test" in refused.detail and "mean 6," in refused.detail
    # Any other count row holds the count itself, from both sides (review round 1,
    # MEDIUM-1): Poisson(40) on 20 / 40 / 60 customers holds every test.
    customers = ss.resolve(_row("e.affected_customers", "count", ("20", "40", "60")),
                           ss.parse_stated(stated("poisson", rate="40")))
    assert customers.rule == ss.RULE_STATED
    assert ss.FREQUENCY_RANGE_TESTS == ("support", "rate", "base", "rate_median", "rate_mass")


def test_round_2s_base_rule_refuses_what_the_rate_test_does_not():
    """Kept, because it refuses cases the rate test passes: a base far from the mean
    while the mean is still inside the range. 0 / 1 / 2 stating Poisson(0.02) (its
    rate 0.02, its P95 count 0, a base of 1) and 0 / 10 / 20 stating Poisson(1) (its
    P95 count 3, a base of 10) each hold the rate test and fail the base test."""
    for figures, rate in ((("0", "1", "2"), "0.02"), (("0", "10", "20"), "1")):
        built = ss.build(ss.parse_stated(stated("poisson", rate=rate)), ss.SourceType.INDUSTRY_BENCHMARK)
        assert float(figures[0]) <= built.mean <= float(figures[2])  # the rate test holds
        refused = _refusal(_frequency(*figures), stated("poisson", rate=rate), frequency=True)
        assert refused.code == "distribution_contradicts_range" and "fails the base test" in refused.detail, figures


def test_a_count_whose_mean_is_undefined_is_refused(monkeypatch):
    """The rate test reads the count's exact mean from its stated parameters, where the
    catalogue has a closed form, and every count of it has one; a count without one
    reads the catalogue's mean, and one whose mean were infinite or undefined is
    refused, never passed."""
    monkeypatch.setattr(ss, "exact_count_mean", lambda distribution, stated=None: None)
    for mean, said in ((None, "undefined"), (float("nan"), "undefined"), (float("inf"), "infinite")):
        monkeypatch.setattr(ss.dist.Poisson, "mean", property(lambda self, mean=mean: mean))
        refused = _refusal(_frequency("1", "2", "4"), FREQUENCY_GOOD, frequency=True)
        assert refused.code == "distribution_contradicts_range"
        assert "fails the rate test" in refused.detail and f"mean {said}," in refused.detail


def test_the_floor_is_one_constant_in_the_inputs(monkeypatch):
    """The floor is RANGE_MASS_FLOOR alone: lowered, the 18.6% case is drawn from;
    it is a limit of the inputs, so a changed floor is a new input digest, and the
    rule that names it is v3."""
    assert ss.RANGE_MASS_FLOOR == Decimal("0.5")
    assert ss.RULE_VERSION == "mythos.economics.parameter-distribution/v3"
    assert ss.limits()["range_mass_floor"] == "0.5"
    assert ss.RANGE_TESTS == ("support", "base", "median", "mass")
    row = _row("average_transaction_value", "money_per_unit", ATV)
    lump = evaluate("x", "notification", "lump_sum", 1, {"amount": _row("x.amt", "money", ("1", "1", "1"))},
                    as_of=date(2026, 10, 6))
    si = ss.ScenarioInput("s", "USD", (ss.LossEvent("ev", "USD", (lump,)),))
    before = ss.digest_of(ss.canonical_inputs(si))
    monkeypatch.setattr(ss, "RANGE_MASS_FLOOR", Decimal("0.15"))
    assert ss.resolve(row, ss.parse_stated(ATV_LITTLE_MASS)).rule == ss.RULE_STATED
    assert ss.digest_of(ss.canonical_inputs(si)) != before


# ======================================================================
# The parameter-set writer
# ======================================================================


def test_a_good_distribution_is_recorded_read_back_and_used_by_a_run(deployment, people):
    """Each variable's distribution and the frequency's, recorded on the new version
    through the POST (by an analyst, the author the signed-in account), stored in the
    one spelling, part of the version's digest, served back, and drawn from by a run
    of a scenario built from the version."""
    document = _payment_document()
    document["variables"]["average_transaction_value"]["distribution"] = stated(
        "lognormal", mu="10.12660", sigma="0.150")  # read in its one spelling
    response = _post_set(_client(people["analyst"]), deployment, document)
    assert response.status_code == 201, response.content
    body = response.json()
    assert (body["version"], body["author"], body["intact"]) == (1, "ann", True)
    served = body["variables"]["average_transaction_value"]["distribution"]
    assert served == ATV_GOOD
    assert body["variables"]["transactions_per_day"]["distribution"] == TPD_GOOD
    assert body["variables"]["recovery_rate"]["distribution"] == RR_GOOD
    assert body["frequency"]["distribution"] == FREQUENCY_GOOD
    assert (body["frequency"]["unit"], body["frequency"]["low"], body["frequency"]["high"]) == ("count", "1", "4")
    # Read back by the owner, a viewer.
    current = _client(people["viewer"]).get(_set_url(deployment, versions=False))
    assert current.status_code == 200 and current.json()["variables"] == body["variables"]
    assert current.json()["frequency"] == body["frequency"]
    version = CustomerParameterSet.objects.get()
    assert version.intact() and version.variable_count == 4
    assert version.content_digest == pset.parse_document(document).digest()
    rows = {row.name: row for row in version.parameter_rows()}
    assert rows["average_transaction_value"].distribution == ATV_GOOD
    assert rows["frequency"].distribution == FREQUENCY_GOOD and rows["frequency"].unit == "count"
    # The distribution and the frequency are the version's content: without them, another digest.
    assert version.content_digest != pset.parse_document(_payment_document(distributions=False)).digest()
    assert version.content_digest != pset.parse_document(_payment_document(frequency=False)).digest()

    # A scenario built from the version, and run: the stated distributions are drawn
    # from, and the frequency makes a draw a year.
    asset, finding = _payment_world(deployment)
    scenario, created = builder.build(deployment, _build_body(asset, finding), author=people["analyst"])
    assert created
    outcome = simulation_service.simulate_scenario(scenario, seed=6, draws=2_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    record = outcome.result.record
    for name, distribution in (("average_transaction_value", "lognormal"), ("transactions_per_day", "gamma"),
                               ("recovery_rate", "beta_binomial_rate")):
        assert record["parameters"][name]["rule"] == ss.RULE_STATED, name
        assert record["parameters"][name]["distribution"]["id"] == distribution, name
    assert record["basis"] == "annual_loss"
    assert record["frequency"]["distribution"]["id"] == "poisson"
    inputs = outcome.result.inputs
    assert inputs["parameters"]["average_transaction_value"]["distribution"] == ATV_GOOD
    assert inputs["frequency"] == ss.FREQUENCY_PARAMETER
    assert inputs["parameters"][ss.FREQUENCY_PARAMETER]["distribution"] == FREQUENCY_GOOD


def test_a_version_that_states_no_distribution_keeps_its_canonical_document():
    """The canonical document, and so the digest, of a version that states no
    distribution and no frequency is the one it had before either could be stated:
    every version already recorded stays intact."""
    content = pset.parse_document(full_document())
    document = content.as_dict()
    assert set(document) == {"schema", "variables", "insurance_sublimits", "insurance_exclusions"}
    assert not any("distribution" in entry for entry in document["variables"].values())
    assert not any("distribution" in entry for entry in document["insurance_sublimits"].values())
    assert pset.FREQUENCY == ss.FREQUENCY_PARAMETER


SET_REFUSALS = [
    ("a gamma whose median lies below the low",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_GAMMA_BELOW_THE_LOW),
     "distribution_contradicts_range",
     "average_transaction_value is 20000 / 25000 / 32000; its gamma fails the median"),
    ("a median above the high",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_MEDIAN_ABOVE_THE_HIGH),
     "distribution_contradicts_range",
     "average_transaction_value is 20000 / 25000 / 32000; its lognormal fails the median"),
    ("less than the floor of its mass in range",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_LITTLE_MASS),
     "distribution_contradicts_range",
     "average_transaction_value is 20000 / 25000 / 32000; its lognormal fails the mass"),
    ("a distribution on a fixed row",
     lambda d: d["variables"]["average_transaction_value"].update(low="25000", high="25000"),
     "distribution_on_fixed_row", "average_transaction_value is 25000 / 25000 / 25000, one figure"),
    ("a sublimit's that contradicts it",
     lambda d: d.update(insurance_sublimits={"notification": _entry(
         "money", "100000", "150000", "200000", distribution=stated("gamma", shape="0.2", scale="750000"))}),
     "distribution_contradicts_range",
     "insurance_sublimit:notification is 100000 / 150000 / 200000; its gamma fails the median"),
    ("a frequency whose rate lies above the high",
     lambda d: d["frequency"].update(low="1", base="2", high="3", distribution=stated("poisson", rate="4")),
     "distribution_contradicts_range", "frequency is 1 / 2 / 3, values of its rate; its poisson fails the rate"),
    ("a fixed rate its distribution's mean is not",
     lambda d: d["frequency"].update(low="2", base="2", high="2", distribution=stated("poisson", rate="3")),
     "distribution_contradicts_range", "frequency is 2 / 2 / 2, values of its rate; its poisson fails the rate"),
    ("a negative binomial whose mean lies above the high",
     lambda d: d["frequency"].update(distribution=stated("negative_binomial", size="4", probability="0.4")),
     "distribution_contradicts_range",
     "frequency is 1 / 2 / 4, values of its rate; its negative_binomial fails the rate"),
    ("a frequency without its distribution",
     lambda d: d["frequency"].pop("distribution"),
     "field_missing", "frequency: ['distribution']"),
    ("a frequency that is not a count",
     lambda d: d["frequency"].update(distribution=stated("gamma", shape="2", scale="1")),
     "frequency_not_a_count", "gamma"),
    ("a frequency in another unit",
     lambda d: d["frequency"].update(unit="count_per_day"),
     "unit_mismatch", "frequency.unit"),
    ("a distribution not for the unit",
     lambda d: d["variables"]["recovery_rate"].update(distribution=stated("lognormal", mu="0", sigma="1")),
     "distribution_not_for_unit", "recovery_rate"),
    ("an expert range for a customer's figure",
     lambda d: d["variables"]["average_transaction_value"].update(
         distribution=stated("pert", minimum="20000", mode="25000", maximum="32000")),
     "expert_not_allowed", ""),
    ("a JSON number in a distribution",
     lambda d: d["variables"]["average_transaction_value"]["distribution"]["params"].update(sigma=0.15),
     "distribution_malformed", "variables.average_transaction_value.distribution: params.sigma"),
    ("a distribution of no catalogue",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=stated("cauchy", loc="1")),
     "distribution_unknown", "variables.average_transaction_value.distribution"),
    ("a distribution's unknown version",
     lambda d: d["variables"]["average_transaction_value"]["distribution"].update(version=2),
     "distribution_version_unknown", "variables.average_transaction_value.distribution"),
    ("a distribution that is not an object",
     lambda d: d["variables"]["average_transaction_value"].update(distribution="lognormal"),
     "distribution_malformed", "variables.average_transaction_value.distribution"),
]


@pytest.mark.parametrize("what, edit, code, detail", SET_REFUSALS, ids=[c[0] for c in SET_REFUSALS])
def test_the_post_refuses_with_the_tests_code_naming_the_variable_and_records_nothing(deployment, people, what,
                                                                                      edit, code, detail):
    document = copy.deepcopy(_payment_document())
    edit(document)
    response = _post_set(_client(people["analyst"]), deployment, document)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code, response.json()
    assert response.json()["detail"].startswith(detail) or detail in response.json()["detail"], response.json()
    _nothing_recorded()


#: (what, the document's edit, the expected code and the test named), on the variables
#: and the frequency a payment scenario reads.
AGREEING = [
    ("gamma below the low",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_GAMMA_BELOW_THE_LOW), "median"),
    ("median above the high",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_MEDIAN_ABOVE_THE_HIGH), "median"),
    ("little mass in range",
     lambda d: d["variables"]["average_transaction_value"].update(distribution=ATV_LITTLE_MASS), "mass"),
    ("fixed row", lambda d: d["variables"]["average_transaction_value"].update(
        low="25000", base="25000", high="25000", distribution=ATV_GOOD), None),
    ("the frequency's", lambda d: d["frequency"].update(low="1", base="2", high="3",
                                                        distribution=stated("poisson", rate="4")), "rate"),
    ("the frequency's implied rate", lambda d: d["frequency"].update(
        low="1000", base="1200", high="1400", distribution=_nb_with_mean("0.1", "1200")), "rate_median"),
]


@pytest.mark.parametrize("what, edit, test", AGREEING, ids=[c[0] for c in AGREEING])
def test_write_time_and_run_time_refusals_agree(deployment, people, monkeypatch, what, edit, test):
    """The POST refuses the version; a version recorded with the test switched off,
    as one recorded before this step or under an earlier floor, is refused by a build
    of it and by the run of a scenario built from it with the same code and the same
    detail, word for word: one test, at write, build and run time."""
    document = _point_document()
    document["frequency"] = _entry("count", "1", "2", "4", source_type="INDUSTRY_BENCHMARK",
                                   evidence_ref=f"{LABEL}: industry loss data", distribution=FREQUENCY_GOOD)
    document["variables"]["average_transaction_value"] = _entry("money_per_unit", *ATV, distribution=ATV_GOOD)
    edit(document)
    written = _post_set(_client(people["analyst"]), deployment, document)
    assert written.status_code == 400, written.content
    code, detail = written.json()["code"], written.json()["detail"]
    assert code == ("distribution_on_fixed_row" if test is None else "distribution_contradicts_range")
    assert test is None or f"fails the {test} test" in detail
    _nothing_recorded()

    with monkeypatch.context() as switched_off:
        switched_off.setattr(ss, "check_fits_range", lambda distribution, parameter, **_: None)
        CustomerParameterSet.record(deployment, SET_KEY, document, author=people["analyst"])
    asset, finding = _payment_world(deployment)
    # A build re-checks the version's distributions under the rule now (review round
    # 1, LOW-3): refused with the same code and detail, and nothing built.
    with pytest.raises(EngineRefused) as built:
        builder.build(deployment, _build_body(asset, finding), author=people["analyst"])
    assert (built.value.code, built.value.detail) == (code, detail)
    assert not FinancialScenario.objects.exists()
    # A scenario built before that check (switched off here) is refused by its run alike.
    with monkeypatch.context() as unchecked:
        unchecked.setattr(builder, "check_set_distributions", lambda rows: None)
        scenario, _ = builder.build(deployment, _build_body(asset, finding), author=people["analyst"])
    run = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert (run.code, run.detail) == (code, detail)
    assert run.result is not None and run.result.status == "refused"  # the inputs decide it: recorded


@pytest.mark.parametrize(
    "figures, rate",
    [(("2", "2", "2"), "2"), (("4", "5", "6"), "5"), (("0.01", "0.05", "0.2"), "0.05")],
    ids=["a fixed rate", "4 to 6 a year", "a rare rate"],
)
def test_a_frequency_that_holds_its_rate_is_recorded_and_run(deployment, people, figures, rate):
    """Through the POST and a run: a fixed rate with Poisson(2), Poisson(5) on 4 / 5 /
    6, and Poisson(0.05) on 0.01 / 0.05 / 0.2 are each recorded, and a scenario built
    from the version draws a year's count from it."""
    low, base, high = figures
    document = _point_document()
    document["frequency"] = _entry("count", low, base, high, source_type="INDUSTRY_BENCHMARK",
                                   evidence_ref=f"{LABEL}: industry loss data",
                                   distribution=stated("poisson", rate=rate))
    response = _post_set(_client(people["analyst"]), deployment, document)
    assert response.status_code == 201, response.content
    assert response.json()["frequency"]["distribution"] == stated("poisson", rate=rate)
    asset, finding = _payment_world(deployment)
    scenario, _ = builder.build(deployment, _build_body(asset, finding), author=people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=4, draws=1_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    record = outcome.result.record
    assert record["basis"] == "annual_loss" and record["frequency"]["parameter"] == ss.FREQUENCY_PARAMETER
    assert record["frequency"]["distribution"]["id"] == "poisson"
    assert record["frequency"]["distribution"]["params"] == {"rate": rate}


def test_a_viewer_is_refused_and_a_body_over_the_limit_is_413(deployment, people):
    document = _payment_document()
    response = _post_set(_client(people["viewer"]), deployment, document)
    assert response.status_code == 403, response.content
    _nothing_recorded()
    padded = json.dumps(document)[:-1] + ", " + json.dumps({"padding": "x" * MAX_BODY_BYTES})[1:]
    response = _post_set(_client(people["analyst"]), deployment, padded, raw=True)
    assert response.status_code == 413, response.content
    declared = _post_set(_client(people["admin"]), deployment, document, CONTENT_LENGTH=str(MAX_BODY_BYTES + 1))
    assert declared.status_code == 413, declared.content
    _nothing_recorded()
    assert _post_set(_client(people["admin"]), deployment, document).status_code == 201


def test_a_stated_distribution_is_refused_503_while_the_engine_will_not_import(deployment, people, monkeypatch):
    """A document that states a distribution needs the probabilistic engine to read
    it: while numpy or the engine will not import it is 503 and nothing is recorded.
    One that states none never imports it, and is recorded as ever."""
    monkeypatch.setitem(sys.modules, "assurance.economics.engine.scenario_simulation", None)
    response = _post_set(_client(people["analyst"]), deployment, _payment_document())
    assert response.status_code == 503, response.content
    _nothing_recorded()
    assert _post_set(_client(people["analyst"]), deployment, _point_document()).status_code == 201


def test_a_versions_transaction_only_writes(deployment, people, monkeypatch):
    """Every check of the version and its rows, each stated distribution's test of
    its figures included, runs before the transaction: inside it, one INSERT per row
    and nothing else, so a stop's write on SQLite waits for the inserts alone."""
    captured: list[list[str]] = []
    real = transaction.atomic

    @contextlib.contextmanager
    def watched(*args, **kwargs):
        with CaptureQueriesContext(connection) as queries, real(*args, **kwargs):
            yield
        captured.append([q["sql"] for q in queries.captured_queries])

    monkeypatch.setattr(econ_models, "transaction", types.SimpleNamespace(atomic=watched))
    response = _post_set(_client(people["analyst"]), deployment, _payment_document())
    assert response.status_code == 201, response.content
    (inside,) = captured
    statements = [q for q in inside if not q.lstrip().upper().startswith(("SAVEPOINT", "RELEASE", "BEGIN", "COMMIT"))]
    assert [q[:120] for q in statements if not q.lstrip().upper().startswith("INSERT")] == []
    assert len(statements) == 1 + FinancialParameter.objects.count() == 5
    # The insert-only path takes nothing its checks did not pass, or that changed since.
    unchecked = CustomerParameterSet(deployment=deployment, set_key="q4", variable_count=1,
                                     content_digest="sha256:" + "a" * 64)
    with pytest.raises(EconomicsRewriteRefused):
        unchecked._insert_as_marked()
    version = CustomerParameterSet(deployment=deployment, set_key="q4", variable_count=1,
                                   content_digest="sha256:" + "a" * 64)
    row = FinancialParameter.from_engine(_row("recovery_rate", "ratio", RR), parameter_set=version,
                                         distribution=RR_GOOD)
    CustomerParameterSet.check_rows(version, [row])
    row.distribution = ATV_GAMMA_BELOW_THE_LOW  # changed after its check
    with pytest.raises(EconomicsRewriteRefused):
        row._insert_as_marked()
    assert CustomerParameterSet.objects.count() == 1


def test_the_scenarios_frequency_and_its_sets_are_one_or_refused(deployment, people):
    """A scenario reads the frequency of the parameter-set version it was built from.
    A scenario holding a frequency of its own as well is a conflict: refused, never
    resolved by taking one, and nothing recorded."""
    CustomerParameterSet.record(deployment, SET_KEY, _payment_document(), author=people["analyst"])
    asset, finding = _payment_world(deployment)
    scenario, _ = builder.build(deployment, _build_body(asset, finding), author=people["analyst"])
    FinancialParameter.objects.create(
        scenario=scenario, name=ss.FREQUENCY_PARAMETER, unit="count", source_type="INDUSTRY_BENCHMARK",
        low="1", base="2", high="4", evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1),
        distribution=FREQUENCY_GOOD,
    )
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert outcome.code == "duplicate_id" and "each state a frequency" in outcome.detail
    assert not SimulationResult.objects.exists()


# ======================================================================
# The builder: the other writer of an event's parameters
# ======================================================================


def test_an_effects_attribute_states_a_distribution_under_the_same_rules(deployment, people):
    """An effect's attribute (a scenario parameter the builder writes) may state its
    distribution: held to the same range test when the build is checked, so a
    contradicting one is refused naming the attribute and the test, a fixed one is
    refused, and nothing is written; one that holds is recorded, served back, part of
    the build's identity, and drawn from by a run."""
    CustomerParameterSet.record(deployment, SET_KEY, _point_document(), author=people["analyst"])
    asset, finding = _payment_world(deployment)
    analyst = _client(people["analyst"])
    refused = _post_build(analyst, deployment, _build_body(asset, finding, incident_response_cost=_attribute(
        "money", "100000", "165000", "300000", distribution=stated("gamma", shape="0.2", scale="825000"))))
    assert refused.status_code == 400, refused.content
    assert refused.json()["code"] == "distribution_contradicts_range"
    assert refused.json()["detail"].startswith(
        "redirect.incident_response_cost is 100000 / 165000 / 300000; its gamma fails the median test")
    fixed = _post_build(analyst, deployment, _build_body(asset, finding, incident_response_cost=_attribute(
        "money", "165000", distribution=stated("lognormal", mu="12.0", sigma="0.35"))))
    assert fixed.status_code == 400 and fixed.json()["code"] == "distribution_on_fixed_row", fixed.content
    malformed = _post_build(analyst, deployment, _build_body(asset, finding, incident_response_cost=_attribute(
        "money", "100000", "165000", "300000", distribution={"id": "lognormal", "version": 1, "params": {"mu": 12}})))
    assert malformed.status_code == 400 and malformed.json()["code"] == "distribution_malformed", malformed.content
    assert not FinancialScenario.objects.exists()
    assert not FinancialParameter.objects.filter(scenario__isnull=False).exists()

    holds = stated("lognormal", mu="12", sigma="0.35")  # P50 162,755; 88% in range
    body = _build_body(asset, finding, incident_response_cost=_attribute("money", "100000", "165000", "300000",
                                                                          source_type="CUSTOMER_PROVIDED",
                                                                          distribution=holds))
    built = _post_build(analyst, deployment, body)
    assert built.status_code == 201, built.content
    (effect,) = built.json()["events"][0]["effects"]
    assert effect["attributes"]["incident_response_cost"]["distribution"] == holds
    assert effect["attributes"]["success_rate"]["distribution"] is None
    row = FinancialParameter.objects.get(name="redirect.incident_response_cost")
    assert row.distribution == holds
    # The same body is the same build; the same figures without the distribution another.
    assert _post_build(analyst, deployment, body).status_code == 200
    plain = _build_body(asset, finding, title="the same, stating none", incident_response_cost=_attribute(
        "money", "100000", "165000", "300000", source_type="CUSTOMER_PROVIDED"))
    assert _post_build(analyst, deployment, plain).status_code == 201
    assert FinancialScenario.objects.count() == 2

    scenario = FinancialScenario.objects.get(uuid=built.json()["scenario"]["uuid"])
    outcome = simulation_service.simulate_scenario(scenario, seed=2, draws=1_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    drawn = outcome.result.record["parameters"]["redirect.incident_response_cost"]
    assert drawn["rule"] == ss.RULE_STATED and drawn["distribution"]["id"] == "lognormal"
    # The build without one has a customer's range and no distribution: refused, as ever.
    other = FinancialScenario.objects.exclude(pk=scenario.pk).get()
    assert simulation_service.simulate_scenario(other, seed=2, draws=1_000).code == "no_admissible_distribution"


def test_a_scenario_rows_distribution_is_refused_at_write_and_at_run_alike(deployment, people):
    """The scenario's own row, as the builder writes one: the same code and detail
    when it is saved and when a row written past the check is run."""
    scenario = FinancialScenario.objects.create(deployment=deployment, title="t", author=people["analyst"])
    fields = dict(scenario=scenario, name="c.amt", unit="money", source_type="CUSTOMER_PROVIDED", currency="USD",
                  low="100000", base="200000", high="400000", evidence_ref=f"{LABEL}: made up",
                  effective_date=date(2026, 9, 1), distribution=stated("gamma", shape="0.2", scale="1000000"))
    with pytest.raises(EngineRefused) as written:
        FinancialParameter.objects.create(**fields)
    assert written.value.code == "distribution_contradicts_range"
    assert "c.amt is 100000 / 200000 / 400000; its gamma fails the median test" in written.value.detail
    row = FinancialParameter(**fields)
    with pytest.raises(ss.ScenarioSimulationRefused) as run:
        ss.resolve(row.as_engine(), row.stated_distribution())
    assert (run.value.code, run.value.detail) == (written.value.code, written.value.detail)


# ======================================================================
# Review round 1 (#156): the reviewer's repros, each a test
# ======================================================================


#: The reviewer's frequency: 1,000 / 1,200 / 1,400 events a year.
BIG = ("1000", "1200", "1400")
ZIP_HALF_6 = stated("zero_inflated_poisson", zero_inflation="0.5", rate="6")


def test_only_the_frequency_reads_its_figures_as_a_rate():
    """MEDIUM-1. The rate reading, and the fixed row it allows, are the frequency's
    alone. Any other count row -- an observed repeat count, a number of affected
    customers -- holds the count itself, so a count distribution on it is held from
    both sides like any figure and never stated on a fixed row: the reviewer's
    ZIP(0.5, 6) on an observed repeat count of 3 / 3 / 3 (half its draws say the effect
    never repeated) and ZIP(0.5, 2400) on 1,200 / 1,200 / 1,200 affected customers are
    refused, and so is ZIP(0.5, 6) on a range of 2 / 3 / 5 (its median count is 0).
    Poisson(40) on 20 / 40 / 60 customers holds every test and is drawn from."""
    for name, figures, distribution in (
        ("bypass.repeat_count", ("3", "3", "3"), ZIP_HALF_6),
        ("e.affected_customers", ("1200", "1200", "1200"),
         stated("zero_inflated_poisson", zero_inflation="0.5", rate="2400")),
    ):
        refused = _refusal(_row(name, "count", figures, source="MYTHOS_OBSERVED"), distribution)
        assert refused.code == "distribution_on_fixed_row", (name, refused.detail)
        assert refused.detail.endswith("one figure: a point mass, and it states a zero_inflated_poisson")
    ranged = _refusal(_row("bypass.repeat_count", "count", ("2", "3", "5"), source="MYTHOS_OBSERVED"), ZIP_HALF_6)
    assert ranged.code == "distribution_contradicts_range"
    assert ranged.detail.startswith(
        "bypass.repeat_count is 2 / 3 / 5; its zero_inflated_poisson fails the median test"), ranged.detail
    assert "P50 0," in ranged.detail
    customers = ss.resolve(_row("e.affected_customers", "count", ("20", "40", "60")),
                           ss.parse_stated(stated("poisson", rate="40")))
    assert customers.rule == ss.RULE_STATED


@pytest.mark.usefixtures("engine_keyring")
def test_an_observed_count_states_no_distribution_on_its_fixed_figure(deployment, people):
    """MEDIUM-1, the reviewer's repro through the builder's POST: an observed approval
    bypass whose repeat count is 3 / 3 / 3, MYTHOS_OBSERVED and bound to its SPINE
    effect, stating ZIP(0.5, 6), was built (201) and drawn from. Refused now, as the
    same row stating a gamma always was, and nothing is built; the row stating none
    is built."""
    from tests.test_economics_builder import _attr, _body, _effect, _link, _observed, _spine
    from tests.test_economics_builder import _payment_world as builder_world

    asset, (finding,) = builder_world(deployment, people, 1)
    row = _observed(deployment)
    spine = _spine(deployment, row)
    analyst = _client(people["analyst"])

    def build_with(distribution):
        repeat = _attr("count", "3", source="MYTHOS_OBSERVED", why="3 repeats", bound=spine)
        if distribution is not None:
            repeat["distribution"] = distribution
        effect = _effect("bypass", asset, origin="observed", observed=row, effect_type="approval_bypassed",
                         process="lending", attributes={"repeat_count": repeat})
        return _post_build(analyst, deployment, _body([effect], [_link(finding, "bypass")]))

    for distribution in (ZIP_HALF_6, stated("gamma", shape="30", scale="0.1")):
        response = build_with(distribution)
        assert response.status_code == 400, response.content
        assert response.json()["code"] == "distribution_on_fixed_row"
        assert response.json()["detail"].startswith("bypass.repeat_count is 3 / 3 / 3, one figure: a point mass")
    assert not FinancialScenario.objects.exists()
    assert build_with(None).status_code == 201


def test_the_frequencys_figures_bound_the_rate_its_count_implies():
    """MEDIUM-2. A negative binomial is a Poisson whose rate is Gamma(size, (1 - p) /
    p), and a zero-inflated Poisson one whose rate is 0 with probability pi and its rate
    otherwise: what they add to a Poisson is uncertainty about the rate, which the
    row's low and high state. So the implied rate is held from both sides: its median
    between the low and the high, and at least RANGE_MASS_FLOOR of it between them.
    The reviewer's negative binomials of mean 1,200 on 1,000 / 1,200 / 1,400, sizes 0.1,
    0.3 and 1, each holding the mean test, are refused by the median of their rate
    (7, 293 and 832 a year); size 10 by its mass (40% of its rate in range); sizes 50
    and 100 hold (76% and 91%). A zero-inflated Poisson whose rate is 0 in half its
    years has a median rate of 0: refused on 1 / 2 / 4. A Poisson's rate is a point,
    as before."""
    for size, failed in (("0.1", "rate_median"), ("0.3", "rate_median"), ("1", "rate_median"), ("10", "rate_mass")):
        refused = _refusal(_frequency(*BIG), _nb_with_mean(size, "1200"), frequency=True)
        assert refused.code == "distribution_contradicts_range", size
        assert f"values of its rate; its negative_binomial fails the {failed} test" in refused.detail, refused.detail
        assert "its rate Gamma(shape " in refused.detail
    for size in ("50", "100"):
        resolved = ss.resolve_frequency(_frequency(*BIG), ss.parse_stated(_nb_with_mean(size, "1200")))
        assert resolved.rule == ss.RULE_STATED, size

    refused = _refusal(_frequency("1", "2", "4"), stated("zero_inflated_poisson", zero_inflation="0.5", rate="4"),
                       frequency=True)
    assert refused.code == "distribution_contradicts_range" and "fails the rate_median test" in refused.detail
    assert "its rate 0 with probability 0.5, else 4: P50 0," in refused.detail
    held = ss.resolve_frequency(_frequency("1", "2", "4"),
                                ss.parse_stated(stated("zero_inflated_poisson", zero_inflation="0.3", rate="2")))
    assert held.rule == ss.RULE_STATED
    for figures, rate in ((("4", "5", "6"), "5"), (("0.01", "0.05", "0.2"), "0.05")):
        assert ss.resolve_frequency(_frequency(*figures), ss.parse_stated(stated("poisson", rate=rate))).drawn
    assert ss.FREQUENCY_RANGE_TESTS == ("support", "rate", "base", "rate_median", "rate_mass")
    gamma = ss.implied_rate(ss.build(ss.parse_stated(_nb_with_mean("100", "1200")), ss.SourceType.INDUSTRY_BENCHMARK))
    assert gamma.gamma.shape == 100.0 and abs(gamma.gamma.shape * gamma.gamma.scale - 1200) < 1e-9


def test_a_fixed_rate_states_only_a_poisson_of_that_rate():
    """MEDIUM-2. A fixed frequency says its rate is known: only a count whose implied
    rate is that exact point may state it, a Poisson of the figure (or a zero-inflated
    one with no zero inflation, which is that Poisson). The reviewer's ZIP(0.7, 1) on
    0.3 / 0.3 / 0.3, whose mean is exactly 0.3, says the rate is 0 in seven years in ten
    and 1 otherwise: refused, as a negative binomial is (its rate is a Gamma)."""
    for figures, distribution in (
        (("0.3", "0.3", "0.3"), stated("zero_inflated_poisson", zero_inflation="0.7", rate="1")),
        (("9", "9", "9"), stated("negative_binomial", size="1", probability="0.1")),
    ):
        refused = _refusal(_frequency(*figures), distribution, frequency=True)
        assert refused.code == "distribution_on_fixed_row", refused.detail
        assert "one rate: a known rate" in refused.detail and "a fixed rate states a poisson" in refused.detail
    for distribution in (stated("poisson", rate="2"), stated("zero_inflated_poisson", zero_inflation="0", rate="2")):
        assert ss.resolve_frequency(_frequency("2", "2", "2"), ss.parse_stated(distribution)).rule == ss.RULE_STATED


def test_a_counts_mean_is_exact():
    """LOW-2. The rate test compares the mean the stated parameters give, exactly, never
    its binary64: ZIP(0.7, 1)'s is 0.3, which binary64 makes 0.30000000000000004, above a
    high of 0.3. On 0 / 0.2 / 0.3 it holds every test (its rate is 0 in 70% of years,
    inside the range); on 0 / 0.1 / 0.2 it fails the rate test, and the mean is
    printed in its shortest spelling."""
    zip_ = stated("zero_inflated_poisson", zero_inflation="0.7", rate="1")
    parsed = ss.parse_stated(zip_)
    assert ss.resolve_frequency(_frequency("0", "0.2", "0.3"), parsed).rule == ss.RULE_STATED
    refused = _refusal(_frequency("0", "0.1", "0.2"), zip_, frequency=True)
    assert "fails the rate test" in refused.detail and "mean 0.3," in refused.detail
    built = ss.build(parsed, ss.SourceType.INDUSTRY_BENCHMARK)
    assert built.mean == 0.30000000000000004 and ss.exact_count_mean(built, parsed) == Fraction(3, 10)
    nb = ss.parse_stated(stated("negative_binomial", size="3", probability="0.1"))
    assert ss.exact_count_mean(ss.build(nb, ss.SourceType.INDUSTRY_BENCHMARK), nb) == 27


TRIANGLE = stated("triangular", minimum="0", mode="1", maximum="2")


def _hours(low, base, high):
    return _row("e.investigation_hours", "hours", (low, base, high), source="EXPERT_ESTIMATE")


def test_the_floor_and_the_median_are_inclusive():
    """LOW-1 and NIT-1, the reviewer's boundary cases. Triangular(0, 1, 2) has exactly
    half its mass in [1, 2] and its P50 at exactly 1: on 1 / 1.5 / 2 its median is the
    low and its mass the floor, and it holds; on 0 / 0.5 / 1 its median is the high,
    and it holds. On 1 / 1.5 / 1.99 its mass is 0.49995, refused and printed so, never
    as 0.5; on 1.0000000000000002 / 1.5 / 2 its median lies one ulp below the low."""
    built = ss.build(ss.parse_stated(TRIANGLE), ss.SourceType.EXPERT_ESTIMATE)
    assert ss.mass_between(built, 1.0, 2.0) == float(ss.RANGE_MASS_FLOOR) and built.ppf(0.5) == 1.0
    assert ss.resolve(_hours("1", "1.5", "2"), ss.parse_stated(TRIANGLE)).rule == ss.RULE_STATED
    assert ss.resolve(_hours("0", "0.5", "1"), ss.parse_stated(TRIANGLE)).rule == ss.RULE_STATED
    refused = _refusal(_hours("1", "1.5", "1.99"), TRIANGLE)
    assert "its triangular fails the mass test" in refused.detail
    assert "P(low <= X <= high) 0.49995 (at least 0.5)" in refused.detail, refused.detail
    refused = _refusal(_hours("1.0000000000000002", "1.5", "2"), TRIANGLE)
    assert "its triangular fails the median test" in refused.detail and "P50 1," in refused.detail


def _broken_import(name):
    raise RuntimeError("numpy: the BLAS library at /opt/vendor/lib/libblas.so is broken")


def test_any_fault_importing_the_engine_is_503_and_keeps_only_its_type(deployment, people, monkeypatch):
    """NIT-2. Not only an ImportError: any fault importing numpy or the engine is 503
    and nothing recorded, as a run maps any to engine_unavailable; and only the fault's
    type is kept, never its message (a path, a library). A document stating no
    distribution never imports the engine, and is recorded."""
    monkeypatch.setattr(pset, "importlib", types.SimpleNamespace(import_module=_broken_import))
    response = _post_set(_client(people["analyst"]), deployment, _payment_document())
    assert response.status_code == 503, response.content
    assert "BLAS" not in response.content.decode()
    _nothing_recorded()
    with pytest.raises(pset.ProbabilisticEngineUnavailable) as unavailable:
        pset.stated_distribution({"distribution": FREQUENCY_GOOD}, "frequency")
    assert "RuntimeError" in str(unavailable.value) and "BLAS" not in str(unavailable.value)
    assert _post_set(_client(people["analyst"]), deployment, _point_document()).status_code == 201


def test_a_build_of_a_set_stating_distributions_needs_the_engine(deployment, people, monkeypatch):
    """LOW-3 and NIT-2. A build re-checks the named version's distributions, so while
    the engine will not import, a build of a version that states any is 503 and
    nothing is built; a version that states none is built without it."""
    CustomerParameterSet.record(deployment, SET_KEY, _payment_document(), author=people["analyst"])
    asset, finding = _payment_world(deployment)
    analyst = _client(people["analyst"])
    with monkeypatch.context() as broken:
        broken.setattr(pset, "importlib", types.SimpleNamespace(import_module=_broken_import))
        response = _post_build(analyst, deployment, _build_body(asset, finding))
        assert response.status_code == 503, response.content
        assert not FinancialScenario.objects.exists()
        CustomerParameterSet.record(deployment, SET_KEY, _point_document(), author=people["analyst"])
        plain = _post_build(analyst, deployment, _build_body(asset, finding, version=2))
        assert plain.status_code == 201, plain.content
    assert _post_build(analyst, deployment, _build_body(asset, finding)).status_code == 201


# ======================================================================
# The spec
# ======================================================================


SPEC_PHRASES = (
    "`mythos.economics.parameter-distribution/v3`",
    "`RANGE_MASS_FLOOR`",
    "`distribution_on_fixed_row`",
    "its median between the low and the high",
    "names the test it failed",
    "9. **A stated distribution must hold its row's figures, from both sides**",
    "values of its rate",
    "12. **A frequency's figures are its rate, not its count",
    "Closed in step 6",
    "\"frequency\": {",
    "The writer of stated distributions",
    "`FREQUENCY_RANGE_TESTS`",
    "**Gamma(size, (1 - p) / p)**",
    "`rate_median`",
    "`rate_mass`",
    "`exact_count_mean`",
    "**A fixed rate is a Poisson of that rate**",
    "`builder.check_set_distributions`",
    "Write time, build time and run time agree",
)


def test_the_spec_states_the_writer_and_the_two_sided_test():
    with open(SPEC, encoding="utf-8") as handle:
        text = handle.read()
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    assert "Still open, to close before any writer states a distribution" not in text
    assert "No writer states a distribution or a frequency yet" not in text
    assert "`COUNT_RANGE_TESTS`" not in text and "No writer states a frequency yet" not in text
