"""Economic Exposure's seeded Monte Carlo sampler (phase E2, MVP step 7a), with no
database: ``assurance/economics/engine/simulation.py``,
``docs/economics/spec-v1.md`` section 23.

Pinned here:

- the sub-streams: each parameter's draws depend on the seed and its own name
  only (the spawn key and the first uniforms of one sub-stream are pinned), so
  adding a parameter never changes another's draws;
- determinism: the same seed gives identical draws and digest, a different seed a
  different digest, two interpreters with different ``PYTHONHASHSEED`` the same
  digest, and numpy's SIMD dispatch (AVX-512, AVX2 or the baseline) the same
  digest; a function that reads a global RNG is caught at run time;
- the summary: Hyndman-Fan type 7 quantiles (numpy's 'linear'), an fsum mean,
  the bands, and the invariants p10 <= p50 <= p90 <= severe, non-negative, across
  a sweep of every family; the compound expected annual loss within five standard
  errors of E[N] E[X];
- an infinite input mean gives no mean and no expected annual loss, never
  Infinity;
- the limits (draws and events), and 100,000 draws within a generous time budget;
- the precision (the Decimal of each float's repr; minor units only for display)
  and the digest (spec 15's result fields, sha256 over the canonical record);
- the safety rule: neither ``django.setup()`` nor the URLconf imports the
  probabilistic engine or numpy, and with all three unimportable the scan's Stop
  still resolves, answers and is saved;
- the spec names every code and states the design;
- (review round 1) an input whose variance is infinite gives a mean but no
  standard error and no mean band (a band that would not cover); a run is refused
  before it samples when it would hold more than MAX_VALUES values, and its
  measured peak stays under the budget's 8 bytes a value; a year's loss too large
  for a float is refused, never an invariant failure; the bands' order-statistic
  ranks are pinned by hand.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import textwrap
import time
import tracemalloc
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest

from assurance.economics.engine import distributions as d
from assurance.economics.engine import simulation as s
from assurance.economics.engine.money import MoneyRefused
from assurance.economics.engine.provenance import SourceType

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "assurance" / "economics" / "engine" / "simulation.py"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
EXPERT = SourceType.EXPERT_ESTIMATE


def _run(parameters, evaluate=None, **options):
    options.setdefault("seed", 2026)
    options.setdefault("model_version", "test-model-1")
    options.setdefault("reporting_currency", "USD")
    options.setdefault("draws", 20_000)
    return s.run(parameters, evaluate, **options)


def _cost(x):
    return x["records"] * x["cost_per_record"] * x["success"]


def _scenario():
    return {
        "records": d.Lognormal.from_median_p90(2000, 20000),
        "cost_per_record": d.Gamma.from_mean_sd(150, 50),
        "success": d.BetaBinomialRate.from_trials(20, 7),
    }


# ------------------------------------------------------------- sub-streams


def test_the_substream_key_and_its_first_draws_are_pinned():
    """The derivation, and numpy's PCG64 and SeedSequence under it. A change here
    changes every run's draws: it is a new SAMPLER_VERSION, in the same reviewed
    change as these pins."""
    assert s.substream_key("breach_cost") == (
        4199591438, 4178147750, 3438062529, 383209817, 2925882490, 4251822201, 1657561395, 1683182749,
    )
    assert s.substream(2026, "breach_cost").random(4).tolist() == [
        0.5322060950984853, 0.016354750404699137, 0.16949246428006504, 0.8109038065881866,
    ]
    assert s.SAMPLER_VERSION == 1
    assert s.SUBSTREAM_DOMAIN == "mythos.economics.substream/v1"


def test_each_name_has_its_own_stream():
    a = s.substream(1, "a").random(10_000)
    b = s.substream(1, "b").random(10_000)
    assert s.substream_key("a") != s.substream_key("b")
    assert not np.array_equal(a, b)
    assert abs(np.corrcoef(a, b)[0, 1]) < 0.05
    # Two parameters of one distribution draw different numbers in one run.
    drawn = s.sample_parameters({"x": d.Gamma(2, 1), "y": d.Gamma(2, 1)}, s.RunRandom(5), 1000)
    assert not np.array_equal(drawn["x"], drawn["y"])


def test_each_seed_has_its_own_stream():
    assert not np.array_equal(s.substream(1, "a").random(100), s.substream(2, "a").random(100))
    assert np.array_equal(s.substream(1, "a").random(100), s.substream(1, "a").random(100))


def test_a_stream_is_issued_once_per_run():
    random = s.RunRandom(3)
    random.stream("x")
    with pytest.raises(s.InvariantBroken):
        random.stream("x")


def test_adding_a_parameter_leaves_the_others_draws_unchanged():
    x = d.Lognormal.from_median_sigma(1000, 0.8)
    alone = s.sample_parameters({"x": x}, s.RunRandom(9), 5000)["x"]
    joined = s.sample_parameters(
        {"a": d.Poisson(4), "x": x, "zz": d.Gamma(2, 3), "y": d.Pert(0, 1, 2, source_type=EXPERT)}, s.RunRandom(9), 5000
    )["x"]
    assert np.array_equal(alone, joined)
    # Through a whole run: the outcome reads x only, so it is unchanged, while the
    # record (and so the digest) names the parameter added.
    first = _run({"x": x}, lambda v: v["x"])
    second = _run({"x": x, "unused": d.Gamma(2, 3)}, lambda v: v["x"])
    assert np.array_equal(first.outcomes, second.outcomes)
    assert first.record["outcomes_sha256"] == second.record["outcomes_sha256"]
    assert first.digest != second.digest


def test_the_frequency_stream_is_not_a_parameter_name():
    with pytest.raises(s.SimulationRefused) as caught:
        _run({"@frequency": d.Gamma(2, 3)})
    assert caught.value.code == "parameter_name_malformed"
    assert not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", s.FREQUENCY_STREAM)


# ------------------------------------------------------------- determinism


def test_the_same_seed_gives_identical_draws_and_digest():
    first = _run(_scenario(), _cost, frequency=d.Poisson(3.0))
    second = _run(_scenario(), _cost, frequency=d.Poisson(3.0))
    assert np.array_equal(first.outcomes, second.outcomes)
    assert np.array_equal(first.event_losses, second.event_losses)
    assert np.array_equal(first.counts, second.counts)
    assert dict(first.record) == dict(second.record)
    assert first.digest == second.digest


def test_a_different_seed_gives_a_different_digest():
    first = _run(_scenario(), _cost, frequency=d.Poisson(3.0), seed=1)
    second = _run(_scenario(), _cost, frequency=d.Poisson(3.0), seed=2)
    assert first.digest != second.digest
    assert first.record["outcomes_sha256"] != second.record["outcomes_sha256"]


_DIGEST_SCRIPT = textwrap.dedent(
    """
    from assurance.economics.engine import distributions as d, simulation as s
    from assurance.economics.engine.provenance import SourceType

    runs = [
        s.run(
            {
                "records": d.Lognormal.from_median_p90(2000, 20000),
                "cost_per_record": d.Gamma.from_mean_sd(150, 50),
                "success": d.BetaBinomialRate.from_trials(20, 7),
            },
            lambda x: x["records"] * x["cost_per_record"] * x["success"],
            frequency=d.NegativeBinomial.from_mean_variance(3, 7),
            seed=2026, model_version="test-model-1", reporting_currency="USD", draws=20_000,
        ),
        s.run({"tail": d.Spliced.from_body(d.Lognormal.from_median_sigma(1000, 1), d.GeneralizedPareto(0.3, 2000, 5000))},
              seed=7, model_version="m", reporting_currency="EUR", draws=20_000),
        s.run({"gpd": d.GeneralizedPareto(-0.3, 1000, 10)}, frequency=d.ZeroInflatedPoisson(0.2, 2),
              seed=8, model_version="m", reporting_currency="JPY", draws=20_000),
        s.run({"pert": d.Pert(10, 40, 200, source_type=SourceType.EXPERT_ESTIMATE),
               "tri": d.Triangular(1, 2, 9, source_type=SourceType.EXPERT_ESTIMATE)},
              lambda x: x["pert"] * x["tri"], seed=9, model_version="m", reporting_currency="KWD", draws=20_000),
    ]
    print(" ".join(run.digest for run in runs))
    """
)


def _digests_in_a_fresh_interpreter(**env) -> list[str]:
    result = subprocess.run(
        [sys.executable, "-c", _DIGEST_SCRIPT],
        cwd=REPO,
        env={**{k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}, **env},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return result.stdout.split()


def test_two_interpreters_with_different_hash_seeds_give_the_same_digest():
    here = _digests_in_a_fresh_interpreter(PYTHONHASHSEED="0")
    there = _digests_in_a_fresh_interpreter(PYTHONHASHSEED="987654321")
    assert len(here) == 4
    assert here == there
    first = _run(_scenario(), _cost, frequency=d.NegativeBinomial.from_mean_variance(3, 7))
    assert here[0] == first.digest


def test_numpys_simd_dispatch_does_not_change_a_digest():
    """numpy picks an AVX-512, AVX2 or baseline implementation of its own exp and
    log by CPU, and they differ in the last bit; the samplers use none of them
    (``exp_portable``, ``expm1_portable`` and numpy's C samplers), so a digest is
    the same with every dispatched feature this CPU has turned off."""
    from numpy._core import _multiarray_umath as umath

    available = [f for f in umath.__cpu_dispatch__ if umath.__cpu_features__.get(f)]
    default = _digests_in_a_fresh_interpreter()
    baseline = _digests_in_a_fresh_interpreter(NPY_DISABLE_CPU_FEATURES=" ".join(available))
    assert default == baseline


def test_a_function_reading_a_global_rng_is_caught():
    """The run samples twice from fresh sub-streams and compares: a function that
    is not pure gives two different outcome vectors, and that is a defect."""
    generator = np.random.default_rng()
    with pytest.raises(s.InvariantBroken, match="not reproducible"):
        _run({"x": d.Gamma(2, 3)}, lambda v: v["x"] + generator.random(v["x"].size))


def test_a_golden_digest():
    """A run whose draws use only IEEE-754 basic operations and square roots
    (triangular, inverted on PCG64's uniforms), so its digest is the same on every
    platform: a change to the record, the summary, the precision or the digest's
    canonical form fails here, and is a new SAMPLER_VERSION or SCHEMA."""
    result = _run(
        {"loss": d.Triangular(100, 400, 2000, source_type=EXPERT)},
        seed=7,
        model_version="golden-1",
        draws=1000,
    )
    assert result.record["p50"] == GOLDEN_P50
    assert result.digest == GOLDEN_DIGEST


GOLDEN_P50 = "744.0092126459089"
GOLDEN_DIGEST = "sha256:cfdeb6a74f3874ea064c0fcc32870b07a71da1d850c531db577ab605f0a52e39"


# ------------------------------------------------------------------ summary


def test_quantiles_are_hyndman_fan_type_7():
    values = np.random.Generator(np.random.PCG64(1)).lognormal(0, 1, 12_345)
    ordered = np.sort(values)
    for p in (Fraction(1, 10), Fraction(1, 2), Fraction(9, 10), Fraction(95, 100), Fraction(999, 1000)):
        # numpy interpolates from the upper end when the fraction is at least a
        # half, so the two agree to a few units in the last place, not exactly.
        assert s.quantile(ordered, p) == pytest.approx(float(np.quantile(values, float(p), method="linear")), rel=1e-12)
    assert s.quantile(np.array([1.0, 2.0, 3.0, 4.0]), Fraction(1, 2)) == 2.5
    assert s.quantile(np.array([1.0, 2.0, 3.0, 4.0]), Fraction(1, 10)) == pytest.approx(1.3)


#: Every family with non-negative draws, for the invariants sweep.
SWEEP = [
    d.Poisson(3.0),
    d.NegativeBinomial.from_mean_variance(4, 10),
    d.ZeroInflatedPoisson(0.6, 1.5),
    d.BetaBinomialRate.from_trials(20, 7),
    d.Lognormal.from_p10_p90(1000, 50000),
    d.Gamma(0.5, 1000),
    d.GeneralizedPareto(0.4, 1000, 0),
    d.GeneralizedPareto(-0.5, 1000, 10),
    d.Spliced.from_body(d.Lognormal.from_median_sigma(1000, 1.0), d.GeneralizedPareto(0.3, 2000, 5000)),
    d.Pert(0, 10, 100, source_type=EXPERT),
    d.Triangular(5, 5, 6, source_type=EXPERT),
]


@pytest.mark.parametrize("dist", SWEEP, ids=[type(x).ID + str(i) for i, x in enumerate(SWEEP)])
def test_summary_invariants_hold_across_a_sweep(dist):
    result = _run({"x": dist}, seed=11)
    summary = result.summary
    assert 0.0 <= summary.p10 <= summary.p50 <= summary.p90 <= summary.severe
    assert summary.mean is not None and summary.mean >= 0.0
    for key, figure in (("p10", summary.p10), ("p50", summary.p50), ("p90", summary.p90)):
        low, high = summary.bands[key]
        assert low <= figure <= high
    values = result.outcomes
    for key, p in (("p10", 0.1), ("p50", 0.5), ("p90", 0.9), ("severe", 0.95)):
        assert getattr(summary, key) == pytest.approx(float(np.quantile(values, p, method="linear")), rel=1e-12)
    assert summary.mean == pytest.approx(float(np.mean(values)), rel=1e-12)
    assert summary.standard_error == pytest.approx(float(np.std(values, ddof=1)) / math.sqrt(values.size), rel=1e-9)
    if not dist.DISCRETE:
        # The true quantile is near the estimate: within one and a half band widths
        # (the band is 95%, about four standard errors wide).
        for key, p in (("p10", 0.1), ("p50", 0.5), ("p90", 0.9)):
            low, high = summary.bands[key]
            assert abs(dist.ppf(p) - getattr(summary, key)) <= 1.5 * (high - low) + 1e-12
        assert abs(summary.mean - dist.mean) <= 5 * summary.standard_error


def test_the_invariants_are_checked():
    good = s.summarize(np.arange(1000, dtype=np.float64), severe_percentile=Decimal(95))
    s.check_invariants(good)
    swapped = s.Summary(**{**good.__dict__, "p10": good.p90, "p90": good.p10})
    with pytest.raises(s.InvariantBroken, match="out of order"):
        s.check_invariants(swapped)
    negative = s.Summary(**{**good.__dict__, "p10": -1.0})
    with pytest.raises(s.InvariantBroken):
        s.check_invariants(negative)
    outside = s.Summary(**{**good.__dict__, "mean": good.bands["mean"][1] + 1})
    with pytest.raises(s.InvariantBroken, match="outside its band"):
        s.check_invariants(outside)


def test_severe_but_plausible_is_p95_unless_stated():
    default = _run({"x": d.Gamma(2, 1000)})
    assert default.record["severe_percentile"] == "95"
    assert default.summary.severe == pytest.approx(float(np.quantile(default.outcomes, 0.95)), rel=1e-12)
    stated = _run({"x": d.Gamma(2, 1000)}, severe_percentile=Decimal("99.5"))
    assert stated.record["severe_percentile"] == "99.5"
    assert stated.summary.severe == pytest.approx(float(np.quantile(stated.outcomes, 0.995)), rel=1e-12)
    assert _run({"x": d.Gamma(2, 1000)}, severe_percentile=90).summary.severe == default.summary.p90
    assert stated.digest != default.digest


# ----------------------------------------------------------------- compound


def test_compound_annual_sums_each_years_events():
    assert s.compound_annual(np.array([2, 0, 1, 0]), np.array([1.0, 2.0, 4.0])).tolist() == [3.0, 0.0, 4.0, 0.0]
    assert s.compound_annual(np.array([0, 0]), np.array([])).tolist() == [0.0, 0.0]
    with pytest.raises(s.InvariantBroken):
        s.compound_annual(np.array([1, 1]), np.array([1.0]))
    with pytest.raises(s.InvariantBroken):
        s.compound_annual(np.array([1.5]), np.array([1.0]))


@pytest.mark.parametrize(
    ("frequency", "severity"),
    [
        (d.Poisson(3.0), d.Lognormal.from_median_sigma(10_000, 0.8)),
        (d.NegativeBinomial.from_mean_variance(2.5, 9), d.Gamma(2.0, 5000)),
        (d.ZeroInflatedPoisson(0.4, 4.0), d.Spliced(d.Gamma(2.0, 1000), d.GeneralizedPareto(0.1, 1500, 4000), 0.1)),
        (d.Poisson(0.2), d.Pert(1000, 5000, 20_000, source_type=EXPERT)),
    ],
    ids=["poisson_lognormal", "nb_gamma", "zip_splice", "rare_pert"],
)
def test_expected_annual_exposure_is_e_n_times_e_x(frequency, severity):
    result = _run({"loss": severity}, frequency=frequency, draws=100_000, seed=31)
    assert result.record["basis"] == "annual_loss"
    expected = frequency.mean * severity.mean
    eal = result.expected_annual_loss
    assert eal is not None and eal == result.mean
    assert abs(float(eal.amount) - expected) <= 5 * result.summary.standard_error, (eal, expected)
    assert result.counts.sum() == result.event_losses.size == result.record["events"]["total"]
    assert np.array_equal(result.outcomes, s.compound_annual(result.counts, result.event_losses))
    assert result.summary.p10 >= 0.0
    assert result.event_summary is not None
    assert result.event_summary.mean == pytest.approx(float(result.event_losses.mean()), rel=1e-12)


def test_years_with_no_event_lose_nothing():
    result = _run({"loss": d.Gamma(2, 100)}, frequency=d.Poisson(0.05), draws=10_000)
    assert result.summary.p10 == result.summary.p50 == result.summary.p90 == 0.0
    assert result.summary.severe >= 0.0
    assert np.count_nonzero(result.outcomes == 0.0) == np.count_nonzero(result.counts == 0)


def test_a_per_draw_run_has_no_expected_annual_loss():
    result = _run(_scenario(), _cost)
    assert result.record["basis"] == "per_draw"
    assert result.record["expected_annual_loss"] is None
    assert result.expected_annual_loss is None
    assert result.record["events"] is None and result.record["frequency"] is None
    assert result.mean is not None


# ------------------------------------------------------------ infinite mean


def test_an_infinite_input_mean_gives_no_mean_and_no_expected_annual_loss():
    result = _run({"tail": d.GeneralizedPareto(1.2, 1000, 100)}, frequency=d.Poisson(2.0))
    record = result.record
    assert record["mean"] is None and record["expected_annual_loss"] is None
    assert record["standard_error_of_mean"] is None and record["bands"]["mean"] is None
    assert record["mean_undefined"]["parameters"] == ["tail"]
    assert result.mean is None and result.expected_annual_loss is None
    assert record["parameters"]["tail"]["mean"] is None
    text = json.dumps(result.as_dict(), allow_nan=False)
    assert "Infinity" not in text and "NaN" not in text
    assert 0 <= result.summary.p10 <= result.summary.p50 <= result.summary.p90 <= result.summary.severe


# ----------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    ("options", "code"),
    [
        ({"seed": -1}, "seed_malformed"),
        ({"seed": 2**64}, "seed_malformed"),
        ({"seed": True}, "seed_malformed"),
        ({"seed": "1"}, "seed_malformed"),
        ({"draws": s.MAX_DRAWS + 1}, "draws_out_of_range"),
        ({"draws": s.MIN_DRAWS - 1}, "draws_out_of_range"),
        ({"draws": 50_000.0}, "draws_out_of_range"),
        ({"draws": True}, "draws_out_of_range"),
        ({"model_version": " "}, "model_version_blank"),
        ({"model_version": None}, "model_version_blank"),
        ({"scenario_id": ""}, "scenario_id_malformed"),
        ({"scenario_id": 5}, "scenario_id_malformed"),
        ({"severe_percentile": 89}, "percentile_out_of_range"),
        ({"severe_percentile": 100}, "percentile_out_of_range"),
        ({"severe_percentile": 95.0}, "percentile_out_of_range"),
        ({"severe_percentile": "95"}, "percentile_out_of_range"),
        ({"severe_percentile": Decimal("NaN")}, "percentile_out_of_range"),
        ({"frequency": d.Gamma(2, 1)}, "frequency_not_a_count"),
        ({"frequency": 3}, "frequency_not_a_count"),
    ],
)
def test_run_refusals(options, code):
    with pytest.raises(s.SimulationRefused) as caught:
        _run({"x": d.Gamma(2, 1)}, **options)
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("parameters", "evaluate", "code"),
    [
        ({}, None, "parameters_malformed"),
        ([("x", d.Gamma(2, 1))], None, "parameters_malformed"),
        ({"x": 3.0}, None, "parameters_malformed"),
        ({"X": d.Gamma(2, 1)}, None, "parameter_name_malformed"),
        ({"1x": d.Gamma(2, 1)}, None, "parameter_name_malformed"),
        ({"a.b": d.Gamma(2, 1)}, None, "parameter_name_malformed"),
        ({"x": d.Gamma(2, 1), "y": d.Gamma(2, 1)}, None, "evaluate_missing"),
        ({"x": d.Gamma(2, 1)}, "x", "evaluate_missing"),
        ({"x": d.Gamma(2, 1)}, lambda v: v["x"][:10], "outcome_malformed"),
        ({"x": d.Gamma(2, 1)}, lambda v: 3.0, "outcome_malformed"),
        ({"x": d.Gamma(2, 1)}, lambda v: v["x"].astype(str), "outcome_malformed"),
        ({"x": d.Gamma(2, 1)}, lambda v: np.full_like(v["x"], np.inf), "outcome_not_finite"),
        ({"x": d.Gamma(2, 1)}, lambda v: np.where(v["x"] > 1, np.nan, v["x"]), "outcome_not_finite"),
        ({"x": d.Gamma(2, 1)}, lambda v: v["x"] - 1.0, "outcome_negative"),
        ({"x": d.Lognormal(300, 1)}, lambda v: v["x"] * 1e150, "out_of_range"),
    ],
)
def test_input_and_outcome_refusals(parameters, evaluate, code):
    with pytest.raises(s.SimulationRefused) as caught:
        _run(parameters, evaluate)
    assert caught.value.code == code


def test_the_reporting_currency_is_refused_with_moneys_codes():
    for currency, code in (("usd", "currency_unknown"), ("HRK", "currency_retired"), ("XAU", "currency_retired")):
        with pytest.raises(MoneyRefused) as caught:
            _run({"x": d.Gamma(2, 1)}, reporting_currency=currency)
        assert caught.value.code == code


def test_the_draws_are_read_only_to_the_function():
    def mutate(v):
        v["x"][0] = 0.0
        return v["x"]

    with pytest.raises(ValueError, match="read-only"):
        _run({"x": d.Gamma(2, 1)}, mutate)


def test_every_code_raised_is_published_and_every_published_code_is_raised():
    codes = set()
    for node in ast.walk(ast.parse(SOURCE.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "SimulationRefused":
            assert isinstance(node.args[0], ast.Constant), ast.dump(node)
            codes.add(node.args[0].value)
    assert codes == set(s.REFUSALS)


# -------------------------------------------------------------------- limits


def test_the_event_cap_is_enforced_before_any_severity_is_sampled():
    calls = []

    def evaluate(v):
        calls.append(1)
        return v["x"]

    with pytest.raises(s.SimulationRefused) as caught:
        _run({"x": d.Gamma(2, 1)}, evaluate, frequency=d.Poisson(20_000.0), draws=1000)
    assert caught.value.code == "events_over_limit"
    assert not calls


def test_the_limits_are_stated():
    assert (s.DEFAULT_DRAWS, s.MIN_DRAWS, s.MAX_DRAWS, s.MAX_EVENTS) == (100_000, 1_000, 1_000_000, 10_000_000)
    assert s.DEFAULT_SEVERE_PERCENTILE == Decimal(95)
    assert s.CONFIDENCE_LEVEL == Decimal("0.95")


#: A budget for one default run of 100,000 simulated years, far above what it
#: takes (about 0.2 seconds on the build machine, sampling twice): it catches a
#: per-draw Python loop, never CI load.
TIME_BUDGET_SECONDS = 60.0


def test_a_default_run_of_100k_draws_finishes_within_budget():
    started = time.perf_counter()
    result = s.run(_scenario(), _cost, frequency=d.Poisson(3.0), seed=2026, model_version="m", reporting_currency="USD")
    elapsed = time.perf_counter() - started
    assert result.record["simulations"] == 100_000 == result.outcomes.size
    assert elapsed < TIME_BUDGET_SECONDS, elapsed


# ----------------------------------------------------------------- precision


def _floats(value):
    if isinstance(value, float):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _floats(item)


def test_figures_are_the_decimal_of_each_floats_repr():
    result = _run(_scenario(), _cost, frequency=d.Poisson(3.0))
    for key, figure in (
        ("p10", result.summary.p10),
        ("p50", result.summary.p50),
        ("p90", result.summary.p90),
        ("mean", result.summary.mean),
        ("severe_plausible", result.summary.severe),
    ):
        text = result.record[key]
        assert Decimal(text) == Decimal(repr(figure))
        assert float(Decimal(text)) == figure
    assert result.p50.amount == Decimal(repr(result.summary.p50))
    assert result.p50.currency == "USD"
    assert not list(_floats(dict(result.record)))
    assert not list(_floats(result.as_dict()))


@pytest.mark.parametrize(("currency", "places"), [("USD", 2), ("JPY", 0), ("KWD", 3)])
def test_minor_units_only_for_display(currency, places):
    result = _run({"x": d.Gamma(2, 1000)}, reporting_currency=currency)
    shown = result.display()["p50"]
    amount, code = shown.split(" ")
    assert code == currency
    assert (len(amount.split(".")[1]) if "." in amount else 0) == places
    assert Decimal(amount) == Decimal(result.record["p50"]).quantize(Decimal(1).scaleb(-places), rounding="ROUND_HALF_EVEN")
    # The record keeps the unrounded figure.
    assert result.record["p50"] != amount


# -------------------------------------------------------------------- digest


def test_the_digest_is_sha256_over_the_canonical_record():
    result = _run(_scenario(), _cost, frequency=d.Poisson(3.0))
    canonical = json.dumps(dict(result.record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert result.digest == "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    assert result.record["outcomes_sha256"] == s.outcomes_digest(result.outcomes)
    assert result.as_dict()["digest"] == result.digest
    assert result.as_dict()["provenance"] == {"numpy": np.__version__}


def test_the_record_carries_spec_15s_result_fields():
    result = _run(_scenario(), _cost, frequency=d.Poisson(3.0), scenario_id=None)
    record = result.record
    for field in (
        "scenario_id", "model_version", "seed", "simulations", "p10", "p50", "p90", "mean",
        "expected_annual_loss", "severe_plausible", "reporting_currency",
    ):
        assert field in record, field
    assert record["scenario_id"] is None
    assert record["seed"] == "2026" and record["simulations"] == 20_000
    assert record["model_version"] == "test-model-1" and record["reporting_currency"] == "USD"
    assert record["schema"] == s.SCHEMA
    assert record["sampler"]["version"] == s.SAMPLER_VERSION
    assert record["sampler"]["bit_generator"] == "PCG64"
    assert set(record["parameters"]) == {"records", "cost_per_record", "success"}
    assert record["parameters"]["records"]["id"] == "lognormal"
    assert record["parameters"]["records"]["version"] == 1
    assert record["frequency"]["id"] == "poisson"
    big = _run({"x": d.Gamma(2, 1)}, seed=2**64 - 1)
    assert big.record["seed"] == "18446744073709551615"


@pytest.mark.parametrize(
    "change",
    [
        {"model_version": "test-model-2"},
        {"scenario_id": "scenario-1"},
        {"reporting_currency": "EUR"},
        {"severe_percentile": 99},
        {"draws": 20_001},
    ],
)
def test_every_input_is_in_the_digest(change):
    base = _run({"x": d.Gamma(2, 1000)})
    assert _run({"x": d.Gamma(2, 1000)}, **change).digest != base.digest


def test_a_parameter_change_is_in_the_digest():
    base = _run({"x": d.Gamma(2, 1000)})
    assert _run({"x": d.Gamma(2, 1001)}).digest != base.digest
    assert _run({"y": d.Gamma(2, 1000)}).digest != base.digest


def test_expert_parameters_are_named():
    result = _run(
        {"x": d.Pert(0, 1, 5, source_type=EXPERT), "y": d.Gamma(2, 1), "z": d.Triangular(0, 1, 2, source_type=EXPERT)},
        lambda v: v["x"] + v["y"] + v["z"],
    )
    assert result.record["expert_parameters"] == ["x", "z"]
    assert result.record["parameters"]["x"]["source_type"] == "EXPERT_ESTIMATE"


# --------------------------------------------------------- the safety rule


_DJANGO_ENV = {"DJANGO_SETTINGS_MODULE": "tests.settings_test"}


def test_django_and_the_urlconf_never_import_the_probabilistic_engine():
    """Nothing Django loads at start imports the distributions, the sampler or
    numpy: ``django.setup()`` and every URLconf, the admin's included."""
    script = textwrap.dedent(
        """
        import json, sys
        import django
        django.setup()
        from django.urls import get_resolver
        get_resolver().reverse_dict
        names = ("numpy", "assurance.economics.engine.distributions", "assurance.economics.engine.simulation")
        print(json.dumps(sorted(m for m in sys.modules if any(m == n or m.startswith(n + ".") for n in names))))
        print(json.dumps("assurance.economics.engine.money" in sys.modules))
        """
    )
    env = {**os.environ, **_DJANGO_ENV}
    env.setdefault("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci")
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True, timeout=300, check=False
    )
    assert result.returncode == 0, result.stderr[-4000:]
    loaded, money_loaded = (json.loads(line) for line in result.stdout.strip().splitlines()[-2:])
    assert loaded == []
    # The check would see an import: the models' registration does load the E1 engine.
    assert money_loaded is True


def test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop():
    """The safety rule, against an import-time fault (the kind #146's review found
    in the economics chain): a fresh pytest under a plugin that makes numpy, the
    distributions and the sampler unimportable before Django loads. The scan's
    Stop route resolves, answers 202 and saves the Stop."""
    env = dict(os.environ)
    env.setdefault("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci")
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_probabilistic_poisoned",
            "-q", "tests/economics_mismatched_core_cases.py::test_the_scan_stop_route_still_resolves_and_answers",
        ],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "1 passed" in result.stdout, result.stdout[-2000:]


def test_numpy_is_pinned_alike_in_both_requirements_files():
    """The service and CI draw the same streams only on the same numpy."""
    pins = {}
    for name in ("requirements.txt", "requirements-dev.txt"):
        found = re.findall(r"^numpy==(\S+)\s*$", (REPO / name).read_text(encoding="utf-8"), flags=re.MULTILINE)
        assert len(found) == 1, (name, found)
        pins[name] = found[0]
    assert pins["requirements.txt"] == pins["requirements-dev.txt"] == np.__version__


# ------------------------------------------------------------------ the spec


SPEC_PHRASES = (
    "## 23. Distributions and simulation",
    "assumptions explicit",
    "`EXPERT_ESTIMATE` or the data are marked sparse",
    "never a float Infinity",
    "Generator(PCG64)",
    "SeedSequence(entropy=seed, spawn_key=K)",
    "adding, removing or reordering another parameter never changes them",
    "PYTHONHASHSEED",
    "Hyndman and Fan's type 7",
    "numpy's `'linear'`",
    "the Decimal of its repr",
    "rounded to the reporting currency's minor unit only to be shown",
    "Severe-but-plausible is P95 of annual loss",
    "100,000 draws",
    "1,000,000",
    "10,000,000",
    "sampled twice",
    "What is not wired yet (step 7b)",
    "Decisions this step takes, which the owner may change",
    "test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop",
    "test_django_and_the_urlconf_never_import_the_probabilistic_engine",
    "exp_portable",
    "numpy==2.3.3",
    "standard_error_undefined",
    "a band from the sample's standard error would not cover at its stated level",
    "30,000,000 values",
    "values_held",
    "chunks of at most 1,000,000",
    "Every splice's CDF is continuous at u",
)


@pytest.mark.parametrize("phrase", SPEC_PHRASES)
def test_the_spec_states_the_design(phrase):
    assert phrase in " ".join(SPEC.read_text(encoding="utf-8").split())


def test_the_spec_names_every_code():
    text = SPEC.read_text(encoding="utf-8")
    codes = [
        *d.CATALOGUE,
        *d.FORMS,
        d.FREQUENCY,
        d.RATE,
        d.SEVERITY,
        d.EXPERT,
        *d.REFUSALS,
        *s.REFUSALS,
        s.SCHEMA,
        s.SUBSTREAM_DOMAIN,
        s.FREQUENCY_STREAM,
        s.ANNUAL_LOSS,
        s.PER_DRAW,
    ]
    missing = [str(code) for code in codes if f"`{code}`" not in text]
    assert not missing, missing


# ------------------------------------------------------ review round 1


def test_an_infinite_input_variance_gives_a_mean_but_no_standard_error():
    """Medium 1: a generalized Pareto of shape in [1/2, 1) has a mean and no
    variance. The sample mean is given; its standard error and band are not, and
    standard_error_undefined names the input."""
    for frequency in (None, d.Poisson(2.0)):
        result = _run({"tail": d.GeneralizedPareto(0.6, 1000, 0)}, frequency=frequency)
        record = result.record
        assert record["mean"] is not None and record["mean_undefined"] is None
        assert record["standard_error_of_mean"] is None and record["bands"]["mean"] is None
        assert record["standard_error_undefined"]["parameters"] == ["tail"]
        assert "variance is infinite" in record["standard_error_undefined"]["reason"]
        assert result.summary.standard_error is None and result.summary.mean is not None
        assert record["bands"]["p50"] is not None
    finite = _run({"tail": d.GeneralizedPareto(0.3, 1000, 0)})
    assert finite.record["standard_error_undefined"] is None
    assert finite.record["bands"]["mean"] is not None
    # An infinite mean has no variance either: both are named.
    heavy = _run({"tail": d.GeneralizedPareto(1.2, 1000, 0), "x": d.Gamma(2, 1)}, lambda v: v["tail"] + v["x"])
    assert heavy.record["standard_error_undefined"]["parameters"] == ["tail"]
    assert heavy.record["mean_undefined"]["parameters"] == ["tail"]


def test_a_mean_band_when_given_covers_at_about_its_level():
    """The regression behind medium 1: at shape 0.3 (finite variance) the 95% band
    covers the true mean in most of 200 seeded runs; at 0.8 the review measured
    58%, which is why no band is given there."""
    true_mean = d.GeneralizedPareto(0.3, 1000, 0).mean
    covered = 0
    for seed in range(200):
        low, high = _run({"tail": d.GeneralizedPareto(0.3, 1000, 0)}, seed=seed, draws=2000).summary.bands["mean"]
        covered += low <= true_mean <= high
    assert covered >= 0.85 * 200, covered
    assert _run({"tail": d.GeneralizedPareto(0.8, 1000, 0)}).summary.bands["mean"] is None


def test_a_run_over_the_value_budget_is_refused_before_it_samples():
    """Medium 2: memory is bounded by the limits. Eight parameters over a million
    years at about ten events a year held about 855 MiB before; now the run is
    refused once the years' counts are drawn, before any event is sampled or the
    function evaluated. A per-draw run is refused before anything is sampled."""
    calls = []

    def evaluate(v):
        calls.append(1)
        return sum(v.values())

    many = {f"p{i}": d.Gamma(2, 1) for i in range(8)}
    with pytest.raises(s.SimulationRefused) as caught:
        _run(many, evaluate, frequency=d.Poisson(9.9), draws=1_000_000)
    assert caught.value.code == "values_over_budget"
    wide = {f"p{i}": d.Gamma(2, 1) for i in range(28)}
    with pytest.raises(s.SimulationRefused) as caught:
        _run(wide, evaluate, draws=1_000_000)
    assert caught.value.code == "values_over_budget"
    assert not calls
    assert s.values_held(27, 1_000_000) == s.MAX_VALUES  # 27 parameters of a million draws: the budget exactly
    assert s.values_held(28, 1_000_000) > s.MAX_VALUES
    assert s.values_held(3, 3_500_000, 1_000_000) == 6 * 3_500_000 + 8 * 1_000_000
    assert s.MAX_VALUES == 30_000_000 and (s.RUN_VECTORS, s.YEAR_VECTORS) == (3, 8)


def _peak(call):
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        result = call()
        return result, tracemalloc.get_traced_memory()[1] - before
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("compound", [False, True], ids=["per_draw", "compound"])
def test_a_runs_measured_peak_is_within_its_count(compound):
    """The budget's count holds: a run's traced peak is at most 8 bytes for each
    value values_held counts, plus about a megabyte of fixed block and chunk
    buffers (measured: 0.7 to 1.0 of the count for a three-factor product with a
    splice; 236 MB for 27 parameters of a million draws, at the budget of 240)."""
    parameters = {"a": d.Lognormal(0, 1), "b": d.Gamma(2, 1), "c": d.Spliced.from_body(
        d.Lognormal.from_median_sigma(1, 0.5), d.GeneralizedPareto(0.1, 1, 2))}
    options = {"frequency": d.Poisson(3.0), "draws": 100_000} if compound else {"draws": 300_000}
    result, peak = _peak(lambda: _run(parameters, lambda v: v["a"] * v["b"] * v["c"], **options))
    length = result.event_losses.size if compound else options["draws"]
    held = s.values_held(3, length, options["draws"] if compound else None)
    assert peak <= 8 * held + s.FIXED_BUFFER_BYTES, (peak, 8 * held)


def test_a_year_too_large_for_a_float_is_refused_not_an_invariant_failure():
    """Low 4: each event is finite, but a year of several sums past the largest
    float. With an infinite-mean input the summary went straight to the
    percentiles and raised InvariantBroken; now it is refused, out_of_range."""
    capped = lambda v: np.minimum(v["tail"], 1.0) * 1.5e308  # noqa: E731
    with pytest.raises(s.SimulationRefused) as caught:
        _run({"tail": d.GeneralizedPareto(1.2, 1, 0.5)}, capped, frequency=d.Poisson(5.0), draws=2000)
    assert caught.value.code == "out_of_range"
    with pytest.raises(s.SimulationRefused) as caught:
        s.summarize(np.array([1.0, np.inf] * 600), severe_percentile=Decimal(95), mean_defined=False)
    assert caught.value.code == "out_of_range"


def test_band_ranks_by_hand():
    """Low 5: the order statistics of 0, 1, ..., 999. For p = 0.1: n p = 100,
    z sqrt(n p (1 - p)) = 1.959964 x 9.486833 = 18.594, ranks floor(81.406) = 81 and
    ceil(118.594) = 119, so values 80 and 118; likewise p = 0.5 (30.990: ranks 469
    and 531), 0.9 (ranks 881 and 919) and 0.95 (13.508: ranks 936 and 964). The
    mean's band is 499.5 -/+ z sqrt(1000 x 1001 / 12 / 1000)."""
    summary = s.summarize(np.arange(1000.0), severe_percentile=Decimal(95))
    assert summary.bands["p10"] == (80.0, 118.0)
    assert summary.bands["p50"] == (468.0, 530.0)
    assert summary.bands["p90"] == (880.0, 918.0)
    assert summary.bands["severe_plausible"] == (935.0, 963.0)
    half_width = 1.959963984540054 * math.sqrt(1000 * 1001 / 12 / 1000)
    assert summary.mean == 499.5
    assert summary.bands["mean"] == (pytest.approx(499.5 - half_width, rel=1e-14), pytest.approx(499.5 + half_width, rel=1e-14))
