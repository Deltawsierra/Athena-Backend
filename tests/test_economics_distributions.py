"""Economic Exposure's distribution catalogue (phase E2, MVP step 7a), with no
database and no Django: ``assurance/economics/engine/distributions.py``,
``docs/economics/spec-v1.md`` section 23.

Pinned here:

- the catalogue: every id, version, kind and form, exactly;
- statistical correctness against known answers, at fixed seeds: each sample's
  mean and variance within five standard errors of the closed form; quantile
  round trips; published quantiles (the normal's, chi-square's through the gamma,
  a lognormal's P90 from its median and sigma, a Poisson CDF); a
  Kolmogorov-Smirnov statistic against each CDF (computed here: SciPy is not in
  CI's set); the Beta-Binomial posterior; a negative binomial from its mean and
  variance reproducing both;
- every refusal, by its code, and that every code raised is published and every
  published code is raised;
- a generalized Pareto mean or variance that is infinite is ``None``, never
  Infinity, in the value and in its record;
- an expert range (PERT, triangular) only for an EXPERT_ESTIMATE parameter or data
  marked sparse;
- sampling reads only the generator it is given, never numpy's or Python's
  global state;
- the portable exp and expm1 the severity samplers use agree with the C library
  to a unit or two in the last place.
"""

from __future__ import annotations

import ast
import json
import math
import random
from decimal import Decimal
from pathlib import Path

import numpy as np
import pytest

from assurance.economics.engine import distributions as d
from assurance.economics.engine.provenance import SourceType

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "assurance" / "economics" / "engine" / "distributions.py"

EXPERT = SourceType.EXPERT_ESTIMATE


def rng(seed: int) -> np.random.Generator:
    return np.random.Generator(np.random.PCG64(seed))


# ------------------------------------------------------------- the catalogue


def test_the_catalogue_ids_versions_kinds_and_forms():
    assert {
        identifier: (cls.VERSION, cls.KIND, cls.FORMS, cls.DISCRETE, cls.EXPERT)
        for identifier, cls in d.CATALOGUE.items()
    } == {
        "poisson": (1, "frequency", ("native",), True, False),
        "negative_binomial": (1, "frequency", ("native", "mean_variance"), True, False),
        "zero_inflated_poisson": (1, "frequency", ("native",), True, False),
        "beta_binomial_rate": (1, "rate", ("native", "prior_and_trials"), False, False),
        "lognormal": (1, "severity", ("native", "median_sigma", "p10_p90", "median_p90"), False, False),
        "gamma": (1, "severity", ("native", "mean_sd"), False, False),
        "generalized_pareto": (1, "severity", ("native", "mean_excess"), False, False),
        "spliced": (1, "severity", ("native", "continuous_at_threshold"), False, False),
        "pert": (1, "expert", ("native",), False, True),
        "triangular": (1, "expert", ("native",), False, True),
    }
    assert set(d.FORMS) == {form for cls in d.CATALOGUE.values() for form in cls.FORMS}


def _splice_lognormal():
    return d.Spliced.continuous(d.Lognormal.from_median_sigma(1000, 0.5), d.GeneralizedPareto(0.1, 800, 2000))


def _splice_gamma():
    return d.Spliced(d.Gamma(2.0, 1000), d.GeneralizedPareto(0.1, 1500, 4000), 0.1)


#: Every family, in several of its forms, with a fixed seed each. The tails are
#: light enough that a sample's fourth moment exists, so its variance has a
#: standard error to test against.
CASES = [
    ("poisson", lambda: d.Poisson(3.0), 11),
    ("poisson_large", lambda: d.Poisson(250.0), 12),
    ("nb_mean_variance", lambda: d.NegativeBinomial.from_mean_variance(4, 10), 13),
    ("nb_native", lambda: d.NegativeBinomial(2.5, 0.2), 14),
    ("zip", lambda: d.ZeroInflatedPoisson(0.3, 2.5), 15),
    ("beta_binomial_rate", lambda: d.BetaBinomialRate.from_trials(20, 7), 16),
    ("lognormal_median_sigma", lambda: d.Lognormal.from_median_sigma(1000, 0.6), 17),
    ("lognormal_p10_p90", lambda: d.Lognormal.from_p10_p90(1000, 5000), 18),
    ("lognormal_median_p90", lambda: d.Lognormal.from_median_p90(2000, 6000), 19),
    ("gamma_native", lambda: d.Gamma(2.5, 1000), 20),
    ("gamma_mean_sd", lambda: d.Gamma.from_mean_sd(5000, 2000), 21),
    ("gpd_positive", lambda: d.GeneralizedPareto(0.1, 1000, 10000), 22),
    ("gpd_negative", lambda: d.GeneralizedPareto(-0.3, 1000, 0), 23),
    ("gpd_exponential", lambda: d.GeneralizedPareto(0.0, 500, 0), 24),
    ("gpd_mean_excess", lambda: d.GeneralizedPareto.from_mean_excess(2000, 1500, 0.15), 25),
    ("splice_lognormal", _splice_lognormal, 26),
    ("splice_gamma", _splice_gamma, 27),
    ("pert", lambda: d.Pert(100, 400, 2000, source_type=EXPERT), 28),
    ("pert_sparse_weighted", lambda: d.Pert(0, 10, 50, source_type="CUSTOMER_PROVIDED", sparse=True, shape=6), 29),
    ("triangular", lambda: d.Triangular(100, 400, 2000, source_type=EXPERT), 30),
]
IDS = [name for name, _, _ in CASES]
N = 200_000
K = 5.0


@pytest.mark.parametrize(("name", "make", "seed"), CASES, ids=IDS)
def test_sample_mean_and_variance_are_within_k_standard_errors(name, make, seed):
    dist = make()
    x = dist.sample(rng(seed), N).astype(np.float64)
    assert x.shape == (N,)
    mean = float(x.mean())
    variance = float(x.var(ddof=1))
    se_mean = math.sqrt(dist.variance / N)
    fourth = float(np.mean((x - mean) ** 4))
    se_variance = math.sqrt(max(fourth - variance * variance, 0.0) / N)
    assert abs(mean - dist.mean) <= K * se_mean, (mean, dist.mean, se_mean)
    assert abs(variance - dist.variance) <= K * se_variance, (variance, dist.variance, se_variance)


PROBABILITIES = (1e-4, 0.001, 0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 0.999)


@pytest.mark.parametrize(("name", "make", "seed"), CASES, ids=IDS)
def test_quantile_round_trips(name, make, seed):
    dist = make()
    for p in PROBABILITIES:
        q = dist.ppf(p)
        assert dist.quantile(p) == q
        if dist.DISCRETE:
            assert isinstance(q, int)
            assert dist.cdf(q) >= p
            assert q == 0 or dist.cdf(q - 1) < p
        else:
            assert dist.cdf(q) == pytest.approx(p, abs=1e-12, rel=1e-10), (p, q)
    # Monotone in p.
    quantiles = [dist.ppf(p) for p in PROBABILITIES]
    assert quantiles == sorted(quantiles)


def test_published_quantiles():
    # The standard normal's 90th and 97.5th percentiles.
    assert d.Z90 == pytest.approx(1.2815515655446004, rel=1e-15)
    assert d.normal_ppf(0.975) == pytest.approx(1.959963984540054, rel=1e-15)
    # A lognormal's P90 from its median and sigma: median * exp(sigma z90).
    assert d.Lognormal.from_median_sigma(1000, 1.0).ppf(0.9) == pytest.approx(3602.2244792791575, rel=1e-13)
    assert d.Lognormal.from_median_sigma(250, 0.5).ppf(0.9) == pytest.approx(250 * math.exp(0.5 * 1.2815515655446004))
    # Chi-square's table, through the gamma (shape df/2, scale 2).
    assert d.Gamma(0.5, 2.0).ppf(0.95) == pytest.approx(3.841458820694124, rel=1e-10)
    assert d.Gamma(5.0, 2.0).ppf(0.95) == pytest.approx(18.307038053275146, rel=1e-10)
    assert d.Gamma(1.0, 2.0).ppf(0.99) == pytest.approx(9.21034037197618, rel=1e-10)
    # P(N <= 2) for a Poisson of rate 1 is 5 / (2e).
    assert d.Poisson(1.0).cdf(2) == pytest.approx(2.5 / math.e, rel=1e-14)
    assert d.Poisson(1.0).ppf(0.9) == 2
    # A generalized Pareto of shape 0 is exponential: its median is sigma ln 2.
    assert d.GeneralizedPareto(0.0, 500).ppf(0.5) == pytest.approx(500 * math.log(2))
    # A symmetric PERT's median is its mode.
    assert d.Pert(0, 50, 100, source_type=EXPERT).ppf(0.5) == pytest.approx(50)


def test_customer_forms_return_what_was_given():
    lognormal = d.Lognormal.from_p10_p90(1000, 50000)
    assert lognormal.ppf(0.1) == pytest.approx(1000, rel=1e-12)
    assert lognormal.ppf(0.9) == pytest.approx(50000, rel=1e-12)
    assert lognormal.record()["form"] == "p10_p90"
    assert lognormal.record()["given"] == {"p10": "1000", "p90": "50000"}
    other = d.Lognormal.from_median_p90(2000, 6000)
    assert other.ppf(0.5) == pytest.approx(2000, rel=1e-12)
    assert other.ppf(0.9) == pytest.approx(6000, rel=1e-12)
    gamma = d.Gamma.from_mean_sd(5000, 2000)
    assert (gamma.mean, math.sqrt(gamma.variance)) == (pytest.approx(5000), pytest.approx(2000))
    gpd = d.GeneralizedPareto.from_mean_excess(2000, 1500, 0.15)
    assert gpd.mean - 2000 == pytest.approx(1500)
    splice = _splice_lognormal()
    # Continuous at the threshold: the splice's CDF there is the body's.
    assert splice.cdf(splice.threshold) == pytest.approx(splice.body.cdf(splice.threshold), rel=1e-14)


def _ks_statistic(dist, sample: np.ndarray) -> float:
    """The Kolmogorov-Smirnov distance between a sample and a CDF: at each sorted
    point, the larger gap either side of the empirical step. For a count, the gap
    at each value of its support (conservative for a discrete law)."""
    x = np.sort(sample)
    n = x.size
    if dist.DISCRETE:
        values, counts = np.unique(x, return_counts=True)
        empirical = np.cumsum(counts) / n
        theoretical = np.array([dist.cdf(int(v)) for v in values])
        return float(np.max(np.abs(empirical - theoretical)))
    f = np.array([dist.cdf(float(v)) for v in x])
    i = np.arange(1, n + 1)
    return float(max(np.max(i / n - f), np.max(f - (i - 1) / n)))


#: Kolmogorov's distribution's upper 0.1% point.
KS_CRITICAL_0_001 = 1.9494746035043753


@pytest.mark.parametrize(("name", "make", "seed"), CASES, ids=IDS)
def test_kolmogorov_smirnov_against_the_cdf(name, make, seed):
    dist = make()
    n = 20_000
    statistic = _ks_statistic(dist, dist.sample(rng(seed + 1000), n))
    assert statistic * math.sqrt(n) < KS_CRITICAL_0_001, statistic


def test_the_ks_statistic_rejects_a_wrong_law():
    """The KS check has teeth: draws of one lognormal fail against another's CDF."""
    drawn = d.Lognormal.from_median_sigma(1000, 0.6).sample(rng(5), 20_000)
    assert _ks_statistic(d.Lognormal.from_median_sigma(1000, 0.66), drawn) * math.sqrt(20_000) > KS_CRITICAL_0_001


def test_the_beta_binomial_posterior():
    """Section 7.2's example: 7 of 20 valid attempts on a uniform prior."""
    rate = d.BetaBinomialRate.from_trials(20, 7)
    assert (rate.alpha, rate.beta) == (8.0, 14.0)
    assert rate.mean == pytest.approx(8 / 22, rel=1e-15)
    assert rate.variance == pytest.approx(8 * 14 / (22**2 * 23), rel=1e-15)
    assert rate.record()["given"] == {"prior_alpha": "1", "prior_beta": "1", "trials": "20", "successes": "7"}
    informed = d.BetaBinomialRate.from_trials(20, 7, prior_alpha=2, prior_beta=3)
    assert informed.mean == pytest.approx((2 + 7) / (2 + 3 + 20), rel=1e-15)
    sample = informed.sample(rng(3), N)
    assert abs(sample.mean() - informed.mean) <= K * math.sqrt(informed.variance / N)


@pytest.mark.parametrize(("mean", "variance"), [(4, 10), (0.2, 0.25), (1000, 1_000_000), (3.5, 3.51)])
def test_a_negative_binomial_from_its_mean_and_variance_reproduces_both(mean, variance):
    nb = d.NegativeBinomial.from_mean_variance(mean, variance)
    assert nb.mean == pytest.approx(mean, rel=1e-12)
    assert nb.variance == pytest.approx(variance, rel=1e-12)
    assert nb.record()["form"] == "mean_variance"


def test_a_negative_binomial_sample_reproduces_both():
    nb = d.NegativeBinomial.from_mean_variance(4, 10)
    x = nb.sample(rng(77), N).astype(np.float64)
    assert abs(x.mean() - 4) <= K * math.sqrt(10 / N)
    assert x.var(ddof=1) > x.mean() * 2  # over-dispersed, as given


# ---------------------------------------------------------------- refusals


def _gpd(threshold):
    return d.GeneralizedPareto(0.2, 500, threshold)


REFUSED = [
    ("nan", lambda: d.Poisson(float("nan")), "not_finite"),
    ("infinity", lambda: d.Poisson(float("inf")), "not_finite"),
    ("decimal_nan", lambda: d.Gamma(Decimal("NaN"), 1), "not_finite"),
    ("negative_infinity_scale", lambda: d.Lognormal(0, float("-inf")), "not_finite"),
    ("bool", lambda: d.Poisson(True), "not_a_number"),
    ("text", lambda: d.Poisson("3"), "not_a_number"),
    ("none", lambda: d.Lognormal(None, 1), "not_a_number"),
    ("huge_int", lambda: d.Lognormal(10**400, 1), "out_of_range"),
    ("poisson_zero", lambda: d.Poisson(0), "scale_not_positive"),
    ("poisson_negative", lambda: d.Poisson(-1.0), "scale_not_positive"),
    ("poisson_huge", lambda: d.Poisson(2e9), "out_of_range"),
    ("nb_size", lambda: d.NegativeBinomial(0, 0.5), "shape_out_of_range"),
    ("nb_p_zero", lambda: d.NegativeBinomial(2, 0), "probability_out_of_range"),
    ("nb_p_one", lambda: d.NegativeBinomial(2, 1), "probability_out_of_range"),
    ("nb_variance_equal", lambda: d.NegativeBinomial.from_mean_variance(4, 4), "not_overdispersed"),
    ("nb_variance_below", lambda: d.NegativeBinomial.from_mean_variance(4, 3), "not_overdispersed"),
    ("nb_mean_zero", lambda: d.NegativeBinomial.from_mean_variance(0, 3), "value_not_positive"),
    ("zip_one", lambda: d.ZeroInflatedPoisson(1.0, 2), "probability_out_of_range"),
    ("zip_negative", lambda: d.ZeroInflatedPoisson(-0.1, 2), "probability_out_of_range"),
    ("zip_rate", lambda: d.ZeroInflatedPoisson(0.2, 0), "scale_not_positive"),
    ("beta_shape", lambda: d.BetaBinomialRate(0, 1), "shape_out_of_range"),
    ("trials_successes_above", lambda: d.BetaBinomialRate.from_trials(20, 21), "trials_malformed"),
    ("trials_none", lambda: d.BetaBinomialRate.from_trials(0, 0), "trials_malformed"),
    ("trials_float", lambda: d.BetaBinomialRate.from_trials(20.0, 7), "trials_malformed"),
    ("trials_negative_successes", lambda: d.BetaBinomialRate.from_trials(20, -1), "trials_malformed"),
    ("trials_bool", lambda: d.BetaBinomialRate.from_trials(True, 1), "trials_malformed"),
    ("prior_zero", lambda: d.BetaBinomialRate.from_trials(20, 7, prior_alpha=0), "shape_out_of_range"),
    ("lognormal_sigma_zero", lambda: d.Lognormal(0, 0), "scale_not_positive"),
    ("lognormal_sigma_negative", lambda: d.Lognormal(0, -1), "scale_not_positive"),
    ("lognormal_mean_overflows", lambda: d.Lognormal(708, 2), "out_of_range"),
    ("lognormal_variance_overflows", lambda: d.Lognormal(0, 30), "out_of_range"),
    ("p10_above_p90", lambda: d.Lognormal.from_p10_p90(5000, 1000), "range_inverted"),
    ("p10_equals_p90", lambda: d.Lognormal.from_p10_p90(1000, 1000), "range_inverted"),
    ("p10_zero", lambda: d.Lognormal.from_p10_p90(0, 1000), "value_not_positive"),
    ("median_above_p90", lambda: d.Lognormal.from_median_p90(1000, 900), "range_inverted"),
    ("median_negative", lambda: d.Lognormal.from_median_sigma(-5, 1), "value_not_positive"),
    ("gamma_shape_zero", lambda: d.Gamma(0, 1), "shape_out_of_range"),
    ("gamma_shape_negative", lambda: d.Gamma(-1, 1), "shape_out_of_range"),
    ("gamma_scale_negative", lambda: d.Gamma(2, -1), "scale_not_positive"),
    ("gamma_sd_zero", lambda: d.Gamma.from_mean_sd(100, 0), "value_not_positive"),
    ("gpd_scale_negative", lambda: d.GeneralizedPareto(0.2, -1), "scale_not_positive"),
    ("gpd_shape_low", lambda: d.GeneralizedPareto(-1.0, 1), "shape_out_of_range"),
    ("gpd_shape_high", lambda: d.GeneralizedPareto(2.5, 1), "shape_out_of_range"),
    ("gpd_threshold_negative", lambda: d.GeneralizedPareto(0.2, 1, -5), "threshold_out_of_range"),
    ("gpd_mean_excess_infinite", lambda: d.GeneralizedPareto.from_mean_excess(1000, 500, 1.0), "shape_out_of_range"),
    ("splice_body", lambda: d.Spliced(d.Poisson(2), _gpd(5000), 0.1), "component_unsupported"),
    ("splice_tail", lambda: d.Spliced(d.Gamma(2, 100), d.Gamma(2, 100), 0.1), "component_unsupported"),
    ("splice_continuous_body", lambda: d.Spliced.continuous(d.Poisson(2), _gpd(5000)), "component_unsupported"),
    (
        "splice_threshold_below_median",
        lambda: d.Spliced(d.Lognormal.from_median_sigma(1000, 1), _gpd(500), 0.1),
        "threshold_out_of_range",
    ),
    ("splice_threshold_zero", lambda: d.Spliced(d.Gamma(2, 100), _gpd(0), 0.1), "threshold_out_of_range"),
    ("splice_probability_one", lambda: d.Spliced(d.Gamma(2, 100), _gpd(5000), 1.0), "probability_out_of_range"),
    ("splice_probability_zero", lambda: d.Spliced(d.Gamma(2, 100), _gpd(5000), 0.0), "probability_out_of_range"),
    ("pert_mode_above", lambda: d.Pert(0, 150, 100, source_type=EXPERT), "mode_out_of_range"),
    ("pert_mode_below", lambda: d.Pert(0, -1, 100, source_type=EXPERT), "mode_out_of_range"),
    ("pert_min_equals_max", lambda: d.Pert(100, 100, 100, source_type=EXPERT), "range_inverted"),
    ("pert_min_above_max", lambda: d.Pert(200, 150, 100, source_type=EXPERT), "range_inverted"),
    ("pert_weight", lambda: d.Pert(0, 50, 100, source_type=EXPERT, shape=0), "shape_out_of_range"),
    ("pert_customer", lambda: d.Pert(0, 50, 100, source_type=SourceType.CUSTOMER_PROVIDED), "expert_not_allowed"),
    ("pert_observed", lambda: d.Pert(0, 50, 100, source_type="MYTHOS_OBSERVED"), "expert_not_allowed"),
    ("pert_unknown_source", lambda: d.Pert(0, 50, 100, source_type="MADE_UP"), "source_type_unrecognised"),
    ("pert_sparse_text", lambda: d.Pert(0, 50, 100, source_type=EXPERT, sparse="yes"), "sparse_malformed"),
    ("triangular_benchmark", lambda: d.Triangular(0, 5, 10, source_type="INDUSTRY_BENCHMARK"), "expert_not_allowed"),
    ("triangular_mode", lambda: d.Triangular(0, 150, 100, source_type=EXPERT), "mode_out_of_range"),
    ("form_unknown", lambda: d.Poisson(3, form="p10_p90"), "form_unrecognised"),
    ("given_malformed", lambda: d.Poisson(3, given=("rate", 3)), "form_unrecognised"),
]


@pytest.mark.parametrize(("name", "build", "code"), REFUSED, ids=[name for name, _, _ in REFUSED])
def test_construction_refusals(name, build, code):
    with pytest.raises(d.DistributionRefused) as caught:
        build()
    assert caught.value.code == code
    assert code in str(caught.value)


@pytest.mark.parametrize(
    ("call", "code"),
    [
        (lambda dist: dist.sample(None, 10), "rng_malformed"),
        (lambda dist: dist.sample(np.random.RandomState(1), 10), "rng_malformed"),
        (lambda dist: dist.sample(np.random, 10), "rng_malformed"),
        (lambda dist: dist.sample(rng(1), -1), "sample_size_out_of_range"),
        (lambda dist: dist.sample(rng(1), 1.5), "sample_size_out_of_range"),
        (lambda dist: dist.sample(rng(1), True), "sample_size_out_of_range"),
        (lambda dist: dist.sample(rng(1), d.MAX_SAMPLE + 1), "sample_size_out_of_range"),
        (lambda dist: dist.ppf(0), "probability_out_of_range"),
        (lambda dist: dist.ppf(1), "probability_out_of_range"),
        (lambda dist: dist.ppf(1.5), "probability_out_of_range"),
        (lambda dist: dist.ppf(float("nan")), "not_finite"),
        (lambda dist: dist.cdf("10"), "not_a_number"),
    ],
)
def test_use_refusals(call, code):
    with pytest.raises(d.DistributionRefused) as caught:
        call(d.Lognormal.from_median_sigma(1000, 1))
    assert caught.value.code == code


def _raised_codes(path: Path, exception: str, helpers: dict[str, int]) -> set[str]:
    """Every code ``exception`` is raised with: its first argument where that is a
    constant, and otherwise (only inside a helper named in ``helpers``) the
    constant each call of that helper passes at the position given."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    codes = set()
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == exception:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    codes.add(first.value)
                else:
                    assert function.name in helpers, (function.name, ast.dump(node))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in helpers:
            argument = node.args[helpers[node.func.id]]
            assert isinstance(argument, ast.Constant) and isinstance(argument.value, str), ast.dump(node)
            codes.add(argument.value)
    return codes


def test_every_code_raised_is_published_and_every_published_code_is_raised():
    assert _raised_codes(SOURCE, "DistributionRefused", {"_positive": 2}) == set(d.REFUSALS)


# ------------------------------------------------- infinite moments are None


@pytest.mark.parametrize("shape", [1.0, 1.2, 2.0])
def test_a_gpd_whose_mean_is_infinite_has_none(shape):
    gpd = d.GeneralizedPareto(shape, 1000, 100)
    assert gpd.mean is None
    assert gpd.variance is None
    record = gpd.record()
    assert record["mean"] is None and record["variance"] is None
    json.dumps(record, allow_nan=False)
    # Its draws and quantiles are still finite numbers.
    assert np.isfinite(gpd.sample(rng(1), 10_000)).all()
    assert math.isfinite(gpd.ppf(0.999))


def test_a_gpd_whose_variance_alone_is_infinite():
    gpd = d.GeneralizedPareto(0.6, 1000, 100)
    assert gpd.mean == pytest.approx(100 + 1000 / 0.4)
    assert gpd.variance is None
    assert d.GeneralizedPareto(0.49, 1000).variance is not None


def test_a_splice_with_an_infinite_tail_mean_has_none():
    splice = d.Spliced.continuous(d.Lognormal.from_median_sigma(1000, 1), d.GeneralizedPareto(1.1, 2000, 5000))
    assert splice.mean is None and splice.variance is None
    assert splice.record()["mean"] is None
    assert splice.record()["tail"]["mean"] is None


def _floats(value):
    if isinstance(value, float):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _floats(item)


@pytest.mark.parametrize(("name", "make", "seed"), CASES, ids=IDS)
def test_a_record_holds_no_float(name, make, seed):
    record = make().record()
    assert not list(_floats(record))
    assert record["id"] in d.CATALOGUE and record["version"] == 1
    json.dumps(record, allow_nan=False)


def test_float_text_is_the_decimal_of_the_repr():
    assert d.float_text(0.1) == "0.1"
    assert d.float_text(100.0) == "100"
    assert d.float_text(1e-05) == "0.00001"
    assert d.float_text(-0.0) == "0"
    assert d.float_text(1.5e20) == "150000000000000000000"
    assert d.float_decimal(0.1) == Decimal("0.1")
    assert float(d.float_decimal(2 / 3)) == 2 / 3
    with pytest.raises(d.DistributionRefused):
        d.float_text(float("inf"))


# ----------------------------------------------------------- expert ranges


def test_an_expert_range_is_allowed_for_an_expert_estimate_or_sparse_data():
    pert = d.Pert(0, 50, 100, source_type=EXPERT)
    assert pert.source_type is SourceType.EXPERT_ESTIMATE
    assert pert.record()["source_type"] == "EXPERT_ESTIMATE"
    assert pert.record()["sparse"] is False
    sparse = d.Triangular(0, 5, 10, source_type="CUSTOMER_PROVIDED", sparse=True)
    assert sparse.record()["source_type"] == "CUSTOMER_PROVIDED"
    assert sparse.record()["sparse"] is True
    for source_type in SourceType:
        if source_type is not SourceType.EXPERT_ESTIMATE:
            with pytest.raises(d.DistributionRefused) as caught:
                d.Pert(0, 50, 100, source_type=source_type)
            assert caught.value.code == "expert_not_allowed"
            d.Pert(0, 50, 100, source_type=source_type, sparse=True)


def test_a_mode_at_either_end_is_allowed():
    assert d.Pert(0, 0, 100, source_type=EXPERT).ppf(0.5) < 50
    assert d.Triangular(0, 100, 100, source_type=EXPERT).ppf(0.5) > 50


# ----------------------------------------------------------- randomness


def test_sampling_reads_only_the_generator_it_is_given():
    """Seeding numpy's or Python's global RNG changes nothing, and sampling leaves
    both untouched."""
    for _, make, _ in CASES:
        dist = make()
        np.random.seed(1)
        random.seed(1)
        first = dist.sample(rng(42), 500)
        np.random.seed(2)
        random.seed(2)
        legacy, python = np.random.get_state(), random.getstate()
        second = dist.sample(rng(42), 500)
        assert np.array_equal(first, second)
        after = np.random.get_state()
        assert legacy[0] == after[0] and np.array_equal(legacy[1], after[1]) and legacy[2:] == after[2:]
        assert random.getstate() == python


def test_counts_are_whole_numbers_and_costs_floats():
    for _, make, _ in CASES:
        dist = make()
        drawn = dist.sample(rng(1), 100)
        assert drawn.dtype == (np.int64 if dist.DISCRETE else np.float64)
    assert d.Poisson(3).sample(rng(1), 0).shape == (0,)


def test_the_splice_draws_from_both_parts():
    splice = _splice_gamma()
    drawn = splice.sample(rng(9), 100_000)
    above = float(np.mean(drawn > splice.threshold))
    assert abs(above - 0.1) <= K * math.sqrt(0.1 * 0.9 / 100_000)
    assert drawn.min() > 0


def _ulps(mine: np.ndarray, reference: np.ndarray) -> float:
    keep = np.abs(reference) > 1e-300
    return float(np.max(np.abs(mine[keep] - reference[keep]) / np.spacing(np.abs(reference[keep]))))


def test_the_portable_exp_and_expm1_agree_with_the_c_library():
    generator = rng(3)
    x = np.concatenate([generator.uniform(-700, 700, 50_000), generator.uniform(-1, 1, 50_000), [0.0, 1e-300]])
    assert _ulps(d.exp_portable(x), np.array([math.exp(v) for v in x])) <= 1.0
    y = np.concatenate([generator.uniform(-40, 80, 50_000), generator.uniform(-1e-9, 1e-9, 10_000), [0.0, -0.99, 1.01]])
    assert _ulps(d.expm1_portable(y), np.array([math.expm1(v) for v in y])) <= 2.0
    assert d.exp_portable(np.array([0.0]))[0] == 1.0
    assert d.expm1_portable(np.array([0.0]))[0] == 0.0


def test_special_functions_known_values():
    assert d.gamma_p(1.0, 1.0) == pytest.approx(1 - math.exp(-1), rel=1e-15)
    assert d.gamma_q(3.0, 2.0) == pytest.approx(5 * math.exp(-2), rel=1e-14)
    assert d.beta_inc(2.0, 2.0, 0.5) == pytest.approx(0.5, rel=1e-15)
    assert d.beta_inc(1.0, 3.0, 0.2) == pytest.approx(1 - 0.8**3, rel=1e-14)
    # A large shape keeps its digits (Stirling's correction in the prefactor):
    # the Poisson CDF at its mean for a rate of a million (mpmath, 40 digits).
    assert d.Poisson(1e6).cdf(1e6) == pytest.approx(0.50026596148628365, rel=1e-12)
