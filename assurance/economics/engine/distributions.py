"""The distributions Economic Exposure's probabilistic engine samples (phase E2,
MVP step 7a; ``docs/economics/spec-v1.md``, section 23).

The owner's specification separates how often a loss event happens from how much
it costs when it does (section 7.1), and says which family suits which: a count of
events, a conditional success rate, a positive heavy-tailed cost, an expert's
range. This module is that catalogue, as frozen values with checked parameters:

- **Frequency** (events a year, or any count): :class:`Poisson`,
  :class:`NegativeBinomial` (over-dispersed counts), :class:`ZeroInflatedPoisson`.
- **Conditional success**: :class:`BetaBinomialRate`, a success rate updated from
  observed trials (section 7.2: 7 of 20 valid attempts, on a stated prior).
- **Severity** (a positive cost): :class:`Lognormal`, :class:`Gamma`,
  :class:`GeneralizedPareto` for the tail, and :class:`Spliced`, a body below a
  threshold and a generalized Pareto tail above it.
- **Expert estimate**: :class:`Pert` and :class:`Triangular`, refused unless the
  parameter's ``source_type`` is ``EXPERT_ESTIMATE`` or its data are marked
  sparse (``expert_not_allowed``): an expert's range never stands in for data
  that exists, and the assumption is stated where it is used (section 7.1).

Every distribution:

- is built from its native parameters or from the forms a customer gives
  (a lognormal from its P10 and P90, or its median and P90; a negative binomial
  from its mean and variance; a gamma from its mean and standard deviation), and
  records which form and the values given;
- refuses, with a published code (:data:`REFUSALS`), a value that is not a
  number, NaN or Infinity, a scale that is not positive, a shape out of its range,
  a mode outside ``[min, max]``, quantiles out of order, and a negative binomial
  whose variance does not exceed its mean;
- has a stable ``ID`` and ``VERSION``, written with every sample set it gives
  (:meth:`Distribution.record`): a change to how one samples is a new version;
- gives ``sample(rng, n)``, ``cdf(x)``, ``ppf(p)`` (also ``quantile``), ``mean``
  and ``variance``. A mean or variance that is infinite (a generalized Pareto with
  shape at least 1, or at least 1/2) is ``None``, never a float Infinity; one that
  is finite but too large to hold as a float is refused when the distribution is
  built (``out_of_range``).

Sampling draws only from the ``numpy.random.Generator`` it is given: never the
global RNG, never a ``RandomState`` (``rng_malformed``). The run gives each
parameter its own sub-stream (:mod:`.simulation`). A draw is numpy's own C
sampler, or, for a lognormal and a generalized Pareto, a standard normal or
exponential passed through :func:`exp_portable` or :func:`expm1_portable`, built
from IEEE-754 basic operations alone: numpy's SIMD ``exp`` and libm's each pick
an implementation by CPU, and they differ in the last bit. The CDF and quantile functions
are scalar and use no third-party special functions: the incomplete gamma and
beta functions are computed here (series and continued fractions), the normal
quantile is the standard library's (``statistics.NormalDist``, Wichura's AS241).

Pure: no Django, no database, no I/O.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Context, Decimal
from statistics import NormalDist
from types import MappingProxyType
from typing import ClassVar

import numpy as np

from .provenance import SourceType

#: What each refusal code of the distribution catalogue means.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "not_a_number": "a parameter is a number (an int, a float or a Decimal), never a bool, text or None",
        "not_finite": "NaN and Infinity are not values any parameter may hold",
        "out_of_range": (
            "the parameters give a mean, a variance or a count too large to hold as a binary64 float or to "
            "sample: refused rather than carried as Infinity"
        ),
        "scale_not_positive": "a scale (a lognormal's sigma, a gamma or Pareto scale) or a rate is greater than zero",
        "value_not_positive": (
            "a value a distribution is built from is greater than zero: a lognormal's median and quantiles, a "
            "mean, a standard deviation, a variance, a mean excess"
        ),
        "shape_out_of_range": (
            "a shape lies in its stated range: a gamma or beta shape and a negative-binomial size above zero, a "
            "PERT weight above zero, a generalized Pareto shape above -1 and at most 2"
        ),
        "probability_out_of_range": (
            "a probability lies in its stated range: a zero inflation in [0, 1), a negative-binomial p, a "
            "splice's tail probability and a quantile's p in (0, 1)"
        ),
        "range_inverted": "a lower bound or quantile is below the upper one: min < max, P10 < P90, median < P90",
        "mode_out_of_range": "an expert estimate's mode lies within [min, max]",
        "not_overdispersed": (
            "a negative binomial needs a variance greater than its mean: equal is a Poisson, and an "
            "under-dispersed count is not modelled"
        ),
        "threshold_out_of_range": (
            "a generalized Pareto threshold is at least zero; a splice's threshold is above zero and at or above "
            "its body's median, so the tail models the tail"
        ),
        "component_unsupported": "a splice is a lognormal or gamma body and a generalized Pareto tail",
        "trials_malformed": "observed trials and successes are whole numbers, with 0 <= successes <= trials and trials >= 1",
        "expert_not_allowed": (
            "PERT and triangular are used only for an EXPERT_ESTIMATE parameter or data marked sparse: an "
            "expert range never stands in for data that exists"
        ),
        "source_type_unrecognised": "a parameter's source_type is one of the eight source types",
        "sparse_malformed": "the sparse mark is True or False",
        "form_unrecognised": "a distribution is built from its native parameters or one of the forms it lists",
        "rng_malformed": (
            "a sample is drawn from an explicit numpy Generator the run seeded: never the global RNG or a "
            "RandomState"
        ),
        "sample_size_out_of_range": "a sample size is a whole number from 0 to MAX_SAMPLE",
    }
)


class DistributionRefused(ValueError):
    """A distribution's parameters, form or use refused. ``code`` is one of
    :data:`REFUSALS`; ``detail`` says what was refused."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


#: The largest sample one call draws (80 MB of binary64).
MAX_SAMPLE = 10_000_000
#: The largest mean a count distribution may have: numpy's Poisson sampler refuses
#: a rate near 1e19, and a count above a billion is not an event frequency.
MAX_COUNT_MEAN = 1e9
#: A generalized Pareto shape lies in (GPD_SHAPE_MIN, GPD_SHAPE_MAX].
GPD_SHAPE_MIN = -1.0
GPD_SHAPE_MAX = 2.0
#: The PERT weight on the mode, unless stated: the classical PERT.
PERT_WEIGHT = 4.0
#: A splice's threshold is at or above this quantile of its body (the median).
SPLICE_MIN_BODY_SHARE = 0.5
#: How many rounds the splice's truncated body may take to fill a sample. Each
#: round draws at least twice what is still needed from a body that keeps at least
#: half of what it draws, so running out is a defect, never chance.
SPLICE_MAX_ROUNDS = 200

_STANDARD_NORMAL = NormalDist()
#: The standard normal's 90th percentile, 1.2815515655446004 (statistics.NormalDist).
Z90 = _STANDARD_NORMAL.inv_cdf(0.9)

#: The four kinds of distribution, by what they describe.
FREQUENCY = "frequency"
RATE = "rate"
SEVERITY = "severity"
EXPERT = "expert"

#: The forms a distribution may be built from.
NATIVE = "native"
MEDIAN_SIGMA = "median_sigma"
P10_P90 = "p10_p90"
MEDIAN_P90 = "median_p90"
MEAN_SD = "mean_sd"
MEAN_VARIANCE = "mean_variance"
PRIOR_AND_TRIALS = "prior_and_trials"
MEAN_EXCESS = "mean_excess"
CONTINUOUS_AT_THRESHOLD = "continuous_at_threshold"
FORMS = (
    NATIVE,
    MEDIAN_SIGMA,
    P10_P90,
    MEDIAN_P90,
    MEAN_SD,
    MEAN_VARIANCE,
    PRIOR_AND_TRIALS,
    MEAN_EXCESS,
    CONTINUOUS_AT_THRESHOLD,
)


# ----------------------------------------------------------- numbers and text


def float_decimal(value) -> Decimal:
    """The ``Decimal`` of a float's ``repr``: the shortest decimal string that reads
    back as exactly this binary64 value (Python's repr, correctly rounded and the
    same on every IEEE-754 platform), converted to ``Decimal`` with no rounding.
    Negative zero is zero. NaN and Infinity are refused (``not_finite``)."""
    number = float(value)
    if not math.isfinite(number):
        raise DistributionRefused("not_finite", repr(number))
    return Decimal(repr(number + 0.0))


def float_text(value) -> str:
    """:func:`float_decimal` in one spelling: plain notation, no exponent, no
    trailing zeros (``100.0`` is ``100``, ``1e-05`` is ``0.00001``), ``0`` for zero.
    Every float a record or a digest holds is written this way, never as a JSON
    number."""
    number = float_decimal(value)
    exact = Context(prec=max(1, len(number.as_tuple().digits)), Emin=-999_999, Emax=999_999)
    text = format(number.normalize(exact), "f")
    return "0" if text in {"-0", "0"} else text


def _number(value, what: str) -> float:
    """``value`` as a finite float: an int, a float or a Decimal (numpy's own
    integer and float scalars too). A bool, text or None is ``not_a_number``; NaN
    and Infinity are ``not_finite``; an int too large for a float ``out_of_range``."""
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, float, Decimal, np.integer, np.floating)):
        raise DistributionRefused("not_a_number", f"{what} is a {type(value).__name__}")
    if isinstance(value, Decimal) and not value.is_finite():
        raise DistributionRefused("not_finite", f"{what} is {value}")
    try:
        number = float(value)
    except OverflowError:
        raise DistributionRefused("out_of_range", f"{what} is too large for a float") from None
    if not math.isfinite(number):
        raise DistributionRefused("not_finite", f"{what} is {number}")
    return number


def _positive(value, what: str, code: str) -> float:
    number = _number(value, what)
    if number <= 0.0:
        raise DistributionRefused(code, f"{what} is {float_text(number)}")
    return number


def _probability(p) -> float:
    """A quantile's ``p``: strictly between 0 and 1. ``ppf(0)`` and ``ppf(1)`` are
    refused rather than answered with a bound that may be infinite."""
    number = _number(p, "p")
    if not 0.0 < number < 1.0:
        raise DistributionRefused("probability_out_of_range", f"p is {float_text(number)}, not in (0, 1)")
    return number


def _check_rng(rng) -> np.random.Generator:
    if not isinstance(rng, np.random.Generator):
        raise DistributionRefused("rng_malformed", f"rng is a {type(rng).__name__}")
    return rng


def _check_size(n) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= MAX_SAMPLE:
        raise DistributionRefused("sample_size_out_of_range", f"n is {n!r}")
    return n


def _finite_moment(compute: Callable[[], float], what: str) -> float:
    """A moment that is finite in theory, refused if it is not finite as a float."""
    try:
        value = compute()
    except OverflowError:
        raise DistributionRefused("out_of_range", f"the {what} overflows a float") from None
    if not math.isfinite(value):
        raise DistributionRefused("out_of_range", f"the {what} overflows a float")
    return value


# ------------------------------------------------------- special functions


_EPS = 2.220446049250313e-16
_TINY = 1e-300


def _iterations(*sizes: float) -> int:
    """How many terms a series or continued fraction may take: these converge in
    O(sqrt(a)) terms, so the bound grows with the arguments and is never reached
    for a value they can converge on."""
    return 1000 + int(20 * math.sqrt(sum(abs(size) for size in sizes)))


def _not_converged(what: str) -> DistributionRefused:
    return DistributionRefused("out_of_range", f"the {what} did not converge for these parameters")


def _log1pmx(u: float) -> float:
    """log(1 + u) - u, keeping its digits when u is small (its series)."""
    if abs(u) >= 0.25:
        return math.log1p(u) - u
    total = 0.0
    power = u
    for k in range(2, 200):
        power *= -u
        term = power / k
        total += term
        if abs(term) <= abs(total) * _EPS:
            break
    return total


#: From here on Stirling's series, four terms, gives lgamma's correction to the
#: last bit, and the prefactors below use it.
_STIRLING_FROM = 100.0


def _stirling(a: float) -> float:
    """delta(a) = lgamma(a) - ((a - 1/2) ln a - a + ln(2 pi) / 2), for a >= 100."""
    a2 = a * a
    return (1.0 / 12.0 - (1.0 / 360.0 - (1.0 / 1260.0 - 1.0 / (1680.0 * a2)) / a2) / a2) / a


def _gamma_prefix(a: float, x: float) -> float:
    """x^a e^-x / Gamma(a). For a large shape the three terms of its logarithm are
    each about a ln a and cancel, so it is computed as
    a log1pmx((x - a) / a) + ln(a / 2 pi) / 2 - delta(a), delta Stirling's
    correction to lgamma (four terms, exact to the last bit from a = 100)."""
    if a < _STIRLING_FROM:
        return math.exp(-x + a * math.log(x) - math.lgamma(a))
    return math.exp(a * _log1pmx((x - a) / a) + 0.5 * math.log(a / (2.0 * math.pi)) - _stirling(a))


def _gamma_series(a: float, x: float) -> float:
    """P(a, x) by its series, for x < a + 1."""
    term = 1.0 / a
    total = term
    denominator = a
    for _ in range(_iterations(a, x)):
        denominator += 1.0
        term *= x / denominator
        total += term
        if abs(term) <= abs(total) * _EPS:
            return total * _gamma_prefix(a, x)
    raise _not_converged("incomplete gamma series")


def _gamma_fraction(a: float, x: float) -> float:
    """Q(a, x) by its continued fraction (modified Lentz), for x >= a + 1."""
    b = x + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b
    h = d
    for i in range(1, _iterations(a, x)):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) <= _EPS:
            return _gamma_prefix(a, x) * h
    raise _not_converged("incomplete gamma continued fraction")


def gamma_p(a: float, x: float) -> float:
    """The regularized lower incomplete gamma function P(a, x), a > 0."""
    if x <= 0.0:
        return 0.0
    if x < a + 1.0:
        return _gamma_series(a, x)
    return 1.0 - _gamma_fraction(a, x)


def gamma_q(a: float, x: float) -> float:
    """The regularized upper incomplete gamma function Q(a, x) = 1 - P(a, x),
    computed directly where it is small."""
    if x <= 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    return _gamma_fraction(a, x)


def _beta_fraction(a: float, b: float, x: float) -> float:
    """The continued fraction of the incomplete beta function (modified Lentz)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _TINY:
        d = _TINY
    d = 1.0 / d
    h = d
    for m in range(1, _iterations(a, b)):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _TINY:
            d = _TINY
        c = 1.0 + aa / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _TINY:
            d = _TINY
        c = 1.0 + aa / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) <= _EPS:
            return h
    raise _not_converged("incomplete beta continued fraction")


def _beta_prefix(a: float, b: float, x: float) -> float:
    """x^a (1 - x)^b / B(a, b). For one large shape, lgamma(big + small) - lgamma(big)
    is (big - 1/2) log1p(small / big) + small ln(big + small) - small + delta(big +
    small) - delta(big). For two large shapes, as for the gamma prefactor,
    around x0 = a / (a + b): a log1pmx((x - x0) / x0) + b log1pmx((x0 - x) / (1 - x0))
    + ln(a b / (2 pi (a + b))) / 2 + delta(a + b) - delta(a) - delta(b)."""
    powers = a * math.log(x) + b * math.log1p(-x)
    if max(a, b) < _STIRLING_FROM:
        return math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + powers)
    if min(a, b) < _STIRLING_FROM:
        # One large shape: lgamma(big + small) - lgamma(big) by Stirling, so the
        # two large logarithms do not cancel.
        big, small = max(a, b), min(a, b)
        ratio = (
            (big - 0.5) * math.log1p(small / big)
            + small * math.log(big + small)
            - small
            + _stirling(big + small)
            - _stirling(big)
        )
        return math.exp(ratio - math.lgamma(small) + powers)
    x0 = a / (a + b)
    return math.exp(
        a * _log1pmx((x - x0) / x0)
        + b * _log1pmx((x0 - x) / (1.0 - x0))
        + 0.5 * math.log(a * b / (2.0 * math.pi * (a + b)))
        + _stirling(a + b)
        - _stirling(a)
        - _stirling(b)
    )


def beta_inc(a: float, b: float, x: float) -> float:
    """The regularized incomplete beta function I_x(a, b), a, b > 0."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = _beta_prefix(a, b, x)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _beta_fraction(a, b, x) / a
    return 1.0 - front * _beta_fraction(b, a, 1.0 - x) / b


def normal_cdf(z: float) -> float:
    """The standard normal CDF, by ``erfc`` so the lower tail keeps its digits."""
    return 0.5 * math.erfc(-z / math.sqrt(2.0))


def normal_ppf(p: float) -> float:
    """The standard normal quantile (``statistics.NormalDist``, Wichura's AS241)."""
    return _STANDARD_NORMAL.inv_cdf(p)


# Cody and Waite's split of ln 2, as fdlibm's e_exp.c has it: LN2_HI ends in 21
# zero bits, so k * LN2_HI is exact for every k an exponent can need.
_LN2_HI = 6.93147180369123816490e-01
_LN2_LO = 1.90821492927058770002e-10
_INV_LN2 = 1.44269504088896338700e00
#: 1/15!, 1/14!, ..., 1/1!, 1/0!: Taylor's coefficients, each a correctly rounded
#: quotient of two exact integers, so the same on every platform.
_TAYLOR = tuple(1.0 / math.factorial(k) for k in range(15, -1, -1))
#: 1/22!, ..., 1/2!, 1/1!: (e^y - 1) / y to degree 21, for |y| < 1 (truncation
#: below 1e-21).
_TAYLOR_EXPM1 = tuple(1.0 / math.factorial(k) for k in range(22, 0, -1))


def _horner(r: np.ndarray, coefficients) -> np.ndarray:
    total = np.full_like(r, coefficients[0])
    for coefficient in coefficients[1:]:
        total = total * r + coefficient
    return total


def exp_portable(x: np.ndarray) -> np.ndarray:
    """e^x, elementwise, from IEEE-754 basic operations only (multiply, add,
    subtract, round to integer, scale by a power of two), each its own numpy
    operation: the same bits on every CPU and C library, which neither numpy's
    SIMD ``exp`` nor libm's guarantees (both choose an implementation by CPU
    feature). x = k ln2 + r with |r| <= ln2 / 2 (Cody and Waite), e^r by Taylor's
    series to degree 15 (truncation below 1e-19), scaled by 2^k exactly. Within
    about one unit in the last place of the true value."""
    x = np.asarray(x, dtype=np.float64)
    k = np.rint(x * _INV_LN2)
    r = (x - k * _LN2_HI) - k * _LN2_LO
    return np.ldexp(_horner(r, _TAYLOR), k.astype(np.int32))


def expm1_portable(y: np.ndarray) -> np.ndarray:
    """e^y - 1, elementwise, by the same rule as :func:`exp_portable`: for
    |y| < 1, y times Taylor's series of (e^y - 1) / y, so a small value keeps its
    digits; beyond, :func:`exp_portable` minus one. Within about two units in the
    last place."""
    y = np.asarray(y, dtype=np.float64)
    near = y * _horner(y, _TAYLOR_EXPM1)
    return np.where(np.abs(y) < 1.0, near, exp_portable(y) - 1.0)


def _invert(cdf: Callable[[float], float], p: float, lo: float, hi: float) -> float:
    """The smallest float at which an increasing continuous ``cdf`` reaches ``p``,
    by bisection to the last bit: ``hi`` is doubled until the CDF reaches ``p``,
    then the bracket is halved until no float lies between its ends."""
    while cdf(hi) < p:
        lo, hi = hi, (hi * 2.0 if hi > 0.0 else 1.0)
        if not math.isfinite(hi):
            raise DistributionRefused("out_of_range", "the quantile is beyond the largest float")
    while True:
        mid = lo + (hi - lo) / 2.0
        if mid <= lo or mid >= hi:
            return hi
        if cdf(mid) < p:
            lo = mid
        else:
            hi = mid


def _invert_discrete(cdf: Callable[[float], float], p: float) -> int:
    """The smallest whole k with ``cdf(k) >= p``."""
    if cdf(0.0) >= p:
        return 0
    lo, hi = 0, 1
    while cdf(float(hi)) < p:
        lo, hi = hi, hi * 2
        if hi > 2**62:
            raise DistributionRefused("out_of_range", "the quantile is beyond any count")
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if cdf(float(mid)) < p:
            lo = mid
        else:
            hi = mid
    return hi


# ------------------------------------------------------------- the base


@dataclass(frozen=True)
class Distribution:
    """One distribution, frozen, its parameters checked when it is built.

    ``form`` says which form it was built from (``native`` or one of the
    customer forms its class lists in ``FORMS``) and ``given`` the values given in
    that form, as (name, value) pairs; both are written with every sample set.
    Subclasses set ``ID``, ``VERSION``, ``KIND`` and ``FORMS``, and implement the
    native parameters, the moments, ``_draw``, ``_cdf`` and ``_ppf``."""

    form: str = field(default=NATIVE, kw_only=True)
    given: tuple = field(default=(), kw_only=True)

    #: The stable id: a sample set records it, and it is never reused.
    ID: ClassVar[str] = ""
    #: The version of how this distribution samples and is parameterised. A change
    #: that alters a single draw from the same stream is a new version.
    VERSION: ClassVar[int] = 1
    #: frequency, rate, severity or expert.
    KIND: ClassVar[str] = ""
    #: The forms this distribution may be built from.
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE,)
    #: True for a count (its draws are int64, its quantile a whole number).
    DISCRETE: ClassVar[bool] = False
    #: True for an expert range (PERT, triangular): allowed only for an
    #: EXPERT_ESTIMATE parameter or sparse data, and it lowers confidence.
    EXPERT: ClassVar[bool] = False

    def _check_form(self) -> None:
        if self.form not in type(self).FORMS:
            raise DistributionRefused("form_unrecognised", f"{type(self).ID} is not built from {self.form!r}")
        pairs = []
        for pair in self.given:
            if not (isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[0], str)):
                raise DistributionRefused("form_unrecognised", f"given holds {pair!r}, not a (name, value) pair")
            pairs.append((pair[0], _number(pair[1], pair[0])))
        object.__setattr__(self, "given", tuple(pairs))

    # The interface. ``sample``, ``cdf`` and ``ppf`` check their arguments, then
    # call the subclass.

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        """``n`` independent draws from ``rng`` alone: float64, or int64 for a count."""
        return self._draw(_check_rng(rng), _check_size(n))

    def cdf(self, x) -> float:
        """P(X <= x)."""
        return self._cdf(_number(x, "x"))

    def ppf(self, p) -> float:
        """The p-quantile, 0 < p < 1: the smallest x with ``cdf(x) >= p``."""
        return self._ppf(_probability(p))

    def quantile(self, p) -> float:
        """The same as :meth:`ppf`."""
        return self.ppf(p)

    @property
    def mean(self) -> float | None:
        raise NotImplementedError

    @property
    def variance(self) -> float | None:
        raise NotImplementedError

    def params(self) -> dict[str, float]:
        """The native parameters, by name."""
        raise NotImplementedError

    def _draw(self, rng: np.random.Generator, n: int) -> np.ndarray:
        raise NotImplementedError

    def _cdf(self, x: float) -> float:
        raise NotImplementedError

    def _ppf(self, p: float):
        raise NotImplementedError

    def record(self) -> dict:
        """What a sample set records about the distribution it was drawn from:
        its id, version and kind, its native parameters, the form it was built
        from and the values given, and its mean and variance (``None`` where
        infinite). Every number is a string (:func:`float_text`)."""
        mean, variance = self.mean, self.variance
        return {
            "id": type(self).ID,
            "version": type(self).VERSION,
            "kind": type(self).KIND,
            "params": {name: float_text(value) for name, value in self.params().items()},
            "form": self.form,
            "given": {name: float_text(value) for name, value in self.given},
            "mean": None if mean is None else float_text(mean),
            "variance": None if variance is None else float_text(variance),
        }


def _set(instance, name: str, value) -> None:
    object.__setattr__(instance, name, value)


# ----------------------------------------------------------- frequency


@dataclass(frozen=True)
class Poisson(Distribution):
    """Events a year at a constant ``rate`` (> 0): mean and variance both the rate."""

    rate: float

    ID: ClassVar[str] = "poisson"
    KIND: ClassVar[str] = FREQUENCY
    DISCRETE: ClassVar[bool] = True

    def __post_init__(self):
        rate = _positive(self.rate, "rate", "scale_not_positive")
        if rate > MAX_COUNT_MEAN:
            raise DistributionRefused("out_of_range", f"rate {float_text(rate)} is above {float_text(MAX_COUNT_MEAN)}")
        _set(self, "rate", rate)
        self._check_form()

    def params(self):
        return {"rate": self.rate}

    @property
    def mean(self):
        return self.rate

    @property
    def variance(self):
        return self.rate

    def _draw(self, rng, n):
        return rng.poisson(self.rate, n).astype(np.int64)

    def _cdf(self, x):
        if x < 0.0:
            return 0.0
        return gamma_q(math.floor(x) + 1.0, self.rate)

    def _ppf(self, p):
        return _invert_discrete(self._cdf, p)


@dataclass(frozen=True)
class NegativeBinomial(Distribution):
    """An over-dispersed count: failures before the ``size``-th success at success
    probability ``probability`` (numpy's parameterisation, size a real > 0).
    Mean ``size(1-p)/p``, variance ``size(1-p)/p^2``: always above the mean.

    :meth:`from_mean_variance` is the form a customer gives, and refuses a
    variance at or below the mean (``not_overdispersed``)."""

    size: float
    probability: float

    ID: ClassVar[str] = "negative_binomial"
    KIND: ClassVar[str] = FREQUENCY
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, MEAN_VARIANCE)
    DISCRETE: ClassVar[bool] = True

    def __post_init__(self):
        size = _positive(self.size, "size", "shape_out_of_range")
        probability = _number(self.probability, "probability")
        if not 0.0 < probability < 1.0:
            raise DistributionRefused("probability_out_of_range", f"p is {float_text(probability)}, not in (0, 1)")
        _set(self, "size", size)
        _set(self, "probability", probability)
        mean = _finite_moment(lambda: size * (1.0 - probability) / probability, "mean")
        _finite_moment(lambda: mean / probability, "variance")
        if mean > MAX_COUNT_MEAN:
            raise DistributionRefused("out_of_range", f"mean {float_text(mean)} is above {float_text(MAX_COUNT_MEAN)}")
        self._check_form()

    @classmethod
    def from_mean_variance(cls, mean, variance) -> NegativeBinomial:
        """From the mean and variance a customer gives: ``p = mean / variance``,
        ``size = mean^2 / (variance - mean)``. The variance must exceed the mean."""
        m = _positive(mean, "mean", "value_not_positive")
        v = _positive(variance, "variance", "value_not_positive")
        if v <= m:
            raise DistributionRefused(
                "not_overdispersed", f"variance {float_text(v)} is not greater than mean {float_text(m)}"
            )
        return cls(m * m / (v - m), m / v, form=MEAN_VARIANCE, given=(("mean", m), ("variance", v)))

    def params(self):
        return {"size": self.size, "probability": self.probability}

    @property
    def mean(self):
        return self.size * (1.0 - self.probability) / self.probability

    @property
    def variance(self):
        return self.size * (1.0 - self.probability) / (self.probability * self.probability)

    def _draw(self, rng, n):
        return rng.negative_binomial(self.size, self.probability, n).astype(np.int64)

    def _cdf(self, x):
        if x < 0.0:
            return 0.0
        return beta_inc(self.size, math.floor(x) + 1.0, self.probability)

    def _ppf(self, p):
        return _invert_discrete(self._cdf, p)


@dataclass(frozen=True)
class ZeroInflatedPoisson(Distribution):
    """A Poisson count that is a structural zero with probability
    ``zero_inflation`` (in [0, 1)): a year in which the event cannot happen at
    all, beside years in which it happens at ``rate``. Mean ``(1-pi) rate``,
    variance ``(1-pi) rate (1 + pi rate)``."""

    zero_inflation: float
    rate: float

    ID: ClassVar[str] = "zero_inflated_poisson"
    KIND: ClassVar[str] = FREQUENCY
    DISCRETE: ClassVar[bool] = True

    def __post_init__(self):
        pi = _number(self.zero_inflation, "zero_inflation")
        if not 0.0 <= pi < 1.0:
            raise DistributionRefused("probability_out_of_range", f"zero_inflation is {float_text(pi)}, not in [0, 1)")
        rate = _positive(self.rate, "rate", "scale_not_positive")
        if rate > MAX_COUNT_MEAN:
            raise DistributionRefused("out_of_range", f"rate {float_text(rate)} is above {float_text(MAX_COUNT_MEAN)}")
        _set(self, "zero_inflation", pi)
        _set(self, "rate", rate)
        self._check_form()

    def params(self):
        return {"zero_inflation": self.zero_inflation, "rate": self.rate}

    @property
    def mean(self):
        return (1.0 - self.zero_inflation) * self.rate

    @property
    def variance(self):
        return (1.0 - self.zero_inflation) * self.rate * (1.0 + self.zero_inflation * self.rate)

    def _draw(self, rng, n):
        # The structural zeros first, then the Poisson counts, each n draws.
        structural = rng.random(n) < self.zero_inflation
        counts = rng.poisson(self.rate, n).astype(np.int64)
        counts[structural] = 0
        return counts

    def _cdf(self, x):
        if x < 0.0:
            return 0.0
        return self.zero_inflation + (1.0 - self.zero_inflation) * gamma_q(math.floor(x) + 1.0, self.rate)

    def _ppf(self, p):
        return _invert_discrete(self._cdf, p)


# ------------------------------------------------------ conditional success


@dataclass(frozen=True)
class BetaBinomialRate(Distribution):
    """A conditional success rate: Beta(``alpha``, ``beta``) on [0, 1].

    :meth:`from_trials` is the update of section 7.2: a Beta(``prior_alpha``,
    ``prior_beta``) prior and ``successes`` of ``trials`` observed attempts give
    the posterior Beta(prior_alpha + successes, prior_beta + trials - successes),
    whose mean is (prior_alpha + successes) / (prior_alpha + prior_beta + trials).
    The prior defaults to the uniform Beta(1, 1), and is recorded with the
    evidence. The rate describes the tested environment only: what scope the
    trials cover is the scenario's to state, never widened here."""

    alpha: float
    beta: float

    ID: ClassVar[str] = "beta_binomial_rate"
    KIND: ClassVar[str] = RATE
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, PRIOR_AND_TRIALS)

    def __post_init__(self):
        _set(self, "alpha", _positive(self.alpha, "alpha", "shape_out_of_range"))
        _set(self, "beta", _positive(self.beta, "beta", "shape_out_of_range"))
        self._check_form()

    @classmethod
    def from_trials(cls, trials, successes, *, prior_alpha=1.0, prior_beta=1.0) -> BetaBinomialRate:
        """The posterior after ``successes`` of ``trials`` attempts."""
        for what, value in (("trials", trials), ("successes", successes)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DistributionRefused("trials_malformed", f"{what} is a {type(value).__name__}")
        if trials < 1 or not 0 <= successes <= trials:
            raise DistributionRefused("trials_malformed", f"{successes} successes of {trials} trials")
        a0 = _positive(prior_alpha, "prior_alpha", "shape_out_of_range")
        b0 = _positive(prior_beta, "prior_beta", "shape_out_of_range")
        return cls(
            a0 + successes,
            b0 + (trials - successes),
            form=PRIOR_AND_TRIALS,
            given=(("prior_alpha", a0), ("prior_beta", b0), ("trials", trials), ("successes", successes)),
        )

    def params(self):
        return {"alpha": self.alpha, "beta": self.beta}

    @property
    def mean(self):
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self):
        total = self.alpha + self.beta
        return self.alpha * self.beta / (total * total * (total + 1.0))

    def _draw(self, rng, n):
        return rng.beta(self.alpha, self.beta, n)

    def _cdf(self, x):
        return beta_inc(self.alpha, self.beta, x)

    def _ppf(self, p):
        return _invert(self._cdf, p, 0.0, 1.0)


# --------------------------------------------------------------- severity


@dataclass(frozen=True)
class Lognormal(Distribution):
    """A positive cost whose logarithm is normal with mean ``mu`` and standard
    deviation ``sigma`` (> 0). The median is ``exp(mu)``.

    Customer forms: :meth:`from_median_sigma`, :meth:`from_p10_p90` (the two
    quantiles fix mu and sigma: ``mu = (ln P10 + ln P90) / 2``, ``sigma =
    (ln P90 - ln P10) / (2 z90)``) and :meth:`from_median_p90` (``sigma =
    (ln P90 - ln median) / z90``), with ``z90`` the standard normal's 90th
    percentile (:data:`Z90`)."""

    mu: float
    sigma: float

    ID: ClassVar[str] = "lognormal"
    KIND: ClassVar[str] = SEVERITY
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, MEDIAN_SIGMA, P10_P90, MEDIAN_P90)

    def __post_init__(self):
        mu = _number(self.mu, "mu")
        sigma = _positive(self.sigma, "sigma", "scale_not_positive")
        _set(self, "mu", mu)
        _set(self, "sigma", sigma)
        _finite_moment(lambda: math.exp(mu + sigma * sigma / 2.0), "mean")
        _finite_moment(lambda: math.expm1(sigma * sigma) * math.exp(2.0 * mu + sigma * sigma), "variance")
        self._check_form()

    @classmethod
    def from_median_sigma(cls, median, sigma) -> Lognormal:
        m = _positive(median, "median", "value_not_positive")
        s = _positive(sigma, "sigma", "scale_not_positive")
        return cls(math.log(m), s, form=MEDIAN_SIGMA, given=(("median", m), ("sigma", s)))

    @classmethod
    def from_p10_p90(cls, p10, p90) -> Lognormal:
        low = _positive(p10, "p10", "value_not_positive")
        high = _positive(p90, "p90", "value_not_positive")
        if low >= high:
            raise DistributionRefused("range_inverted", f"P10 {float_text(low)} is not below P90 {float_text(high)}")
        mu = (math.log(low) + math.log(high)) / 2.0
        sigma = (math.log(high) - math.log(low)) / (2.0 * Z90)
        return cls(mu, sigma, form=P10_P90, given=(("p10", low), ("p90", high)))

    @classmethod
    def from_median_p90(cls, median, p90) -> Lognormal:
        m = _positive(median, "median", "value_not_positive")
        high = _positive(p90, "p90", "value_not_positive")
        if m >= high:
            raise DistributionRefused("range_inverted", f"median {float_text(m)} is not below P90 {float_text(high)}")
        return cls(math.log(m), (math.log(high) - math.log(m)) / Z90, form=MEDIAN_P90, given=(("median", m), ("p90", high)))

    def params(self):
        return {"mu": self.mu, "sigma": self.sigma}

    @property
    def mean(self):
        return math.exp(self.mu + self.sigma * self.sigma / 2.0)

    @property
    def variance(self):
        return math.expm1(self.sigma * self.sigma) * math.exp(2.0 * self.mu + self.sigma * self.sigma)

    def partial_moment(self, r: int, upper: float) -> float:
        """E[X^r ; X <= upper], for a splice's body."""
        s2 = self.sigma * self.sigma
        return math.exp(r * self.mu + r * r * s2 / 2.0) * normal_cdf((math.log(upper) - self.mu - r * s2) / self.sigma)

    def _draw(self, rng, n):
        # One standard normal per draw (numpy's C ziggurat), then exp(mu + sigma z)
        # by exp_portable, so a draw does not depend on which exp the CPU selects.
        return exp_portable(self.mu + self.sigma * rng.standard_normal(n))

    def _cdf(self, x):
        if x <= 0.0:
            return 0.0
        return normal_cdf((math.log(x) - self.mu) / self.sigma)

    def _ppf(self, p):
        return math.exp(self.mu + self.sigma * normal_ppf(p))


@dataclass(frozen=True)
class Gamma(Distribution):
    """A positive cost, Gamma(``shape`` k > 0, ``scale`` theta > 0): mean k theta,
    variance k theta^2. Customer form: :meth:`from_mean_sd` (``k = (mean/sd)^2``,
    ``theta = sd^2 / mean``)."""

    shape: float
    scale: float

    ID: ClassVar[str] = "gamma"
    KIND: ClassVar[str] = SEVERITY
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, MEAN_SD)

    def __post_init__(self):
        shape = _positive(self.shape, "shape", "shape_out_of_range")
        scale = _positive(self.scale, "scale", "scale_not_positive")
        _set(self, "shape", shape)
        _set(self, "scale", scale)
        _finite_moment(lambda: shape * scale, "mean")
        _finite_moment(lambda: shape * scale * scale, "variance")
        self._check_form()

    @classmethod
    def from_mean_sd(cls, mean, sd) -> Gamma:
        m = _positive(mean, "mean", "value_not_positive")
        s = _positive(sd, "sd", "value_not_positive")
        return cls((m / s) ** 2, s * s / m, form=MEAN_SD, given=(("mean", m), ("sd", s)))

    def params(self):
        return {"shape": self.shape, "scale": self.scale}

    @property
    def mean(self):
        return self.shape * self.scale

    @property
    def variance(self):
        return self.shape * self.scale * self.scale

    def partial_moment(self, r: int, upper: float) -> float:
        """E[X^r ; X <= upper], for a splice's body."""
        return (
            self.scale**r
            * math.exp(math.lgamma(self.shape + r) - math.lgamma(self.shape))
            * gamma_p(self.shape + r, upper / self.scale)
        )

    def _draw(self, rng, n):
        return self.scale * rng.standard_gamma(self.shape, n)

    def _cdf(self, x):
        if x <= 0.0:
            return 0.0
        return gamma_p(self.shape, x / self.scale)

    def _ppf(self, p):
        return _invert(self._cdf, p, 0.0, max(self.mean, self.scale))


@dataclass(frozen=True)
class GeneralizedPareto(Distribution):
    """The tail of a cost above ``threshold`` (u >= 0): shape xi in (-1, 2],
    scale sigma > 0. P(X > x) = (1 + xi (x - u) / sigma)^(-1/xi), exponential at
    xi = 0, bounded above at u - sigma/xi for xi < 0.

    The mean, u + sigma / (1 - xi), exists only for xi < 1, and the variance,
    sigma^2 / ((1 - xi)^2 (1 - 2 xi)), only for xi < 1/2: beyond them each is
    ``None``, never Infinity. Customer form: :meth:`from_mean_excess` (the mean
    loss above the threshold, ``sigma = (1 - xi) e``, for xi < 1)."""

    shape: float
    scale: float
    threshold: float = 0.0

    ID: ClassVar[str] = "generalized_pareto"
    KIND: ClassVar[str] = SEVERITY
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, MEAN_EXCESS)

    def __post_init__(self):
        shape = _number(self.shape, "shape")
        if not GPD_SHAPE_MIN < shape <= GPD_SHAPE_MAX:
            raise DistributionRefused(
                "shape_out_of_range",
                f"shape {float_text(shape)} is not in ({float_text(GPD_SHAPE_MIN)}, {float_text(GPD_SHAPE_MAX)}]",
            )
        scale = _positive(self.scale, "scale", "scale_not_positive")
        threshold = _number(self.threshold, "threshold")
        if threshold < 0.0:
            raise DistributionRefused("threshold_out_of_range", f"threshold {float_text(threshold)} is negative")
        _set(self, "shape", shape)
        _set(self, "scale", scale)
        _set(self, "threshold", threshold)
        if shape < 1.0:
            _finite_moment(lambda: threshold + scale / (1.0 - shape), "mean")
        if shape < 0.5:
            _finite_moment(lambda: scale * scale / ((1.0 - shape) ** 2 * (1.0 - 2.0 * shape)), "variance")
        self._check_form()

    @classmethod
    def from_mean_excess(cls, threshold, mean_excess, shape) -> GeneralizedPareto:
        xi = _number(shape, "shape")
        if not GPD_SHAPE_MIN < xi < 1.0:
            raise DistributionRefused(
                "shape_out_of_range", f"a mean excess exists only for a shape below 1, not {float_text(xi)}"
            )
        e = _positive(mean_excess, "mean_excess", "value_not_positive")
        u = _number(threshold, "threshold")
        return cls(
            xi, (1.0 - xi) * e, u, form=MEAN_EXCESS, given=(("threshold", u), ("mean_excess", e), ("shape", xi))
        )

    def params(self):
        return {"shape": self.shape, "scale": self.scale, "threshold": self.threshold}

    @property
    def mean(self):
        if self.shape >= 1.0:
            return None
        return self.threshold + self.scale / (1.0 - self.shape)

    @property
    def variance(self):
        if self.shape >= 0.5:
            return None
        return self.scale * self.scale / ((1.0 - self.shape) ** 2 * (1.0 - 2.0 * self.shape))

    def _draw(self, rng, n):
        # One standard exponential E per draw (numpy's C ziggurat); then
        # x = u + (sigma / xi) expm1(xi E), whose survival is exactly e^-E, by
        # expm1_portable (and u + sigma E at xi = 0), so a draw does not depend on
        # which exp the CPU selects.
        e = rng.standard_exponential(n)
        if self.shape == 0.0:
            return self.threshold + self.scale * e
        return self.threshold + (self.scale / self.shape) * expm1_portable(self.shape * e)

    def _cdf(self, x):
        z = (x - self.threshold) / self.scale
        if z <= 0.0:
            return 0.0
        if self.shape == 0.0:
            return -math.expm1(-z)
        if self.shape < 0.0 and z >= -1.0 / self.shape:
            return 1.0
        return -math.expm1(-math.log1p(self.shape * z) / self.shape)

    def _ppf(self, p):
        if self.shape == 0.0:
            return self.threshold - self.scale * math.log1p(-p)
        return self.threshold + self.scale * math.expm1(-self.shape * math.log1p(-p)) / self.shape


@dataclass(frozen=True)
class Spliced(Distribution):
    """A body below a threshold and a generalized Pareto tail above it: the body
    (a :class:`Lognormal` or :class:`Gamma`) truncated to ``(0, u]`` with weight
    ``1 - tail_probability``, and ``tail`` (whose own threshold is u) with weight
    ``tail_probability``.

    ``tail_probability`` is given (``native``), or :meth:`continuous` sets it to
    the body's own probability above u, so the CDF is continuous at the
    threshold. The threshold is at or above the body's median (the tail models
    the tail), and the tail probability is in (0, 1)."""

    body: Distribution
    tail: GeneralizedPareto
    tail_probability: float

    ID: ClassVar[str] = "spliced"
    KIND: ClassVar[str] = SEVERITY
    FORMS: ClassVar[tuple[str, ...]] = (NATIVE, CONTINUOUS_AT_THRESHOLD)

    def __post_init__(self):
        if not isinstance(self.body, (Lognormal, Gamma)):
            raise DistributionRefused("component_unsupported", f"the body is a {type(self.body).__name__}")
        if not isinstance(self.tail, GeneralizedPareto):
            raise DistributionRefused("component_unsupported", f"the tail is a {type(self.tail).__name__}")
        threshold = self.tail.threshold
        if threshold <= 0.0 or self.body.cdf(threshold) < SPLICE_MIN_BODY_SHARE:
            raise DistributionRefused(
                "threshold_out_of_range",
                f"threshold {float_text(threshold)} is below the body's median {float_text(self.body.ppf(0.5))}",
            )
        pi = _number(self.tail_probability, "tail_probability")
        if not 0.0 < pi < 1.0:
            raise DistributionRefused(
                "probability_out_of_range", f"tail_probability is {float_text(pi)}, not in (0, 1)"
            )
        _set(self, "tail_probability", pi)
        self._check_form()

    @classmethod
    def continuous(cls, body: Distribution, tail: GeneralizedPareto) -> Spliced:
        """The splice whose tail probability is the body's own above the threshold."""
        if not isinstance(body, (Lognormal, Gamma)) or not isinstance(tail, GeneralizedPareto):
            raise DistributionRefused("component_unsupported", "a lognormal or gamma body and a generalized Pareto tail")
        return cls(body, tail, 1.0 - body.cdf(tail.threshold), form=CONTINUOUS_AT_THRESHOLD)

    @property
    def threshold(self) -> float:
        return self.tail.threshold

    @property
    def _body_share(self) -> float:
        return self.body.cdf(self.threshold)

    def params(self):
        return {"tail_probability": self.tail_probability, "threshold": self.threshold}

    def record(self):
        record = super().record()
        record["body"] = self.body.record()
        record["tail"] = self.tail.record()
        return record

    def _tail_moment(self, r: int) -> float | None:
        if r == 1:
            return self.tail.mean
        if self.tail.variance is None:
            return None
        return self.tail.variance + self.tail.mean**2

    @property
    def mean(self):
        tail_mean = self._tail_moment(1)
        if tail_mean is None:
            return None
        below = self.body.partial_moment(1, self.threshold) / self._body_share
        return (1.0 - self.tail_probability) * below + self.tail_probability * tail_mean

    @property
    def variance(self):
        tail_second = self._tail_moment(2)
        if tail_second is None:
            return None
        below = self.body.partial_moment(2, self.threshold) / self._body_share
        second = (1.0 - self.tail_probability) * below + self.tail_probability * tail_second
        return max(second - self.mean**2, 0.0)

    def _draw(self, rng, n):
        # n uniforms choose body or tail; then the body's draws, by rejection of
        # the body above the threshold; then the tail's draws. All from rng.
        in_tail = rng.random(n) >= 1.0 - self.tail_probability
        drawn = np.empty(n, dtype=np.float64)
        drawn[~in_tail] = self._truncated_body(rng, int(n - np.count_nonzero(in_tail)))
        drawn[in_tail] = self.tail._draw(rng, int(np.count_nonzero(in_tail)))
        return drawn

    def _truncated_body(self, rng, needed: int) -> np.ndarray:
        kept = []
        share = self._body_share
        for _ in range(SPLICE_MAX_ROUNDS):
            if needed == 0:
                break
            batch = self.body._draw(rng, int(needed / share * 2.0) + 64)
            accepted = batch[batch <= self.threshold][:needed]
            kept.append(accepted)
            needed -= accepted.size
        if needed:
            raise DistributionRefused("out_of_range", "the truncated body did not fill its sample")
        return np.concatenate(kept) if kept else np.empty(0, dtype=np.float64)

    def _cdf(self, x):
        if x <= 0.0:
            return 0.0
        if x <= self.threshold:
            return (1.0 - self.tail_probability) * self.body.cdf(x) / self._body_share
        return (1.0 - self.tail_probability) + self.tail_probability * self.tail.cdf(x)

    def _ppf(self, p):
        body_weight = 1.0 - self.tail_probability
        if p <= body_weight:
            return min(self.body.ppf(p / body_weight * self._body_share), self.threshold)
        return self.tail.ppf((p - body_weight) / self.tail_probability)


# ----------------------------------------------------------------- expert


def _check_expert(instance) -> None:
    """An expert range is used only for an EXPERT_ESTIMATE parameter or data
    marked sparse (``expert_not_allowed``)."""
    try:
        source_type = SourceType(instance.source_type)
    except ValueError:
        raise DistributionRefused("source_type_unrecognised", repr(instance.source_type)) from None
    if not isinstance(instance.sparse, bool):
        raise DistributionRefused("sparse_malformed", f"sparse is a {type(instance.sparse).__name__}")
    if source_type is not SourceType.EXPERT_ESTIMATE and not instance.sparse:
        raise DistributionRefused(
            "expert_not_allowed", f"{type(instance).ID} for a {source_type.value} parameter whose data are not sparse"
        )
    _set(instance, "source_type", source_type)


def _check_bounds(instance) -> None:
    low = _number(instance.minimum, "minimum")
    mode = _number(instance.mode, "mode")
    high = _number(instance.maximum, "maximum")
    if low >= high:
        raise DistributionRefused("range_inverted", f"min {float_text(low)} is not below max {float_text(high)}")
    if not low <= mode <= high:
        raise DistributionRefused(
            "mode_out_of_range", f"mode {float_text(mode)} is outside [{float_text(low)}, {float_text(high)}]"
        )
    _set(instance, "minimum", low)
    _set(instance, "mode", mode)
    _set(instance, "maximum", high)


def _expert_record(instance, record: dict) -> dict:
    record["source_type"] = instance.source_type.value
    record["sparse"] = instance.sparse
    return record


@dataclass(frozen=True)
class Pert(Distribution):
    """An expert's (min, mode, max): a beta on [min, max] with
    ``alpha = 1 + w (mode - min) / (max - min)`` and
    ``beta = 1 + w (max - mode) / (max - min)``, ``w`` the weight on the mode
    (``shape``, 4 unless stated). Mean ``(min + w mode + max) / (w + 2)``.

    ``source_type`` is required: anything but ``EXPERT_ESTIMATE`` is refused
    unless ``sparse`` is True."""

    minimum: float
    mode: float
    maximum: float
    source_type: SourceType = field(kw_only=True)
    sparse: bool = field(default=False, kw_only=True)
    shape: float = field(default=PERT_WEIGHT, kw_only=True)

    ID: ClassVar[str] = "pert"
    KIND: ClassVar[str] = EXPERT
    EXPERT: ClassVar[bool] = True

    def __post_init__(self):
        _check_expert(self)
        _check_bounds(self)
        _set(self, "shape", _positive(self.shape, "shape", "shape_out_of_range"))
        self._check_form()

    @property
    def _alpha(self) -> float:
        return 1.0 + self.shape * (self.mode - self.minimum) / (self.maximum - self.minimum)

    @property
    def _beta(self) -> float:
        return 1.0 + self.shape * (self.maximum - self.mode) / (self.maximum - self.minimum)

    def params(self):
        return {"minimum": self.minimum, "mode": self.mode, "maximum": self.maximum, "shape": self.shape}

    def record(self):
        return _expert_record(self, super().record())

    @property
    def mean(self):
        return (self.minimum + self.shape * self.mode + self.maximum) / (self.shape + 2.0)

    @property
    def variance(self):
        a, b = self._alpha, self._beta
        width = self.maximum - self.minimum
        return width * width * a * b / ((a + b) ** 2 * (a + b + 1.0))

    def _draw(self, rng, n):
        return self.minimum + (self.maximum - self.minimum) * rng.beta(self._alpha, self._beta, n)

    def _cdf(self, x):
        if x <= self.minimum:
            return 0.0
        if x >= self.maximum:
            return 1.0
        return beta_inc(self._alpha, self._beta, (x - self.minimum) / (self.maximum - self.minimum))

    def _ppf(self, p):
        a, b = self._alpha, self._beta
        return self.minimum + (self.maximum - self.minimum) * _invert(lambda t: beta_inc(a, b, t), p, 0.0, 1.0)


@dataclass(frozen=True)
class Triangular(Distribution):
    """An expert's (min, mode, max) as a triangle. Sampled by inverting the CDF
    on a uniform. The same expert rule as :class:`Pert`."""

    minimum: float
    mode: float
    maximum: float
    source_type: SourceType = field(kw_only=True)
    sparse: bool = field(default=False, kw_only=True)

    ID: ClassVar[str] = "triangular"
    KIND: ClassVar[str] = EXPERT
    EXPERT: ClassVar[bool] = True

    def __post_init__(self):
        _check_expert(self)
        _check_bounds(self)
        self._check_form()

    def params(self):
        return {"minimum": self.minimum, "mode": self.mode, "maximum": self.maximum}

    def record(self):
        return _expert_record(self, super().record())

    @property
    def mean(self):
        return (self.minimum + self.mode + self.maximum) / 3.0

    @property
    def variance(self):
        a, c, b = self.minimum, self.mode, self.maximum
        return (a * a + b * b + c * c - a * b - a * c - b * c) / 18.0

    def _draw(self, rng, n):
        a, c, b = self.minimum, self.mode, self.maximum
        q = rng.random(n)
        left = a + np.sqrt(q * (b - a) * (c - a))
        right = b - np.sqrt((1.0 - q) * (b - a) * (b - c))
        return np.where(q < (c - a) / (b - a), left, right)

    def _cdf(self, x):
        a, c, b = self.minimum, self.mode, self.maximum
        if x <= a:
            return 0.0
        if x >= b:
            return 1.0
        if x <= c:
            return (x - a) ** 2 / ((b - a) * (c - a))
        return 1.0 - (b - x) ** 2 / ((b - a) * (b - c))

    def _ppf(self, p):
        a, c, b = self.minimum, self.mode, self.maximum
        if p < (c - a) / (b - a):
            return a + math.sqrt(p * (b - a) * (c - a))
        return b - math.sqrt((1.0 - p) * (b - a) * (b - c))


#: Every distribution, by its stable id.
CATALOGUE: Mapping[str, type[Distribution]] = MappingProxyType(
    {
        cls.ID: cls
        for cls in (
            Poisson,
            NegativeBinomial,
            ZeroInflatedPoisson,
            BetaBinomialRate,
            Lognormal,
            Gamma,
            GeneralizedPareto,
            Spliced,
            Pert,
            Triangular,
        )
    }
)
