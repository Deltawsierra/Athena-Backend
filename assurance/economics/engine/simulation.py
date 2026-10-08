"""The seeded Monte Carlo sampler (phase E2, MVP step 7a;
``docs/economics/spec-v1.md``, section 23).

Each draw samples every uncertain parameter and evaluates a caller-supplied pure
function of them (step 7b passes the scenario engine's formulas). With a
frequency, each draw is a simulated year: N events drawn from the frequency, each
event's parameters drawn afresh, and the year's loss the sum of its N event
losses (:func:`compound_annual`). The run summarises the outcome as P10, P50,
P90, the mean, the expected annual loss and a severe-but-plausible percentile,
each with its Monte Carlo uncertainty, and writes a reproducibility digest over
everything that decided it.

The rules:

- **One seed, named sub-streams.** A run is seeded by one 64-bit seed. Each
  parameter draws from its own ``Generator(PCG64)``, seeded by
  ``SeedSequence(seed, spawn_key=K(name))`` where ``K(name)`` is the SHA-256 of
  :data:`SUBSTREAM_DOMAIN`, a zero byte and the name's UTF-8, read as eight
  little-endian 32-bit words (:func:`substream`). A parameter's draws depend on
  the seed and its own name only: adding, removing or reordering another
  parameter never changes them. Nothing reads the global RNG, and nothing depends
  on Python's string hashing (``PYTHONHASHSEED``).
- **Bounded, in time and memory.** :data:`DEFAULT_DRAWS` (100,000) draws by
  default, between :data:`MIN_DRAWS` and :data:`MAX_DRAWS`; a compound run's
  events across all years at most :data:`MAX_EVENTS`; and at most
  :data:`MAX_VALUES` values held at once (:func:`values_held`). More is refused
  before it is sampled (a compound run's events, once the years' counts are
  drawn and before any event is).
- **Floats inside, Decimal outside.** Draws and arithmetic are binary64. The
  mean is ``math.fsum`` (a correctly rounded sum) divided by the count; the
  sample variance is ``fsum`` of the squared deviations over ``n - 1``. A
  quantile is Hyndman and Fan's type 7 (numpy's ``'linear'``) at the exact
  rational position ``(n - 1) p``. Each summary float becomes the ``Decimal`` of
  its ``repr`` (:func:`.distributions.float_decimal`): the shortest decimal that
  reads back as that float, with no rounding. It is rounded to the reporting
  currency's minor unit only to be shown (``Money.display``, ROUND_HALF_EVEN).
- **Losses only.** Every outcome is finite and at least zero (no benefit model is
  enabled): a negative or non-finite outcome is refused, never summarised.
- **Invariants, at run time.** p10 <= p50 <= p90 <= severe-but-plausible, every
  one at least zero, each inside its confidence band; and the run is reproducible:
  it is sampled twice from fresh sub-streams and the two outcome vectors must be
  identical, bit for bit. A broken invariant is :class:`InvariantBroken`, a
  defect, never the input's fault.
- **A mean that does not exist is not estimated.** When any input's mean is
  infinite (a generalized Pareto with shape >= 1), the mean, the expected annual
  loss and their standard error are ``None``, with the inputs named; the
  percentiles are still given. When any input's variance is infinite (shape >=
  1/2), the mean is given but its standard error and band are ``None``, with the
  inputs named: a band from the sample's standard error would not cover at its
  stated level.

Pure: no Django, no database, no I/O. Not wired to the formulas, the records or
any route yet (step 7b).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from types import MappingProxyType

import numpy as np

from .distributions import Distribution, float_decimal, normal_ppf
from .money import Money, check_reporting_currency, decimal_text

#: The record's schema.
SCHEMA = "mythos.economics.simulation/v1"
#: The version of the sampler itself: the sub-stream derivation, the order draws
#: are taken in, the compound sum, the summary's statistics. A change that alters
#: any draw or any summary figure for the same inputs is a new version.
SAMPLER_VERSION = 1
#: The bit generator every sub-stream uses.
BIT_GENERATOR = "PCG64"
#: Hashed before each parameter's name to give its sub-stream's spawn key.
SUBSTREAM_DOMAIN = "mythos.economics.substream/v1"
#: The frequency's sub-stream. "@" is never in a parameter name, so no parameter
#: can share it.
FREQUENCY_STREAM = "@frequency"

DEFAULT_DRAWS = 100_000
MIN_DRAWS = 1_000
MAX_DRAWS = 1_000_000
#: The most events a compound run may sample across all its years (80 MB a vector).
MAX_EVENTS = 10_000_000
MAX_SEED = 2**64 - 1
#: The most values a run may hold at once (240 MB as binary64), counted before
#: anything is sampled (in a compound run, once the years' event counts are
#: drawn and before any event is) by :func:`values_held`. More is refused
#: (``values_over_budget``), so memory is bounded by the limits, not by luck.
MAX_VALUES = 30_000_000
#: Vectors of the sampled length a run holds beside its parameters' at its peak:
#: the first sample's outcomes, kept while the run is sampled again; the
#: evaluated function's result; and one more, for the function's temporaries or a
#: splice's buffer.
RUN_VECTORS = 3
#: Vectors one per simulated year a compound run holds beside them: the event
#: counts and the annual losses of both samples, and the compound sum's indices.
YEAR_VECTORS = 8
#: Sums and squared deviations are taken this many values at a time.
_CHUNK = 16_384
#: A run's peak beyond 8 bytes for each value :func:`values_held` counts: the
#: block and chunk buffers of the portable exp, the triangular inversion and the
#: sums, about a megabyte whatever the run's size.
FIXED_BUFFER_BYTES = 1_000_000

#: The percentiles every result reports.
P10, P50, P90 = Decimal(10), Decimal(50), Decimal(90)
#: Severe-but-plausible is this percentile of the outcome unless a run states
#: another, from 90 (so it is never below P90) to below 100.
DEFAULT_SEVERE_PERCENTILE = Decimal(95)
#: The two-sided level of every confidence band.
CONFIDENCE_LEVEL = Decimal("0.95")
_Z = normal_ppf(float((1 + CONFIDENCE_LEVEL) / 2))

#: What a result says its percentiles and mean are of.
ANNUAL_LOSS = "annual_loss"
PER_DRAW = "per_draw"

QUANTILE_METHOD = (
    "Hyndman-Fan type 7 (numpy 'linear'): sort the n outcomes; h = (n - 1) p, exact; "
    "q = x[floor(h)] + (h - floor(h)) (x[floor(h) + 1] - x[floor(h)]), in binary64, clamped to that interval"
)
BAND_METHOD = (
    "a percentile's band is the pair of order statistics at ranks floor(n p - z s) and ceil(n p + z s), "
    "s = sqrt(n p (1 - p)), clamped to [1, n]; the mean's is mean -/+ z standard errors; z is the standard "
    "normal's (1 + level) / 2 quantile"
)
PRECISION = (
    "binary64 floats inside the run; mean = fsum / n; variance = fsum of squared deviations / (n - 1); each "
    "summary float is written as the Decimal of its repr, unrounded; rounded to the reporting currency's minor "
    "unit (ROUND_HALF_EVEN) only for display"
)
SUBSTREAM_METHOD = (
    "Generator(PCG64(SeedSequence(entropy=seed, spawn_key=K))), K = the SHA-256 of the domain, a zero byte "
    "and the parameter name's UTF-8, as eight little-endian uint32 words"
)

#: What each refusal code of the sampler means.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "seed_malformed": "a seed is a whole number from 0 to 2^64 - 1, never a bool or text",
        "draws_out_of_range": "a run takes from MIN_DRAWS to MAX_DRAWS draws, a whole number",
        "events_over_limit": "a compound run's events, across all its simulated years, are at most MAX_EVENTS",
        "parameter_name_malformed": (
            "a parameter name is 1 to 100 characters: lowercase ASCII letters, digits and '_', starting with a letter"
        ),
        "parameters_malformed": "a run's parameters are a non-empty mapping of names to distributions",
        "frequency_not_a_count": "a frequency is a count distribution (Poisson, negative binomial, zero-inflated Poisson)",
        "evaluate_missing": "a run of more than one parameter needs a function to evaluate them",
        "outcome_malformed": "the evaluated function returns one number per draw",
        "outcome_not_finite": "every outcome is a finite number: NaN and Infinity are never summarised",
        "outcome_negative": "every outcome is a loss, at least zero: no benefit model is enabled",
        "out_of_range": "an outcome, a year's loss or a summary statistic too large to hold as a binary64 float",
        "values_over_budget": (
            "a run holds at most MAX_VALUES values at once, counted as (parameters + RUN_VECTORS) times the "
            "sampled length, plus YEAR_VECTORS per simulated year in a compound run: refused before anything is "
            "sampled, and in a compound run before any event is"
        ),
        "percentile_out_of_range": "severe-but-plausible is an int or Decimal percentile from 90 to below 100",
        "model_version_blank": "a run names the model version it ran, as text that is not blank",
        "scenario_id_malformed": "a scenario id is text that is not blank, or none",
    }
)


class SimulationRefused(ValueError):
    """A run's inputs refused. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


class InvariantBroken(RuntimeError):
    """A runtime invariant failed: a defect in the engine or in the function it
    evaluated, never a fault of the inputs."""


_NAME = re.compile(r"[a-z][a-z0-9_]{0,99}")


def check_seed(seed) -> int:
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= MAX_SEED:
        raise SimulationRefused("seed_malformed", repr(seed))
    return seed


def check_name(name) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise SimulationRefused("parameter_name_malformed", repr(name))
    return name


def check_draws(draws) -> int:
    if isinstance(draws, bool) or not isinstance(draws, int) or not MIN_DRAWS <= draws <= MAX_DRAWS:
        raise SimulationRefused("draws_out_of_range", f"{draws!r}; from {MIN_DRAWS} to {MAX_DRAWS}")
    return draws


def check_severe_percentile(value) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise SimulationRefused("percentile_out_of_range", f"a {type(value).__name__}")
    percentile = Decimal(value)
    if not percentile.is_finite() or not Decimal(90) <= percentile < Decimal(100):
        raise SimulationRefused("percentile_out_of_range", str(value))
    return percentile


# ------------------------------------------------------------ randomness


def substream_key(name: str) -> tuple[int, ...]:
    """The spawn key of ``name``'s sub-stream: the SHA-256 of
    :data:`SUBSTREAM_DOMAIN`, a zero byte and the name's UTF-8, as eight
    little-endian 32-bit words."""
    digest = hashlib.sha256(SUBSTREAM_DOMAIN.encode("ascii") + b"\x00" + name.encode("utf-8")).digest()
    return tuple(int.from_bytes(digest[i : i + 4], "little") for i in range(0, 32, 4))


def substream(seed: int, name: str) -> np.random.Generator:
    """The generator ``name`` draws from in a run seeded by ``seed``."""
    sequence = np.random.SeedSequence(entropy=check_seed(seed), spawn_key=substream_key(name))
    return np.random.Generator(np.random.PCG64(sequence))


class RunRandom:
    """The one source of randomness of one run: its seed, and the sub-stream each
    name draws from. A name is issued once: two parameters on one stream would
    draw the same numbers, so a second request is a defect."""

    def __init__(self, seed: int):
        self.seed = check_seed(seed)
        self._issued: set[str] = set()

    def stream(self, name: str) -> np.random.Generator:
        if name in self._issued:
            raise InvariantBroken(f"the sub-stream {name!r} was issued twice in one run")
        self._issued.add(name)
        return substream(self.seed, name)


def _frozen(values: np.ndarray) -> np.ndarray:
    values.flags.writeable = False
    return values


def sample_parameters(parameters: Mapping[str, Distribution], random: RunRandom, n: int) -> dict[str, np.ndarray]:
    """``n`` draws of each parameter, each from its own sub-stream, read-only."""
    return {name: _frozen(parameters[name].sample(random.stream(name), n)) for name in sorted(parameters)}


def compound_annual(counts: np.ndarray, event_losses: np.ndarray) -> np.ndarray:
    """Each simulated year's loss: year i holds ``counts[i]`` events, taken in order
    from ``event_losses``, and its loss is their sum (zero for a year with none).
    Each year's events are one contiguous run, summed by ``np.add.reduceat`` (the
    same operations every time, on every CPU), with indices one per year, never one
    per event. A sum too large for a float is Infinity here, refused by the
    summary."""
    counts = np.asarray(counts)
    event_losses = np.asarray(event_losses, dtype=np.float64)
    if counts.ndim != 1 or counts.dtype.kind not in "iu" or (counts < 0).any():
        raise InvariantBroken("event counts are a vector of whole numbers at least zero")
    if event_losses.shape != (int(counts.sum()),):
        raise InvariantBroken("one event loss per event")
    annual = np.zeros(counts.size, dtype=np.float64)
    if event_losses.size:
        occupied = counts > 0
        starts = np.cumsum(counts) - counts
        with np.errstate(over="ignore"):
            annual[occupied] = np.add.reduceat(event_losses, starts[occupied])
    return annual


def values_held(parameter_count: int, length: int, years: int | None = None) -> int:
    """The values a run holds at its peak, by its own count: (parameters +
    :data:`RUN_VECTORS`) vectors of the sampled length (the draws, or the events
    of a compound run), and :data:`YEAR_VECTORS` per simulated year in a compound
    run. The evaluated function's own temporaries beyond one vector are its own."""
    return (parameter_count + RUN_VECTORS) * length + (0 if years is None else YEAR_VECTORS * years)


def _check_budget(parameter_count: int, length: int, years: int | None = None) -> None:
    held = values_held(parameter_count, length, years)
    if held > MAX_VALUES:
        what = f"{length} draws" if years is None else f"{length} events in {years} years"
        raise SimulationRefused(
            "values_over_budget", f"{parameter_count} parameters and {what} hold {held} values; at most {MAX_VALUES}"
        )


def _evaluated(evaluate, samples: Mapping[str, np.ndarray], n: int) -> np.ndarray:
    result = np.asarray(evaluate(samples))
    if result.shape != (n,) or result.dtype.kind not in "iuf":
        raise SimulationRefused("outcome_malformed", f"shape {result.shape}, dtype {result.dtype}; {n} numbers wanted")
    if result.dtype == np.float64 and result.flags.owndata and result.flags.writeable:
        outcome = result  # the function's own new vector: no second copy
    else:
        outcome = result.astype(np.float64)  # a draw vector (read-only), a view, or not float64
    del result
    if not np.isfinite(outcome).all():
        raise SimulationRefused("outcome_not_finite", f"{int(np.count_nonzero(~np.isfinite(outcome)))} of {n}")
    if (outcome < 0.0).any():
        raise SimulationRefused("outcome_negative", f"{int(np.count_nonzero(outcome < 0.0))} of {n}")
    outcome += 0.0  # no negative zero
    return outcome


@dataclass(frozen=True)
class _Sampled:
    outcomes: np.ndarray
    counts: np.ndarray | None
    event_losses: np.ndarray | None


def _sample(parameters, evaluate, frequency, seed: int, draws: int) -> _Sampled:
    random = RunRandom(seed)
    if frequency is None:
        return _Sampled(_evaluated(evaluate, sample_parameters(parameters, random, draws), draws), None, None)
    counts = frequency.sample(random.stream(FREQUENCY_STREAM), draws)
    events = int(counts.sum())
    if events > MAX_EVENTS:
        raise SimulationRefused("events_over_limit", f"{events} events in {draws} years; at most {MAX_EVENTS}")
    _check_budget(len(parameters), events, draws)
    if events:
        event_losses = _evaluated(evaluate, sample_parameters(parameters, random, events), events)
    else:
        event_losses = np.empty(0, dtype=np.float64)
    return _Sampled(compound_annual(counts, event_losses), counts, event_losses)


# --------------------------------------------------------------- summary


def quantile(ordered: np.ndarray, p: Fraction) -> float:
    """Hyndman and Fan's type 7 quantile of sorted values at ``p`` (exact)."""
    n = ordered.size
    h = (n - 1) * p
    low = math.floor(h)
    lower = float(ordered[low])
    if low + 1 >= n or h == low:
        return lower
    upper = float(ordered[low + 1])
    return min(max(lower + float(h - low) * (upper - lower), lower), upper)


def quantile_band(ordered: np.ndarray, p: Fraction) -> tuple[float, float]:
    """The distribution-free confidence band of the ``p`` quantile: two order
    statistics either side of it (:data:`BAND_METHOD`)."""
    n = ordered.size
    centre = float(n * p)
    spread = _Z * math.sqrt(centre * float(1 - p))
    low_rank = max(1, math.floor(centre - spread))
    high_rank = min(n, math.ceil(centre + spread))
    return float(ordered[low_rank - 1]), float(ordered[high_rank - 1])


@dataclass(frozen=True)
class Summary:
    """The statistics of one vector of outcomes, as floats."""

    count: int
    p10: float
    p50: float
    p90: float
    severe: float
    severe_percentile: Decimal
    mean: float | None
    standard_error: float | None
    bands: Mapping[str, tuple[float, float] | None]


def _fsum(values: np.ndarray, square_about: float | None = None) -> float:
    """``math.fsum`` of ``values`` (or of their squared deviations from
    ``square_about``), a chunk at a time: correctly rounded, and never a list of
    every value."""

    def chunks():
        for start in range(0, values.size, _CHUNK):
            part = values[start : start + _CHUNK]
            if square_about is not None:
                part = part - square_about
                with np.errstate(over="ignore"):  # an overflow is refused by the caller
                    part = part * part
            yield from part.tolist()

    return math.fsum(chunks())


def summarize(
    values: np.ndarray, *, severe_percentile: Decimal, mean_defined: bool = True, error_defined: bool = True
) -> Summary:
    """The percentiles, mean, standard error and bands of ``values``, with the
    invariants checked. Without ``mean_defined`` there is no mean; without
    ``error_defined`` (an input's variance is infinite) there is no standard error
    and no band for the mean: the sample's would understate the uncertainty."""
    if not np.isfinite(values).all():
        raise SimulationRefused("out_of_range", "a year's loss is too large to hold as a float")
    ordered = np.sort(values, kind="stable")
    n = ordered.size
    points = {"p10": P10, "p50": P50, "p90": P90, "severe_plausible": severe_percentile}
    figures = {key: quantile(ordered, Fraction(point) / 100) for key, point in points.items()}
    bands: dict[str, tuple[float, float] | None] = {
        key: quantile_band(ordered, Fraction(point) / 100) for key, point in points.items()
    }
    mean = standard_error = None
    bands["mean"] = None
    if mean_defined:
        try:
            mean = _fsum(values) / n
        except OverflowError:
            raise SimulationRefused("out_of_range", "the outcomes' sum overflows a float") from None
        if not math.isfinite(mean):
            raise SimulationRefused("out_of_range", "the outcomes' mean overflows a float")
    if mean is not None and error_defined:
        try:
            variance = _fsum(values, square_about=mean) / (n - 1)
        except OverflowError:
            raise SimulationRefused("out_of_range", "the outcomes' variance overflows a float") from None
        if not math.isfinite(variance):
            raise SimulationRefused("out_of_range", "the outcomes' variance overflows a float")
        standard_error = math.sqrt(variance / n)
        bands["mean"] = (mean - _Z * standard_error, mean + _Z * standard_error)
    summary = Summary(
        count=n,
        p10=figures["p10"],
        p50=figures["p50"],
        p90=figures["p90"],
        severe=figures["severe_plausible"],
        severe_percentile=severe_percentile,
        mean=mean,
        standard_error=standard_error,
        bands=MappingProxyType(bands),
    )
    check_invariants(summary)
    return summary


def check_invariants(summary: Summary) -> None:
    """p10 <= p50 <= p90 <= severe, all at least zero, a mean at least zero, and
    each figure inside its band. Raises :class:`InvariantBroken`."""
    order = (summary.p10, summary.p50, summary.p90, summary.severe)
    if not all(math.isfinite(x) for x in order):
        raise InvariantBroken(f"a percentile is not finite: {order}")
    if not summary.p10 <= summary.p50 <= summary.p90 <= summary.severe:
        raise InvariantBroken(f"percentiles out of order: p10, p50, p90, severe = {order}")
    if summary.p10 < 0.0:
        raise InvariantBroken(f"a loss percentile is negative: p10 = {summary.p10}")
    if summary.mean is not None and summary.mean < 0.0:
        raise InvariantBroken(f"a loss mean is negative: {summary.mean}")
    figures = {"p10": summary.p10, "p50": summary.p50, "p90": summary.p90, "severe_plausible": summary.severe}
    if summary.mean is not None and summary.bands["mean"] is not None:
        figures["mean"] = summary.mean
    for key, figure in figures.items():
        low, high = summary.bands[key]
        if not low <= figure <= high:
            raise InvariantBroken(f"{key} {figure} is outside its band [{low}, {high}]")


# ----------------------------------------------------------------- result


def _amount(value: float | None, currency: str) -> Money | None:
    return None if value is None else Money(float_decimal(value), currency)


def _text(amount: Money | None) -> str | None:
    return None if amount is None else decimal_text(amount.amount)


def _summary_block(summary: Summary, currency: str) -> dict:
    return {
        "p10": _text(_amount(summary.p10, currency)),
        "p50": _text(_amount(summary.p50, currency)),
        "p90": _text(_amount(summary.p90, currency)),
        "severe_plausible": _text(_amount(summary.severe, currency)),
        "mean": _text(_amount(summary.mean, currency)),
        "standard_error_of_mean": _text(_amount(summary.standard_error, currency)),
        "bands": {
            key: None if band is None else [_text(_amount(band[0], currency)), _text(_amount(band[1], currency))]
            for key, band in summary.bands.items()
        },
    }


def canonical_json(record: Mapping) -> bytes:
    """The bytes a digest is taken over: sorted keys, no whitespace, ASCII, and no
    float anywhere (every number in a record is text or an int)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )


def outcomes_digest(outcomes: np.ndarray) -> str:
    """``sha256:`` and the SHA-256 of the outcomes as little-endian binary64 (read
    in place, not copied)."""
    return "sha256:" + hashlib.sha256(np.ascontiguousarray(outcomes, dtype="<f8").data).hexdigest()


@dataclass(frozen=True)
class SimulationResult:
    """One run's result. :attr:`record` is everything the digest covers;
    :attr:`digest` is ``sha256:`` and the SHA-256 of its canonical JSON. The
    outcome vector (annual losses, or per-draw outcomes) is kept, read-only, for
    the caller; it is not in the record, its digest is."""

    record: Mapping
    digest: str
    reporting_currency: str
    summary: Summary
    event_summary: Summary | None
    outcomes: np.ndarray
    counts: np.ndarray | None
    event_losses: np.ndarray | None

    def _money(self, value: float | None) -> Money | None:
        return _amount(value, self.reporting_currency)

    @property
    def p10(self) -> Money:
        return self._money(self.summary.p10)

    @property
    def p50(self) -> Money:
        return self._money(self.summary.p50)

    @property
    def p90(self) -> Money:
        return self._money(self.summary.p90)

    @property
    def severe_plausible(self) -> Money:
        return self._money(self.summary.severe)

    @property
    def mean(self) -> Money | None:
        return self._money(self.summary.mean)

    @property
    def expected_annual_loss(self) -> Money | None:
        if self.record["basis"] != ANNUAL_LOSS:
            return None
        return self._money(self.summary.mean)

    def display(self) -> dict[str, str | None]:
        """The figures to show, each rounded to the reporting currency's minor unit
        (``Money.display``): for presentation only, never computed with again."""
        figures = {
            "p10": self.p10,
            "p50": self.p50,
            "p90": self.p90,
            "mean": self.mean,
            "expected_annual_loss": self.expected_annual_loss,
            "severe_plausible": self.severe_plausible,
        }
        return {key: None if amount is None else amount.display() for key, amount in figures.items()}

    def as_dict(self) -> dict:
        """The record, its digest, the display figures, and the library versions
        it ran on (provenance, outside the digest: the digest already covers every
        draw through the outcomes' hash, so a library change that alters a draw
        changes it)."""
        return {
            **self.record,
            "digest": self.digest,
            "display": self.display(),
            "provenance": {"numpy": np.__version__},
        }


def run(
    parameters: Mapping[str, Distribution],
    evaluate: Callable[[Mapping[str, np.ndarray]], object] | None = None,
    *,
    seed: int,
    model_version: str,
    reporting_currency: str,
    frequency: Distribution | None = None,
    draws: int = DEFAULT_DRAWS,
    severe_percentile: int | Decimal = DEFAULT_SEVERE_PERCENTILE,
    scenario_id: str | None = None,
) -> SimulationResult:
    """One seeded Monte Carlo run.

    ``parameters`` maps names to distributions; ``evaluate`` maps a dict of draw
    vectors (read-only, one per name) to one outcome per draw, vectorised and
    pure (it may be omitted for a single parameter: the outcome is its draws).
    Without ``frequency``, a draw is one evaluation, and the result's basis is
    ``per_draw``: there is no expected annual loss. With it, a draw is a
    simulated year of N ~ frequency events, each evaluated on fresh draws of the
    parameters, and the year's loss is their sum (basis ``annual_loss``): the
    percentiles, mean and severe-but-plausible are of the annual loss, the
    expected annual loss is its mean, and the event-loss distribution is given
    beside it."""
    if not isinstance(parameters, Mapping) or not parameters:
        raise SimulationRefused("parameters_malformed", "no parameters")
    for name, distribution in parameters.items():
        check_name(name)
        if not isinstance(distribution, Distribution):
            raise SimulationRefused("parameters_malformed", f"{name} is a {type(distribution).__name__}")
    if frequency is not None and not (isinstance(frequency, Distribution) and type(frequency).DISCRETE):
        raise SimulationRefused("frequency_not_a_count", type(frequency).__name__)
    if evaluate is None:
        if len(parameters) != 1:
            raise SimulationRefused("evaluate_missing", f"{len(parameters)} parameters")
        (only,) = parameters

        def evaluate(samples):
            return samples[only]

    elif not callable(evaluate):
        raise SimulationRefused("evaluate_missing", f"evaluate is a {type(evaluate).__name__}")
    check_seed(seed)
    check_draws(draws)
    if not isinstance(model_version, str) or not model_version.strip():
        raise SimulationRefused("model_version_blank", repr(model_version))
    if scenario_id is not None and (not isinstance(scenario_id, str) or not scenario_id.strip()):
        raise SimulationRefused("scenario_id_malformed", repr(scenario_id))
    check_reporting_currency(reporting_currency)
    severe = check_severe_percentile(severe_percentile)
    if frequency is None:
        _check_budget(len(parameters), draws)  # a compound run checks once its events are counted

    sampled = _sample(parameters, evaluate, frequency, seed, draws)
    # Reproducibility, enforced: the same seed and inputs, sampled again from
    # fresh sub-streams, give the same outcomes, bit for bit.
    replayed = _sample(parameters, evaluate, frequency, seed, draws)
    reproduced = outcomes_digest(sampled.outcomes) == outcomes_digest(replayed.outcomes)
    del replayed
    if not reproduced:
        raise InvariantBroken("the same seed and inputs gave different outcomes: the run is not reproducible")

    infinite_mean = sorted(name for name, d in parameters.items() if d.mean is None)
    infinite_variance = sorted(name for name, d in parameters.items() if d.variance is None)
    mean_defined, error_defined = not infinite_mean, not infinite_variance
    defined = {"mean_defined": mean_defined, "error_defined": error_defined}
    summary = summarize(sampled.outcomes, severe_percentile=severe, **defined)
    event_summary = None
    if frequency is not None and sampled.event_losses.size >= MIN_DRAWS:
        event_summary = summarize(sampled.event_losses, severe_percentile=severe, **defined)

    basis = PER_DRAW if frequency is None else ANNUAL_LOSS
    block = _summary_block(summary, reporting_currency)
    record = {
        "schema": SCHEMA,
        "scenario_id": scenario_id,
        "model_version": model_version,
        "seed": str(seed),
        "simulations": draws,
        "reporting_currency": reporting_currency,
        "basis": basis,
        "p10": block["p10"],
        "p50": block["p50"],
        "p90": block["p90"],
        "mean": block["mean"],
        "expected_annual_loss": block["mean"] if basis == ANNUAL_LOSS else None,
        "severe_plausible": block["severe_plausible"],
        "severe_percentile": decimal_text(severe),
        "standard_error_of_mean": block["standard_error_of_mean"],
        "confidence_level": decimal_text(CONFIDENCE_LEVEL),
        "bands": block["bands"],
        "mean_undefined": (
            None
            if mean_defined
            else {"reason": "an input's mean is infinite: the sample mean estimates nothing", "parameters": infinite_mean}
        ),
        "standard_error_undefined": (
            None
            if error_defined
            else {
                "reason": (
                    "an input's variance is infinite: the sample's standard error understates the mean's "
                    "uncertainty, and a band from it would not cover at its stated level"
                ),
                "parameters": infinite_variance,
            }
        ),
        "events": None
        if frequency is None
        else {
            "total": int(sampled.event_losses.size),
            "summary": None if event_summary is None else _summary_block(event_summary, reporting_currency),
        },
        "parameters": {name: parameters[name].record() for name in sorted(parameters)},
        "frequency": None if frequency is None else frequency.record(),
        "expert_parameters": sorted(name for name, d in parameters.items() if type(d).EXPERT),
        "sampler": {
            "version": SAMPLER_VERSION,
            "bit_generator": BIT_GENERATOR,
            "substreams": SUBSTREAM_METHOD,
            "substream_domain": SUBSTREAM_DOMAIN,
            "frequency_stream": FREQUENCY_STREAM,
            "quantile_method": QUANTILE_METHOD,
            "band_method": BAND_METHOD,
            "precision": PRECISION,
        },
        "outcomes_sha256": outcomes_digest(sampled.outcomes),
    }
    digest = "sha256:" + hashlib.sha256(canonical_json(record)).hexdigest()
    return SimulationResult(
        record=MappingProxyType(record),
        digest=digest,
        reporting_currency=reporting_currency,
        summary=summary,
        event_summary=event_summary,
        outcomes=_frozen(sampled.outcomes),
        counts=None if sampled.counts is None else _frozen(sampled.counts),
        event_losses=None if sampled.event_losses is None else _frozen(sampled.event_losses),
    )
