"""A portfolio of scenarios aggregated from their draws (Economic Exposure E5;
``docs/economics/spec-v1.md``, section 28; the owner's specification, section 24).

Customer-level exposure is never the sum of every scenario's P90: shared causes and
shared consequences make scenarios move together, and the same loss can be counted
in two of them. So a portfolio is aggregated from DRAWS, year by year:

- **One seed, a sub-stream per scenario, aligned years.** Every included scenario is
  drawn again for the portfolio's own seed and draws: each from sub-streams of that
  one seed keyed by the scenario and the stream (:func:`substream_key`,
  :data:`STREAM_DOMAIN`), so draw ``y`` is the same simulated year ``y`` in every
  scenario, and adding or removing a scenario changes no other scenario's draws.
  Within a scenario, a year is step 7b's: the same plan, parameters, twins and
  insurance (``scenario_simulation._sample``), with the year's count handed in.
- **Correlation groups** (:data:`DRIVER`). Scenarios in one group share ONE common
  driver per simulated year, a Gamma of mean 1 whose variance is the group's
  recorded strength; each member's annual rate (the rate its frequency implies) is
  multiplied by it, and the year's count is a Poisson of that product: a
  Gamma-mixed rate. Scenarios in different groups, or in none, are independent. No
  copula.
- **A shared event is counted once.** Which events of two scenarios are one loss
  event is decided before the draws (:func:`shared_events`), and only the event
  that is counted is drawn; the others are left out of their scenarios' draws.
- **Normalised before it is summed.** Each scenario's annual losses are multiplied,
  draw by draw, by the factor that normalises one unit of its currency at its as-of
  date into the reporting currency at the valuation date (step 3's order, section
  12.4: every step is a multiplication), and only then summed.
- **Summed per year, never by percentile.** The portfolio's annual loss in year
  ``y`` is the sum of its scenarios' normalised annual losses in year ``y``;
  its P10, P50, P90, mean, expected annual loss and severe-but-plausible are step
  7a's summary of that vector.
- **Each scenario's contribution to the mean AND to the tail.** To the mean: its
  own mean over the same years, and the portfolio's mean IS their sum (the mean of a
  sum is the sum of the means), each the correctly rounded binary64 mean written
  as its shortest decimal, summed exactly. To the tail: its mean over the years in
  the tail -- the ``ceil(n (1 - p))`` years of largest total, p the severe
  percentile -- whose sum is the portfolio's expected shortfall there. The largest
  mean contributor may differ from the largest tail contributor (specification,
  section 24).

Pure: no Django, no database, no clock. Floats inside, decimal strings outside, as
step 7a's record: no float in the record.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Context, Decimal, Inexact, localcontext
from fractions import Fraction
from types import MappingProxyType

import numpy as np

from . import distributions as dist
from . import scenario_simulation as ss
from . import simulation as sim
from .money import check_reporting_currency, decimal_text
from .provenance import SourceType

#: The record's schema.
SCHEMA = "mythos.economics.portfolio/v1"
#: The version of this aggregation: the streams, the driver, the sums, the record.
ENGINE_VERSION = 1
#: Hashed with a scenario (or a group) and a stream's name to key its sub-stream.
STREAM_DOMAIN = "mythos.economics.portfolio-stream/v1"
#: The stream of a scenario's annual rate, and of a group's driver.
RATE_STREAM = "@rate"
DRIVER_STREAM = "@driver"

#: The correlation groups' common driver (the decided MVP; copulas are not modelled).
DRIVER_VERSION = "mythos.economics.group-driver/v1"
DRIVER = (
    "each correlation group has ONE common driver per simulated year, M ~ Gamma(shape 1/v, scale v): mean 1 and "
    "variance v, the group's recorded strength. Every member's annual rate -- the rate its frequency implies: a "
    "Poisson's lambda; a negative binomial's Gamma(size, (1 - p) / p); a zero-inflated Poisson's 0 with probability "
    "pi, else lambda -- is multiplied by M, and the year's count is a Poisson of that product (a Gamma-mixed rate). "
    "A scenario in no group has M = 1, so its count is distributed as its frequency states. Scenarios in different "
    "groups, or in none, are independent"
)

#: Which events of two scenarios are one loss event (step 5's rule, section 24.5).
SHARED_EVENTS_VERSION = "mythos.economics.portfolio-shared-events/v1"
SHARED_EVENTS_RULE = (
    "two events of different scenarios are ONE loss event, counted once, when an effect of each is the same SPINE "
    "effect; when they have the same grouping key (template and version, asset and business process) and an "
    "observation of one is within 24 hours, inclusive, of an observation of the other; or when both are of "
    "hypothetical effects alone with the same key. A key's events of hypothetical effects alone join the one event "
    "of their key, among the other scenarios' observed events, where they add the most gross cash at base (ties: "
    "at high, then low, then the first by scenario and event key), never every one. Joining is transitive. Of the "
    "events that are one, the one of the largest gross cash at base, normalised, is counted (ties: high, then low, "
    "then the first by scenario and event key), and every other is left out of its scenario's draws"
)
#: Step 5's grouping window (``builder.GROUPING_WINDOW``; a test holds them equal).
WINDOW = timedelta(hours=24)

#: The most scenarios a portfolio totals, and the most groups it declares.
MAX_SCENARIOS = 50
MAX_GROUPS = 20
#: A group's strength (the driver's variance) is above zero and at most this.
STRENGTH_MAX = Decimal(10)
#: The lines a portfolio sums: the gross cash, and the retained cash (a scenario
#: with no insurance policy retains its gross). Market value is never added to cash.
LINES = (ss.GROSS_CASH, ss.RETAINED_CASH)
#: Values the portfolio holds per scenario (its two annual lines) and beside them
#: (the two totals, a sorted copy, and the tail's indices), each of the draws.
LINES_PER_MEMBER = 2
PORTFOLIO_TEMPORARIES = 4
#: How far the sum of the scenarios' means may be from the mean of the per-draw
#: totals (relative, and at least one unit absolute): the two differ by rounding.
AGREEMENT = 1e-12

REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "nothing_to_total": "a portfolio totals at least one scenario whose result may be totalled",
        "no_annual_loss": "a scenario a portfolio sums states a frequency: a draw is a simulated year",
        "member_malformed": "each scenario is in a portfolio once, in order, with a positive normalisation factor",
        "group_malformed": (
            "a correlation group has a key of 1 to 60 lowercase letters, digits, '-' and '_', a strength above 0 and "
            f"at most {STRENGTH_MAX} (the variance of its common driver), a source type and its evidence, and "
            "names each of its scenarios once; a scenario is in one group at most"
        ),
        "scenarios_over_limit": f"a portfolio totals at most {MAX_SCENARIOS} scenarios and declares at most "
        f"{MAX_GROUPS} groups",
        "rate_out_of_range": "a scenario's annual rate, times its group's driver, is above the largest count mean a "
        "draw holds",
    }
)


class PortfolioRefused(ValueError):
    """A portfolio refused. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


# ------------------------------------------------------------------ versions


def limits() -> dict:
    """Every limit that decides what a portfolio records: part of its inputs."""
    return {
        "max_scenarios": MAX_SCENARIOS,
        "max_groups": MAX_GROUPS,
        "strength_max": decimal_text(STRENGTH_MAX),
        "max_values": sim.MAX_VALUES,
        "max_events": sim.MAX_EVENTS,
        "max_count_mean": dist.float_text(dist.MAX_COUNT_MEAN),
        "lines_per_member": LINES_PER_MEMBER,
        "portfolio_temporaries": PORTFOLIO_TEMPORARIES,
        "grouping_window_hours": int(WINDOW.total_seconds() // 3600),
        "agreement": dist.float_text(AGREEMENT),
    }


def versions() -> dict:
    """Every version a portfolio's figures rest on, with its limits: part of its
    inputs, so a change to any is a new stored result, never an old one returned."""
    return {
        "portfolio": ENGINE_VERSION,
        "schema": SCHEMA,
        "group_driver": DRIVER_VERSION,
        "shared_events": SHARED_EVENTS_VERSION,
        "stream_domain": STREAM_DOMAIN,
        "scenario_simulation": ss.ENGINE_VERSION,
        "sampler": sim.SAMPLER_VERSION,
        "bit_generator": sim.BIT_GENERATOR,
        "numpy": np.__version__,
        "limits": limits(),
    }


# ------------------------------------------------------------- shared events


@dataclass(frozen=True)
class EventRef:
    """One loss event of one scenario, as the shared-event rule reads it: its
    grouping key (template id and version, asset, business process; ``None`` for an
    event no built effect is in), the SPINE effects and observation times of its
    effects, whether it is of hypothetical effects alone, and its gross cash at low,
    base and high (step 4's, normalised into the reporting currency)."""

    scenario: str
    event_key: str
    key: tuple | None
    spine_effects: frozenset[str]
    observed_at: tuple[datetime, ...]
    hypothetical: bool
    gross: tuple[Decimal, Decimal, Decimal]

    @property
    def order(self) -> tuple[str, str]:
        return (self.scenario, self.event_key)

    @property
    def rank(self) -> tuple:
        """Sorts the event to count first: the largest at base, then high, then
        low, then the first by scenario and event key."""
        low, base, high = self.gross
        return (-base, -high, -low, self.scenario, self.event_key)


@dataclass(frozen=True)
class Joined:
    """Events of several scenarios that are one loss event: ``kept`` is counted,
    ``joined`` are not, and ``by`` names the links that made them one."""

    kept: EventRef
    joined: tuple[EventRef, ...]
    by: tuple[str, ...]


def _within(first: Sequence[datetime], second: Sequence[datetime]) -> bool:
    """Whether an observation of ``first`` is within :data:`WINDOW` (inclusive) of
    one of ``second``: both sorted, merged once."""
    i = j = 0
    while i < len(first) and j < len(second):
        if abs(first[i] - second[j]) <= WINDOW:
            return True
        if first[i] < second[j]:
            i += 1
        else:
            j += 1
    return False


def shared_events(events: Iterable[EventRef]) -> tuple[Joined, ...]:
    """The loss events :data:`SHARED_EVENTS_RULE` makes one, each with the event
    counted. Events no other joins are not listed. Deterministic: the input's order
    never changes the answer."""
    events = sorted(events, key=lambda e: e.order)
    parent = list(range(len(events)))
    kinds: dict[int, set[str]] = defaultdict(set)

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int, kind: str) -> None:
        a, b = find(i), find(j)
        root = min(a, b)
        if a != b:
            parent[max(a, b)] = root
            kinds[root] |= kinds.pop(max(a, b), set())
        kinds[root].add(kind)

    by_spine: dict[str, list[int]] = defaultdict(list)
    by_key: dict[tuple, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        for spine in sorted(event.spine_effects):
            by_spine[spine].append(index)
        if event.key is not None:
            by_key[event.key].append(index)
    for spine in sorted(by_spine):
        first, *rest = by_spine[spine]
        for other in rest:
            union(first, other, "spine_effect")
    for key in sorted(by_key, key=repr):
        members = by_key[key]
        observed = [i for i in members if events[i].observed_at]
        for a_at, a in enumerate(observed):
            for b in observed[a_at + 1:]:
                if events[a].scenario != events[b].scenario and _within(
                    sorted(events[a].observed_at), sorted(events[b].observed_at)
                ):
                    union(a, b, "window")
        hypothetical = [i for i in members if events[i].hypothetical and not events[i].observed_at]
        for other in hypothetical[1:]:
            union(hypothetical[0], other, "hypothetical")

    def components() -> dict[int, list[int]]:
        found: dict[int, list[int]] = defaultdict(list)
        for index in range(len(events)):
            found[find(index)].append(index)
        return found

    def top(indices: list[int]) -> EventRef:
        return min((events[i] for i in indices), key=lambda e: e.rank)

    # A key's events of hypothetical effects alone take part in the one event of
    # their key, among the observed ones, where they add the most at base (step 5's
    # pricing, section 24.5): never in every one, so they bridge nothing.
    for root, indices in sorted(components().items()):
        if not all(events[i].hypothetical and not events[i].observed_at for i in indices):
            continue
        key = events[indices[0]].key
        if key is None:
            continue
        found = components()
        candidates = [
            (other, members) for other, members in sorted(found.items())
            if other != find(root) and any(events[i].key == key and events[i].observed_at for i in members)
        ]
        if not candidates:
            continue
        mine = top(indices)

        def gain(members: list[int], mine: EventRef = mine) -> tuple:
            theirs = top(members)
            low, base, high = (max(Decimal(0), m - t) for m, t in zip(mine.gross, theirs.gross, strict=True))
            return (-base, -high, -low, theirs.order)

        chosen, _ = min(candidates, key=lambda item: gain(item[1]))
        union(chosen, indices[0], "hypothetical")

    joined = []
    for root, indices in components().items():
        if len(indices) < 2:
            continue
        kept = top(indices)
        others = tuple(sorted((events[i] for i in indices if events[i] is not kept), key=lambda e: e.order))
        joined.append(Joined(kept, others, tuple(sorted(kinds.get(root, set())))))
    return tuple(sorted(joined, key=lambda j: j.kept.order))


# ------------------------------------------------------------------- members


@dataclass(frozen=True)
class Member:
    """One scenario of the portfolio: its id (the scenario version's uuid), the
    step-7b input of the events it is drawn with (``None`` where every event it has
    is counted in another scenario: it adds nothing), the factor that normalises
    its currency into the reporting currency, and its group."""

    scenario_id: str
    si: ss.ScenarioInput | None
    factor: Decimal
    group: str | None = None


@dataclass(frozen=True)
class Group:
    """A correlation group: its key, its strength (the variance of its common
    driver) and the source that strength rests on."""

    key: str
    strength: Decimal
    source_type: SourceType


def without_events(si: ss.ScenarioInput, dropped: Iterable[str]) -> ss.ScenarioInput | None:
    """``si`` with the events ``dropped`` left out (each counted in another
    scenario), and the derived parameters only they read; ``None`` where none is
    left."""
    dropped = set(dropped)
    if not dropped:
        return si
    events = tuple(event for event in si.events if event.loss_event_id not in dropped)
    if not events:
        return None
    read = {cited.parameter.name for event in events for c in event.components for cited in c.inputs}
    derived = {name: contributors for name, contributors in dict(si.derived).items() if name in read}
    return replace(si, events=events, derived=MappingProxyType(derived))


def substream_key(owner: str, name: str) -> tuple[int, ...]:
    """The spawn key of ``owner``'s (``scenario:<uuid>`` or ``group:<key>``) stream
    ``name``: the SHA-256 of :data:`STREAM_DOMAIN`, a zero byte, the owner, a zero
    byte and the name, as eight little-endian 32-bit words."""
    digest = hashlib.sha256(
        STREAM_DOMAIN.encode("ascii") + b"\x00" + owner.encode("utf-8") + b"\x00" + name.encode("utf-8")
    ).digest()
    return tuple(int.from_bytes(digest[i : i + 4], "little") for i in range(0, 32, 4))


class OwnedRandom(sim.RunRandom):
    """The portfolio's one seed, as one scenario's (or group's) randomness: each
    stream a sub-stream of the seed keyed by its owner and name, issued once."""

    def __init__(self, seed: int, owner: str):
        super().__init__(seed)
        self.owner = owner

    def stream(self, name: str) -> np.random.Generator:
        if name in self._issued:
            raise sim.InvariantBroken(f"the sub-stream {name!r} of {self.owner} was issued twice")
        self._issued.add(name)
        sequence = np.random.SeedSequence(entropy=self.seed, spawn_key=substream_key(self.owner, name))
        return np.random.Generator(np.random.PCG64(sequence))


def _rates(distribution: dist.Distribution, rng: np.random.Generator, n: int) -> np.ndarray:
    """``n`` years' annual rates of a count of the catalogue: the rate it implies
    (``scenario_simulation.ImpliedRate``)."""
    kind = type(distribution)
    if kind is dist.Poisson:
        return np.full(n, distribution.rate, dtype=np.float64)
    if kind is dist.NegativeBinomial:
        p = distribution.probability
        return rng.gamma(distribution.size, (1.0 - p) / p, n)
    if kind is dist.ZeroInflatedPoisson:
        return np.where(rng.random(n) < distribution.zero_inflation, 0.0, distribution.rate)
    raise ss.ScenarioSimulationRefused("frequency_not_a_count", kind.ID)


def _driver(group: Group, seed: int, n: int) -> np.ndarray:
    v = float(group.strength)
    return OwnedRandom(seed, f"group:{group.key}").stream(DRIVER_STREAM).gamma(1.0 / v, v, n)


def _hash(hasher, label: str, vector: np.ndarray) -> None:
    kind = "<i8" if vector.dtype.kind in "iu" else "<f8"
    hasher.update(label.encode("utf-8") + b"\x00" + str(vector.size).encode("ascii") + b"\x00")
    hasher.update(np.ascontiguousarray(vector, dtype=kind).data)


def _noop(stage: str) -> None:
    return None


@dataclass
class _Drawn:
    digest: str
    occurrences: dict[str, int]
    lines: dict[str, dict[str, np.ndarray]]


def _check(members: Sequence[Member], groups: Sequence[Group]) -> None:
    if not members:
        raise PortfolioRefused("nothing_to_total", "no scenario is included")
    if len(members) > MAX_SCENARIOS or len(groups) > MAX_GROUPS:
        raise PortfolioRefused("scenarios_over_limit", f"{len(members)} scenarios, {len(groups)} groups")
    ids = [m.scenario_id for m in members]
    if ids != sorted(set(ids)):
        raise PortfolioRefused("member_malformed", "each scenario once, in order of its id")
    keys = [g.key for g in groups]
    if keys != sorted(set(keys)):
        raise PortfolioRefused("group_malformed", "each group once, in order of its key")
    for group in groups:
        if not isinstance(group.strength, Decimal) or not Decimal(0) < group.strength <= STRENGTH_MAX:
            raise PortfolioRefused("group_malformed", f"{group.key}: strength {group.strength}")
        if not isinstance(group.source_type, SourceType):
            raise PortfolioRefused("group_malformed", f"{group.key}: source type {group.source_type!r}")
    for member in members:
        if member.group is not None and member.group not in keys:
            raise PortfolioRefused("group_malformed", f"{member.scenario_id} names no declared group")
        if not isinstance(member.factor, Decimal) or not member.factor.is_finite() or member.factor <= 0:
            raise PortfolioRefused("member_malformed", f"{member.scenario_id}: factor {member.factor}")
        if member.si is not None and not isinstance(member.si, ss.ScenarioInput):
            raise PortfolioRefused("member_malformed", f"{member.scenario_id}: not a scenario input")


def _draw(
    members: Sequence[Member],
    plans: Mapping[str, ss._Plan | None],
    groups: Sequence[Group],
    *,
    seed: int,
    draws: int,
    held: int,
    keep: bool,
    check_time: Callable[[str], None],
) -> _Drawn:
    """Every scenario's annual lines for the portfolio's seed, normalised, and the
    digest of every vector drawn (each group's driver, each scenario's counts and
    lines). Kept only where ``keep``: the first sample is hashed and let go."""
    hasher = hashlib.sha256()
    used = sorted({m.group for m in members if m.group is not None and m.si is not None})
    drivers = {g.key: _driver(g, seed, draws) for g in groups if g.key in used}
    for key in used:
        _hash(hasher, f"group/{key}/driver", drivers[key])
    check_time("drivers")
    occurrences: dict[str, int] = {}
    lines: dict[str, dict[str, np.ndarray]] = {}
    for member in members:
        sid = member.scenario_id
        p = plans[sid]
        if p is None:
            gross = np.zeros(draws, dtype=np.float64)
            retained = gross
            counts = np.zeros(draws, dtype=np.int64)
        else:
            random = OwnedRandom(seed, f"scenario:{sid}")
            rates = _rates(p.frequency.distribution, random.stream(RATE_STREAM), draws)
            if member.group is not None:
                rates *= drivers[member.group]
            if not np.isfinite(rates).all() or rates.max(initial=0.0) > dist.MAX_COUNT_MEAN:
                raise PortfolioRefused("rate_out_of_range", f"{sid}: a year's rate above {dist.MAX_COUNT_MEAN:g}")
            counts = random.stream(sim.FREQUENCY_STREAM).poisson(rates).astype(np.int64, copy=False)
            del rates
            total = int(counts.sum())
            if total > sim.MAX_EVENTS:
                raise sim.SimulationRefused("events_over_limit", f"{sid}: {total} occurrences in {draws} years")
            peak = held + ss.values_held(p, total, draws)
            if peak > sim.MAX_VALUES:
                raise sim.SimulationRefused(
                    "values_over_budget", f"{sid}: {peak} values with the portfolio's own; at most {sim.MAX_VALUES}"
                )
            sample = ss._sample(p, seed, draws, check_time, random=random, counts=counts)
            gross = sample.annual[ss.GROSS_CASH]
            retained = sample.annual[ss.RETAINED_CASH] if p.si.policy is not None else gross
            del sample
        factor = float(member.factor)
        if member.factor != 1:
            scaled = gross * factor
            retained = scaled if retained is gross else retained * factor
            gross = scaled
        for line, vector in ((ss.GROSS_CASH, gross), (ss.RETAINED_CASH, retained)):
            if not np.isfinite(vector).all():
                raise sim.SimulationRefused("out_of_range", f"{sid}: a year's {line}, normalised, overflows a float")
        occurrences[sid] = int(counts.sum())
        _hash(hasher, f"scenario/{sid}/counts", counts)
        _hash(hasher, f"scenario/{sid}/{ss.GROSS_CASH}", gross)
        _hash(hasher, f"scenario/{sid}/{ss.RETAINED_CASH}", retained)
        if keep:
            lines[sid] = {ss.GROSS_CASH: gross, ss.RETAINED_CASH: retained}
        del gross, retained, counts
        check_time(f"scenario {sid}")
    return _Drawn("sha256:" + hasher.hexdigest(), occurrences, lines)


# --------------------------------------------------------------- the figures


def _exact_sum(values: Iterable[Decimal]) -> Decimal:
    """The exact sum of decimals (each at most 17 significant digits): never rounded."""
    with localcontext(Context(prec=5000, Emin=-999_999, Emax=999_999, traps=[Inexact])):
        return sum(values, Decimal(0))


def _mean_of(vector: np.ndarray) -> Decimal:
    """``vector``'s correctly rounded binary64 mean, as its shortest decimal."""
    return dist.float_decimal(sim._fsum(vector) / vector.size)


def _agrees(total: Decimal, reference: float) -> bool:
    return abs(float(total) - reference) <= AGREEMENT * max(abs(reference), 1.0)


def _undefined(sid: str, p: ss._Plan | None, line: str) -> tuple[list[str], list[str]]:
    """The parameters of ``line`` of one scenario whose mean, or variance, is
    infinite: its cash components' inputs and frequency, and its policy's terms for
    the retained cash."""
    if p is None:
        return [], []
    inputs = [p.resolved[name] for c in p.components if c.cash and c.estimated for name in c.reads.values()]
    inputs += [p.frequency] if p.frequency is not None else []
    if line == ss.RETAINED_CASH and p.si.policy is not None:
        inputs += [p.resolved[name] for name in p.terms.values()]
    mean, variance = ss._defined(inputs)
    return [f"{sid}:{name}" for name in mean], [f"{sid}:{name}" for name in variance]


def tail_draws(draws: int, severe_percentile: Decimal) -> int:
    """How many years the tail holds: ``ceil(n (1 - p / 100))``, exactly."""
    return math.ceil(Fraction(draws) * (1 - Fraction(severe_percentile) / 100))


def _largest(by: Mapping[str, Decimal]) -> str:
    return min(by, key=lambda sid: (-by[sid], sid))


def _line(
    line: str,
    drawn: _Drawn,
    members: Sequence[Member],
    plans: Mapping[str, ss._Plan | None],
    *,
    draws: int,
    severe: Decimal,
    currency: str,
) -> tuple[dict, dict]:
    """One line's summary block and its contributions."""
    total = np.zeros(draws, dtype=np.float64)
    for member in members:
        total += drawn.lines[member.scenario_id][line]
    infinite_mean: list[str] = []
    infinite_variance: list[str] = []
    for member in members:
        mean, variance = _undefined(member.scenario_id, plans[member.scenario_id], line)
        infinite_mean += mean
        infinite_variance += variance
    summary = sim.summarize(
        total, severe_percentile=severe, mean_defined=not infinite_mean, error_defined=not infinite_variance
    )
    block = sim.summary_block(summary, currency)
    block["mean_undefined"] = sorted(infinite_mean) or None
    block["standard_error_undefined"] = sorted(infinite_variance) or None
    k = tail_draws(draws, severe)
    if summary.mean is None:
        block["expected_annual_exposure"] = None
        block["expected_shortfall"] = None
        reason = (
            f"the mean does not exist: {', '.join(sorted(infinite_mean))} has an infinite mean, so neither does a "
            "contribution to it or the expected shortfall"
        )
        return block, {"mean": None, "tail": None, "largest": None, "not_reported": reason}
    by_mean = {m.scenario_id: _mean_of(drawn.lines[m.scenario_id][line]) for m in members}
    mean = _exact_sum(by_mean.values())
    if not _agrees(mean, summary.mean):
        raise sim.InvariantBroken(f"the scenarios' means sum to {mean}, the totals' mean is {summary.mean}")
    order = np.argsort(total, kind="stable")
    tail = order[draws - k:]
    del order
    by_tail = {
        m.scenario_id: dist.float_decimal(sim._fsum(drawn.lines[m.scenario_id][line][tail]) / k) for m in members
    }
    shortfall = _exact_sum(by_tail.values())
    if not _agrees(shortfall, sim._fsum(total[tail]) / k):
        raise sim.InvariantBroken(f"the tail contributions sum to {shortfall}, the tail's mean differs")
    del tail, total
    block["mean"] = decimal_text(mean)
    block["expected_annual_exposure"] = block["mean"]
    block["expected_shortfall"] = decimal_text(shortfall)
    contributions = {
        "mean": {"total": decimal_text(mean), "by_scenario": {sid: decimal_text(v) for sid, v in by_mean.items()}},
        "tail": {
            "percentile": decimal_text(severe),
            "draws": k,
            "measure": "expected shortfall: the mean of the tail's years",
            "total": decimal_text(shortfall),
            "by_scenario": {sid: decimal_text(v) for sid, v in by_tail.items()},
        },
        "largest": {"mean": _largest(by_mean), "tail": _largest(by_tail)},
        "not_reported": None,
    }
    return block, contributions


@dataclass(frozen=True)
class PortfolioSimulation:
    """One portfolio drawn: :attr:`record` is everything :attr:`digest` covers."""

    record: Mapping
    digest: str


def run(
    members: Sequence[Member],
    groups: Sequence[Group] = (),
    *,
    seed: int,
    draws: int = sim.DEFAULT_DRAWS,
    severe_percentile=sim.DEFAULT_SEVERE_PERCENTILE,
    reporting_currency: str,
    input_digest: str,
    check_time: Callable[[str], None] | None = None,
) -> PortfolioSimulation:
    """Aggregate ``members`` for ``seed``: see the module's rules. Refused before
    anything is sampled where the inputs decide it (no member, a scenario with no
    frequency, too many values to hold); the run is sampled twice, from fresh
    streams, and the two must agree bit for bit, as step 7a's."""
    sim.check_seed(seed)
    sim.check_draws(draws)
    severe = sim.check_severe_percentile(severe_percentile)
    check_reporting_currency(reporting_currency)
    check_time = check_time or _noop
    members, groups = tuple(members), tuple(groups)
    _check(members, groups)
    plans: dict[str, ss._Plan | None] = {}
    for member in members:
        if member.si is None:
            plans[member.scenario_id] = None
            continue
        p = ss.plan(member.si)
        if p.frequency is None:
            raise PortfolioRefused("no_annual_loss", member.scenario_id)
        plans[member.scenario_id] = p
    used = {m.group for m in members if m.group is not None and m.si is not None}
    held = (LINES_PER_MEMBER * len(members) + len(used) + PORTFOLIO_TEMPORARIES) * draws
    if held > sim.MAX_VALUES:
        raise sim.SimulationRefused("values_over_budget", f"{held} values; at most {sim.MAX_VALUES}")
    check_time("plan")

    first = _draw(members, plans, groups, seed=seed, draws=draws, held=held, keep=False, check_time=check_time)
    drawn = _draw(members, plans, groups, seed=seed, draws=draws, held=held, keep=True, check_time=check_time)
    if drawn.digest != first.digest:
        raise sim.InvariantBroken("the same seed and members gave different draws: the portfolio is not reproducible")

    blocks, contributions = {}, {}
    for line in LINES:
        blocks[line], contributions[line] = _line(
            line, drawn, members, plans, draws=draws, severe=severe, currency=reporting_currency
        )
        check_time(f"summary {line}")
    by_key = {g.key: g for g in groups}
    record = {
        "schema": SCHEMA,
        "engine_version": ENGINE_VERSION,
        "seed": str(seed),
        "simulations": draws,
        "reporting_currency": reporting_currency,
        "basis": ss.ANNUAL_BASIS,
        "statement": (
            "a draw is a simulated year, the same year in every scenario; the portfolio's loss in a year is the sum "
            "of its scenarios' annual losses that year, each normalised into the reporting currency"
        ),
        "severe_percentile": decimal_text(severe),
        "confidence_level": decimal_text(sim.CONFIDENCE_LEVEL),
        "headline": ss.RETAINED_CASH
        if any(p is not None and p.si.policy is not None for p in plans.values())
        else ss.GROSS_CASH,
        "lines": blocks,
        "contributions": contributions,
        "members": {
            m.scenario_id: {
                "group": m.group,
                "factor": decimal_text(m.factor),
                "events": [] if m.si is None else [event.loss_event_id for event in m.si.events],
                "occurrences": drawn.occurrences[m.scenario_id],
                "frequency": None if plans[m.scenario_id] is None
                else plans[m.scenario_id].frequency.distribution.record(),
            }
            for m in members
        },
        "groups": {
            key: {
                "strength": decimal_text(by_key[key].strength),
                "source_type": by_key[key].source_type.value,
                "driver": {
                    "id": "gamma",
                    "shape": dist.float_text(1.0 / float(by_key[key].strength)),
                    "scale": dist.float_text(float(by_key[key].strength)),
                    "mean": "1",
                    "variance": decimal_text(by_key[key].strength),
                },
                "members": sorted(m.scenario_id for m in members if m.group == key),
                "drawn": key in used,
            }
            for key in sorted(by_key)
        },
        "versions": versions(),
        "input_digest": input_digest,
        "outcomes_sha256": drawn.digest,
    }
    ss.no_float(record)
    return PortfolioSimulation(record=MappingProxyType(record), digest=ss.digest_of(record))


__all__ = [
    "DRIVER",
    "DRIVER_VERSION",
    "ENGINE_VERSION",
    "LINES",
    "MAX_GROUPS",
    "MAX_SCENARIOS",
    "REFUSALS",
    "SCHEMA",
    "SHARED_EVENTS_RULE",
    "SHARED_EVENTS_VERSION",
    "STREAM_DOMAIN",
    "STRENGTH_MAX",
    "WINDOW",
    "EventRef",
    "Group",
    "Joined",
    "Member",
    "OwnedRandom",
    "PortfolioRefused",
    "PortfolioSimulation",
    "limits",
    "run",
    "shared_events",
    "substream_key",
    "tail_draws",
    "versions",
    "without_events",
]
