"""A portfolio of scenarios aggregated from their draws (Economic Exposure E5;
``docs/economics/spec-v1.md``, section 31; the owner's specification, section 24).

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
  Gamma-mixed rate. A group has two members at least. Scenarios in different
  groups, or in none, are independent. No copula.
- **A shared event is counted once A YEAR** (:data:`SHARED_EVENTS_RULE`, the lead's
  interim decision on review round 1, HIGH-1). Which events of two scenarios are one
  loss event is decided before the draws, pair by pair (:func:`links_between`,
  :func:`shared_events`); every scenario keeps every one of its events, drawn at its
  own frequency, and in each simulated year the portfolio counts each shared event
  once: at the LARGEST of the joined scenarios' losses of it that year, never their
  sum. (Where its events are a chain -- two of them, of two scenarios, linked only
  through a third -- at the largest total of a set of its events no two of which are
  linked: :func:`counted_sets`.) So the portfolio is at least each included scenario
  year by year, and at every percentile; a rare duplicate never hides a frequent
  loss; and adding a scenario never lowers it, as no pair of the others' events
  becomes linked by it (exactly; in binary64, to the last place).
- **Normalised before it is summed.** Each scenario's annual losses are multiplied,
  draw by draw, by the factor that normalises one unit of its currency at its as-of
  date into the reporting currency at the valuation date (step 3's order, section
  12.4: every step is a multiplication), and only then summed.
- **Summed per year, never by percentile, in one order.** The portfolio's annual
  loss in year ``y`` is the sum, added in one fixed order (:func:`ordered_sum`), of
  every scenario's losses that year of its events no other is linked to, and then of
  each shared loss event's count; its P10, P50, P90, mean, expected annual loss and
  severe-but-plausible are step 7a's summary of that vector. A scenario's own annual
  loss is the sum, in the same order, of its own events' losses (those in one shared
  loss event summed first, as the counted sets are): its terms are some of the
  portfolio's, or each at most one of them, all non-negative, so the portfolio's is
  at least it exactly, year by year, in binary64 too (rounding is monotone).
- **Each scenario's contribution to the mean AND to the tail.** A scenario carries
  its own event losses not shared, and each shared event's largest loss in the
  years its own is the largest (ties: the first scenario). To the mean: its mean of
  that over the same years, and the portfolio's mean IS their sum (the mean of a sum
  is the sum of the means), each the correctly rounded binary64 mean written as its
  shortest decimal, summed exactly. To the tail: its mean over the years in the tail
  -- the ``ceil(n (1 - p))`` years of largest total, p the severe percentile --
  whose sum is the portfolio's expected shortfall there. The largest mean
  contributor may differ from the largest tail contributor (specification, section
  24).

Pure: no Django, no database, no clock. Floats inside, decimal strings outside, as
step 7a's record: no float in the record.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
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
#: Still 1: nothing was recorded under review round 1's first draft (never merged).
ENGINE_VERSION = 1
#: Hashed with a scenario (or a group) and a stream's name to key its sub-stream.
STREAM_DOMAIN = "mythos.economics.portfolio-stream/v1"
#: The stream of a scenario's annual rate, and of a group's driver.
RATE_STREAM = "@rate"
DRIVER_STREAM = "@driver"

#: The correlation groups' common driver (the decided MVP; copulas are not modelled).
DRIVER_VERSION = "mythos.economics.group-driver/v1"
DRIVER = (
    "each correlation group of two or more included scenarios has ONE common driver per simulated year, M ~ "
    "Gamma(shape 1/v, scale v): mean 1 and variance v, the group's recorded strength. Every member's annual rate -- "
    "the rate its frequency implies: a Poisson's lambda; a negative binomial's Gamma(size, (1 - p) / p); a "
    "zero-inflated Poisson's 0 with probability pi, else lambda -- is multiplied by M, and the year's count is a "
    "Poisson of that product (a Gamma-mixed rate, which also widens each member's own count, keeping its mean: owner "
    "decision 31.10 #2). A scenario in no group has M = 1, so its count is distributed as its frequency states. "
    "Scenarios in different groups, or in none, are independent"
)

#: Which events of two scenarios are one loss event (step 5's grouping key, window
#: and SPINE effects, section 24.5), and how one is counted (once a year, at its
#: largest loss that year).
SHARED_EVENTS_VERSION = "mythos.economics.portfolio-shared-events/v1"
SHARED_EVENTS_RULE = (
    "two events of different scenarios are LINKED -- directly one loss event -- when an effect of each is the same "
    "SPINE effect; when they have the same grouping key (template and version, asset and business process) and an "
    "observation of one is within 24 hours, inclusive, of an observation of the other; or when they have the same "
    "grouping key and one of them at least is of hypothetical effects alone. The pair's own attributes decide it, "
    "never a third event, and a scenario's own events are never linked. Events linked directly or through others are "
    "one shared loss event. Every scenario keeps every one of its events, drawn at its own frequency. In each "
    "simulated year a shared loss event is counted ONCE: at the largest total that year of a set of its events no two "
    "of which are linked. Where every two of its events of two scenarios are linked, those sets are its scenarios' "
    "own events, so it is counted at the LARGEST of the joined scenarios' losses of it that year (a scenario with two "
    "of its events, at their sum), never their sum across scenarios; where its events are a chain (two linked only "
    "through a third), at the largest of the sets"
)
#: Step 5's grouping window (``builder.GROUPING_WINDOW``; a test holds them equal).
WINDOW = timedelta(hours=24)

#: The most scenarios a portfolio totals, and the most groups it declares.
MAX_SCENARIOS = 50
MAX_GROUPS = 20
#: The most sets of its events a shared loss event may be counted at (one per
#: scenario where its events are all linked; a chain has more).
MAX_COUNTED_SETS = 64
#: A group's strength (the driver's variance) is at least this and at most that:
#: below the floor the driver is 1 to the last digit (and a float's inverse can
#: overflow); above the ceiling the tail is no group's this engine is calibrated for.
STRENGTH_MIN = Decimal("0.000001")
STRENGTH_MAX = Decimal(10)
#: The lines a portfolio sums: the gross cash, and the retained cash (a scenario
#: with no insurance policy retains its gross). Market value is never added to cash.
LINES = (ss.GROSS_CASH, ss.RETAINED_CASH)
#: Values the portfolio holds, each of the draws: per event of each scenario, its two
#: annual lines; per shared loss event, while a line is summarised, its count, which
#: set is counted, and a scenario's sum of its events in it; and beside them, the
#: total, a sorted copy, its order, a set's total, a scenario's own line or its
#: contribution, and their masks.
LINES_PER_EVENT = 2
LINES_PER_SHARED_EVENT = 3
PORTFOLIO_TEMPORARIES = 6
#: How far the sum of the scenarios' means may be from the mean of the per-draw
#: totals (relative, and at least one unit absolute): the two differ by rounding.
AGREEMENT = 1e-12

REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "nothing_to_total": "a portfolio totals at least one scenario whose result may be totalled",
        "no_annual_loss": "a scenario a portfolio sums states a frequency: a draw is a simulated year",
        "member_malformed": "each scenario is in a portfolio once, in order, with a positive normalisation factor",
        "group_malformed": (
            "a correlation group has a key of 1 to 60 lowercase letters, digits, '-' and '_', a strength from "
            f"{STRENGTH_MIN} to {STRENGTH_MAX} (the variance of its common driver), a source type and its evidence, "
            "and names each of its scenarios once; a scenario is in one group at most"
        ),
        "group_too_small": "a correlation group names two scenarios at least: a group of one correlates with nothing",
        "shared_malformed": (
            "a shared loss event joins events of two scenarios at least, each an event of a scenario in the "
            "portfolio, linked pair by pair, and an event is in one shared loss event at most"
        ),
        "shared_too_complex": (
            f"a shared loss event is counted at the largest of at most {MAX_COUNTED_SETS} sets of its events no two "
            "of which are linked: its events are too long a chain"
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
        "max_counted_sets": MAX_COUNTED_SETS,
        "strength_min": decimal_text(STRENGTH_MIN),
        "strength_max": decimal_text(STRENGTH_MAX),
        "max_values": sim.MAX_VALUES,
        "max_events": sim.MAX_EVENTS,
        "max_count_mean": dist.float_text(dist.MAX_COUNT_MEAN),
        "lines_per_event": LINES_PER_EVENT,
        "lines_per_shared_event": LINES_PER_SHARED_EVENT,
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
    base and high (step 4's, normalised into the reporting currency: shown, never
    used to choose what is counted)."""

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


@dataclass(frozen=True)
class Joined:
    """Events of several scenarios that are one loss event, in order; the pairs of
    them (indices into ``events``, of two scenarios) the rule links directly, and
    the kinds of those links. Each event is drawn in its own scenario; a year counts
    one of the sets :func:`counted_sets` lists, the largest that year."""

    events: tuple[EventRef, ...]
    by: tuple[str, ...]
    links: tuple[tuple[int, int], ...]

    @property
    def scenarios(self) -> tuple[str, ...]:
        return tuple(sorted({e.scenario for e in self.events}))

    @property
    def one_event(self) -> bool:
        """Whether every two of its events of two scenarios are linked directly: then
        the sets a year counts are its scenarios' own, and it is counted at the
        largest scenario's loss of it."""
        pairs = sum(
            1 for i, a in enumerate(self.events) for b in self.events[i + 1:] if a.scenario != b.scenario
        )
        return pairs == len(self.links)


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


def _alone_hypothetical(event: EventRef) -> bool:
    return event.hypothetical and not event.observed_at


def links_between(a: EventRef, b: EventRef) -> tuple[str, ...]:
    """The kinds of :data:`SHARED_EVENTS_RULE` that make ``a`` and ``b`` directly
    one loss event, in order; none for two events of one scenario. A pair's own
    attributes decide it, never a third event."""
    if a.scenario == b.scenario:
        return ()
    kinds = []
    if a.spine_effects & b.spine_effects:
        kinds.append("spine_effect")
    if a.key is not None and a.key == b.key:
        if _alone_hypothetical(a) or _alone_hypothetical(b):
            kinds.append("hypothetical")
        if a.observed_at and b.observed_at and _within(sorted(a.observed_at), sorted(b.observed_at)):
            kinds.append("window")
    return tuple(sorted(kinds))


def shared_events(events: Iterable[EventRef]) -> tuple[Joined, ...]:
    """The loss events :data:`SHARED_EVENTS_RULE` makes one: the connected events,
    each with the pairs linked directly. Events no other is linked to are not
    listed. Deterministic: the input's order never changes the answer."""
    events = sorted(events, key=lambda e: e.order)
    parent = list(range(len(events)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    # Only events that share a SPINE effect or a key can be linked: compare those.
    buckets: dict[object, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        for spine in event.spine_effects:
            buckets[("spine", spine)].append(index)
        if event.key is not None:
            buckets[("key", event.key)].append(index)
    pairs: dict[tuple[int, int], tuple[str, ...]] = {}
    for bucket in buckets.values():
        for at, i in enumerate(bucket):
            for j in bucket[at + 1:]:
                if (i, j) not in pairs:
                    pairs[(i, j)] = links_between(events[i], events[j])
    linked = sorted(pair for pair, kinds in pairs.items() if kinds)
    for i, j in linked:
        a, b = find(i), find(j)
        if a != b:
            parent[max(a, b)] = min(a, b)
    found: dict[int, list[int]] = defaultdict(list)
    for index in range(len(events)):
        found[find(index)].append(index)
    joined = []
    for indices in found.values():
        if len(indices) < 2:
            continue
        at = {index: position for position, index in enumerate(indices)}
        links = tuple(sorted((at[i], at[j]) for i, j in linked if i in at))
        kinds = sorted({kind for i, j in linked if i in at for kind in pairs[(i, j)]})
        joined.append(Joined(tuple(events[i] for i in indices), tuple(kinds), links))
    return tuple(sorted(joined, key=lambda j: j.events[0].order))


def counted_sets(one: Joined, limit: int | None = None) -> tuple[tuple[int, ...], ...] | None:
    """The sets of ``one``'s events a year may count: every largest set no two of
    whose events are linked directly (a scenario's own events never are), each in
    order, in order. For a loss event whose events of two scenarios are all linked,
    these are its scenarios' own events. ``None`` past ``limit`` sets
    (:data:`MAX_COUNTED_SETS`)."""
    limit = MAX_COUNTED_SETS if limit is None else limit
    n = len(one.events)
    linked: list[set[int]] = [set() for _ in range(n)]
    for i, j in one.links:
        linked[i].add(j)
        linked[j].add(i)
    together = [set(range(n)) - linked[i] - {i} for i in range(n)]
    found: list[tuple[int, ...]] = []
    # Bron-Kerbosch, with a pivot, over the events that may be counted together.
    stack = [(frozenset(), frozenset(range(n)), frozenset())]
    while stack:
        chosen, candidates, excluded = stack.pop()
        if not candidates and not excluded:
            found.append(tuple(sorted(chosen)))
            if len(found) > limit:
                return None
            continue
        pivot = min(candidates | excluded, key=lambda u: (-len(together[u] & candidates), u))
        for v in sorted(candidates - together[pivot]):
            stack.append((chosen | {v}, candidates & together[v], excluded & together[v]))
            candidates = candidates - {v}
            excluded = excluded | {v}
    return tuple(sorted(found))


# ------------------------------------------------------------------- members


@dataclass(frozen=True)
class Member:
    """One scenario of the portfolio: its id (the scenario version's uuid), the
    step-7b input it is drawn with (every one of its events), the factor that
    normalises its currency into the reporting currency, and its group."""

    scenario_id: str
    si: ss.ScenarioInput
    factor: Decimal
    group: str | None = None


@dataclass(frozen=True)
class Group:
    """A correlation group: its key, its strength (the variance of its common
    driver) and the source that strength rests on."""

    key: str
    strength: Decimal
    source_type: SourceType


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


def ordered_sum(vectors: Sequence[np.ndarray], n: int) -> np.ndarray:
    """Each year's sum of ``vectors``, added in their order, one IEEE addition at a
    time, into a new vector. Rounding is monotone, so of non-negative terms a sum in
    the same order of more of them, or of each at least as large, is never smaller:
    what the portfolio's domination of each scenario rests on."""
    out = np.zeros(n, dtype=np.float64) if not vectors else np.array(vectors[0], dtype=np.float64, copy=True)
    for vector in vectors[1:]:
        np.add(out, vector, out=out)
    return out


def _noop(stage: str) -> None:
    return None


@dataclass
class _Drawn:
    """What the draws hold: each scenario's annual loss of each of its events no
    other is linked to, by line; each shared loss event's events' annual losses, by
    position in it and line; the years' occurrences; and the digest of every vector
    drawn."""

    digest: str
    occurrences: dict[str, int]
    alone: dict[str, dict[str, list[np.ndarray]]]
    shared: list[dict[int, dict[str, np.ndarray]]]


def _connected(n: int, links: Sequence[tuple[int, int]]) -> bool:
    reached, frontier = {0}, [0]
    while frontier:
        at = frontier.pop()
        for i, j in links:
            for a, b in ((i, j), (j, i)):
                if a == at and b not in reached:
                    reached.add(b)
                    frontier.append(b)
    return len(reached) == n


def _check(members: Sequence[Member], groups: Sequence[Group], shared: Sequence[Joined]) -> None:
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
        if not isinstance(group.strength, Decimal) or not STRENGTH_MIN <= group.strength <= STRENGTH_MAX:
            raise PortfolioRefused("group_malformed", f"{group.key}: strength {group.strength}")
        if not isinstance(group.source_type, SourceType):
            raise PortfolioRefused("group_malformed", f"{group.key}: source type {group.source_type!r}")
        named = [m.scenario_id for m in members if m.group == group.key]
        if len(named) == 1:
            raise PortfolioRefused("group_too_small", f"{group.key} applies to {named[0]} alone")
    events: dict[str, set[str]] = {}
    for member in members:
        if member.group is not None and member.group not in keys:
            raise PortfolioRefused("group_malformed", f"{member.scenario_id} names no declared group")
        if not isinstance(member.factor, Decimal) or not member.factor.is_finite() or member.factor <= 0:
            raise PortfolioRefused("member_malformed", f"{member.scenario_id}: factor {member.factor}")
        if not isinstance(member.si, ss.ScenarioInput):
            raise PortfolioRefused("member_malformed", f"{member.scenario_id}: not a scenario input")
        events[member.scenario_id] = {event.loss_event_id for event in member.si.events}
    seen: set[tuple[str, str]] = set()
    for one in shared:
        orders = [event.order for event in one.events]
        if len(one.scenarios) < 2 or orders != sorted(set(orders)) or any(
            sid not in events or key not in events[sid] for sid, key in orders
        ):
            raise PortfolioRefused("shared_malformed", f"{orders}")
        if seen & set(orders):
            raise PortfolioRefused("shared_malformed", f"an event in two shared loss events: {orders}")
        seen.update(orders)
        # The links are the rule's, pair by pair, and they join every event.
        n = len(one.events)
        pairs = {(i, j): links_between(one.events[i], one.events[j]) for i in range(n) for j in range(i + 1, n)}
        expected = tuple(pair for pair, kinds in pairs.items() if kinds)
        kinds = tuple(sorted({kind for pair in expected for kind in pairs[pair]}))
        if tuple(one.links) != expected or tuple(one.by) != kinds or not _connected(n, expected):
            raise PortfolioRefused("shared_malformed", f"the links of {orders} are not the rule's")


def _draw(
    members: Sequence[Member],
    plans: Mapping[str, ss._Plan],
    groups: Sequence[Group],
    shared: Sequence[Joined],
    *,
    seed: int,
    draws: int,
    held: int,
    keep: bool,
    check_time: Callable[[str], None],
) -> _Drawn:
    """Every scenario's annual loss of each of its events for the portfolio's seed,
    normalised, and the digest of every vector drawn (each group's driver, each
    scenario's counts and event losses). Kept only where ``keep``: the first sample
    is hashed and let go."""
    hasher = hashlib.sha256()
    used = sorted({m.group for m in members if m.group is not None})
    drivers = {g.key: _driver(g, seed, draws) for g in groups if g.key in used}
    for key in used:
        _hash(hasher, f"group/{key}/driver", drivers[key])
    check_time("drivers")
    where = {event.order: (at, position) for at, one in enumerate(shared) for position, event in enumerate(one.events)}
    occurrences: dict[str, int] = {}
    alone: dict[str, dict[str, list[np.ndarray]]] = {}
    joined: list[dict[int, dict[str, np.ndarray]]] = [{} for _ in shared]
    for member in members:
        sid = member.scenario_id
        p = plans[sid]
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
        _hash(hasher, f"scenario/{sid}/counts", counts)
        factor = float(member.factor)
        mine: dict[str, list[np.ndarray]] = {line: [] for line in LINES}
        parts: dict[tuple[int, int], dict[str, np.ndarray]] = {}
        for index, event in enumerate(p.si.events):
            lines = sample.events[index]
            annual: dict[str, np.ndarray] = {}
            for line in LINES:
                if lines[line] is None:
                    # No policy: the gross is retained, the same values (held once).
                    annual[line] = annual[ss.GROSS_CASH]
                else:
                    vector = sim.compound_annual(counts, lines[line])
                    if member.factor != 1:
                        vector *= factor
                    if not np.isfinite(vector).all():
                        raise sim.SimulationRefused("out_of_range", f"{sid}: a year's {line}, normalised, overflows")
                    annual[line] = vector
                _hash(hasher, f"scenario/{sid}/event/{event.loss_event_id}/{line}", annual[line])
            at = where.get((sid, event.loss_event_id))
            if at is None:
                for line in LINES:
                    mine[line].append(annual[line])
            else:
                parts[at] = annual
        del sample
        occurrences[sid] = total
        if keep:
            alone[sid] = mine
            for (at, position), annual in parts.items():
                joined[at][position] = annual
        del mine, parts, counts
        check_time(f"scenario {sid}")
    return _Drawn("sha256:" + hasher.hexdigest(), occurrences, alone, joined)


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


def _undefined(sid: str, p: ss._Plan, line: str) -> tuple[list[str], list[str]]:
    """The parameters of ``line`` of one scenario whose mean, or variance, is
    infinite: its cash components' inputs and frequency, and its policy's terms for
    the retained cash."""
    inputs = [p.resolved[name] for c in p.components if c.cash and c.estimated for name in c.reads.values()]
    inputs += [p.frequency] if p.frequency is not None else []
    if line == ss.RETAINED_CASH and p.si.policy is not None:
        inputs += [p.resolved[name] for name in p.terms.values()]
    mean, variance = ss._defined(inputs)
    return [f"{sid}:{name}" for name in mean], [f"{sid}:{name}" for name in variance]


def tail_draws(draws: int, severe_percentile: Decimal) -> int:
    """How many years the tail holds: ``ceil(n (1 - p / 100))``, exactly."""
    return math.ceil(Fraction(draws) * (1 - Fraction(severe_percentile) / 100))


def _tail_mean(vector: np.ndarray, k: int) -> float:
    """The mean of ``vector``'s ``k`` largest values (ties by draw order)."""
    order = np.argsort(vector, kind="stable")
    return sim._fsum(vector[order[vector.size - k:]]) / k


def _largest(by: Mapping[str, Decimal]) -> str:
    return min(by, key=lambda sid: (-by[sid], sid))


def _block(vector: np.ndarray, *, severe: Decimal, currency: str, mean_undefined: list[str],
           variance_undefined: list[str], k: int) -> dict:
    summary = sim.summarize(
        vector, severe_percentile=severe, mean_defined=not mean_undefined, error_defined=not variance_undefined
    )
    block = sim.summary_block(summary, currency)
    block["mean_undefined"] = sorted(mean_undefined) or None
    block["standard_error_undefined"] = sorted(variance_undefined) or None
    block["expected_annual_exposure"] = block["mean"]
    block["expected_shortfall"] = None if summary.mean is None else dist.float_text(_tail_mean(vector, k))
    return block


def _parts(sid: str, chosen: Iterable[int], one: Joined, held: Mapping[int, Mapping[str, np.ndarray]], line: str,
           draws: int) -> np.ndarray | None:
    """``sid``'s loss that year of the events ``chosen`` of ``one``: the sum of its
    events among them, in order (the one vector itself where it has one)."""
    vectors = [held[i][line] for i in chosen if one.events[i].scenario == sid]
    if not vectors:
        return None
    return vectors[0] if len(vectors) == 1 else ordered_sum(vectors, draws)


def _line(
    line: str,
    drawn: _Drawn,
    members: Sequence[Member],
    plans: Mapping[str, ss._Plan],
    shared: Sequence[Joined],
    sets: Sequence[tuple[tuple[int, ...], ...]],
    *,
    draws: int,
    severe: Decimal,
    currency: str,
) -> tuple[dict, dict, dict, list[dict]]:
    """One line's summary block, its contributions, each scenario's own block over
    the same years, and each shared event's years by the scenario counted."""
    k = tail_draws(draws, severe)
    # Each shared loss event, each year: the largest total of a set it may count
    # (ties: the first set), and which set that is.
    counts, winners = [], []
    for at in range(len(shared)):
        held = drawn.shared[at]
        best = winner = None
        for number, chosen in enumerate(sets[at]):
            value = ordered_sum([held[i][line] for i in chosen], draws)
            if best is None:
                best, winner = value, np.zeros(draws, dtype=np.uint8)
                continue
            larger = value > best
            np.copyto(best, value, where=larger)
            winner[larger] = number
            del value, larger
        counts.append(best)
        winners.append(winner)
    total = ordered_sum([vector for m in members for vector in drawn.alone[m.scenario_id][line]] + counts, draws)
    infinite_mean: list[str] = []
    infinite_variance: list[str] = []
    own_blocks: dict[str, dict] = {}
    for member in members:
        sid = member.scenario_id
        mean, variance = _undefined(sid, plans[sid], line)
        infinite_mean += mean
        infinite_variance += variance
        mine = [_parts(sid, range(len(one.events)), one, drawn.shared[at], line, draws)
                for at, one in enumerate(shared)]
        own = ordered_sum(drawn.alone[sid][line] + [part for part in mine if part is not None], draws)
        del mine
        # The portfolio is at least each of its scenarios, year by year, exactly: its
        # terms are a superset of the scenario's, each at least the scenario's own.
        if (total < own).any():
            raise sim.InvariantBroken(f"a year's portfolio {line} is below {sid}'s own")
        own_blocks[sid] = _block(own, severe=severe, currency=currency, mean_undefined=mean,
                                 variance_undefined=variance, k=k)
        del own
    block = _block(total, severe=severe, currency=currency, mean_undefined=infinite_mean,
                   variance_undefined=infinite_variance, k=k)
    years = []
    for at, one in enumerate(shared):
        counted = counts[at] > 0.0
        by = {}
        for sid in one.scenarios:
            numbers = [n for n, chosen in enumerate(sets[at]) if any(one.events[i].scenario == sid for i in chosen)]
            by[sid] = int(np.count_nonzero(counted & np.isin(winners[at], numbers)))
        years.append({"years_with_loss": int(np.count_nonzero(counted)), "years_counted_by": by})
    if block["mean"] is None:
        reason = (
            f"the mean does not exist: {', '.join(sorted(infinite_mean))} has an infinite mean, so neither does a "
            "contribution to it or the expected shortfall"
        )
        return block, {"mean": None, "tail": None, "largest": None, "not_reported": reason}, own_blocks, years
    order = np.argsort(total, kind="stable")
    tail = order[draws - k:].copy()
    del order
    by_mean, by_tail = {}, {}
    for member in members:
        sid = member.scenario_id
        # A scenario carries its events no other is linked to, and its own events in
        # the set each shared loss event is counted at that year.
        contribution = ordered_sum(drawn.alone[sid][line], draws)
        for at, one in enumerate(shared):
            for number, chosen in enumerate(sets[at]):
                part = _parts(sid, chosen, one, drawn.shared[at], line, draws)
                if part is not None:
                    np.add(contribution, part, out=contribution, where=winners[at] == number)
        by_mean[sid] = _mean_of(contribution)
        by_tail[sid] = dist.float_decimal(sim._fsum(contribution[tail]) / k)
        del contribution
    mean = _exact_sum(by_mean.values())
    reference = float(block["mean"])
    if not _agrees(mean, reference):
        raise sim.InvariantBroken(f"the scenarios' means sum to {mean}, the totals' mean is {reference}")
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
    return block, contributions, own_blocks, years


@dataclass(frozen=True)
class PortfolioSimulation:
    """One portfolio drawn: :attr:`record` is everything :attr:`digest` covers."""

    record: Mapping
    digest: str


def run(
    members: Sequence[Member],
    groups: Sequence[Group] = (),
    shared: Sequence[Joined] = (),
    *,
    seed: int,
    draws: int = sim.DEFAULT_DRAWS,
    severe_percentile=sim.DEFAULT_SEVERE_PERCENTILE,
    reporting_currency: str,
    input_digest: str,
    check_time: Callable[[str], None] | None = None,
) -> PortfolioSimulation:
    """Aggregate ``members`` for ``seed``, counting each of ``shared`` once a year:
    see the module's rules. Refused before anything is sampled where the inputs
    decide it (no member, a scenario with no frequency, a group of one, a shared
    loss event too long a chain, too many values to hold); the run is sampled twice,
    from fresh streams, and the two must agree bit for bit, as step 7a's."""
    sim.check_seed(seed)
    sim.check_draws(draws)
    severe = sim.check_severe_percentile(severe_percentile)
    check_reporting_currency(reporting_currency)
    check_time = check_time or _noop
    members, groups, shared = tuple(members), tuple(groups), tuple(shared)
    _check(members, groups, shared)
    sets = []
    for one in shared:
        found = counted_sets(one)
        if found is None:
            raise PortfolioRefused("shared_too_complex", f"the shared loss event of {one.events[0].order}")
        sets.append(found)
    plans: dict[str, ss._Plan] = {}
    for member in members:
        p = ss.plan(member.si)
        if p.frequency is None:
            raise PortfolioRefused("no_annual_loss", member.scenario_id)
        plans[member.scenario_id] = p
    used = {m.group for m in members if m.group is not None}
    events = sum(len(m.si.events) for m in members)
    held = (LINES_PER_EVENT * events + LINES_PER_SHARED_EVENT * len(shared) + len(used) + PORTFOLIO_TEMPORARIES) * draws
    if held > sim.MAX_VALUES:
        raise sim.SimulationRefused("values_over_budget", f"{held} values; at most {sim.MAX_VALUES}")
    check_time("plan")

    common = {"seed": seed, "draws": draws, "held": held, "check_time": check_time}
    first = _draw(members, plans, groups, shared, keep=False, **common)
    drawn = _draw(members, plans, groups, shared, keep=True, **common)
    if drawn.digest != first.digest:
        raise sim.InvariantBroken("the same seed and members gave different draws: the portfolio is not reproducible")

    blocks, contributions, owns, years = {}, {}, {}, {}
    for line in LINES:
        blocks[line], contributions[line], owns[line], years[line] = _line(
            line, drawn, members, plans, shared, sets, draws=draws, severe=severe, currency=reporting_currency
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
            "of its scenarios' annual losses that year, each normalised into the reporting currency, every shared "
            "loss event counted once, at the largest of the joined scenarios' losses of it that year (where its "
            "events are a chain, at the largest total of a set of them no two of which are linked)"
        ),
        "severe_percentile": decimal_text(severe),
        "confidence_level": decimal_text(sim.CONFIDENCE_LEVEL),
        "headline": ss.RETAINED_CASH if any(p.si.policy is not None for p in plans.values()) else ss.GROSS_CASH,
        "lines": blocks,
        "contributions": contributions,
        "members": {
            m.scenario_id: {
                "group": m.group,
                "factor": decimal_text(m.factor),
                "events": [event.loss_event_id for event in m.si.events],
                "shared": sorted(e.event_key for one in shared for e in one.events if e.scenario == m.scenario_id),
                "occurrences": drawn.occurrences[m.scenario_id],
                "frequency": plans[m.scenario_id].frequency.distribution.record(),
                "own": {line: owns[line][m.scenario_id] for line in LINES},
            }
            for m in members
        },
        "shared": [
            {
                "events": [[e.scenario, e.event_key] for e in one.events],
                "by": list(one.by),
                "links": [list(pair) for pair in one.links],
                "one_event": one.one_event,
                "sets": [list(chosen) for chosen in sets[at]],
                "years": {line: years[line][at] for line in LINES},
            }
            for at, one in enumerate(shared)
        ],
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
    "MAX_COUNTED_SETS",
    "MAX_GROUPS",
    "MAX_SCENARIOS",
    "REFUSALS",
    "SCHEMA",
    "SHARED_EVENTS_RULE",
    "SHARED_EVENTS_VERSION",
    "STREAM_DOMAIN",
    "STRENGTH_MAX",
    "STRENGTH_MIN",
    "WINDOW",
    "EventRef",
    "Group",
    "Joined",
    "Member",
    "OwnedRandom",
    "PortfolioRefused",
    "PortfolioSimulation",
    "counted_sets",
    "limits",
    "links_between",
    "ordered_sum",
    "run",
    "shared_events",
    "substream_key",
    "tail_draws",
    "versions",
]
