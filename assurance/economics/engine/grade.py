"""The confidence grade of a simulated scenario, with its reason (MVP step 8;
``docs/economics/spec-v1.md``, section 26.2; the owner's specification, section 8).

A grade says how much of an estimate rests on evidence and how much on
assumption. It is computed from a line's EVIDENCE MIX: the share of the line's
LEVEL that rests on each class of source. Each parameter the line reads is weighted
by its share of the base-case level (:func:`.sensitivity.level_shares`: an additive
decomposition at base -- each cash component's base over the total, split among its
inputs by their elasticity of it; a frequency one half), never by a raw count and
never by its variance alone, so a FIXED figure counts exactly as a range at the same
base does: an expert's $5,000,000 guess is the evidence it is whether it is stated as
one figure or as a range around it. A parameter derived across several effects'
attributes (the builder's larger loss) rests on the contributors whose base supplies
its own; its share is split equally among their source types.

Under a policy both lines are graded, the gross cash and the retained cash (whose
level reads the policy's terms too), and the HEADLINE grade is the lower of the two
(:func:`headline`): a retained figure resting on an expert's deductible is not graded
on the gross alone.

Then the downgrades of spec-v1 (section 12.5's rule: each lowers the grade one
step, A to B to C to D, never below D), each firing at most once:

- ``stale_inputs``: a figure the run reads -- a cash component's, a policy term
  where a policy applies, the frequency, or a derived value's contributor -- is
  past its ``fresh_until`` at the run's as-of date;
- ``stale_source``: such a figure rests on a feed source (its ``evidence_ref``
  names ``financial-source:<key>``, spec section 29) that is stale, blocked or
  missing at the run's as-of date; the rule names every figure each such source
  feeds;
- ``expert_figures``: a MATERIAL figure (a level share of at least
  :data:`MATERIAL_SHARE`) rests on an expert's estimate or on no named source,
  fixed or ranged;
- ``derived_values``: a material figure is a derived larger-loss value.

Collapsing a range to one figure at its base never raises the grade: the level
shares, the sources and the dates are those of the base, which a collapse keeps.

``Unknown`` -- Mythos cannot responsibly quantify the scenario -- where the run
was refused (a refusal for conflicting inputs says so), a cash component is
unknown (the cash figure would read "at least"), the line has no level to weigh (it
is zero at base, or the frequency's base is zero), or a parameter of an annual run is
drawn per occurrence (it is not ranked yet).

Every threshold is the owner's to set: they are constants here, and they and the
classes are in :func:`version_record`, whose digest every grade carries.

Pure: no Django, no numpy, no I/O.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Context, Decimal
from fractions import Fraction
from types import MappingProxyType

from .confidence import ConfidenceGrade, downgraded
from .money import decimal_text
from .provenance import SourceType

VERSION = "mythos.economics.confidence-grade/v3"

#: The class each source type counts in.
CLASSES: Mapping[SourceType, str] = MappingProxyType(
    {
        SourceType.CUSTOMER_PROVIDED: "customer",
        SourceType.MYTHOS_OBSERVED: "observed",
        SourceType.OFFICIAL_PUBLIC: "authoritative",
        SourceType.LICENSED_MARKET: "authoritative",
        SourceType.INDUSTRY_BENCHMARK: "benchmark",
        SourceType.CALCULATED: "calculated",
        SourceType.EXPERT_ESTIMATE: "expert",
        SourceType.UNKNOWN: "unsourced",
    }
)
CLASS_ORDER = ("customer", "observed", "authoritative", "calculated", "benchmark", "expert", "unsourced")
#: Evidence: the customer's own figures, Mythos's observations and current
#: authoritative external data (section 8's grade A mix).
EVIDENCE = frozenset({"customer", "observed", "authoritative"})
#: Assumption: a person's estimate, or a figure nothing names the source of.
ASSUMPTION = frozenset({"expert", "unsourced"})

#: The owner's thresholds, strongest grade first: a grade holds where the evidence
#: share is at least its floor and the assumption share at most its ceiling.
#: Below C's ceiling the grade is D. Compared exactly, as fractions.
THRESHOLDS: Mapping[ConfidenceGrade, Mapping[str, Decimal | None]] = MappingProxyType(
    {
        ConfidenceGrade.A: MappingProxyType({"evidence_at_least": Decimal("0.80"), "assumption_at_most": Decimal("0.05")}),
        ConfidenceGrade.B: MappingProxyType({"evidence_at_least": Decimal("0.50"), "assumption_at_most": Decimal("0.25")}),
        ConfidenceGrade.C: MappingProxyType({"evidence_at_least": None, "assumption_at_most": Decimal("0.50")}),
    }
)
#: A figure is material, for the expert and derived downgrades, where its share of
#: the base-case level is at least this.
MATERIAL_SHARE = Decimal("0.05")

STALE = "stale_inputs"
STALE_SOURCE = "stale_source"
EXPERT = "expert_figures"
DERIVED = "derived_values"
DOWNGRADES: Mapping[str, str] = MappingProxyType(
    {
        STALE: (
            "a figure the run reads (a cash component's, a policy term where a policy applies, the frequency, or a "
            "derived value's contributor) is past its fresh_until at the run's as-of date"
        ),
        STALE_SOURCE: (
            "a figure the run reads rests on a feed source (financial-source:<key>) that is stale, blocked or "
            "missing at the run's as-of date: past its freshness SLA, past twice it, or with no version a run may use"
        ),
        EXPERT: (
            "a material figure (a level share of at least the materiality) rests on an expert's estimate or on no "
            "named source, fixed or ranged"
        ),
        DERIVED: "a material figure is a derived larger-loss value across several effects' attributes",
    }
)
#: Refusals that mean the inputs conflict (owner's specification, section 27:
#: surfaced, never resolved by silently taking one).
CONFLICTS = frozenset(
    {"distribution_contradicts_range", "derived_malformed", "currency_mismatch", "duplicate_id", "spine_effect_inconsistent"}
)

LEVEL = "level"
#: Which grade is the card's, where a policy applies.
HEADLINE_RULE = (
    "under a policy the gross cash and the retained cash are graded apart, each by its own level, and the headline "
    "grade is the lower of the two (Unknown lowest); where they are equal, the retained cash's, the line the "
    "headline figures are. Without a policy the gross cash's grade is the headline"
)
#: Strongest first: the order :func:`headline` compares on.
ORDER = (ConfidenceGrade.A, ConfidenceGrade.B, ConfidenceGrade.C, ConfidenceGrade.D, ConfidenceGrade.UNKNOWN)
_CONTEXT = Context(prec=60, rounding=ROUND_HALF_EVEN)
_SHARE_QUANTUM = Decimal("0.000001")


def version_record() -> dict:
    """Everything a grade depends on besides its inputs: the classes, the
    thresholds, the materiality and the downgrades. Its digest is the grade's
    version digest."""
    return {
        "version": VERSION,
        "weighting": (
            "each figure's share of the base-case level: an additive decomposition at base, each cash component's "
            "base over the total split among its inputs by their elasticity of it, a frequency one half"
        ),
        "lines": HEADLINE_RULE,
        "classes": {source.value: name for source, name in CLASSES.items()},
        "evidence": sorted(EVIDENCE),
        "assumption": sorted(ASSUMPTION),
        "thresholds": {
            grade.value: {key: None if value is None else decimal_text(value) for key, value in rule.items()}
            for grade, rule in THRESHOLDS.items()
        },
        "below_c": ConfidenceGrade.D.value,
        "material_share": decimal_text(MATERIAL_SHARE),
        "downgrades": dict(DOWNGRADES),
        "downgrade_step": "each fires at most once and lowers the grade one step, never below D (spec-v1 12.5)",
        "conflicts": sorted(CONFLICTS),
    }


def version_digest() -> str:
    text = json.dumps(version_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Weighted:
    """One figure as the grade reads it: the source types it rests on (its own,
    or those of the contributors that supply a derived value's base), its share of
    the base-case level, and whether it is a derived value."""

    name: str
    sources: tuple[SourceType, ...]
    level: Decimal
    derived: bool = False

    def __post_init__(self):
        sources = tuple(SourceType(s) for s in self.sources)
        if not sources:
            raise ValueError(f"{self.name} rests on no source")
        object.__setattr__(self, "sources", sources)
        if not isinstance(self.level, Decimal) or not self.level.is_finite() or self.level < 0:
            raise ValueError(f"{self.name}'s level share is a finite Decimal at or above zero")


@dataclass(frozen=True)
class Grade:
    grade: ConfidenceGrade
    base: ConfidenceGrade | None
    reason: str
    weighting: str | None
    shares: Mapping[str, str] = field(default_factory=dict)
    downgrades: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    expert: tuple[str, ...] = ()
    derived: tuple[str, ...] = ()
    unknown_because: str | None = None
    stale_sources: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "grade": self.grade.value,
            "base_grade": None if self.base is None else self.base.value,
            "reason": self.reason,
            "weighting": self.weighting,
            "evidence_mix": dict(self.shares),
            "downgrades": [{"rule": rule, "meaning": DOWNGRADES[rule]} for rule in self.downgrades],
            "stale_parameters": list(self.stale),
            "stale_source_parameters": list(self.stale_sources),
            "material_expert_figures": list(self.expert),
            "material_derived_figures": list(self.derived),
            "unknown_because": self.unknown_because,
            "version": VERSION,
            "version_digest": version_digest(),
        }


def _unknown(why: str, weighting: str | None = None, shares: Mapping[str, str] | None = None) -> Grade:
    return Grade(ConfidenceGrade.UNKNOWN, None, f"Unknown: {why}", weighting, dict(shares or {}), unknown_because=why)


def _incomplete(unknown: list[str]) -> str:
    return (
        f"{len(unknown)} cash component(s) could not be computed ({', '.join(unknown)}): the cash figure would read "
        "only 'at least'"
    )


def _percent(share: Fraction) -> str:
    return decimal_text((Decimal(share.numerator) / Decimal(share.denominator) * 100).quantize(Decimal("0.1")))


def base_grade(evidence: Fraction, assumption: Fraction) -> ConfidenceGrade:
    """The grade the evidence mix gives before any downgrade (:data:`THRESHOLDS`)."""
    for grade, rule in THRESHOLDS.items():
        floor, ceiling = rule["evidence_at_least"], rule["assumption_at_most"]
        if floor is not None and evidence < Fraction(floor):
            continue
        if ceiling is not None and assumption > Fraction(ceiling):
            continue
        return grade
    return ConfidenceGrade.D


def grade(
    *,
    refusal: str | None,
    unknown_cash_components: Iterable[str],
    weighted: Iterable[Weighted],
    stale: Iterable[str] = (),
    per_occurrence: Iterable[str] = (),
    undefined: str | None = None,
    stale_sources: Iterable[str] = (),
) -> Grade:
    """The grade of one line of one run. ``refusal`` is the run's refusal code, or
    ``None`` for a completed run; ``unknown_cash_components`` names every cash
    component the run could not compute; ``weighted`` is every figure the line reads
    (and the frequency), with its level share; ``stale`` names every figure the run
    reads that is past its ``fresh_until``; ``stale_sources`` names every figure the
    run reads that rests on a stale, blocked or missing feed source; ``per_occurrence`` names the parameters
    of an annual run drawn per occurrence; ``undefined`` says why the line has no
    level to weigh, where it has none. See the module's rules."""
    if refusal is not None:
        if refusal in CONFLICTS:
            return _unknown(f"the inputs conflict ({refusal}): the run was refused, and nothing is quantified")
        return _unknown(f"the run was refused ({refusal}), and nothing is quantified")
    per_occurrence = sorted(per_occurrence)
    if per_occurrence:
        return _unknown(
            f"{', '.join(per_occurrence)} drawn per occurrence in an annual run: such a parameter is not ranked or "
            "weighed yet"
        )
    unknown = sorted(unknown_cash_components)
    if undefined is not None:
        return _unknown(undefined + (f"; and {_incomplete(unknown)}" if unknown else ""))
    items = list(weighted)
    total = sum((Fraction(item.level) for item in items), Fraction(0))
    if not items or total == 0:
        if unknown:
            return _unknown(_incomplete(unknown))
        return _unknown("the base-case gross cash is zero, or reads no figure: there is no level to weigh")
    by_class = dict.fromkeys(CLASS_ORDER, Fraction(0))
    for item in items:
        share = Fraction(item.level) / total / len(item.sources)
        for source in item.sources:
            by_class[CLASSES[source]] += share
    evidence = sum((by_class[name] for name in EVIDENCE), Fraction(0))
    assumption = sum((by_class[name] for name in ASSUMPTION), Fraction(0))
    shares = {
        name: decimal_text(_CONTEXT.divide(Decimal(value.numerator), Decimal(value.denominator)).quantize(_SHARE_QUANTUM))
        for name, value in by_class.items()
    }
    if unknown:
        # The evidence mix is shown; the grade is not given to an incomplete figure.
        return _unknown(_incomplete(unknown), LEVEL, shares)
    base = base_grade(evidence, assumption)

    def material(item: Weighted) -> bool:
        return Fraction(item.level) / total >= Fraction(MATERIAL_SHARE)

    stale_names = tuple(sorted(set(stale)))
    stale_source_names = tuple(sorted(set(stale_sources)))
    expert_names = tuple(
        sorted(item.name for item in items if material(item) and any(CLASSES[s] in ASSUMPTION for s in item.sources))
    )
    derived_names = tuple(sorted(item.name for item in items if item.derived and material(item)))
    fired = tuple(
        rule
        for rule, names in (
            (STALE, stale_names), (STALE_SOURCE, stale_source_names), (EXPERT, expert_names), (DERIVED, derived_names)
        )
        if names
    )
    final = downgraded(base, len(fired))
    reason = (
        f"{final.value}: weighed by each figure's share of the base-case level, {_percent(evidence)}% of the result "
        f"rests on customer, observed or authoritative figures, "
        f"{_percent(by_class['benchmark'] + by_class['calculated'])}% on benchmarks or calculated values and "
        f"{_percent(assumption)}% on expert or unsourced estimates, which is {base.value}"
    )
    if fired:
        details = {STALE: stale_names, STALE_SOURCE: stale_source_names, EXPERT: expert_names, DERIVED: derived_names}
        reason += "; lowered " + ", ".join(f"one step for {rule} ({', '.join(details[rule])})" for rule in fired)
    return Grade(
        final, base, reason, LEVEL, shares, fired, stale_names, expert_names, derived_names,
        stale_sources=stale_source_names,
    )


def headline(gross: Grade, retained: Grade | None) -> tuple[str, Grade]:
    """The headline grade (:data:`HEADLINE_RULE`) and the line it is: the lower of
    the gross cash's and the retained cash's; equal, the retained cash's. Without a
    retained grade (no policy), the gross cash's."""
    if retained is None:
        return "gross_cash", gross
    if ORDER.index(gross.grade) > ORDER.index(retained.grade):
        return "gross_cash", gross
    return "retained_cash", retained


__all__ = [
    "ASSUMPTION",
    "CLASSES",
    "CONFLICTS",
    "DERIVED",
    "DOWNGRADES",
    "EVIDENCE",
    "EXPERT",
    "HEADLINE_RULE",
    "MATERIAL_SHARE",
    "ORDER",
    "STALE",
    "STALE_SOURCE",
    "THRESHOLDS",
    "VERSION",
    "Grade",
    "Weighted",
    "base_grade",
    "grade",
    "headline",
    "version_digest",
    "version_record",
]
