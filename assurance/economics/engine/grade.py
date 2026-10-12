"""The confidence grade of a simulated scenario, with its reason (MVP step 8;
``docs/economics/spec-v1.md``, section 26.2; the owner's specification, section 8).

A grade says how much of an estimate rests on evidence and how much on
assumption. It is computed from the run's EVIDENCE MIX: the share of the result's
uncertainty that rests on each class of source, each parameter weighted by its
sensitivity importance (:mod:`.sensitivity`) and never by a raw count -- a
negligible expert guess beside a dominant customer figure is not half the
evidence. A parameter derived across several effects' attributes (the builder's
larger loss) rests on its contributors: its importance is shared equally among
their source types.

Then the downgrades of spec-v1 (section 12.5's rule: each lowers the grade one
step, A to B to C to D, never below D), each firing at most once:

- ``stale_inputs``: a figure the gross cash reads is past its ``fresh_until`` at
  the run's as-of date;
- ``expert_ranges``: a material parameter (importance at least
  :data:`MATERIAL_IMPORTANCE`) draws from an expert range (a PERT or triangular:
  section 23.1 says it should lower the grade);
- ``derived_values``: a material parameter is a derived larger-loss value.

``Unknown`` -- Mythos cannot responsibly quantify the scenario -- where the run
was refused (a refusal for conflicting inputs says so), or a cash component is
unknown (the cash figure would read "at least").

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

VERSION = "mythos.economics.confidence-grade/v1"

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
#: A parameter is material, for the expert and derived downgrades, where its
#: importance is at least this. With :data:`.sensitivity.MAX_SWINGS` at 20, no
#: parameter beyond the twentieth can reach it (twenty-one at 1/20 would sum past 1).
MATERIAL_IMPORTANCE = Decimal("0.05")

STALE = "stale_inputs"
EXPERT = "expert_ranges"
DERIVED = "derived_values"
DOWNGRADES: Mapping[str, str] = MappingProxyType(
    {
        STALE: "a figure the gross cash reads is past its fresh_until at the run's as-of date",
        EXPERT: "a material parameter draws from an expert range (PERT or triangular)",
        DERIVED: "a material parameter is a derived larger-loss value across several effects' attributes",
    }
)
#: Refusals that mean the inputs conflict (owner's specification, section 27:
#: surfaced, never resolved by silently taking one).
CONFLICTS = frozenset(
    {"distribution_contradicts_range", "derived_malformed", "currency_mismatch", "duplicate_id", "spine_effect_inconsistent"}
)

IMPORTANCE = "importance"
EQUAL = "equal"
_CONTEXT = Context(prec=60, rounding=ROUND_HALF_EVEN)
_SHARE_QUANTUM = Decimal("0.000001")


def version_record() -> dict:
    """Everything a grade depends on besides its inputs: the classes, the
    thresholds, the materiality and the downgrades. Its digest is the grade's
    version digest."""
    return {
        "version": VERSION,
        "classes": {source.value: name for source, name in CLASSES.items()},
        "evidence": sorted(EVIDENCE),
        "assumption": sorted(ASSUMPTION),
        "thresholds": {
            grade.value: {key: None if value is None else decimal_text(value) for key, value in rule.items()}
            for grade, rule in THRESHOLDS.items()
        },
        "below_c": ConfidenceGrade.D.value,
        "material_importance": decimal_text(MATERIAL_IMPORTANCE),
        "downgrades": dict(DOWNGRADES),
        "downgrade_step": "each fires at most once and lowers the grade one step, never below D (spec-v1 12.5)",
        "conflicts": sorted(CONFLICTS),
    }


def version_digest() -> str:
    text = json.dumps(version_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Weighted:
    """One parameter as the grade reads it: the source types its draws rest on
    (its own, or each contributor's), its importance, and whether it draws from an
    expert range or is a derived value."""

    name: str
    sources: tuple[SourceType, ...]
    importance: Decimal
    expert: bool = False
    derived: bool = False

    def __post_init__(self):
        sources = tuple(SourceType(s) for s in self.sources)
        if not sources:
            raise ValueError(f"{self.name} rests on no source")
        object.__setattr__(self, "sources", sources)
        if not isinstance(self.importance, Decimal) or not self.importance.is_finite() or self.importance < 0:
            raise ValueError(f"{self.name}'s importance is a finite Decimal at or above zero")


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

    def as_dict(self) -> dict:
        return {
            "grade": self.grade.value,
            "base_grade": None if self.base is None else self.base.value,
            "reason": self.reason,
            "weighting": self.weighting,
            "evidence_mix": dict(self.shares),
            "downgrades": [{"rule": rule, "meaning": DOWNGRADES[rule]} for rule in self.downgrades],
            "stale_parameters": list(self.stale),
            "material_expert_parameters": list(self.expert),
            "material_derived_parameters": list(self.derived),
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
) -> Grade:
    """The grade of one run. ``refusal`` is the run's refusal code, or ``None``
    for a completed run; ``unknown_cash_components`` names every cash component
    the run could not compute; ``weighted`` is every parameter the gross cash
    reads, with its importance; ``stale`` names every such figure past its
    ``fresh_until``. See the module's rules."""
    if refusal is not None:
        if refusal in CONFLICTS:
            return _unknown(f"the inputs conflict ({refusal}): the run was refused, and nothing is quantified")
        return _unknown(f"the run was refused ({refusal}), and nothing is quantified")
    unknown = sorted(unknown_cash_components)
    items = list(weighted)
    if not items:
        if unknown:
            return _unknown(_incomplete(unknown))
        return _unknown("the gross cash reads no parameter")
    total = sum((Fraction(item.importance) for item in items), Fraction(0))
    weighting = IMPORTANCE
    weights = {item.name: Fraction(item.importance) for item in items}
    if total == 0:
        # Nothing in the run is uncertain (or the output never moves): no
        # parameter contributes to the variance, so each counts alike.
        weighting = EQUAL
        weights = {item.name: Fraction(1) for item in items}
        total = Fraction(len(items))
    by_class = dict.fromkeys(CLASS_ORDER, Fraction(0))
    for item in items:
        share = weights[item.name] / total / len(item.sources)
        for source in item.sources:
            by_class[CLASSES[source]] += share
    evidence = sum((by_class[name] for name in EVIDENCE), Fraction(0))
    assumption = sum((by_class[name] for name in ASSUMPTION), Fraction(0))
    base = base_grade(evidence, assumption)

    def material(item: Weighted) -> bool:
        if weighting == EQUAL:
            return True
        return weights[item.name] / total >= Fraction(MATERIAL_IMPORTANCE)

    stale_names = tuple(sorted(set(stale)))
    expert_names = tuple(sorted(item.name for item in items if item.expert and material(item)))
    derived_names = tuple(sorted(item.name for item in items if item.derived and material(item)))
    fired = tuple(
        rule for rule, names in ((STALE, stale_names), (EXPERT, expert_names), (DERIVED, derived_names)) if names
    )
    final = downgraded(base, len(fired))
    shares = {
        name: decimal_text(_CONTEXT.divide(Decimal(value.numerator), Decimal(value.denominator)).quantize(_SHARE_QUANTUM))
        for name, value in by_class.items()
    }
    if unknown:
        # The evidence mix is shown; the grade is not given to an incomplete figure.
        return _unknown(_incomplete(unknown), weighting, shares)
    weighed = "by sensitivity importance" if weighting == IMPORTANCE else "equally: nothing in the run is uncertain"
    reason = (
        f"{final.value}: weighed {weighed}, {_percent(evidence)}% of the result rests on customer, observed or "
        f"authoritative figures, {_percent(by_class['benchmark'] + by_class['calculated'])}% on benchmarks or "
        f"calculated values and {_percent(assumption)}% on expert or unsourced estimates, which is {base.value}"
    )
    if fired:
        details = {STALE: stale_names, EXPERT: expert_names, DERIVED: derived_names}
        reason += "; lowered " + ", ".join(f"one step for {rule} ({', '.join(details[rule])})" for rule in fired)
    return Grade(final, base, reason, weighting, shares, fired, stale_names, expert_names, derived_names)


__all__ = [
    "ASSUMPTION",
    "CLASSES",
    "CONFLICTS",
    "DERIVED",
    "DOWNGRADES",
    "EVIDENCE",
    "EXPERT",
    "MATERIAL_IMPORTANCE",
    "STALE",
    "THRESHOLDS",
    "VERSION",
    "Grade",
    "Weighted",
    "base_grade",
    "grade",
    "version_digest",
    "version_record",
]
