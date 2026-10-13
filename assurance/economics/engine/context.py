"""What step 11's sources may do, and what they never do (MVP step 11;
``docs/economics/spec-v1.md``, section 31.5).

The specification (section 10) says what each family is FOR: a cloud price catalog
is evidence for a recovery, rebuild, hosting or control cost; a public company's
filings for its revenue and margin; a regulator's enforcement for scenario
precedent and remediation context -- "never automatic penalty prediction". So
three rules, CONTEXT ONLY:

- **A prefill is a suggestion a person accepts.** :func:`suggest_cloud_cost` and
  :func:`suggest_from_facts` turn a stored version's records into a
  :class:`Suggestion`: a low, base and high for ONE parameter-set variable the
  source may prefill (:data:`PREFILL_TARGETS`), as an ``EXPERT_ESTIMATE`` entry whose
  evidence names the snapshot version (``financial-source:<key> v<n> <hash>``).
  A suggestion is not a parameter, and nothing here writes one: a person accepts it
  by recording it in a parameter-set version, signed in. A figure resting on a
  cloud price or an EDGAR fact any other way -- another source type, another
  variable, a scenario parameter, a version no person recorded -- is refused
  (``prefill_not_accepted``; :func:`citation_refusal`, :func:`rests_on_prefill`).
  EDGAR figures prefill only a company whose shares are listed
  (``suggestion_not_public``).
- **Context is never a figure.** A figure whose evidence cites or names an
  enforcement listing, a filing watch or segment revenue is refused
  (``context_only_source``): an enforcement amount never becomes a fine or penalty
  figure, and so never reaches a loss component, which computes only from cited
  figures.
- **Precedent is listed, with its citation.** :func:`precedent_entry` is one
  enforcement record as a scenario lists it: the agency, date, respondent,
  category, the amounts the listing STATED (as text, labelled as stated), and the
  citation -- with :data:`PRECEDENT_STATEMENT`.

Pure: no Django, no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_HALF_EVEN, Decimal
from types import MappingProxyType

from . import catalogs
from .feeds import EVIDENCE_PREFIX, MALFORMED_REFERENCE, feed_reference
from .money import MoneyRefused, compute, decimal_text, parse_decimal
from .parameter_set import EVIDENCE_REF_MAX, VARIABLES
from .provenance import SourceType

#: Every code the context rules refuse with.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "context_only_source": (
            "an enforcement record, a filing watch or segment revenue is context only (spec, section 31.5): a figure "
            "never rests on one, names one in its evidence or takes an amount from one, so no enforcement amount is "
            "ever a fine or penalty figure or reaches a loss"
        ),
        "prefill_not_accepted": (
            "a figure resting on a cloud price or an EDGAR fact is a person's accepted suggestion: an EXPERT_ESTIMATE "
            "variable of a parameter-set version a signed-in person records, for a variable that source may prefill "
            "(spec, section 31.5); never a scenario parameter, another source type, or a version no person recorded"
        ),
        "suggestion_target_unrecognised": "the variable is not one this source may prefill",
        "suggestion_source_unrecognised": "the source is not a step-11 source that may prefill a figure",
        "suggestion_observation_missing": "an observation the suggestion names is not in the version it reads",
        "suggestion_units_differ": "the observations a suggestion rests on are priced in different units",
        "suggestion_quantity_malformed": (
            "a cloud cost suggestion takes the quantity the person expects, a plain positive decimal, in the "
            "observations' unit"
        ),
        "suggestion_not_public": (
            "EDGAR figures prefill a public company's only: its filing watch names a ticker on an exchange"
        ),
        "suggestion_out_of_range": (
            "the figures make no parameter: a negative operating margin, or no complete annual period"
        ),
        "suggestion_malformed": "the suggestion route's query names one source, one target and what it rests on",
        # Review round 1 of #165 (MEDIUM-3, MEDIUM-4; the lead's decisions).
        "licence_restricts_redistribution": (
            "the source's licence class does not allow its raw values to be redistributed (restricted, licensed): "
            "its provenance is served -- source, version, snapshot hash, date, and for an enforcement record the "
            "agency, date and citation -- never a value, an amount or its text"
        ),
        "prefill_version_unknown": (
            "a figure accepted from a prefill names the source version it was accepted from, by number and snapshot "
            "hash, and no stored version of that source is that one: the evidence is never taken on trust"
        ),
    }
)

#: The licence classes whose raw values may be served to a viewer: ``open`` (its terms
#: allow redistributing it) and ``customer`` (the customer's own data). ``restricted``
#: and ``licensed`` serve provenance only (the lead's interim decision, held for the
#: owner); ``unreviewed`` serves nothing.
SERVES_VALUES = frozenset({"open", "customer"})


def serves_values(license_class) -> bool:
    """Whether a version of ``license_class`` may have its raw values served to a viewer."""
    return license_class in SERVES_VALUES


#: The accepted version a prefill figure names: ``financial-source:<key> v<n> sha256:<hex>``,
#: as a suggestion's entry writes it.
_ACCEPTED = re.compile(r"financial-source:([a-z0-9][a-z0-9-]*) v([1-9][0-9]{0,8}) (sha256:[0-9a-f]{64})(?:\s|$)")


def accepted_version(evidence_ref) -> tuple[str, int, str] | None:
    """``(key, version, snapshot hash)`` of the version a prefill figure's evidence names
    it was accepted from, or ``None`` where it names none in that form."""
    match = _ACCEPTED.match(evidence_ref) if isinstance(evidence_ref, str) else None
    if match is None:
        return None
    return match.group(1), int(match.group(2)), match.group(3)

#: What a suggestion is, said wherever one is shown.
SUGGESTION_STATEMENT = (
    "a suggestion, not a parameter: nothing has been recorded. A person accepts it by recording the entry in a "
    "parameter-set version, signed in; until then no run reads it"
)
#: What a precedent is, said wherever one is listed.
PRECEDENT_STATEMENT = (
    "context only: a regulator's published action, listed as precedent with its citation. It is never a fine or "
    "penalty figure, never a prediction of one, and never summed into a loss; its amounts are as the listing stated "
    "them"
)

#: The parameter-set variables each kind of prefill source may suggest, with the unit
#: each takes: a cloud price suggests a control or recovery cost; an EDGAR fact the
#: company's revenue and operating margin.
CLOUD_COST_TARGETS: Mapping[str, str] = MappingProxyType(
    {"remediation_license_cost_per_year": "money_per_year", "vendor_exit_cost": "money_per_unit"}
)
EDGAR_TARGETS: Mapping[str, str] = MappingProxyType({"annual_revenue": "money_per_year", "operating_margin": "ratio"})
PREFILL_TARGETS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {catalogs.CLOUD_PRICE: CLOUD_COST_TARGETS, catalogs.COMPANY_FACT: EDGAR_TARGETS}
)
#: The most observations one cloud cost suggestion rests on.
MAX_PICKS = 10
#: How many fiscal years an EDGAR suggestion reads (the newest is the base).
EDGAR_YEARS = 3
#: An annual period, in days (a 52- or 53-week fiscal year included).
ANNUAL_DAYS = (350, 380)
CENT = Decimal("0.01")
RATIO_PLACES = Decimal("0.0001")

_CONTEXT_EDGAR = re.compile(r"sec-edgar-(submissions|segments)-cik[0-9]{10}")


class SuggestionRefused(ValueError):
    """A suggestion the rules refuse. ``code`` is one of :data:`REFUSALS` (or a
    governance code: the version's licence)."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS.get(code, code)}{suffix}")


# --------------------------------------------------------------- the citation rule


def context_keys() -> tuple[str, ...]:
    """The keys of every static context-only source (enforcement listings)."""
    return tuple(sorted(key for key, feed in catalogs.CATALOG_REGISTRY.items() if feed.use == catalogs.CONTEXT))


def cited_source(evidence_ref):
    """The step-11 source ``evidence_ref`` cites as ``financial-source:<key>``, or
    ``None``."""
    key = feed_reference(evidence_ref)
    if key is None or key == MALFORMED_REFERENCE:
        return None
    return catalogs.known(key)


def citation_refusal(evidence_ref, *, name: str, source_type, in_parameter_set: bool) -> tuple[str, str] | None:
    """Why a figure ``name`` of ``source_type`` whose evidence is ``evidence_ref`` may
    not be recorded, as ``(code, detail)``, or ``None``:

    - its evidence NAMES a context-only source anywhere -- an enforcement listing's
      key, an EDGAR filing watch's or segment source's, in any case, cited or not:
      ``context_only_source``;
    - it CITES a prefill source (a cloud price catalog, EDGAR companyfacts) and is not
      an ``EXPERT_ESTIMATE`` parameter-set variable that source may prefill:
      ``prefill_not_accepted``.

    Whether a PERSON recorded the version is :func:`rests_on_prefill`'s to ask, of
    the version."""
    text = evidence_ref if isinstance(evidence_ref, str) else ""
    lowered = text.lower()
    for key in context_keys():
        if key in lowered:
            return "context_only_source", f"{name} names {key}"
    found = _CONTEXT_EDGAR.search(lowered)
    if found is not None:
        return "context_only_source", f"{name} names {found.group(0)}"
    feed = cited_source(text)
    if feed is None or feed.use != catalogs.PREFILL:
        return None
    targets = PREFILL_TARGETS.get(feed.kind, {})
    if not in_parameter_set or name not in targets:
        return "prefill_not_accepted", f"{name} may not rest on {feed.key}: it prefills {sorted(targets)} only"
    if str(getattr(source_type, "value", source_type)) != SourceType.EXPERT_ESTIMATE.value:
        return "prefill_not_accepted", f"{name} rests on {feed.key} as {source_type}, not as an accepted EXPERT_ESTIMATE"
    named = accepted_version(text)
    if named is None or named[0] != feed.key:
        return "prefill_not_accepted", (
            f"{name} cites {feed.key} without the version it was accepted from (v<n> sha256:<hash>)"
        )
    return None


def rests_on_prefill(evidence_ref) -> bool:
    """Whether ``evidence_ref`` cites a prefill source: the version holding it must be
    one a signed-in person recorded."""
    feed = cited_source(evidence_ref)
    return feed is not None and feed.use == catalogs.PREFILL


# ----------------------------------------------------------------- suggestions


@dataclass(frozen=True)
class Suggestion:
    """A low, base and high for one parameter-set variable, read from one stored
    version of one prefill source: NOT a parameter (:data:`SUGGESTION_STATEMENT`)."""

    target: str
    unit: str
    currency: str | None
    low: Decimal
    base: Decimal
    high: Decimal
    source_key: str
    version: int
    snapshot_hash: str
    effective_date: date
    basis: str
    rests_on: tuple[Mapping, ...]

    @property
    def evidence_ref(self) -> str:
        """The accepted entry's evidence: the snapshot version it was read from, by
        key, version and hash, and how."""
        text = f"{EVIDENCE_PREFIX}{self.source_key} v{self.version} {self.snapshot_hash} accepted suggestion: {self.basis}"
        return text[:EVIDENCE_REF_MAX]

    def entry(self) -> dict:
        """The parameter-set entry a person records to accept it, as the
        parameter-set document spells one."""
        entry = {
            "unit": self.unit,
            "low": decimal_text(self.low),
            "base": decimal_text(self.base),
            "high": decimal_text(self.high),
            "source_type": SourceType.EXPERT_ESTIMATE.value,
            "evidence_ref": self.evidence_ref,
            "effective_date": self.effective_date.isoformat(),
        }
        if self.currency is not None:
            entry["currency"] = self.currency
        return entry

    def as_dict(self) -> dict:
        return {
            "status": "suggestion",
            "statement": SUGGESTION_STATEMENT,
            "target": self.target,
            "variable": f"variables.{self.target}",
            "entry": self.entry(),
            "source": {"key": self.source_key, "version": self.version, "snapshot_hash": self.snapshot_hash},
            "basis": self.basis,
            "rests_on": [dict(item) for item in self.rests_on],
        }


def _target(kind: str, target) -> str:
    targets = PREFILL_TARGETS.get(kind)
    if targets is None:
        raise SuggestionRefused("suggestion_source_unrecognised", kind)
    if not isinstance(target, str) or target not in targets:
        raise SuggestionRefused("suggestion_target_unrecognised", f"{target!r}: this source prefills {sorted(targets)}")
    # The parameter set's own schema names the unit; the table above must agree.
    if VARIABLES[target].unit.value != targets[target]:
        raise SuggestionRefused("suggestion_target_unrecognised", f"{target} is {VARIABLES[target].unit.value}")
    return target


def _median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return compute(lambda: (ordered[middle - 1] + ordered[middle]) / 2)


def _cents(value: Decimal) -> Decimal:
    return compute(lambda: value.quantize(CENT, rounding=ROUND_HALF_EVEN))


def suggest_cloud_cost(
    target,
    picks,
    quantity,
    *,
    source_key: str,
    version: int,
    snapshot_hash: str,
    retrieved: date,
) -> Suggestion:
    """A suggested cost for ``target`` (:data:`CLOUD_COST_TARGETS`) from the prices
    ``picks`` (one to :data:`MAX_PICKS` observations of one version, priced in one
    unit), times ``quantity`` units (a decimal string: units a year for a yearly
    cost, units one exit takes for a vendor's exit cost): the lowest price for the
    low, the median for the base and the highest for the high, each rounded to the
    cent (half-even). It holds from the day the version was retrieved."""
    target = _target(catalogs.CLOUD_PRICE, target)
    picks = list(picks)
    if not 1 <= len(picks) <= MAX_PICKS or not all(isinstance(p, catalogs.PriceObservation) for p in picks):
        raise SuggestionRefused("suggestion_malformed", f"one to {MAX_PICKS} prices")
    if len({p.observation_id for p in picks}) != len(picks):
        raise SuggestionRefused("suggestion_malformed", "a price named twice")
    units = sorted({p.unit for p in picks})
    if len(units) != 1:
        raise SuggestionRefused("suggestion_units_differ", f"{units}")
    try:
        amount = parse_decimal(quantity, "quantity")
    except MoneyRefused:
        raise SuggestionRefused("suggestion_quantity_malformed", repr(quantity)[:40]) from None
    if amount <= 0:
        raise SuggestionRefused("suggestion_quantity_malformed", f"{quantity} is not positive")
    prices = [p.usd_price for p in picks]
    low, base, high = (_cents(compute(lambda v=v: v * amount)) for v in (min(prices), _median(prices), max(prices)))
    unit = CLOUD_COST_TARGETS[target]
    per = "a year" if unit == "money_per_year" else "per unit"
    return Suggestion(
        target=target,
        unit=unit,
        currency="USD",
        low=low,
        base=base,
        high=high,
        source_key=source_key,
        version=version,
        snapshot_hash=snapshot_hash,
        effective_date=retrieved,
        basis=(
            f"{decimal_text(amount)} {units[0]} {per} at the lowest, median and highest of {len(picks)} "
            f"{picks[0].provider} price(s), to the cent"
        ),
        rests_on=tuple(
            MappingProxyType(
                {"observation_id": p.observation_id, "sku": p.sku, "region": p.region, "unit": p.unit,
                 "usd_price": decimal_text(p.usd_price), "effective_date": p.effective_date.isoformat(),
                 "description": p.description}
            )
            for p in sorted(picks, key=lambda p: p.observation_id)
        ),
    )


def _annual(facts) -> dict[tuple[date, date], dict[str, catalogs.CompanyFact]]:
    """The company's annual figures (a 10-K, one fiscal year long, the company's own,
    not a segment's), by period, each concept's from its LATEST filing (a restated
    figure replaces the one first filed)."""
    periods: dict[tuple[date, date], dict[str, catalogs.CompanyFact]] = {}
    for fact in facts:
        days = (fact.period_end - fact.period_start).days
        if fact.form != "10-K" or fact.segment_axis or not ANNUAL_DAYS[0] <= days <= ANNUAL_DAYS[1]:
            continue
        held = periods.setdefault((fact.period_start, fact.period_end), {})
        known = held.get(fact.concept)
        if known is None or (fact.filed, fact.accession) > (known.filed, known.accession):
            held[fact.concept] = fact
    return periods


def _revenue(held: dict[str, catalogs.CompanyFact]) -> catalogs.CompanyFact | None:
    for concept in catalogs.REVENUE_CONCEPTS:
        if f"us-gaap:{concept}" in held:
            return held[f"us-gaap:{concept}"]
    return None


def suggest_from_facts(
    target,
    facts,
    entity,
    *,
    source_key: str,
    version: int,
    snapshot_hash: str,
) -> Suggestion:
    """A suggested ``annual_revenue`` or ``operating_margin`` from a company's
    companyfacts version, for a company whose filing watch (``entity``) shows its
    shares listed (``suggestion_not_public`` otherwise). It reads the newest
    :data:`EDGAR_YEARS` fiscal years the company filed a 10-K for: the newest is the
    base, the lowest and highest of them the low and the high. Revenue is the first
    of :data:`catalogs.REVENUE_CONCEPTS` a year reports; the margin is operating
    income over that revenue, to four places (half-even), and a negative one is
    refused (``suggestion_out_of_range``: no parameter is negative). It holds from
    the newest year's filing date."""
    target = _target(catalogs.COMPANY_FACT, target)
    if not isinstance(entity, catalogs.CompanyEntity) or not entity.listed:
        raise SuggestionRefused("suggestion_not_public", "the company's filing watch names no listed ticker")
    years = []
    for period, held in sorted(_annual(facts).items(), key=lambda item: item[0][1], reverse=True):
        revenue = _revenue(held)
        if revenue is None:
            continue
        if target == "operating_margin":
            income = held.get("us-gaap:" + catalogs.OPERATING_INCOME_CONCEPTS[0])
            if income is None:
                continue
            years.append((period, revenue, income))
        else:
            years.append((period, revenue, None))
        if len(years) == EDGAR_YEARS:
            break
    if not years:
        raise SuggestionRefused("suggestion_out_of_range", f"no complete annual period for {target}")
    if target == "annual_revenue":
        values = [revenue.value for _p, revenue, _i in years]
        if any(value < 0 for value in values):
            raise SuggestionRefused("suggestion_out_of_range", "a negative revenue")
        values = [_cents(value) for value in values]
        unit, currency, how = "money_per_year", "USD", "revenue"
    else:
        values = []
        for _period, revenue, income in years:
            if revenue.value <= 0:
                raise SuggestionRefused("suggestion_out_of_range", "no revenue to take a margin of")
            margin = compute(lambda i=income, r=revenue: (i.value / r.value).quantize(RATIO_PLACES, ROUND_HALF_EVEN))
            if margin < 0:
                raise SuggestionRefused(
                    "suggestion_out_of_range", f"an operating margin of {margin} in the year to {_period[1]}"
                )
            values.append(margin)
        unit, currency, how = "ratio", None, "operating income over revenue, to four places"
    newest = years[0]
    used = [fact for _p, revenue, income in years for fact in (revenue, income) if fact is not None]
    return Suggestion(
        target=target,
        unit=unit,
        currency=currency,
        low=min(values),
        base=values[0],
        high=max(values),
        source_key=source_key,
        version=version,
        snapshot_hash=snapshot_hash,
        effective_date=max(fact.filed for fact in (newest[1], newest[2]) if fact is not None),
        basis=f"{how} of the {len(years)} newest fiscal years filed on 10-K, the newest the base",
        rests_on=tuple(
            MappingProxyType(
                {"concept": f.concept, "period_start": f.period_start.isoformat(), "period_end": f.period_end.isoformat(),
                 "value": decimal_text(f.value), "form": f.form, "filed": f.filed.isoformat(), "accession": f.accession}
            )
            for f in sorted(used, key=lambda f: (f.period_end, f.concept))
        ),
    )


# ------------------------------------------------------------------ precedent


def families_of(feed) -> tuple[str, ...]:
    """The loss families an enforcement source gives precedent for."""
    return tuple(feed.config.get("families", ())) if feed is not None else ()


def precedent_entry(record: catalogs.EnforcementRecord, *, source_key: str, version: int) -> dict:
    """One enforcement record as a scenario lists it: context, with its citation, its
    amounts as the listing stated them (text, never a figure)."""
    return {
        "agency": record.agency,
        "date": record.action_date.isoformat(),
        "respondent": record.respondent,
        "category": record.category,
        "stated_amounts": {
            "currency": record.currency,
            **{name: None if value is None else decimal_text(value) for name, value in record.amounts().items()},
            "as": "stated by the listing, not a figure of this scenario",
        },
        "citation": {"url": record.citation_url, "text": record.citation_text},
        "source": {"key": source_key, "version": version},
    }


__all__ = [
    "CLOUD_COST_TARGETS",
    "EDGAR_TARGETS",
    "EDGAR_YEARS",
    "MAX_PICKS",
    "PRECEDENT_STATEMENT",
    "PREFILL_TARGETS",
    "REFUSALS",
    "SUGGESTION_STATEMENT",
    "Suggestion",
    "SuggestionRefused",
    "citation_refusal",
    "cited_source",
    "context_keys",
    "families_of",
    "precedent_entry",
    "rests_on_prefill",
    "suggest_cloud_cost",
    "suggest_from_facts",
]
