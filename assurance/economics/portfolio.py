"""A deployment's portfolio: its scenarios aggregated from their draws (Economic
Exposure E5; ``docs/economics/spec-v1.md``, section 28). The thin Django half of
:mod:`assurance.economics.engine.portfolio`.

:func:`simulate_portfolio` picks, for one deployment, each current scenario
version's latest stored result and totals only those :func:`report.may_be_totalled`
admits; every other scenario is listed with its reason (:data:`EXCLUSIONS`), never
silently dropped. It normalises each included scenario into the reporting currency
at the valuation date (step 3's order), finds the loss events two scenarios share
and counts each once, draws the included scenarios again on one seed with their
correlation groups, and records a :class:`~assurance.economics.models.PortfolioResult`:

- **Idempotent on its inputs**: the included results' digests, the exclusions, the
  groups and their parameters, the normalisations, the shared events, every
  version and limit (the input digest), the seed and the draws. The same inputs
  return the row already recorded; every check runs before the transaction, which
  only inserts.
- **No transaction or lock is held during the draws** (the SAFETY RULE): every read
  is autocommit, and the one ``atomic`` block is the insert after the draws.
- **Never raises.** A refusal the inputs decide is recorded; one they do not (the
  time budget, memory, a defect, an engine that will not import) is returned and
  never recorded; a request the rows refuse (a group naming a scenario this
  deployment does not hold, a source it may not read) is returned, 400.

:func:`build_document` is the portfolio's report: built from the stored rows ONLY
(no draw, no clock, no engine), canonical JSON with its own digest, every stored
row checked first as step 6's report checks its own -- the portfolio's digests and
each included scenario's result, card and series (:func:`stored_row_failures`) --
and served as a refusal where any fails. It is graded no higher than its lowest
included scenario, lower still where an expert's or nobody's judgement sets a
group's strength (:func:`portfolio_grade`), and the banner rule applies to it.

Nothing here is on a stop path. This module imports the engine (and numpy) only
when a portfolio is simulated, never at load and never to build the document.
"""

from __future__ import annotations

import re
import time
import uuid as _uuid
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_FLOOR, ROUND_HALF_EVEN, Context, Decimal, localcontext

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from assurance.models import Deployment

from . import report
from .engine import currency as _currency
from .engine import loss as engine_loss
from .engine import money
from .engine import parameter_set as pset
from .engine.confidence import ConfidenceGrade, downgraded
from .engine.money import Money, MoneyRefused, decimal_text
from .engine.parameters import POINTS, ParameterRefused
from .engine.provenance import SourceType
from .models import (
    SIMULATION_COMPLETED,
    SIMULATION_REFUSED,
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    FinancialScenario,
    FinancialSource,
    FinancialValidityCard,
    LossEvent,
    PortfolioResult,
    ScenarioBuild,
    SimulationCharts,
    SimulationResult,
    SourceNotUsableForProduction,
    canonical_digest,
)

#: The schema of the canonical inputs, and of the portfolio's report.
INPUTS_SCHEMA = "mythos.economics.portfolio-inputs/v1"
REPORT_SCHEMA = "mythos.economics.portfolio-report/v1"
#: Which scenarios a portfolio totals, and which result of each.
SELECTION_VERSION = "mythos.economics.portfolio-selection/v1"
SELECTION = (
    "every scenario version of the deployment that no other version supersedes; of each, its latest stored "
    "simulation result by record order (the one results/ serves without ?simulation=), never an older one in its "
    "place; included only where report.may_be_totalled admits that result's report (its own digest, a completed "
    "run, every stored row verified, graded A to D), the run is annual (it states a frequency), its stored rows "
    "still give its inputs, and its amounts normalise into the reporting currency at the valuation date. Every "
    "other version is listed with its reason"
)
#: The grade rule.
GRADE_RULE = (
    "no higher than the lowest included scenario's grade, each first lowered one step for every downgrade its "
    "normalisation carries (an estimated or stale rate or index, section 12.5); then one step lower, once, where "
    "the strength of a group that applies to an included scenario rests on EXPERT_ESTIMATE or UNKNOWN; never below D"
)
#: A group strength resting on one of these lowers the grade (section 26.2's rule).
ASSUMPTION_SOURCES = frozenset({SourceType.EXPERT_ESTIMATE.value, SourceType.UNKNOWN.value})
#: The one deadline of a portfolio request: step 6's.
TIME_BUDGET_SECONDS = 120.0
#: Refusals the inputs do not decide: returned, never recorded (503).
UNRECORDED = frozenset(
    {"time_over_budget", "memory_exhausted", "invariant_broken", "engine_unavailable", "simulation_failed"}
)
#: Why a scenario version is not in a portfolio's figures.
EXCLUSIONS = {
    "superseded": "a later version of the same scenario supersedes this one: the later version is the one totalled",
    "no_result": "no simulation result is recorded for this scenario version",
    "unverified": "its latest result's stored rows fail a check: none of its figures is evidence",
    "refused": "its latest run was refused: it has no figures",
    "no_card": "its latest result has no Validity Card: it is not graded",
    "unknown": "its latest result is graded Unknown: not for capital decisions",
    "not_totalled": "report.may_be_totalled refuses its latest result's report",
    "no_annual_loss": (
        "its run states no frequency: a draw is one occurrence, not a simulated year, so it has no annual loss to sum"
    ),
    "inputs_changed": "its stored rows no longer give the inputs its latest result was run on",
    "currency_unnormalisable": "its amounts cannot be normalised into the reporting currency at the valuation date",
}
#: The checks :func:`stored_row_failures` runs, in order.
INTEGRITY_CHECKS = ("input_digest", "result_digest", "member_rows")
#: The lines a portfolio sums, in this order (the engine's).
LINES = ("gross_cash", "retained_cash")
#: What a portfolio is not, stated in every one.
LIMITATIONS = (
    "a total of the deployment's current scenario versions whose latest result may be totalled; every other is "
    "listed with its reason and is not in the figures, which then read as at least the included scenarios' loss",
    "dependence only through the correlation groups declared: one common Gamma driver of each group's annual rates; "
    "no copula, no dependence between severities; scenarios in different groups, or in none, are independent, and "
    "a customer figure two scenarios read is drawn apart in each",
    "a group's driver also widens each member's own count of events a year (the mixed rate is over-dispersed); "
    "it keeps the mean",
    "a shared loss event is found by SPINE effect and step 5's grouping key and window; events of hypothetical "
    "effects alone are matched by key; the event counted is the largest at base, not re-built at the larger loss "
    "of every effect it joins",
    "each scenario is normalised by one factor, its as-of date to the valuation date in step 3's order; currency "
    "and index uncertainty are not in the figures",
    "market value is never added to cash and is not aggregated; insurance is each scenario's own, applied per event "
    "occurrence, and no limit is shared across scenarios",
    "a portfolio is graded no higher than its lowest included scenario and lower where an expert sets a group's "
    "strength; nothing here is calibrated against realised losses",
    "a portfolio graded Unknown, refused or unverified is not for capital decisions and is excluded from every total",
)

_GROUP_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,59}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_REQUEST_REQUIRED = frozenset({"seed", "reporting_currency", "valuation_date"})
_REQUEST_OPTIONAL = frozenset({"policy", "normalization", "groups"})
_GROUP_FIELDS = frozenset({"group", "strength", "source_type", "evidence_ref", "scenarios"})
_NORMALIZATION_REQUIRED = frozenset({"base_currency", "providers", "index", "sources"})
_NORMALIZATION_OPTIONAL = frozenset({"index_max_lag_months"})
_INDEX_FIELDS = frozenset({"series_id", "geography", "category", "base"})
#: The most FX providers and sources a normalisation names, and its largest lag.
MAX_PROVIDERS = 5
MAX_SOURCES = 10
MAX_INDEX_LAG_MONTHS = 12
MAX_EVIDENCE = 500


class PortfolioRequestRefused(ValueError):
    """A portfolio request refused before anything is drawn or recorded (400)."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


# ------------------------------------------------------------------ the request


@dataclass(frozen=True)
class GroupRequest:
    key: str
    strength: Decimal
    source_type: str
    evidence_ref: str
    scenarios: tuple[str, ...]


@dataclass(frozen=True)
class NormalizationRequest:
    base_currency: str
    providers: tuple[str, ...]
    index: tuple[str, str, str, str]
    index_max_lag_months: int
    sources: tuple[str, ...]


@dataclass(frozen=True)
class PortfolioRequest:
    seed: int
    policy: str
    draws: int
    severe_percentile: Decimal
    reporting_currency: str
    valuation_date: date
    normalization: NormalizationRequest | None
    groups: tuple[GroupRequest, ...]


def _refused(code: str, detail: str) -> PortfolioRequestRefused:
    return PortfolioRequestRefused(code, detail)


def _object(value, path: str, required: frozenset, optional: frozenset = frozenset()) -> dict:
    try:
        return pset._object(value, path, required, optional)
    except ParameterRefused as refused:
        raise _refused(refused.code, refused.detail) from None


def _text(value, path: str, *, longest: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > longest:
        raise _refused("field_malformed", f"{path} is text of 1 to {longest} characters")
    return value


def _currency_code(value, path: str) -> str:
    if not isinstance(value, str):
        raise _refused("field_malformed", f"{path} is a currency code")
    try:
        money.check_reporting_currency(value, path)
    except MoneyRefused as refused:
        raise _refused(refused.code, refused.detail) from None
    return value


def _uuids(value, path: str, *, most: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= most:
        raise _refused("field_malformed", f"{path} is a list of 1 to {most} uuids")
    if any(not isinstance(item, str) or not _UUID.fullmatch(item) for item in value) or len(set(value)) != len(value):
        raise _refused("field_malformed", f"{path} names each uuid once, lowercase and hyphenated")
    return tuple(value)


def _normalization(value) -> NormalizationRequest:
    body = _object(value, "normalization", _NORMALIZATION_REQUIRED, _NORMALIZATION_OPTIONAL)
    providers = body["providers"]
    if not isinstance(providers, list) or not 1 <= len(providers) <= MAX_PROVIDERS:
        raise _refused("field_malformed", f"normalization.providers is a list of 1 to {MAX_PROVIDERS} providers")
    providers = tuple(_text(p, "normalization.providers[]") for p in providers)
    if len(set(providers)) != len(providers):
        raise _refused("field_malformed", "normalization.providers names each provider once")
    index = _object(body["index"], "normalization.index", _INDEX_FIELDS)
    lag = body.get("index_max_lag_months", 0)
    if type(lag) is not int or not 0 <= lag <= MAX_INDEX_LAG_MONTHS:
        raise _refused("field_malformed", f"normalization.index_max_lag_months is 0 to {MAX_INDEX_LAG_MONTHS}")
    return NormalizationRequest(
        base_currency=_currency_code(body["base_currency"], "normalization.base_currency"),
        providers=providers,
        index=tuple(_text(index[name], f"normalization.index.{name}") for name in
                    ("series_id", "geography", "category", "base")),
        index_max_lag_months=lag,
        sources=_uuids(body["sources"], "normalization.sources", most=MAX_SOURCES),
    )


def _groups(value) -> tuple[GroupRequest, ...]:
    from .engine import portfolio as ep

    if not isinstance(value, list) or len(value) > ep.MAX_GROUPS:
        raise _refused("group_malformed", f"groups is a list of at most {ep.MAX_GROUPS} groups")
    groups, seen, keys = [], set(), set()
    for at, item in enumerate(value):
        path = f"groups[{at}]"
        body = _object(item, path, _GROUP_FIELDS)
        key = body["group"]
        if not isinstance(key, str) or not _GROUP_KEY.fullmatch(key) or key in keys:
            raise _refused("group_malformed", f"{path}.group is a key of its own: 1 to 60 of a-z, 0-9, '-' and '_'")
        keys.add(key)
        try:
            strength = money.parse_decimal(body["strength"], f"{path}.strength")
        except MoneyRefused as refused:
            raise _refused("group_malformed", refused.detail) from None
        if not Decimal(0) < strength <= ep.STRENGTH_MAX:
            raise _refused("group_malformed", f"{path}.strength is above 0 and at most {ep.STRENGTH_MAX}")
        source = body["source_type"]
        if not isinstance(source, str) or source not in {t.value for t in SourceType}:
            raise _refused("group_malformed", f"{path}.source_type is one of {sorted(t.value for t in SourceType)}")
        scenarios = _uuids(body["scenarios"], f"{path}.scenarios", most=ep.MAX_SCENARIOS)
        twice = sorted(seen & set(scenarios))
        if twice:
            raise _refused("group_malformed", f"a scenario is in one group at most: {twice}")
        seen.update(scenarios)
        groups.append(GroupRequest(key, strength, source, _text(body["evidence_ref"], f"{path}.evidence_ref",
                                                                 longest=MAX_EVIDENCE), tuple(sorted(scenarios))))
    return tuple(sorted(groups, key=lambda g: g.key))


def parse_request(body, *, policies, parse_seed) -> PortfolioRequest:
    """A portfolio request read exactly, or refused: the seed and the policy as a
    scenario's simulate request reads them (``parse_seed``, step 6's), the reporting
    currency, the valuation date, and optionally a normalisation and the groups."""
    body = _object(body, "body", _REQUEST_REQUIRED, _REQUEST_OPTIONAL)
    seed, policy, _ = parse_seed({"seed": body["seed"], **({"policy": body["policy"]} if "policy" in body else {})})
    try:
        valuation_date = pset._date(body["valuation_date"], "valuation_date")
    except MoneyRefused as refused:
        raise _refused(refused.code, refused.detail) from None
    normalization = None if body.get("normalization") is None else _normalization(body["normalization"])
    return PortfolioRequest(
        seed=seed,
        policy=policy,
        draws=policies[policy]["draws"],
        severe_percentile=policies[policy]["severe_percentile"],
        reporting_currency=_currency_code(body["reporting_currency"], "reporting_currency"),
        valuation_date=valuation_date,
        normalization=normalization,
        groups=_groups(body.get("groups", [])),
    )


# ------------------------------------------------------------------ the outcome


@dataclass(frozen=True)
class PortfolioOutcome:
    """What :func:`simulate_portfolio` gives: the recorded result (``None`` when
    nothing was recorded), whether this call recorded it, and the code and detail of
    a refusal; ``refused_request`` where the request itself was refused (400)."""

    result: PortfolioResult | None
    created: bool
    code: str | None = None
    detail: str = ""
    refused_request: bool = False


def _exclusion(scenario: FinancialScenario, code: str, reason: str, result: SimulationResult | None = None) -> dict:
    return {
        "scenario": str(scenario.uuid),
        "title": scenario.title,
        "result": None if result is None else str(result.uuid),
        "code": code,
        "meaning": EXCLUSIONS[code],
        "reason": reason,
    }


def _report_exclusion(document: dict) -> str:
    """Which exclusion a report :func:`report.may_be_totalled` refuses names, in the
    order :func:`report.banner_reason` gives its reasons."""
    if not (document.get("integrity") or {}).get("verified", False) or not report.verifies(document):
        return "unverified"
    if document.get("status") != SIMULATION_COMPLETED:
        return "refused"
    if document.get("grade") is None:
        return "no_card"
    if document.get("grade") == report.UNKNOWN:
        return "unknown"
    return "not_totalled"


@dataclass
class _Normalizer:
    """The normalisation of one unit of a scenario's currency at its as-of date into
    the reporting currency at the valuation date, or why there is none."""

    request: PortfolioRequest
    policy: object | None = None
    fx_book: object | None = None
    index_book: object | None = None
    sources: list | None = None

    def factor(self, currency: str, as_of: date | None) -> tuple[dict | None, str | None]:
        reporting, valuation = self.request.reporting_currency, self.request.valuation_date
        if as_of is None:
            return None, "no build records the date its amounts are as of"
        if currency == reporting and as_of == valuation:
            return {"rule": "identity", "factor": "1", "downgrades": [], "record": None}, None
        if self.policy is None:
            return None, (
                f"its amounts are in {currency} as of {as_of.isoformat()}, not in {reporting} at "
                f"{valuation.isoformat()}, and the request names no normalisation policy"
            )
        from .engine.normalization import UNAVAILABLE, normalize

        try:
            normalized = normalize(
                Money(Decimal(1), currency), event_date=as_of, valuation_date=valuation, policy=self.policy,
                fx_book=self.fx_book, index_book=self.index_book,
            )
        except MoneyRefused as refused:
            return None, f"{refused.code}: {refused.detail}"
        if normalized.status == UNAVAILABLE:
            unavailable = normalized.unavailable
            return None, f"{unavailable.reason} at {unavailable.step}: {unavailable.detail}"
        return {
            "rule": "normalized",
            "factor": decimal_text(normalized.value.amount),
            "downgrades": list(normalized.confidence_downgrades),
            "record": normalized.as_dict(),
        }, None


def _normalizer(deployment, request: PortfolioRequest) -> _Normalizer:
    """The request's normalisation policy and the books of the sources it names, each
    one this deployment may read and a production run may use; refused (400)
    otherwise."""
    wanted = request.normalization
    if wanted is None:
        return _Normalizer(request)
    from .engine.cost_index import IndexSelector
    from .engine.fx import FXPolicy
    from .engine.normalization import NormalizationPolicy
    from .snapshots import fx_book, index_book

    rows = {
        str(row.uuid): row
        for row in FinancialSource.objects.filter(
            Q(deployment__isnull=True) | Q(deployment=deployment), uuid__in=list(wanted.sources)
        )
    }
    missing = [u for u in wanted.sources if u not in rows]
    if missing:
        raise _refused("source_not_found", f"not a source this deployment may read: {missing}")
    sources = [rows[u] for u in wanted.sources]
    for source in sources:
        try:
            source.check_usable_for_production(deployment)
        except SourceNotUsableForProduction as refused:
            raise _refused(refused.code, refused.detail) from None
    try:
        policy = NormalizationPolicy(
            wanted.base_currency, request.reporting_currency, FXPolicy(wanted.providers),
            IndexSelector(*wanted.index, wanted.base_currency), wanted.index_max_lag_months,
        )
    except MoneyRefused as refused:
        raise _refused(refused.code, refused.detail) from None
    return _Normalizer(
        request, policy, fx_book(sources, deployment=deployment), index_book(sources, deployment=deployment),
        sources,
    )


def _event_refs(scenario: FinancialScenario, build: ScenarioBuild | None, factor: Decimal, ep) -> list:
    """Each loss event of ``scenario`` as the shared-event rule reads it, its gross
    cash at low, base and high (step 4's) normalised by ``factor``."""
    policy = None if build is None else CustomerParameterSet.objects.get(pk=build.parameter_set_id).content(
    ).insurance_policy()
    refs = []
    for row in LossEvent.objects.filter(scenario=scenario).order_by("event_key", "id"):
        assessment = engine_loss.assess(row.as_engine(), policy)
        with localcontext(Context(prec=60)):
            gross = tuple(assessment.gross.total.at(point).amount * factor for point in POINTS)
        effects = list(CausalEffect.objects.filter(scenario=scenario, loss_event=row).order_by("id"))
        keys = {(e.template_id, e.template_version, e.asset, e.business_process) for e in effects}
        refs.append(
            ep.EventRef(
                scenario=str(scenario.uuid),
                event_key=row.event_key,
                key=next(iter(keys)) if len(keys) == 1 else None,
                spine_effects=frozenset(e.spine_effect for e in effects if e.spine_effect),
                observed_at=tuple(sorted(e.occurred_at for e in effects if e.occurred_at is not None)),
                hypothetical=bool(effects) and all(e.origin == "hypothetical" for e in effects),
                gross=gross,
            )
        )
    return refs


def _engine():
    from .engine import distributions, scenario_simulation, simulation
    from .engine import portfolio as ep
    from .simulation_service import load_input

    return ep, scenario_simulation, simulation, distributions, load_input


def simulate_portfolio(deployment, request: PortfolioRequest, *, time_budget: float = TIME_BUDGET_SECONDS
                       ) -> PortfolioOutcome:
    """Total ``deployment``'s scenarios for ``request``, and record the portfolio,
    or return the one recorded for the same inputs. Never raises: see the module's
    rules."""
    try:
        return _simulate(deployment, request, time_budget)
    except PortfolioRequestRefused as refused:
        return PortfolioOutcome(None, False, refused.code, refused.detail, refused_request=True)
    except MemoryError:
        return PortfolioOutcome(None, False, "memory_exhausted", "the portfolio could not hold its values")
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        code = getattr(error, "code", None)
        if code in UNRECORDED:
            # The deadline ran out between two stages of the selection: nothing recorded.
            return PortfolioOutcome(None, False, code, getattr(error, "detail", ""))
        return PortfolioOutcome(None, False, "simulation_failed", f"{type(error).__name__}: {error}")


def _simulate(deployment, request: PortfolioRequest, time_budget: float) -> PortfolioOutcome:
    deadline = time.monotonic() + time_budget
    try:
        ep, ss, sim, dist, load_input = _engine()
    except Exception as error:  # noqa: BLE001 - an import fault of numpy or the engine is a returned refusal
        return PortfolioOutcome(None, False, "engine_unavailable", f"{type(error).__name__}: {error}")

    def check_time(stage: str) -> None:
        if time.monotonic() > deadline:
            raise ss.ScenarioSimulationRefused("time_over_budget", f"past {time_budget:g} s at {stage}")

    scenarios = list(FinancialScenario.objects.filter(deployment=deployment).order_by("id"))
    newer = {s.supersedes_id: s for s in scenarios if s.supersedes_id is not None}
    heads = sorted((s for s in scenarios if s.pk not in newer), key=lambda s: str(s.uuid))
    if len(heads) > ep.MAX_SCENARIOS:
        raise _refused("scenarios_over_limit", f"{len(heads)} current scenario versions; at most {ep.MAX_SCENARIOS}")
    current = {str(s.uuid) for s in heads}
    named = sorted({sid for g in request.groups for sid in g.scenarios} - current)
    if named:
        raise _refused("scenario_not_found", f"a group names what is not a current scenario version here: {named}")
    group_of = {sid: g.key for g in request.groups for sid in g.scenarios}
    normalizer = _normalizer(deployment, request)

    excluded = [
        _exclusion(s, "superseded", f"superseded by {newer[s.pk].uuid}")
        for s in sorted((s for s in scenarios if s.pk in newer), key=lambda s: str(s.uuid))
    ]
    included = []
    for scenario in heads:
        check_time(f"selection {scenario.uuid}")
        result = SimulationResult.objects.filter(scenario=scenario, deployment_id=deployment.pk).order_by("-id").first()
        if result is None:
            excluded.append(_exclusion(scenario, "no_result", report.NO_RESULT))
            continue
        document = report.build_report(result)
        if not report.may_be_totalled(document):
            code = _report_exclusion(document)
            excluded.append(_exclusion(scenario, code, document.get("banner_reason") or EXCLUSIONS[code], result))
            continue
        if (document.get("simulation") or {}).get("basis") != ss.ANNUAL_BASIS:
            excluded.append(_exclusion(scenario, "no_annual_loss", EXCLUSIONS["no_annual_loss"], result))
            continue
        try:
            si = load_input(scenario)
            again = ss.digest_of(ss.canonical_inputs(si, severe_percentile=Decimal(result.severe_percentile)))
        except (EconomicsRefused, ParameterRefused, MoneyRefused, ss.ScenarioSimulationRefused,
                sim.SimulationRefused, dist.DistributionRefused) as refused:
            excluded.append(_exclusion(scenario, "inputs_changed", f"{refused.code}: {refused.detail}", result))
            continue
        if again != result.input_digest:
            excluded.append(_exclusion(scenario, "inputs_changed", f"{again}, not {result.input_digest}", result))
            continue
        build = ScenarioBuild.objects.filter(scenario=scenario).first()
        normalization, why = normalizer.factor(si.currency, None if build is None else build.as_of)
        if normalization is None:
            excluded.append(_exclusion(scenario, "currency_unnormalisable", why, result))
            continue
        included.append((scenario, result, document, si, build, normalization))

    # The loss events two scenarios share are one: each counted once.
    refs = []
    for scenario, _, _, _, build, normalization in included:
        refs += _event_refs(scenario, build, Decimal(normalization["factor"]), ep)
    joined = ep.shared_events(refs)
    counted_in: dict[tuple[str, str], tuple[str, str]] = {}
    for one in joined:
        for event in one.joined:
            counted_in[event.order] = one.kept.order

    members, member_inputs = [], []
    for scenario, result, document, si, build, normalization in included:
        sid = str(scenario.uuid)
        dropped = sorted(key for (owner, key) in counted_in if owner == sid)
        kept = ep.without_events(si, dropped)
        members.append(ep.Member(sid, kept, Decimal(normalization["factor"]), group_of.get(sid)))
        grade = document["grade"]
        member_inputs.append(
            {
                "scenario": sid,
                "title": scenario.title,
                "result": str(result.uuid),
                "result_digest": result.result_digest,
                "input_digest": result.input_digest,
                "seed": result.seed,
                "draws": result.draws,
                "grade": grade,
                "graded": downgraded(ConfidenceGrade(grade), len(normalization["downgrades"])).value,
                "currency": si.currency,
                "as_of": build.as_of.isoformat(),
                "insured": si.policy is not None,
                "normalization": normalization,
                "group": group_of.get(sid),
                "events": [] if kept is None else [event.loss_event_id for event in kept.events],
                "counted_elsewhere": [
                    {"event_key": key, "counted_in": {"scenario": counted_in[(sid, key)][0],
                                                      "event_key": counted_in[(sid, key)][1]}}
                    for key in dropped
                ],
            }
        )
    in_portfolio = {m.scenario_id for m in members}
    groups = [ep.Group(g.key, g.strength, SourceType(g.source_type)) for g in request.groups]
    inputs = {
        "schema": INPUTS_SCHEMA,
        "deployment": str(deployment.uuid),
        "policy": request.policy,
        "reporting_currency": request.reporting_currency,
        "valuation_date": request.valuation_date.isoformat(),
        "severe_percentile": decimal_text(request.severe_percentile),
        "selection": {"version": SELECTION_VERSION, "rule": SELECTION},
        "normalization": None if normalizer.policy is None else {
            "policy": normalizer.policy.as_dict(),
            "sources": [
                {"uuid": str(s.uuid), "source_key": s.source_key, "version": s.version,
                 "snapshot_hash": s.snapshot_hash}
                for s in normalizer.sources
            ],
        },
        "members": member_inputs,
        "excluded": sorted(excluded, key=lambda e: e["scenario"]),
        "groups": [
            {
                "group": g.key,
                "strength": decimal_text(g.strength),
                "source_type": g.source_type,
                "evidence_ref": g.evidence_ref,
                "scenarios": list(g.scenarios),
                "applied_to": [sid for sid in g.scenarios if sid in in_portfolio],
            }
            for g in request.groups
        ],
        "shared_events": [
            {
                "counted": {"scenario": one.kept.scenario, "event_key": one.kept.event_key,
                            "gross_base": decimal_text(one.kept.gross[1])},
                "joined": [{"scenario": e.scenario, "event_key": e.event_key, "gross_base": decimal_text(e.gross[1])}
                           for e in one.joined],
                "by": list(one.by),
            }
            for one in joined
        ],
        "rules": {
            "group_driver": {"version": ep.DRIVER_VERSION, "rule": ep.DRIVER},
            "shared_events": {"version": ep.SHARED_EVENTS_VERSION, "rule": ep.SHARED_EVENTS_RULE},
            "grade": GRADE_RULE,
        },
        "versions": ep.versions(),
    }
    input_digest = canonical_digest(inputs)
    found = _existing(deployment, input_digest, request.seed, request.draws)
    if found is not None:
        return PortfolioOutcome(found, False, found.refusal_code or None, found.refusal_detail)

    started_at = timezone.now()
    clock = time.monotonic()
    record = refusal = None
    if not members:
        refusal = ("nothing_to_total", "no current scenario version's latest result may be totalled: each is listed "
                   "with its reason")
    else:
        refusals = (ep.PortfolioRefused, ss.ScenarioSimulationRefused, sim.SimulationRefused,
                    dist.DistributionRefused, MoneyRefused, ParameterRefused, EconomicsRefused)
        try:
            # No transaction is open here, and none is opened until the insert below:
            # a stop's write never waits behind the draws (the SAFETY RULE).
            drawn = ep.run(
                members, groups, seed=request.seed, draws=request.draws, severe_percentile=request.severe_percentile,
                reporting_currency=request.reporting_currency, input_digest=input_digest, check_time=check_time,
            )
            record = dict(drawn.record)
        except refusals as refused:
            refusal = (refused.code, refused.detail)
        except (sim.InvariantBroken, AssertionError) as broken:
            return PortfolioOutcome(None, False, "invariant_broken", f"{type(broken).__name__}: {broken}")
        if refusal is not None and refusal[0] in UNRECORDED:
            return PortfolioOutcome(None, False, *refusal)
    finished_at = timezone.now()
    row = PortfolioResult(
        deployment=deployment,
        seed=str(request.seed),
        draws=request.draws,
        severe_percentile=inputs["severe_percentile"],
        reporting_currency=request.reporting_currency,
        valuation_date=request.valuation_date,
        input_digest=input_digest,
        result_digest="" if record is None else canonical_digest(record),
        status=SIMULATION_COMPLETED if record is not None else SIMULATION_REFUSED,
        refusal_code="" if refusal is None else refusal[0],
        refusal_detail="" if refusal is None else refusal[1],
        inputs=inputs,
        record=record,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int(round((time.monotonic() - clock) * 1000)),
    )
    try:
        # Every check, the lookup of the same identity included, before the
        # transaction, which only inserts.
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = _existing(deployment, input_digest, request.seed, request.draws)
        if found is None:
            raise
        return PortfolioOutcome(found, False, found.refusal_code or None, found.refusal_detail)
    return PortfolioOutcome(row, True, row.refusal_code or None, row.refusal_detail)


def _existing(deployment, input_digest: str, seed: int, draws: int) -> PortfolioResult | None:
    return PortfolioResult.objects.filter(
        deployment=deployment, input_digest=input_digest, seed=str(seed), draws=draws
    ).first()


# ------------------------------------------------------------------ the stored rows


def _member_failure(row: PortfolioResult, member: dict) -> str | None:
    """Why an included scenario's stored rows no longer bear out what the portfolio
    totalled, or ``None``: its result is this deployment's and that scenario's, its
    digests are the ones totalled, its result, card and series verify as step 6's
    report checks them, and its card's grade is the one totalled."""
    try:
        result = SimulationResult.objects.filter(uuid=member.get("result"), deployment_id=row.deployment_id).first()
    except (DjangoValidationError, ValueError, TypeError):
        result = None
    if result is None:
        return "its result is not recorded in this deployment"
    scenario = FinancialScenario.objects.filter(pk=result.scenario_id).first()
    if scenario is None or str(scenario.uuid) != member.get("scenario"):
        return "the result is another scenario's"
    if (result.input_digest, result.result_digest) != (member.get("input_digest"), member.get("result_digest")):
        return "the result's digests are not the ones totalled"
    card = FinancialValidityCard.objects.filter(simulation=result).first()
    charts = SimulationCharts.objects.filter(simulation=result).first()
    failed = report.stored_row_failures(result, card, charts, scenario)
    if failed:
        return f"its stored rows fail {', '.join(failed)}"
    if report.verified_grade(card, result) != member.get("grade"):
        return "its card's grade is not the one totalled"
    return None


def stored_row_failures(row: PortfolioResult) -> tuple[list[str], list[dict]]:
    """The checks of :data:`INTEGRITY_CHECKS` the stored rows of ``row`` fail, in
    order, and each included scenario whose rows fail, with why. Plain hashing and
    reads: no engine, no numpy."""
    failed = []
    try:
        intact = canonical_digest(row.inputs) == row.input_digest
    except (TypeError, ValueError):
        intact = False
    if not intact:
        failed.append("input_digest")
    if row.status == SIMULATION_COMPLETED:
        try:
            recorded = isinstance(row.record, dict) and canonical_digest(row.record) == row.result_digest
        except (TypeError, ValueError):
            recorded = False
        if not recorded:
            failed.append("result_digest")
    elif row.record is not None or row.result_digest:
        failed.append("result_digest")
    members = (row.inputs.get("members") or []) if intact and isinstance(row.inputs, dict) else []
    failing = []
    for member in members:
        why = _member_failure(row, member) if isinstance(member, dict) else "malformed"
        if why is not None:
            failing.append({"scenario": member.get("scenario") if isinstance(member, dict) else None, "reason": why})
    if failing:
        failed.append("member_rows")
    return failed, failing


# ------------------------------------------------------------------ grade and banner


_LADDER = ("A", "B", "C", "D")


def portfolio_grade(inputs: dict) -> dict:
    """The portfolio's grade, from its stored inputs (:data:`GRADE_RULE`)."""
    members = inputs.get("members") or []
    if not members:
        return {"grade": None, "rule": GRADE_RULE, "reason": "no scenario is included: nothing is graded"}
    graded = [
        (downgraded(ConfidenceGrade(m["grade"]), len(m["normalization"]["downgrades"])), m["scenario"]) for m in members
    ]
    lowest, which = min(graded, key=lambda g: (-_LADDER.index(g[0].value), g[1]))
    expert = sorted(
        g["group"] for g in inputs.get("groups") or [] if g["applied_to"] and g["source_type"] in ASSUMPTION_SOURCES
    )
    grade = downgraded(lowest, 1 if expert else 0)
    normalised = sorted(m["scenario"] for m in members if m["normalization"]["downgrades"])
    reason = f"the lowest included scenario, {which}, is graded {lowest.value}"
    if normalised:
        reason += f" (after its normalisation's downgrades, where it carries any: {', '.join(normalised)} do)"
    if expert:
        reason += (f"; one step lower, {grade.value}, because the strength of {', '.join(expert)} rests on an "
                   "expert's estimate or no named source")
    return {
        "grade": grade.value,
        "base": lowest.value,
        "lowest_scenario": which,
        "downgrades": [{"code": "expert_correlation", "groups": expert}] if expert else [],
        "normalization_downgrades": normalised,
        "rule": GRADE_RULE,
        "reason": reason,
    }


def banner_reason(row: PortfolioResult, grade: str | None, failed: list[str]) -> str | None:
    """Why the portfolio is not for capital decisions, or ``None``: step 6's rule
    (:func:`report.banner_reason`) at portfolio level. It fails closed."""
    if failed:
        return _unverified(failed)
    if row.status != SIMULATION_COMPLETED:
        return f"the portfolio was refused ({row.refusal_code}): it has no figures"
    if grade is None:
        return "no included scenario is graded: the portfolio is not graded"
    if grade not in report.GRADES_FOR_TOTALS:
        return f"graded {grade}: not a grade a total may sum"
    return None


def _unverified(failed: list[str]) -> str:
    return (
        f"{report.STORED_ROW_UNVERIFIED}: the stored rows fail {', '.join(failed)}: a row no longer gives its digest, "
        "or no longer bears out what was totalled; served as a refusal"
    )


# ------------------------------------------------------------------ the document


def _allocated(by: dict[str, str], total: str, shown) -> tuple[dict[str, str], str]:
    """Contributions shown at the minor unit so they sum EXACTLY to the shown total:
    the total rounded half-even, each contribution floored, and the units left over
    given to the largest remainders (ties: the first scenario)."""
    unit = Decimal(1).scaleb(-shown.minor_unit)
    with localcontext(Context(prec=200)):
        total_shown = Decimal(total).quantize(unit, rounding=ROUND_HALF_EVEN)
        floors = {sid: Decimal(v).quantize(unit, rounding=ROUND_FLOOR) for sid, v in by.items()}
        extra = int((total_shown - sum(floors.values(), Decimal(0))) / unit)
        if not 0 <= extra <= len(floors):
            raise ValueError("the shown contributions cannot sum to the shown total")
        for sid in sorted(by, key=lambda sid: (-(Decimal(by[sid]) - floors[sid]), sid))[:extra]:
            floors[sid] += unit
    return {sid: format(value, "f") for sid, value in sorted(floors.items())}, format(total_shown, "f")


def _share(part: str, whole: str) -> str | None:
    if Decimal(whole) == 0:
        return None
    with localcontext(Context(prec=60)):
        return format((Decimal(part) / Decimal(whole)).quantize(Decimal("1E-10"), rounding=ROUND_HALF_EVEN), "f")


def _contributions(record: dict, titles: dict[str, str], shown) -> dict:
    lines = {}
    for line in LINES:
        held = record["contributions"][line]
        if held.get("mean") is None:
            lines[line] = {"not_reported": held.get("not_reported")}
            continue
        mean, tail = held["mean"], held["tail"]
        mean_shown, mean_total = _allocated(mean["by_scenario"], mean["total"], shown)
        tail_shown, tail_total = _allocated(tail["by_scenario"], tail["total"], shown)
        by_mean = sorted(mean["by_scenario"], key=lambda sid: (-Decimal(mean["by_scenario"][sid]), sid))
        by_tail = sorted(tail["by_scenario"], key=lambda sid: (-Decimal(tail["by_scenario"][sid]), sid))
        lines[line] = {
            "mean": {"total": mean_total, "measure": "the expected annual loss"},
            "tail": {"total": tail_total, "percentile": tail["percentile"], "draws": tail["draws"],
                     "measure": tail["measure"]},
            "scenarios": [
                {
                    "scenario": sid,
                    "title": titles.get(sid),
                    "mean": mean_shown[sid],
                    "tail": tail_shown[sid],
                    "share_of_mean": _share(mean["by_scenario"][sid], mean["total"]),
                    "share_of_tail": _share(tail["by_scenario"][sid], tail["total"]),
                    "rank_by_mean": by_mean.index(sid) + 1,
                    "rank_by_tail": by_tail.index(sid) + 1,
                }
                for sid in sorted(mean["by_scenario"])
            ],
            "largest": held["largest"],
            "largest_differ": held["largest"]["mean"] != held["largest"]["tail"],
        }
    return {
        **lines,
        "statement": (
            "each scenario's contribution to the mean is its own mean over the portfolio's years, and to the tail its "
            "mean over the tail's years (the years of largest total beyond the severe percentile); they sum to the "
            "expected annual loss and to the expected shortfall exactly, in the stored record at every digit and here "
            "at the minor unit (each floored, the units left over to the largest remainders); a share is rounded to "
            "10 places"
        ),
    }


def _summary(record: dict, shown) -> dict:
    lines = {}
    for line in LINES:
        block = record["lines"][line]
        lines[line] = {
            **report._block(block, shown=shown, annual=True, no_annual="", missing=""),
            "expected_shortfall": shown(block.get("expected_shortfall")),
        }
        if block.get("expected_shortfall") is None:
            lines[line]["not_reported"]["expected_shortfall"] = lines[line]["not_reported"].get("mean", "no mean")
    return {
        "basis": record["basis"],
        "statement": record["statement"],
        "headline": record["headline"],
        "severe_percentile": record["severe_percentile"],
        "confidence_level": record["confidence_level"],
        "lines": lines,
    }


def build_document(row: PortfolioResult) -> dict:
    """The report of ``row``, with its digest: from the stored rows only."""
    deployment_uuid = str(Deployment.objects.get(pk=row.deployment_id).uuid)
    shown = report._Shown(row.reporting_currency)
    failed, failing = stored_row_failures(row)
    completed = row.status == SIMULATION_COMPLETED
    figures = completed and not failed
    inputs = row.inputs if "input_digest" not in failed else {}
    grade = portfolio_grade(inputs) if not failed else None
    why = banner_reason(row, None if grade is None else grade["grade"], failed)
    withheld = _unverified(failed) if failed else None
    if not completed:
        refusal = {"code": row.refusal_code, "detail": row.refusal_detail}
    elif failed:
        refusal = {"code": report.STORED_ROW_UNVERIFIED, "detail": withheld}
    else:
        refusal = None
    excluded = inputs.get("excluded") or []
    members = inputs.get("members") or []
    titles = {m["scenario"]: m.get("title") for m in members}
    record = row.record if figures else None
    not_reported = withheld or f"refused: {row.refusal_code}"
    untrusted = {"not_reported": f"{report.STORED_ROW_UNVERIFIED}: the stored inputs no longer give their digest"}
    document = {
        "schema": REPORT_SCHEMA,
        "deployment": deployment_uuid,
        "portfolio": {
            "uuid": str(row.uuid),
            "status": row.status,
            "seed": row.seed,
            "draws": row.draws,
            "severe_percentile": row.severe_percentile,
            "policy": inputs.get("policy"),
            "reporting_currency": row.reporting_currency,
            "valuation_date": row.valuation_date.isoformat(),
            "input_digest": row.input_digest,
            "result_digest": row.result_digest or None,
            "outcomes_sha256": None if record is None else record.get("outcomes_sha256"),
            "started_at": row.started_at.isoformat(),
            "finished_at": row.finished_at.isoformat(),
            "recorded_at": row.recorded_at.isoformat(),
        },
        "versions": inputs.get("versions"),
        "currency": {"code": row.reporting_currency, "minor_unit": shown.minor_unit, "rounding": report.ROUNDING},
        "status": row.status,
        "refusal": refusal,
        "integrity": {"verified": not failed, "checks": list(INTEGRITY_CHECKS), "failed": list(failed),
                      "scenarios_failed": failing},
        "grade": grade,
        "banner": None if why is None else report.UNKNOWN_BANNER,
        "excluded_from_totals": why is not None,
        "banner_reason": why,
        "complete": bool(inputs) and not excluded,
        "reads_as": "the loss of every current scenario version" if inputs and not excluded
        else "at least: the included scenarios only; every excluded one is listed with its reason",
        "scenarios": untrusted if not inputs else {
            "included": [
                {key: m.get(key) for key in ("scenario", "title", "result", "result_digest", "input_digest", "grade",
                                             "graded", "currency", "as_of", "insured", "normalization", "group",
                                             "events", "counted_elsewhere")}
                for m in members
            ],
            "excluded": excluded,
            "selection": inputs.get("selection"),
        },
        "groups": untrusted if not inputs else inputs.get("groups"),
        "shared_events": untrusted if not inputs else inputs.get("shared_events"),
        "normalization": untrusted if not inputs else inputs.get("normalization"),
        "rules": untrusted if not inputs else inputs.get("rules"),
        "summary": {"not_reported": not_reported} if record is None else _summary(record, shown),
        "contributions": {"not_reported": not_reported} if record is None
        else _contributions(record, titles, shown),
        "limitations": list(LIMITATIONS),
    }
    document["digest"] = report.digest_of(document)
    return document


def latest(deployment) -> PortfolioResult | None:
    """The deployment's latest portfolio, by record order."""
    return PortfolioResult.objects.filter(deployment=deployment).order_by("-id").first()


def find(deployment, result_uuid) -> PortfolioResult | None:
    try:
        wanted = _uuid.UUID(str(result_uuid))
    except ValueError:
        return None
    return PortfolioResult.objects.filter(deployment=deployment, uuid=wanted).first()


def table_available() -> bool:
    """Whether economics can read its currency table now."""
    try:
        _currency.require_pinned()
    except _currency.CurrencyTableInvalid:
        return False
    return True


__all__ = [
    "ASSUMPTION_SOURCES",
    "EXCLUSIONS",
    "GRADE_RULE",
    "INPUTS_SCHEMA",
    "INTEGRITY_CHECKS",
    "LIMITATIONS",
    "REPORT_SCHEMA",
    "SELECTION",
    "UNRECORDED",
    "PortfolioOutcome",
    "PortfolioRequest",
    "PortfolioRequestRefused",
    "banner_reason",
    "build_document",
    "find",
    "latest",
    "parse_request",
    "portfolio_grade",
    "simulate_portfolio",
    "stored_row_failures",
]
