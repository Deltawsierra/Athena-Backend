"""The Financial Exposure Validity Card of a stored simulation result (MVP step 8;
``docs/economics/spec-v1.md``, section 26): its sensitivity analysis, its
confidence grade and every field of the owner's card (the owner's specification,
section 8), recorded once.

:func:`issue_card` takes one :class:`~assurance.economics.models.SimulationResult`
and:

1. for a completed run, makes the sensitivity analysis on the run's OWN draws
   (:mod:`assurance.economics.engine.sensitivity`): it reloads the scenario version
   as step 7b read it, and refuses unless its canonical inputs give the run's input
   digest and its draws the run's outcomes digest;
2. grades the run (:mod:`assurance.economics.engine.grade`) from the stored
   inputs and that analysis;
3. builds the card (:func:`build_card`): every owner field, from the stored result,
   the scenario version's append-only rows and the analysis, or saying it has no
   data -- never a made-up value -- and what was read when it was issued (the
   review status, the inventory entry, the findings' status, the deployment's
   system fingerprint), kept as issued;
4. records it, append-only, one card per result: the same result returns the card
   already recorded, and two issues racing past that read are stopped by the
   one-to-one key, the later returning the first's.

The card is REPRODUCIBLE from what is stored: :func:`build_card` given the stored
result, the stored analysis and the card's own ``issued`` section gives the
stored card exactly (:func:`reproduces`).

A failure that the stored rows do not decide (the engine will not import, the
draws are not reproduced on this platform, the time budget, memory, a fault) is
returned with its code and never recorded. **Never raises.** Nothing here is on a
stop path; nothing Django loads at start imports it, and it imports the engine,
and numpy, only when called. No route serves it: step 6 serves reports.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import simulation_service
from .engine.formulas import ESTIMATED, MARKET_VALUE
from .models import (
    SIMULATION_COMPLETED,
    CausalEffect,
    EconomicsRefused,
    EffectFinding,
    FinancialScenario,
    FinancialValidityCard,
    LossEvent,
    ModelInventoryEntry,
    ScenarioBuild,
    SimulationResult,
    canonical_digest,
    card_digest,
)

CARD_SCHEMA = "mythos.economics.validity-card/v1"
CARD_VERSION = 1
#: The card names this many most sensitive variables.
TOP_DRIVERS = 5
#: The model inventory id an admin registers this engine's releases under
#: (spec, section 6); the version is :func:`model_release`'s.
MODEL_ID = "economic-exposure"
TIME_BUDGET_SECONDS = simulation_service.TIME_BUDGET_SECONDS
NEVER_CALIBRATED = "never; no calibration set exists"

#: Failures returned and never recorded: the stored rows do not decide them.
UNRECORDED = frozenset(
    {
        "engine_unavailable",
        "inputs_changed",
        "result_not_reproduced",
        "time_over_budget",
        "memory_exhausted",
        "invariant_broken",
        "card_failed",
    }
)

OBSERVED_STATUS = (
    "in force when the scenario version was built: the builder refuses an observed effect whose signature does "
    "not verify, or that is not held (spec, section 24.2)"
)
HYPOTHETICAL_STATUS = "hypothetical: declared by an analyst on the findings that enable it; nothing was observed"


@dataclass(frozen=True)
class CardOutcome:
    """What :func:`issue_card` gives: the recorded card (``None`` when nothing was
    recorded), whether this call recorded it, and the failure's code and detail."""

    card: FinancialValidityCard | None
    created: bool
    code: str | None = None
    detail: str = ""


def _engine():
    from .engine import distributions, grade, money, scenario_simulation, sensitivity, simulation

    return distributions, grade, money, scenario_simulation, sensitivity, simulation


# ------------------------------------------------------------- the release


def model_release(versions) -> dict:
    """The engine release a card and a receipt name: a token (what the receipt's
    ``model.version`` holds, and what the inventory registers) and the digest of
    everything the figures, the analysis, the grade and the card rest on (the
    receipt's ``model.build_digest``): every version and limit of the run, the
    sensitivity method, the grade's classes and thresholds, and the card's schema."""
    _, grade, _, _, sensitivity, _ = _engine()
    token = (
        f"mythos.economics:simulation-{versions.get('scenario_simulation')}+sensitivity-{sensitivity.VERSION}"
        f"+card-{CARD_VERSION}"
    )
    build = {
        "engine": versions,
        "sensitivity": sensitivity.version_record(),
        "grade": grade.version_record(),
        "card": {"schema": CARD_SCHEMA, "version": CARD_VERSION, "top_drivers": TOP_DRIVERS},
    }
    return {"version": token, "build_digest": canonical_digest(build)}


# ------------------------------------------------------------- what is read


def _cash_reads(inputs) -> tuple[list[str], dict[str, str], list[str], list[dict]]:
    """From a run's canonical inputs: every parameter a known cash component reads,
    the latest as-of date it is read at, the unknown cash components, and every
    unknown component (cash or market value) with its reason."""
    reads: dict[str, str] = {}
    unknown_cash, unknown = [], []
    for event in inputs.get("events", []):
        for component in event["components"]:
            where = f"{event['event_key']}/{component['component_id']}"
            if component["status"] != ESTIMATED:
                unknown.append(
                    {
                        "component": where,
                        "family": component["family"],
                        "reason": component["unknown_reason"],
                        "inputs": list(component["missing"]),
                    }
                )
                if component["family"] != MARKET_VALUE:
                    unknown_cash.append(where)
                continue
            if component["family"] == MARKET_VALUE:
                continue
            for name in component["reads"].values():
                reads[name] = max(reads.get(name, component["as_of"]), component["as_of"])
    return sorted(reads), reads, unknown_cash, unknown


def _as_of(inputs) -> str | None:
    dates = [c["as_of"] for event in inputs.get("events", []) for c in event["components"]]
    return max(dates) if dates else None


def _freshness(inputs, as_of_by_name: dict[str, str], as_of: str | None, critical: set[str]) -> dict:
    rows = []
    stale = []
    parameters = inputs.get("parameters", {})
    frequency = inputs.get("frequency")
    for name in sorted(parameters):
        held = parameters[name]
        read_at = as_of_by_name.get(name) or (as_of if name == frequency else None)
        fresh_until, effective = held.get("fresh_until"), held.get("effective_date")
        is_stale = bool(read_at and fresh_until and read_at > fresh_until)
        age = None
        if read_at and effective:
            age = (date.fromisoformat(read_at) - date.fromisoformat(effective)).days
        if is_stale and (name in as_of_by_name or name == frequency):
            stale.append(name)
        rows.append(
            {
                "name": name,
                "source_type": held.get("source_type"),
                "effective_date": effective,
                "fresh_until": fresh_until,
                "read_as_of": read_at,
                "age_days": age,
                "stale": is_stale,
                "critical": name in critical,
            }
        )
    return {
        "as_of": as_of,
        "parameters": rows,
        "stale": stale,
        "statement": (
            "each figure's age is from the date it holds from to the date the run read it; a figure past its "
            "fresh_until is stale and lowers the grade one step (stale_inputs). No parameter names a FinancialSource "
            "snapshot yet (evidence_ref is text, spec section 22), so a source's own retrieval age is not shown"
        ),
    }


def _weighted(inputs, sensitivity, reads: list[str]):
    """Every parameter the gross cash reads (and the frequency), with its source
    types (a derived one's contributors'), its importance from the analysis
    (zero for a figure that is fixed or not ranked) and its expert and derived marks."""
    _, grade, _, _, _, _ = _engine()
    ranked = {entry["name"]: entry for entry in (sensitivity or {}).get("ranked", [])}
    parameters = inputs.get("parameters", {})
    derived = inputs.get("derived", {})
    names = list(reads)
    if inputs.get("frequency") and inputs["frequency"] not in names:
        names.append(inputs["frequency"])
    items = []
    for name in sorted(names):
        contributors = derived.get(name, [])
        sources = [parameters[c]["source_type"] for c in contributors] or [parameters[name]["source_type"]]
        entry = ranked.get(name)
        items.append(
            grade.Weighted(
                name=name,
                sources=tuple(sources),
                importance=Decimal(entry["importance"]) if entry else Decimal(0),
                expert=bool(entry and entry["expert"]),
                derived=bool(contributors),
            )
        )
    return items


# ------------------------------------------------------------------ issued


def issued_context(result: SimulationResult, scenario: FinancialScenario) -> dict:
    """What the card reads as it is issued, and keeps as issued: the scenario's
    review status, the inventory entry of the engine release (if an admin
    registered one), each enabling finding's status, and the deployment's system
    fingerprint now (used only where the scenario version recorded none)."""
    from assurance.models import Deployment, Finding

    from .builder import review_status

    release = model_release(result.versions)
    entry = (
        ModelInventoryEntry.objects.filter(model_id=MODEL_ID, version=release["version"][:64])
        .order_by("-revision")
        .first()
    )
    effects = list(CausalEffect.objects.filter(scenario=scenario))
    links = list(EffectFinding.objects.filter(effect_id__in=[e.pk for e in effects]))
    found = {
        str(f.uuid): {"status": f.status, "severity": f.severity}
        for f in Finding.objects.filter(deployment_id=scenario.deployment_id, uuid__in=sorted({x.finding for x in links}))
    }
    fingerprint = {"value": None, "unavailable": None}
    try:
        from assurance.fingerprint import compute_system_fingerprint

        deployment = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=scenario.deployment_id)
        )
        fingerprint["value"] = compute_system_fingerprint(deployment)
    except Exception as error:  # noqa: BLE001 - an unreadable fingerprint is stated as unavailable, never guessed
        fingerprint["unavailable"] = f"{type(error).__name__}: {error}"
    return {
        "at": timezone.now().isoformat(),
        "reviewer_status": review_status(scenario),
        "model_inventory": None
        if entry is None
        else {
            "model_id": entry.model_id,
            "version": entry.version,
            "revision": entry.revision,
            "owner": entry.owner,
            "intended_use": entry.intended_use,
            "limitations": entry.limitations,
            "retirement_date": entry.retirement_date.isoformat() if entry.retirement_date else None,
        },
        "findings": {uuid: found.get(uuid) for uuid in sorted({x.finding for x in links})},
        "deployment_system_fingerprint": fingerprint,
    }


# -------------------------------------------------------------------- card


def _description(scenario, events, effects, links) -> str:
    parts = []
    for event in events:
        mine = [e for e in effects if e.loss_event_id == event.pk]
        templates = sorted({f"{e.template_id} v{e.template_version}" for e in mine})
        findings = {x.finding for x in links if x.effect_id in {e.pk for e in mine}}
        what = event.trigger or "an effect"
        where = event.business_process or "an unnamed business process"
        priced = f", priced by {', '.join(templates)}" if templates else ""
        enabled = f", enabled by {len(findings)} finding(s)" if findings else ""
        parts.append(f"{what} on {where}{priced}{enabled}")
    count = len(events)
    return f"{scenario.title}. {count} causal loss event(s): " + "; ".join(parts) + "."


def build_card(result: SimulationResult, *, sensitivity: dict | None, issued: dict) -> dict:
    """The Validity Card of ``result``, from the stored result, the scenario
    version's rows, the stored sensitivity analysis and what was read at issue
    (``issued``). Deterministic: the same arguments give the same card."""
    _, grade, money, _, sens, _ = _engine()
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    inputs = result.inputs or {}
    completed = result.status == SIMULATION_COMPLETED
    record = result.record if completed else None
    events = list(LossEvent.objects.filter(scenario=scenario).order_by("event_key", "id"))
    effects = list(CausalEffect.objects.filter(scenario=scenario).order_by("effect_key", "id"))
    links = list(EffectFinding.objects.filter(effect_id__in=[e.pk for e in effects]).order_by("finding", "id"))
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    release = model_release(result.versions)

    reads, as_of_by_name, unknown_cash, unknown = _cash_reads(inputs)
    as_of = build.as_of.isoformat() if build is not None else _as_of(inputs)
    drivers = (sensitivity or {}).get("ranked", [])[:TOP_DRIVERS]
    material = {
        entry["name"]
        for entry in (sensitivity or {}).get("ranked", [])
        if Decimal(entry["importance"]) >= grade.MATERIAL_IMPORTANCE
    }
    freshness = _freshness(inputs, as_of_by_name, as_of, material | {d["name"] for d in drivers})
    graded = grade.grade(
        refusal=None if completed else (result.refusal_code or "refused"),
        unknown_cash_components=unknown_cash,
        weighted=_weighted(inputs, sensitivity, reads) if completed else [],
        stale=freshness["stale"],
    ).as_dict()
    mix = graded["evidence_mix"]

    def share(classes: tuple[str, ...], meaning: str) -> dict:
        if not mix:
            return {"share": None, "unavailable": "the run was refused: nothing was weighed", "meaning": meaning}
        names = [
            {"name": entry.name, "importance": money.decimal_text(entry.importance)}
            for entry in (_weighted(inputs, sensitivity, reads) if completed else [])
            if any(grade.CLASSES[s] in classes for s in entry.sources)
        ]
        total = sum(Decimal(mix[c]) for c in classes)
        return {
            "share": money.decimal_text(total),
            "classes": list(classes),
            "weighting": graded["weighting"],
            "parameters": names,
            "meaning": meaning,
        }

    observed = [e for e in effects if e.origin == "observed"]
    hypothetical = [e for e in effects if e.origin != "observed"]
    findings_status = issued.get("findings", {})

    if scenario.system_fingerprint:
        fingerprint = {
            "value": scenario.system_fingerprint,
            "binding": "scenario",
            "statement": "the SPINE system fingerprint the scenario version was bound to when it was recorded",
        }
    else:
        at_issue = issued.get("deployment_system_fingerprint") or {}
        fingerprint = {
            "value": at_issue.get("value"),
            "binding": "deployment_at_issue" if at_issue.get("value") else None,
            "statement": (
                "the scenario version records no system fingerprint (the builder records none yet, spec section "
                "24.9); this is the deployment's SPINE fingerprint when the card was issued, not when the scenario "
                "was built"
                if at_issue.get("value")
                else f"unavailable: the scenario version records none, and the deployment's could not be read "
                f"({at_issue.get('unavailable')})"
            ),
        }

    if completed:
        line = record["scenario"]["headline"]
        block = record["scenario"][line]
        figure_names = ("p10", "p50", "p90", "mean", "expected_annual_exposure", "severe_plausible")
        figures = {
            "line": line,
            "basis": record["basis"],
            "reporting_currency": record["reporting_currency"],
            **{name: block.get(name) for name in figure_names},
            "complete": record["scenario"]["complete"],
            "gross_cash": {name: record["scenario"]["gross_cash"].get(name) for name in figure_names},
            "statement": (
                "full precision, as the stored result holds them; rounded to the currency's minor unit only to be "
                "shown. A null figure does not exist for this run (no frequency: no expected annual exposure; an "
                "infinite mean: no mean), and is never estimated"
            ),
        }
    else:
        figures = {
            "unavailable": f"the run was refused ({result.refusal_code}): {result.refusal_detail}",
            "line": None,
        }

    reproduction = {
        "seed": result.seed,
        "draws": result.draws,
        "severe_percentile": result.severe_percentile,
        "input_digest": result.input_digest,
        "result_digest": result.result_digest or None,
        "outcomes_sha256": record["outcomes_sha256"] if completed else None,
        "sensitivity_digest": None if sensitivity is None else canonical_digest(sensitivity),
        "replay": (
            "simulation_service.simulate_scenario(scenario, seed, draws) on the same numpy and platform gives the "
            "same result digest (spec, section 23.8); another platform compares the summary"
        ),
    }

    most_sensitive = (
        {"unavailable": "the run was refused: nothing was analysed", "variables": []}
        if sensitivity is None
        else {
            "method": {"id": sens.METHOD_ID, "version": sens.VERSION},
            "basis": sensitivity["basis"],
            "variables": [
                {
                    "name": entry["name"],
                    "rank": entry["rank"],
                    "importance": entry["importance"],
                    "direction": entry["direction"],
                    "source_types": entry["source_types"],
                    "low_outcome": (entry["swing"] or {}).get("low_outcome"),
                    "high_outcome": (entry["swing"] or {}).get("high_outcome"),
                }
                for entry in drivers
            ],
            "fixed": [f["name"] for f in sensitivity["fixed"]],
        }
    )

    expert = sorted(set((record or {}).get("expert_parameters", [])))
    assumptions = {
        "expert_ranges": expert,
        "rules": [
            inputs.get("rules", {}).get("rule"),
            "every parameter is drawn once per simulated year (spec, section 25.2)",
            "insurance is applied per event occurrence, its limit read per event (spec, section 25.4)",
            "market value is reported apart and never added to cash loss",
        ],
    }
    unknown_variables = {
        "components": unknown,
        "refusal": None if completed else {"code": result.refusal_code, "detail": result.refusal_detail},
        "statement": "an unknown component has no amount and is never read as zero",
    }
    reviewer = issued.get("reviewer_status")

    fields = {
        "scenario": {
            "id": str(scenario.uuid),
            "title": scenario.title,
            "description": _description(scenario, events, effects, links),
            "events": [
                {
                    "event_key": event.event_key,
                    "trigger": event.trigger or None,
                    "business_process": event.business_process or None,
                    "spine_effect": event.effect or None,
                    "templates": [
                        list(pair)
                        for pair in sorted(
                            {(e.template_id, e.template_version) for e in effects if e.loss_event_id == event.pk}
                        )
                    ],
                }
                for event in events
            ],
        },
        "model_version": {
            "version": release["version"],
            "build_digest": release["build_digest"],
            "engine": result.versions,
            "methods": {
                "sensitivity": {"id": sens.METHOD_ID, "version": sens.VERSION},
                "grade": {"version": grade.VERSION, "version_digest": grade.version_digest()},
                "card": {"schema": CARD_SCHEMA, "version": CARD_VERSION},
            },
            "inventory": issued.get("model_inventory")
            or {"entry": None, "statement": f"no model inventory entry registers {MODEL_ID} {release['version']}"},
        },
        "system_fingerprint": fingerprint,
        "technical_evidence": {
            "observed_effects": [
                {
                    "effect_key": e.effect_key,
                    "observed_effect": e.observed_effect,
                    "observation": e.observation,
                    "spine_effect": e.spine_effect or None,
                    "effect_type": e.effect_type,
                    "asset": e.asset,
                    "business_process": e.business_process,
                    "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                    "status": OBSERVED_STATUS,
                }
                for e in observed
            ],
            "hypothetical_effects": [
                {
                    "effect_key": e.effect_key,
                    "effect_type": e.effect_type,
                    "asset": e.asset,
                    "business_process": e.business_process,
                    "status": HYPOTHETICAL_STATUS,
                }
                for e in hypothetical
            ],
            "findings": [
                {
                    "finding": x.finding,
                    "effect_key": next(e.effect_key for e in effects if e.pk == x.effect_id),
                    "role": x.role,
                    "status_at_issue": findings_status.get(x.finding),
                }
                for x in links
            ],
            "statement": None if effects else "the scenario version names no SPINE effect and no finding",
        },
        "customer_specific_share": share(("customer",), "the customer's own figures"),
        "benchmark_derived_share": share(("benchmark",), "industry benchmarks: a prior, never customer-specific truth"),
        "expert_estimated_share": share(("expert", "unsourced"), "a person's estimate, or a figure with no source"),
        "confidence_grade": graded,
        "last_calibrated": {"date": None, "calibration_set": None, "statement": NEVER_CALIBRATED},
        "most_sensitive_variables": most_sensitive,
        "data_freshness": freshness,
        "figures": figures,
        "unknown_variables": unknown_variables,
        "reproduction": reproduction,
    }
    card = {
        "schema": CARD_SCHEMA,
        "scenario_id": str(scenario.uuid),
        "simulation": str(result.uuid),
        "status": result.status,
        "confidence_grade": graded["grade"],
        "fields": fields,
        # The owner's specification, section 15: the card's key fields.
        "evidence_mix": mix,
        "assumptions": assumptions,
        "unknowns": unknown_variables["components"],
        "freshness": {"as_of": freshness["as_of"], "stale": freshness["stale"]},
        "calibration_date": None,
        "reviewer_status": reviewer,
        "issued": issued,
    }
    # One JSON value with no object held twice (core refuses a card that shares
    # one), exactly as it reads back from its column.
    return json.loads(json.dumps(card, allow_nan=False))


def reproduces(card: FinancialValidityCard) -> bool:
    """Whether the stored card is exactly what :func:`build_card` gives from the
    stored result, the stored analysis and the card's own issued section."""
    result = SimulationResult.objects.get(pk=card.simulation_id)
    rebuilt = build_card(result, sensitivity=card.sensitivity, issued=card.card.get("issued", {}))
    return card_digest(rebuilt) == card_digest(card.card) == card.card_digest


# ------------------------------------------------------------------- issue


def _code(error) -> tuple[str, str]:
    return getattr(error, "code", "card_failed"), getattr(error, "detail", "") or str(error)


def issue_card(result: SimulationResult, *, time_budget: float = TIME_BUDGET_SECONDS) -> CardOutcome:
    """The Validity Card of ``result``: the one recorded, or one made and recorded
    now. Never raises: see the module's rules."""
    try:
        return _issue(result, time_budget)
    except MemoryError:
        return CardOutcome(None, False, "memory_exhausted", "the analysis could not hold its values")
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        return CardOutcome(None, False, "card_failed", f"{type(error).__name__}: {error}")


def _issue(result: SimulationResult, time_budget: float) -> CardOutcome:
    found = FinancialValidityCard.objects.filter(simulation=result).first()
    if found is not None:
        return CardOutcome(found, False)
    try:
        distributions, grade, money, ss, sens, sim = _engine()
    except Exception as error:  # noqa: BLE001 - an import fault of numpy or the engine is a returned refusal
        return CardOutcome(None, False, "engine_unavailable", f"{type(error).__name__}: {error}")
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    sensitivity = None
    if result.status == SIMULATION_COMPLETED:
        clock = time.monotonic()

        def check_time(stage: str) -> None:
            if time.monotonic() - clock > time_budget:
                raise ss.ScenarioSimulationRefused("time_over_budget", f"past {time_budget} s at {stage}")

        refusals = (
            sens.SensitivityRefused,
            ss.ScenarioSimulationRefused,
            sim.SimulationRefused,
            distributions.DistributionRefused,
            money.MoneyRefused,
            EconomicsRefused,
        )
        try:
            si = simulation_service.load_input(scenario)
            sensitivity = sens.analyse(
                si,
                seed=int(result.seed),
                draws=result.draws,
                severe_percentile=Decimal(result.severe_percentile),
                input_digest=result.input_digest,
                outcomes_sha256=result.record["outcomes_sha256"],
                check_time=check_time,
            )
        except refusals as refused:
            return CardOutcome(None, False, *_code(refused))
        except (sim.InvariantBroken, AssertionError) as broken:
            return CardOutcome(None, False, "invariant_broken", f"{type(broken).__name__}: {broken}")
    issued = issued_context(result, scenario)
    card = build_card(result, sensitivity=sensitivity, issued=issued)
    row = FinancialValidityCard(
        deployment_id=result.deployment_id,
        scenario=scenario,
        simulation=result,
        schema=CARD_SCHEMA,
        confidence_grade=card["confidence_grade"],
        grade_version_digest=card["fields"]["confidence_grade"]["version_digest"],
        card=card,
        card_digest=card_digest(card),
        sensitivity=sensitivity,
        sensitivity_digest="" if sensitivity is None else canonical_digest(sensitivity),
        issued_at=timezone.now(),
    )
    try:
        # Every check, the lookup of a card of the same result included, before the
        # transaction, which only inserts (as step 7b's result).
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = FinancialValidityCard.objects.filter(simulation=result).first()
        if found is None:
            raise
        return CardOutcome(found, False)
    return CardOutcome(row, True)


__all__ = [
    "CARD_SCHEMA",
    "CARD_VERSION",
    "MODEL_ID",
    "NEVER_CALIBRATED",
    "TOP_DRIVERS",
    "UNRECORDED",
    "CardOutcome",
    "build_card",
    "issue_card",
    "issued_context",
    "model_release",
    "reproduces",
]
