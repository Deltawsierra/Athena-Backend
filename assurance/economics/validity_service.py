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
   inputs and that analysis: each figure, fixed or ranged, weighted by its share
   of the base-case level, and every figure's freshness evaluated at the run's
   as-of date; under a policy the gross cash and the retained cash are graded
   apart, and the headline grade is the lower of the two;
3. builds the card (:func:`build_card`): every owner field, from the stored result,
   the scenario version's append-only rows and the analysis, or saying it has no
   data -- never a made-up value -- and what was read when it was issued (the
   review status, the inventory entry, the findings' status, and the deployment's
   system fingerprint only where the scenario version records none: the builder
   records the deployment's when it builds one), kept as issued;
4. records it, append-only, one card per result: the same result returns the card
   already recorded, and two issues racing past that read are stopped by the
   one-to-one key, the later returning the first's.

The card is REPRODUCIBLE from what is stored: :func:`build_card` given the stored
result, the stored analysis and the card's own ``issued`` section gives the
stored card exactly (:func:`reproduces`), under the release the card records
(:func:`release_record`; :func:`release_changed` says when today's differs).

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
from .engine import feeds as feed_rules
from .engine.formulas import ESTIMATED, MARKET_VALUE
from .engine.pack_inputs import SCHEMAS as INDUSTRY_PACKS
from .models import (
    SIMULATION_COMPLETED,
    CausalEffect,
    EconomicsRefused,
    EffectFinding,
    FinancialScenario,
    FinancialValidityCard,
    LossEvent,
    FinancialParameter,
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


def release_record(versions) -> dict:
    """Everything the figures, the analysis, the grade and the card rest on: every
    version and limit of the run, the sensitivity method, the grade's classes,
    thresholds and downgrades, and the card's schema. A card records it, and a
    receipt names its digest, so a stored receipt is verified against the release
    it was made under, never today's (spec, section 26.6)."""
    _, grade, _, _, sensitivity, _ = _engine()
    return {
        "engine": versions,
        "sensitivity": sensitivity.version_record(),
        "grade": grade.version_record(),
        "card": {"schema": CARD_SCHEMA, "version": CARD_VERSION, "top_drivers": TOP_DRIVERS},
    }


def model_release(versions) -> dict:
    """The engine release a card and a receipt name: a token (what the receipt's
    ``model.version`` holds, and what the inventory registers), the digest of
    :func:`release_record` (the receipt's ``model.build_digest``), and the record."""
    record = release_record(versions)
    token = (
        f"mythos.economics:simulation-{versions.get('scenario_simulation')}+sensitivity-"
        f"{record['sensitivity']['version']}+card-{CARD_VERSION}"
    )
    return {"version": token, "build_digest": canonical_digest(record), "record": record}


# ------------------------------------------------------------- what is read


def _reads(inputs) -> tuple[dict[str, set[str]], list[str], list[dict]]:
    """From a run's canonical inputs: what reads each parameter (``cash`` for a
    known cash component, ``market_value``, ``unknown_component``, ``policy`` for a
    term of the policy the run applies, ``frequency``, ``contributor`` for a derived
    value's contributor); the unknown cash components; and every unknown component
    (cash or market value) with its reason."""
    roles: dict[str, set[str]] = {}
    unknown_cash, unknown = [], []
    for event in inputs.get("events", []):
        for component in event["components"]:
            where = f"{event['event_key']}/{component['component_id']}"
            known = component["status"] == ESTIMATED
            if not known:
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
            role = "unknown_component" if not known else "market_value" if component["family"] == MARKET_VALUE else "cash"
            for name in component["reads"].values():
                roles.setdefault(name, set()).add(role)
    policy = inputs.get("policy")
    if policy is not None:
        for name in policy["terms"].values():
            roles.setdefault(name, set()).add("policy")
    if inputs.get("frequency"):
        roles.setdefault(inputs["frequency"], set()).add("frequency")
    for derived, contributors in inputs.get("derived", {}).items():
        if "cash" in roles.get(derived, set()):
            for name in contributors:
                roles.setdefault(name, set()).add("contributor")
    return roles, unknown_cash, unknown


#: What reading a figure makes it count toward the grade's stale_inputs.
GRADED_ROLES = frozenset({"cash", "policy", "frequency", "contributor"})


def _as_of(inputs, build) -> str | None:
    """The run's as-of date: its build's, else the latest its components were
    computed at."""
    if build is not None:
        return build.as_of.isoformat()
    dates = [c["as_of"] for event in inputs.get("events", []) for c in event["components"]]
    return max(dates) if dates else None


#: What a figure nothing reads is, by where its row is.
UNREAD = {
    "scenario": "nothing: a parameter of the scenario version that no component, policy or frequency reads",
    "parameter_set": "nothing: a parameter-set variable no component reads",
}


def _feed_freshness(inputs, roles, issued) -> tuple[list[dict], list[str], str]:
    """The feed sources the run's figures rest on, as read at issue (``issued``'s
    ``feed_sources``), each with the figures it feeds; every figure the run reads
    that rests on a stale, blocked or missing source (the grade's ``stale_source``);
    and the claim the card may make: ``current``, or ``stale`` where a source is
    blocked or missing (spec, section 29). A card issued before feed sources were
    read (no ``feed_sources``) shows none."""
    held = issued.get("feed_sources")
    if held is None:
        return [], [], "current"
    fed = feed_rules.referenced_keys(inputs.get("parameters"))
    sources, lowered, blocked = [], set(), False
    for key in sorted(fed):
        state = held.get(key) or {"source_key": key, "state": feed_rules.MISSING,
                                  "not_evaluated": "not read when the card was issued"}
        if state["state"] in feed_rules.DOWNGRADING:
            lowered |= {name for name in fed[key] if roles.get(name, set()) & GRADED_ROLES}
        blocked = blocked or state["state"] in feed_rules.BLOCKING
        sources.append({**state, "feeds": fed[key]})
    return sources, sorted(lowered), "stale" if blocked else "current"


def _freshness(inputs, roles, rows_unread, as_of: str | None, critical: set[str]) -> dict:
    """The freshness of EVERY figure: each parameter of the run's inputs (the
    components', the policy's, the frequency, every derived value's contributors),
    every parameter of the scenario version nothing reads and every variable of the
    parameter-set version no component reads (``rows_unread``: each row with where it
    is, ``scenario`` or ``parameter_set``), each evaluated at the run's as-of date. A
    figure with no as-of to read it at says it was not evaluated, never that it is
    fresh."""
    figures = {name: (held.get("source_type"), held.get("effective_date"), held.get("fresh_until"), None)
               for name, held in inputs.get("parameters", {}).items()}
    for where, row in rows_unread:
        figures.setdefault(
            row.name,
            (row.source_type, row.effective_date.isoformat(), row.fresh_until.isoformat() if row.fresh_until else None,
             where),
        )
    rows, stale, stale_not_graded = [], [], []
    for name in sorted(figures):
        source, effective, fresh_until, where = figures[name]
        read_by = sorted(roles.get(name, set())) or [UNREAD[where or "parameter_set"]]
        graded = bool(roles.get(name, set()) & GRADED_ROLES)
        evaluated = as_of is not None
        is_stale = None if not evaluated else bool(fresh_until and as_of > fresh_until)
        age = None
        if evaluated and effective:
            age = (date.fromisoformat(as_of) - date.fromisoformat(effective)).days
        if is_stale:
            (stale if graded else stale_not_graded).append(name)
        rows.append(
            {
                "name": name,
                "source_type": source,
                "read_by": read_by,
                "effective_date": effective,
                "fresh_until": fresh_until,
                "evaluated": evaluated,
                "age_days": age,
                "stale": is_stale,
                "counts_toward_grade": graded,
                "critical": name in critical,
            }
        )
    return {
        "as_of": as_of,
        "parameters": rows,
        "stale": stale,
        "stale_not_graded": stale_not_graded,
        "statement": (
            "every figure is evaluated at the run's as-of date: its age is from the date it holds from, and one past "
            "its fresh_until is stale. A stale figure the run reads (a cash component's, a term of the policy it "
            "applies, the frequency, a derived value's contributor) lowers the grade one step (stale_inputs); one "
            "nothing in the cash figures reads -- a scenario parameter or a parameter-set variable nothing reads "
            "among them -- is shown and does not. A figure whose evidence names a feed source "
            "(financial-source:<key>) lowers the grade one step where that source is stale, blocked or missing at "
            "the as-of date (stale_source); a blocked or missing source makes the card's claim stale (spec, section "
            "28)"
            if as_of is not None
            else "not evaluated: the run has no as-of date to read its figures at"
        ),
    }


def _level(sensitivity, line: str) -> dict | None:
    """The analysis's level record of ``line`` (``gross_cash`` or
    ``retained_cash``), or None where it has none."""
    return ((sensitivity or {}).get("level") or {}).get(line)


def _weighted(inputs, sensitivity, line: str = "gross_cash"):
    """Every figure ``line`` reads (and the frequency), with its share of the line's
    base-case level from the analysis (fixed figures and ranges alike), the source
    types it rests on (a derived value's: those of the contributors that supply its
    base) and its derived mark."""
    _, grade, _, _, _, _ = _engine()
    parameters = inputs.get("parameters", {})
    items = []
    for entry in (_level(sensitivity, line) or {}).get("parameters", []):
        if entry["derived_from"]:
            supplied = entry["supplied_by"] or entry["derived_from"]
            sources = tuple(parameters[c]["source_type"] for c in supplied)
        else:
            sources = (entry["source_type"],)
        items.append(
            grade.Weighted(name=entry["name"], sources=sources, level=Decimal(entry["share"]),
                           derived=bool(entry["derived_from"]))
        )
    return items


# ------------------------------------------------------------------ issued


def issued_context(result: SimulationResult, scenario: FinancialScenario) -> dict:
    """What the card reads as it is issued, and keeps as issued: the scenario's
    review status, the inventory entry of the engine release (if an admin
    registered one), each enabling finding's status, and, only where the scenario
    version recorded no system fingerprint, the deployment's now. Where the version
    recorded one, the deployment's is not read (``None``): the card binds the
    build's and says nothing of the deployment's today."""
    from assurance.models import Finding

    from .builder import current_system_fingerprint, review_status

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
    fingerprint = None
    if not scenario.system_fingerprint:
        # Never raises: one that cannot be read is stated as unavailable, never guessed.
        value, unavailable = current_system_fingerprint(scenario.deployment_id)
        fingerprint = {"value": value or None, "unavailable": unavailable or None}
    context = {
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
    # The feed sources the run's figures rest on (spec, section 29), read now at the
    # run's as-of date and kept as issued: only where a figure names one.
    keys = feed_rules.referenced_keys((result.inputs or {}).get("parameters"))
    if keys:
        from . import feeds

        build = ScenarioBuild.objects.filter(scenario=scenario).first()
        as_of = _as_of(result.inputs or {}, build)
        context["feed_sources"] = feeds.states_for(
            keys, deployment=scenario.deployment_id, as_of=date.fromisoformat(as_of) if as_of else None,
            parameters=(result.inputs or {}).get("parameters"),
        )
    return context


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


def pack_statement(build: ScenarioBuild | None, effects) -> dict | None:
    """The industry pack a scenario version was built under, for its card: the pack's
    id and version, the cautions of the templates its effects were assigned to, and
    what the pack never prices; ``None`` for a banking build (or none, or a pack the
    registry does not hold), whose card names no pack, as no card did before E7 (spec,
    section 37)."""
    if build is None or build.pack not in INDUSTRY_PACKS:
        return None
    from .engine import pack_registry  # an industry pack's card only: never at load

    pack = pack_registry.PACKS[build.pack]
    cautions: list[str] = []
    for effect in effects:
        chosen = pack_registry.template(effect.template_id, effect.template_version)
        cautions.extend(c for c in (chosen.cautions if chosen else ()) if c not in cautions)
    return {"id": build.pack, "cautions": cautions, "excluded": list(pack.excluded)}


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

    roles, unknown_cash, unknown = _reads(inputs)
    as_of = _as_of(inputs, build)
    rows_unread = [("scenario", row) for row in FinancialParameter.objects.filter(scenario=scenario).order_by("name", "id")]
    if build is not None:
        rows_unread += [
            ("parameter_set", row)
            for row in FinancialParameter.objects.filter(parameter_set_id=build.parameter_set_id).order_by("name", "id")
        ]
    drivers = (sensitivity or {}).get("ranked", [])[:TOP_DRIVERS]
    # Both lines are graded where a policy applies, each by its own level; the
    # headline is the lower (grade.HEADLINE_RULE).
    lines = ["gross_cash"] + (["retained_cash"] if completed and _level(sensitivity, "retained_cash") else [])
    weighted = {line: _weighted(inputs, sensitivity, line) if completed else [] for line in lines}
    material = set()
    for items in weighted.values():
        level_total = sum((item.level for item in items), Decimal(0))
        material |= {item.name for item in items if level_total and item.level / level_total >= grade.MATERIAL_SHARE}
    freshness = _freshness(inputs, roles, rows_unread, as_of, material | {d["name"] for d in drivers})
    feed_sources, stale_sources, claim = _feed_freshness(inputs, roles, issued)
    freshness.update(sources=feed_sources, stale_sources=stale_sources, claim=claim)
    grades = {
        line: grade.grade(
            refusal=None if completed else (result.refusal_code or "refused"),
            unknown_cash_components=unknown_cash,
            weighted=weighted[line],
            stale=freshness["stale"],
            stale_sources=stale_sources,
            per_occurrence=(sensitivity or {}).get("per_occurrence", []),
            undefined=(_level(sensitivity, line) or {}).get("undefined_because") if completed else None,
        )
        for line in lines
    }
    graded_line, headline = grade.headline(grades["gross_cash"], grades.get("retained_cash"))
    graded = {
        **headline.as_dict(),
        "line": graded_line,
        "rule": grade.HEADLINE_RULE,
        "lines": {line: grades[line].as_dict() if line in grades else None for line in ("gross_cash", "retained_cash")},
    }
    mix = graded["evidence_mix"]
    importance = {entry["name"]: entry["importance"] for entry in (sensitivity or {}).get("ranked", [])}

    def share(classes: tuple[str, ...], meaning: str) -> dict:
        if not mix:
            return {"share": None, "unavailable": graded["reason"], "meaning": meaning}
        names = [
            {"name": entry.name, "level_share": money.decimal_text(entry.level),
             "importance": importance.get(entry.name, "0")}
            for entry in weighted[graded_line]
            if any(grade.CLASSES[s] in classes for s in entry.sources)
        ]
        total = sum(Decimal(mix[c]) for c in classes)
        return {
            "share": money.decimal_text(total),
            "classes": list(classes),
            "line": graded_line,
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
    elif scenario.system_fingerprint_unavailable:
        # Built after the builder recorded fingerprints, and it could not have one: its
        # reason is in the builder's fixed words (a fault's type, never its message).
        at_issue = issued.get("deployment_system_fingerprint") or {}
        at_build = (
            "the builder recorded no system fingerprint when it built the scenario version: "
            f"{scenario.system_fingerprint_unavailable}"
        )
        fingerprint = {
            "value": at_issue.get("value"),
            "binding": "deployment_at_issue" if at_issue.get("value") else None,
            "statement": (
                f"{at_build}; this is the deployment's SPINE fingerprint when the card was issued, not when the "
                "scenario was built"
                if at_issue.get("value")
                else f"unavailable: {at_build}; and the deployment's could not be read either: "
                f"{at_issue.get('unavailable')}"
            ),
        }
    else:
        # A version recorded before the builder recorded fingerprints: as it always read.
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
            # The release the figures, the analysis, the grade and this card were made
            # under: a receipt is verified against it, never today's (section 26.6).
            "release": release["record"],
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
    pack = pack_statement(build, effects)
    if pack is not None:
        # An industry pack's scenario names its pack, with what its figures are read
        # with (E7, spec section 37); a banking card is the card it was, byte for byte.
        fields["scenario"]["pack"] = pack
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
        "freshness": {
            "as_of": freshness["as_of"],
            "stale": freshness["stale"],
            "stale_sources": stale_sources,
            "claim": claim,
        },
        "calibration_date": None,
        "reviewer_status": reviewer,
        "issued": issued,
    }
    # One JSON value with no object held twice (core refuses a card that shares
    # one), exactly as it reads back from its column.
    return json.loads(json.dumps(card, allow_nan=False))


def release_changed(card: FinancialValidityCard) -> bool:
    """Whether the release the card was made under (its recorded release record)
    differs from today's for the same run versions: the code has changed since,
    which is not tampering (spec, section 26.6)."""
    recorded = card.card["fields"]["model_version"].get("release")
    engine = (recorded or {}).get("engine")
    if recorded is None or engine is None:
        return True
    return canonical_digest(recorded) != canonical_digest(release_record(engine))


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
            # The result's own input: a residual run's with its control effect (section 28).
            si = simulation_service.load_input_of(result)
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
    "release_changed",
    "release_record",
    "reproduces",
]
