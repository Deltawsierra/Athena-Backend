"""One remediation option per scenario version, its residual run and its economics
(MVP step 13; ``docs/economics/spec-v1.md``, section 28): the thin Django half of
:mod:`assurance.economics.engine.remediation`.

- :func:`record_option` records ONE option of a scenario version, append-only:
  its form held by the engine, each reduction admitted by the run's own
  parameter-to-distribution rule, each SPINE id it names found in the version's
  deployment, and a retest it cites verified: an observed control effect only where
  the retest gate's own verdict is that the control held. The same option again
  returns the one recorded; another option is a new version.
- :func:`simulate_option` makes the current run (where it is missing) and the
  residual run under ONE deadline, each through step 7b's service, idempotent, and
  issues each one's Validity Card. NO transaction or lock is held while either Monte
  Carlo runs: each service's transaction only inserts, after its run.
- :func:`roi_document` serves the option's economics from stored rows only, as
  canonical JSON with its own digest: the two runs paired by their inputs (the
  residual run's inputs are the current run's with the option added), each
  verified as step 6's report verifies a result (:func:`report.build_report`,
  :func:`report.stored_row_failures`, :func:`report.may_be_totalled`); the banner
  and the exclusion from every total where either is Unknown, refused, card-less
  or unverified; and the hard security veto (:func:`veto`), which always wins.

Nothing here is on a stop path, and nothing reads or writes what a stop or the
decision reads. The simulation, card and engine modules are imported inside the
functions that run them: nothing Django loads at start imports them, or numpy.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from django.db import IntegrityError, transaction

from assurance.models import Asset, Deployment, Finding, RetestClosureEvidence, WorkflowChainOutcome

from . import report
from .engine import remediation as engine_remediation
from .models import (
    SIMULATION_COMPLETED,
    CausalEffect,
    EconomicsRefused,
    EffectFinding,
    FinancialScenario,
    LossComponent,
    LossEvent,
    RemediationOption,
    ScenarioBuild,
    SimulationResult,
    canonical_digest,
)

#: The checks the ROI document runs on its own rows, before each run's report's:
#: the option still gives its digest, the residual run names that option, and the
#: current run is the residual run's inputs without the option.
ROI_CHECKS = ("option_digest", "residual_option", "current_pairing")

#: What the ROI document is not, stated in every one.
ROI_LIMITATIONS = (
    "the economics of one option against the scenario as it is: an expected annual exposure is a modelled mean, not a "
    "forecast, and the ROI is decision support, not a guaranteed return",
    "the costs are read at their base for the ROI and the payback; their range is shown as the first-year "
    "investment, and no cost uncertainty is simulated",
    "the residual run uses the current run's seed and parameter streams (common random numbers), so the reduction "
    "carries little Monte Carlo noise of its own; components the option does not act on are the current run's",
    "a frequency reduction stops whole occurrences of the components it acts on, and needs a scenario that states "
    "a frequency",
    "the control effect's own evidence does not enter either run's confidence grade in this step: both cards grade "
    "the scenario's figures, and the control effect's source is shown beside them",
    "an observed control effect is cited and verified, not yet learnt from: there is no Bayesian update of the "
    "reductions from observed evidence",
    "the hard security veto is read from SPINE's findings and chains as they stand when this document is built; it "
    "always wins, and a blocker status that cannot be read counts as applying",
)

#: How the veto is decided (the owner's specification, "Hard security veto").
VETO_POLICY = (
    "a finding the scenario rests on is a hard release blocker where Mythos policy places a deployment holding it in "
    "a blocking decision (assurance.decision.FINDING_SEVERITY_DECISIONS: an active finding of trusted severity, high "
    "or critical, places it at needs_remediation or not_recommended); an observed effect is one where its workflow's "
    "chain is violated and sets the composition's not_recommended floor; a status that cannot be read counts as "
    "applying"
)


# ------------------------------------------------------------ SPINE reads


def retest_digest(record: RetestClosureEvidence, finding: Finding) -> str:
    """How a retest record is cited (``engine.remediation.RETEST_CITATION_SCHEMA``):
    the digest of the record's identity and everything the retest gate reads of it,
    so a citation pins the record as it was when cited."""
    return canonical_digest(
        {
            "schema": engine_remediation.RETEST_CITATION_SCHEMA,
            "record": str(record.uuid),
            "finding": str(finding.uuid),
            "origin": record.origin,
            "content_digest": record.content_digest,
            "fixtures": record.fixtures,
            "document": record.document,
            "created_at": record.created_at.isoformat(),
        }
    )


def _linked_findings(scenario: FinancialScenario) -> list[str]:
    """The findings the scenario version rests on, by uuid, sorted."""
    effects = CausalEffect.objects.filter(scenario=scenario).values_list("pk", flat=True)
    return sorted({str(f) for f in EffectFinding.objects.filter(effect_id__in=list(effects)).values_list(
        "finding", flat=True)})


def resolve_retest(scenario: FinancialScenario, digest: str):
    """The retest record a citation names: a record of a finding this scenario
    version rests on, in its deployment, whose :func:`retest_digest` is ``digest``;
    ``(record, finding)``, or ``None``."""
    findings = {
        str(f.uuid): f for f in Finding.objects.filter(deployment_id=scenario.deployment_id,
                                                       uuid__in=_linked_findings(scenario))
    }
    for record in RetestClosureEvidence.objects.filter(finding__in=list(findings.values())).order_by("pk"):
        finding = next(f for f in findings.values() if f.pk == record.finding_id)
        if retest_digest(record, finding) == digest:
            return record, finding
    return None


def control_held(scenario: FinancialScenario, digest: str) -> tuple[bool, list[str], dict | None]:
    """Whether the retest ``digest`` cites shows the control held, by the retest
    gate's OWN verdict (:func:`assurance.retest_closure.refusal_reasons`), never a
    second judgement: the record must be its finding's latest and carry a closure.
    ``(held, reasons, the record's identity)``."""
    from assurance import retest_closure

    found = resolve_retest(scenario, digest)
    if found is None:
        return False, [engine_remediation.REFUSALS["retest_unverifiable"]], None
    record, finding = found
    identity = {"record": str(record.uuid), "finding": str(finding.uuid)}
    latest = retest_closure.latest_record(finding)
    if latest is None or latest.pk != record.pk:
        return False, ["a later retest of the finding is recorded: the gate reads the latest, not this one"], identity
    reasons = retest_closure.refusal_reasons(finding)
    return not reasons, list(reasons), identity


def utility_retained(scenario: FinancialScenario, digest: str | None) -> dict:
    """Utility retained (the owner's specification, section 21): from the cited
    retest's replay -- legitimate use ``retained`` and every behaviour its repair
    contract preserves retained -- or ``broken``; ``Unknown`` where nothing is cited,
    the citation no longer resolves, or the replay cannot tell."""
    from assurance import retest_closure

    if digest is None:
        return {"status": "unknown", "evidence": None,
                "reason": "no Achilles retest or green-team evidence is cited: utility retained is Unknown"}
    found = resolve_retest(scenario, digest)
    if found is None:
        return {"status": "unknown", "evidence": {"digest": digest, "resolved": False},
                "reason": "the cited retest no longer resolves to a record of a finding this scenario rests on"}
    record, finding = found
    document = record.document if isinstance(record.document, dict) else {}
    replay = document.get("replay") if isinstance(document.get("replay"), dict) else {}
    contract = document.get("contract") if isinstance(document.get("contract"), dict) else {}
    preserved = contract.get("preserved") if isinstance(contract.get("preserved"), dict) else {}
    readings = [replay.get("utility"), *preserved.values()]
    evidence = {"digest": digest, "resolved": True, "record": str(record.uuid), "finding": str(finding.uuid)}
    if retest_closure.BROKEN in readings:
        return {"status": "broken", "evidence": evidence,
                "reason": "the retest's replay reads legitimate use, or a behaviour its repair contract preserves, "
                "broken"}
    if replay.get("utility") == retest_closure.RETAINED and all(r == retest_closure.RETAINED for r in preserved.values()):
        return {"status": "retained", "evidence": evidence,
                "reason": "the retest's replay reads legitimate use retained, and every behaviour its repair contract "
                "preserves retained"}
    return {"status": "unknown", "evidence": evidence,
            "reason": "the retest's replay cannot tell whether legitimate use survives"}


def veto(scenario: FinancialScenario) -> dict:
    """The hard security veto (the owner's specification, "Hard security veto";
    decided: the veto always wins). ``applies`` is True where a finding the scenario
    rests on, or an observed effect of it, is a hard release blocker in Mythos policy
    (:data:`VETO_POLICY`); ``"unknown"`` where that cannot be read, which counts as
    applying; False only where every one was read and none is. Never raises: a
    fault reading SPINE is ``"unknown"``, with the fault's type."""
    try:
        blockers, unreadable = _blockers(scenario)
    except Exception as error:  # noqa: BLE001 - an unreadable blocker status is "unknown", which applies
        blockers, unreadable = [], [{"kind": "spine", "id": None,
                                     "reason": f"SPINE could not be read ({type(error).__name__})"}]
    if blockers:
        applies = True
        reason = "a hard release blocker in Mythos policy: " + "; ".join(b["reason"] for b in blockers)
    elif unreadable:
        applies = "unknown"
        reason = "whether this is a hard release blocker cannot be read, so the veto is treated as applying: " + \
            "; ".join(u["reason"] for u in unreadable)
    else:
        applies = False
        reason = "no finding or observed effect this scenario rests on is a hard release blocker in Mythos policy"
    return {
        "applies": applies,
        "reason": reason,
        "remediation_required": applies is not False,
        "statement": None if applies is False else engine_remediation.VETO_STATEMENT,
        "blockers": blockers,
        "unreadable": unreadable,
        "policy": VETO_POLICY,
    }


def acceptance_lapse(finding: Finding, now) -> str | None:
    """Why ``finding``'s acceptance no longer stands, as the decision reads it
    (owner decision Q6, :func:`assurance.decision.accepted_risk_signal`), or ``None``
    while it stands: its ``risk_accepted_until`` after ``now`` and the severity it was
    accepted at covering the finding's severity now (``decision._acceptance_covers``)."""
    from assurance import decision as _decision

    until = finding.risk_accepted_until
    if until is None:
        return "its acceptance never named an end"
    if until <= now:
        return f"its acceptance lapsed at {until.isoformat()}"
    if not _decision._acceptance_covers(finding):
        return "it was accepted at a lower severity than it has now, or at none"
    return None


def _blockers(scenario: FinancialScenario) -> tuple[list[dict], list[dict]]:
    from assurance import decision as _decision
    from assurance.dispatch import _BLOCKING_DECISIONS
    from assurance.models import RESOLVED_FINDING_STATUSES, SEVERITY_ORDER, UNTRUSTED_SEVERITY_STATUSES, severity_rank

    blockers: list[dict] = []
    unreadable: list[dict] = []
    linked = _linked_findings(scenario)
    rows = {str(f.uuid): f for f in Finding.objects.filter(deployment_id=scenario.deployment_id, uuid__in=linked)}
    now = _decision.decision_now(Deployment.objects.get(pk=scenario.deployment_id))
    for uuid in linked:
        finding = rows.get(uuid)
        if finding is None:
            unreadable.append({"kind": "finding", "id": uuid,
                               "reason": f"finding {uuid} is not one of the deployment's findings now"})
            continue
        lapse = None
        if finding.status == Finding.Status.ACCEPTED:
            # An accepted finding is settled only while its acceptance STANDS, as the
            # decision reads it (owner decision Q6). One that lapsed, never named an
            # end, or was made at a lower severity is a risk nobody carries now: read
            # as an active finding of its severity.
            lapse = acceptance_lapse(finding, now)
            if lapse is None:
                continue
        elif finding.status in RESOLVED_FINDING_STATUSES:
            continue
        if finding.status in UNTRUSTED_SEVERITY_STATUSES:
            unreadable.append({"kind": "finding", "id": uuid,
                               "reason": f"finding {uuid} is {finding.status}: its severity can no longer be trusted"})
            continue
        severity = (finding.severity or "").strip().lower()
        if severity not in SEVERITY_ORDER:
            unreadable.append({"kind": "finding", "id": uuid,
                               "reason": f"finding {uuid} has no severity Mythos policy reads ({finding.severity!r})"})
            continue
        placed = next((d for t, d in _decision.FINDING_SEVERITY_DECISIONS if severity_rank(severity) >= severity_rank(t)),
                      None)
        if placed in _BLOCKING_DECISIONS:
            carried = "" if lapse is None else f", accepted but {lapse}: nobody carries the risk now"
            blockers.append({"kind": "finding", "id": uuid, "severity": severity, "status": finding.status,
                             "acceptance": lapse,
                             "places_the_deployment_at": str(placed),
                             "reason": f"finding {uuid} ({severity}, {finding.status}{carried}) places the deployment "
                             f"at {placed}"})
    observed = list(CausalEffect.objects.filter(scenario=scenario, origin="observed").order_by("effect_key", "pk"))
    if observed:
        from assurance import workflow_chains

        outcomes = {
            str(row.uuid): row for row in WorkflowChainOutcome.objects.filter(
                deployment_id=scenario.deployment_id, uuid__in=[e.observed_effect for e in observed])
        }
        composition = workflow_chains.composition_for(Deployment.objects.get(pk=scenario.deployment_id))
        blocking = composition.decision in _BLOCKING_DECISIONS
        for effect in observed:
            row = outcomes.get(effect.observed_effect)
            if row is None:
                unreadable.append({"kind": "effect", "id": effect.effect_key,
                                   "reason": f"effect {effect.effect_key}'s SPINE outcome is not the deployment's now"})
            elif blocking and row.workflow in composition.deciding:
                blockers.append({"kind": "effect", "id": effect.effect_key, "workflow": row.workflow,
                                 "places_the_deployment_at": str(composition.decision),
                                 "reason": f"effect {effect.effect_key}'s workflow {row.workflow} has a violated chain, "
                                 f"which places the deployment at {composition.decision}"})
    if not linked and not observed:
        unreadable.append({"kind": "scenario", "id": str(scenario.uuid),
                           "reason": "the scenario names no finding and no observed effect to read"})
    return blockers, unreadable


# ------------------------------------------------------------ the option


def _check_reductions(option: engine_remediation.Option) -> None:
    """Each reduction admitted by the run's own parameter-to-distribution rule now,
    so an option a run would refuse is refused when it is written. The engine (and
    numpy) is imported here, when an option is written: one that will not import is
    ``ProbabilisticEngineUnavailable``, answered 503, and nothing is recorded."""
    from .engine import parameter_set as pset

    try:
        from .engine import distributions
        from .engine import scenario_simulation as ss
    except Exception as error:  # noqa: BLE001 - any import fault of numpy or the engine is a returned 503
        raise pset.ProbabilisticEngineUnavailable(
            f"the probabilistic engine will not import ({type(error).__name__})"
        ) from None

    for parameter in option.reductions():
        form = option.distributions.get(parameter.name)
        try:
            ss.resolve(parameter, None if form is None else ss.parse_stated(form, f"{parameter.name}.distribution"))
        except ss.ScenarioSimulationRefused as refused:
            raise _EngineCode(refused.code, ss.REFUSALS[refused.code], refused.detail) from None
        except distributions.DistributionRefused as refused:
            raise _EngineCode(refused.code, distributions.REFUSALS[refused.code], refused.detail) from None


class _EngineCode(ValueError):
    def __init__(self, code: str, meaning: str, detail: str):
        self.code, self.meaning, self.detail = code, meaning, detail
        super().__init__(f"{code}: {meaning} ({detail})")


def _check_spine(scenario: FinancialScenario, option: engine_remediation.Option) -> None:
    """Every SPINE id the option names is found in the version's deployment, and
    every component it acts on is the version's."""
    for item in option.dependencies:
        if item["kind"] == "finding":
            found = Finding.objects.filter(deployment_id=scenario.deployment_id, uuid=item["id"]).exists()
        elif item["kind"] == "asset":
            found = Asset.objects.filter(deployment_id=scenario.deployment_id, uuid=item["id"]).exists()
        else:
            continue
        if not found:
            raise engine_remediation.RemediationRefused("dependency_not_found", f"{item['kind']} {item['id']}")
    if option.families is not None:
        for family in option.families:
            if not LossComponent.objects.filter(loss_event__scenario=scenario, family=family).exists():
                raise engine_remediation.RemediationRefused("option_matches_nothing", family)
    if option.components is not None:
        keys = set()
        for event in LossEvent.objects.filter(scenario=scenario):
            keys.update(f"{event.event_key}/{key}" for key in
                        LossComponent.objects.filter(loss_event=event).values_list("component_key", flat=True))
        unknown = sorted(set(option.components) - keys)
        if unknown:
            raise engine_remediation.RemediationRefused("remediation_target_unknown", ", ".join(unknown))


def record_option(scenario: FinancialScenario, body, *, author) -> tuple[RemediationOption, bool]:
    """Record ``body`` as the ONE remediation option of ``scenario``, or return the
    one recorded for the same option (``created`` False). Refused with a code: the
    engine's form (:func:`engine.remediation.parse_option`); a reduction the run's
    rule would refuse; an id not in the deployment; a citation that cannot be
    verified (``retest_unverifiable``), or a retest that does not show the control
    held (``retest_control_not_held``); another option already held
    (``remediation_option_held``). Every check runs before the transaction, which
    only inserts."""
    option = engine_remediation.parse_option(body)
    _check_reductions(option)
    _check_spine(scenario, option)
    if option.observed_by is not None:
        held, reasons, _ = control_held(scenario, option.observed_by)
        if not held:
            code = "retest_unverifiable" if resolve_retest(scenario, option.observed_by) is None else \
                "retest_control_not_held"
            raise engine_remediation.RemediationRefused(code, "; ".join(reasons))
    if option.utility_evidence is not None and resolve_retest(scenario, option.utility_evidence) is None:
        raise engine_remediation.RemediationRefused("retest_unverifiable", "utility_evidence")
    digest = engine_remediation.option_digest(str(scenario.uuid), option.document)
    found = RemediationOption.objects.filter(scenario=scenario).first()
    if found is not None:
        if found.option_digest == digest:
            return found, False
        raise EconomicsRefused("remediation_option_held", f"scenario {scenario.uuid}")
    row = RemediationOption(
        deployment_id=scenario.deployment_id,
        scenario=scenario,
        title=option.title,
        document=dict(option.document),
        option_digest=digest,
        currency=option.currency,
        time_to_implement_days=option.time_to_implement_days,
        observed_by=option.observed_by or "",
        utility_evidence=option.utility_evidence or "",
        author=author,
    )
    try:
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "remediation_option_held":
            raise
        found = RemediationOption.objects.filter(scenario=scenario).first()
        if found is None:
            raise
        if found.option_digest != digest:
            raise EconomicsRefused("remediation_option_held", f"scenario {scenario.uuid}") from None
        return found, False
    return row, True


# ------------------------------------------------------------ the runs


@dataclass
class OptionRuns:
    """What :func:`simulate_option` gave: each run's outcome and its card's, or the
    code and detail of what stopped it (``stage``: the run that did not record)."""

    current: object | None = None
    current_card: object | None = None
    residual: object | None = None
    residual_card: object | None = None
    code: str | None = None
    detail: str = ""
    stage: str | None = None
    overrun: list[str] = field(default_factory=list)

    @property
    def created(self) -> bool:
        return any(o is not None and o.created for o in (self.current, self.residual))


def simulate_option(option: RemediationOption, *, seed: int, draws: int, severe_percentile, time_budget: float
                    ) -> OptionRuns:
    """The current run of ``option``'s scenario version (where it is missing) and the
    option's residual run, with ``seed`` and ``draws``, each through step 7b's service
    (idempotent: the same inputs return the stored row, and never run a second), and
    each one's Validity Card, all under ONE deadline (``time_budget``): a stage with
    nothing left is not started, and records nothing. No transaction or lock is held
    while either run computes."""
    from . import simulation_service, validity_service

    deadline = time.monotonic() + time_budget

    def remaining() -> float:
        return deadline - time.monotonic()

    runs = OptionRuns()
    scenario = FinancialScenario.objects.get(pk=option.scenario_id)
    # The residual run holds more values than its current run (its reduction factor,
    # its uniform draws and a reduction's draws per occurrence): checked FIRST, so a
    # pair that cannot both fit is refused before either runs, never a completed
    # current run beside a refused residual one (review round 1, LOW-2).
    unfit = simulation_service.residual_unfit(scenario, option, seed=seed, draws=draws)
    if unfit is not None:
        (runs.code, runs.detail), runs.stage = unfit, "residual"
        return runs
    for stage, remediation in (("current", None), ("residual", option)):
        if remaining() <= 0:
            runs.overrun.append(f"the {stage} run")
            runs.code, runs.detail, runs.stage = "time_over_budget", f"the deadline ran out before the {stage} run", stage
            return runs
        outcome = simulation_service.simulate_scenario(
            scenario, seed=seed, draws=draws, severe_percentile=severe_percentile, time_budget=remaining(),
            remediation=remediation,
        )
        setattr(runs, stage, outcome)
        if outcome.result is None:
            runs.code, runs.detail, runs.stage = outcome.code, outcome.detail, stage
            return runs
        if remaining() > 0:
            card = validity_service.issue_card(outcome.result, time_budget=remaining())
        else:
            card = validity_service.CardOutcome(None, False, "time_over_budget",
                                                f"the deadline ran out before the {stage} run's Validity Card")
        if card.code == "time_over_budget":
            runs.overrun.append(f"the {stage} run's Validity Card")
        setattr(runs, f"{stage}_card", card)
    return runs


# ------------------------------------------------------------ the ROI document

#: The gross-cash figures shown beside the headline's (decision 6, the owner's interim).
GROSS_FIGURES = (
    "current_expected_annual_exposure",
    "residual_expected_annual_exposure",
    "expected_reduction",
    "risk_adjusted_roi",
    "payback",
    "tail_reduction",
)


def ss_gross() -> str:
    """The gross-cash line's name, as the run's record names it (no engine import)."""
    return "gross_cash"


def deployment_decision(scenario: FinancialScenario) -> dict:
    """The deployment's standing decision as last recorded (``Deployment.decision``),
    shown beside the economics as a statement and NOT as a veto: an owner's interim
    (decision 9). Read, never recomputed, so the document stays a read of stored rows."""
    from assurance.dispatch import _BLOCKING_DECISIONS

    stored = Deployment.objects.filter(pk=scenario.deployment_id).values_list("decision", flat=True).first()
    if not stored:
        statement = "the deployment has no standing decision; this ROI does not stand in for one"
    else:
        statement = f"deployment decision: {stored}; this ROI does not override it"
    return {
        "decision": stored or None,
        "blocking": bool(stored) and stored in _BLOCKING_DECISIONS,
        "statement": statement,
        "veto": "not a veto: the hard security veto reads the findings and effects this scenario rests on",
        "source": "the deployment's stored standing decision, as last recorded; not recomputed here",
    }


def _current_of(residual: SimulationResult) -> SimulationResult | None:
    """The current run a residual run is paired with: the scenario version's own
    run (no option) of the same seed and draws whose inputs are EXACTLY the residual
    run's without its remediation -- so its input digest is the digest of those."""
    inputs = residual.inputs if isinstance(residual.inputs, dict) else {}
    try:
        digest = canonical_digest({key: value for key, value in inputs.items() if key != "remediation"})
    except (TypeError, ValueError):
        return None
    return SimulationResult.objects.filter(
        scenario_id=residual.scenario_id, remediation__isnull=True, input_digest=digest, seed=residual.seed,
        draws=residual.draws,
    ).first()


def _side(result: SimulationResult | None, built: dict | None) -> dict:
    if result is None:
        return {"not_reported": "no current run of the same seed and draws is recorded: simulate the option again"}
    return {
        "simulation": str(result.uuid),
        "status": result.status,
        "seed": result.seed,
        "draws": result.draws,
        "severe_percentile": result.severe_percentile,
        "input_digest": result.input_digest,
        "result_digest": result.result_digest or None,
        "refusal": None if not result.refusal_code else {"code": result.refusal_code, "detail": result.refusal_detail},
        "grade": built["grade"],
        "banner_reason": built["banner_reason"],
        "excluded_from_totals": built["excluded_from_totals"],
        "integrity": built["integrity"],
        "report_digest": built["digest"],
    }


def _option_part(option: RemediationOption, document: dict, observed: dict | None) -> dict:
    effect = document.get("control_effect") if isinstance(document.get("control_effect"), dict) else {}
    return {
        "uuid": str(option.uuid),
        "title": option.title,
        "digest": option.option_digest,
        "recorded_at": option.recorded_at.isoformat(),
        "author": option.author_username or None,
        "currency": option.currency,
        "implementation_cost": document.get("implementation_cost"),
        "recurring_cost": document.get("recurring_cost"),
        "time_to_implement_days": option.time_to_implement_days,
        "dependencies": document.get("dependencies"),
        "control_effect": {
            "frequency_reduction": effect.get("frequency_reduction"),
            "magnitude_reduction": effect.get("magnitude_reduction"),
            "acts_on": effect.get("acts_on"),
            "observed_by": observed,
            "statement": "a reduction is shown as recorded; one resting on MYTHOS_OBSERVED cites the retest it was "
            "observed in, verified when the option was recorded and again now",
        },
        "utility_evidence": option.utility_evidence or None,
    }


def roi_document(scenario: FinancialScenario, residual: SimulationResult | None = None) -> dict | None:
    """The ROI document of ``scenario``'s remediation option (spec, section 28), for
    ``residual`` (else the option's latest residual run): canonical JSON with its own
    digest, from stored rows only; ``None`` where the version holds no option or the
    option has no residual run. See the module's rules."""
    option = RemediationOption.objects.filter(scenario=scenario).first()
    if option is None:
        return None
    if residual is None:
        residual = SimulationResult.objects.filter(scenario=scenario, remediation=option).order_by("-id").first()
        if residual is None:
            return None
    deployment_uuid = str(Deployment.objects.get(pk=scenario.deployment_id).uuid)
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    code = build.currency if build is not None else option.currency
    shown = report._Shown(code)

    failed: list[str] = []
    parsed = None
    document = option.document if isinstance(option.document, dict) else {}
    try:
        parsed = option.option()
        if engine_remediation.option_digest(str(scenario.uuid), parsed.document) != option.option_digest or \
                dict(parsed.document) != document:
            raise ValueError("the option no longer gives its digest")
    except (ValueError, TypeError):
        failed.append("option_digest")
        parsed = None
    block = residual.inputs.get("remediation") if isinstance(residual.inputs, dict) else None
    named = (block.get("option"), block.get("option_digest")) if isinstance(block, dict) else None
    if residual.remediation_id != option.pk or named != (str(option.uuid), option.option_digest):
        failed.append("residual_option")
    current = _current_of(residual)
    if current is None:
        failed.append("current_pairing")

    residual_report = report.build_report(residual)
    current_report = None if current is None else report.build_report(current)
    marked = residual_report.get("residual_of") or {}
    if (marked.get("option"), marked.get("option_digest")) != (str(option.uuid), option.option_digest):
        if "residual_option" not in failed:
            failed.append("residual_option")
    for side, built in (("current", current_report), ("residual", residual_report)):
        if built is not None:
            failed.extend(f"{side}:{check}" for check in built["integrity"]["failed"])

    observed = None
    observed_reasons: list[str] = []
    if option.observed_by:
        held, observed_reasons, identity = control_held(scenario, option.observed_by)
        observed = {"digest": option.observed_by, "verified": held, "reasons": observed_reasons, **(identity or {})}

    completed = (
        current is not None and current.status == SIMULATION_COMPLETED and residual.status == SIMULATION_COMPLETED
    )
    figures_shown = completed and not failed and parsed is not None
    vetoed = veto(scenario)
    if figures_shown:
        line, now = engine_remediation.line_of(current.record)
        residual_line, after = engine_remediation.line_of(residual.record)
        if line != residual_line:
            figures_shown = False
            failed.append("current_pairing")
    if figures_shown:
        investment = engine_remediation.first_year_investment(parsed)
        figures = engine_remediation.economics(now, after, investment, code, vetoed=vetoed["applies"] is not False)
        # Beside the headline (retained cash under a policy), the same economics on
        # the gross-cash line, before insurance: an owner's interim (decision 6). The
        # headline is unchanged.
        if line == ss_gross():
            figures["gross_cash"] = None
        else:
            gross = engine_remediation.economics(
                engine_remediation.line_of(current.record, ss_gross())[1],
                engine_remediation.line_of(residual.record, ss_gross())[1],
                investment, code, vetoed=vetoed["applies"] is not False,
            )
            figures["gross_cash"] = {key: gross[key] for key in GROSS_FIGURES}
        figures["gross_cash_statement"] = (
            "the gross-cash line's reduction, ROI and payback, before insurance, shown beside the headline line's "
            "(retained cash under a policy, else gross cash, which is then the headline itself); the headline is "
            "unchanged"
        )
    else:
        line = None
        if failed:
            figures = {"not_reported": f"{report.STORED_ROW_UNVERIFIED}: the stored rows fail {', '.join(failed)}"}
        else:
            refused = [side for side, run in (("current", current), ("residual", residual))
                       if run is not None and run.status != SIMULATION_COMPLETED]
            figures = {"not_reported": f"the {' and '.join(refused)} run was refused: there are no figures to "
                       "compare, and no ROI is computed on a refusal"}

    grade = None
    if current_report is not None:
        grade = engine_remediation.lower_grade(current_report["grade"], residual_report["grade"])
    why = None
    if failed:
        why = f"{report.STORED_ROW_UNVERIFIED}: the stored rows fail {', '.join(failed)}"
    elif not report.may_be_totalled(current_report):
        why = f"the current run: {current_report['banner_reason'] or 'not a run a total may sum'}"
    elif not report.stands(residual_report):
        # The residual run is never exposure (its report says so, and no total sums
        # it): it is read as a sound account of its run, completed, verified, graded.
        why = f"the residual run: {residual_report['banner_reason'] or 'not a sound account of its run'}"
    elif observed is not None and not observed["verified"]:
        why = "the control effect's cited retest no longer shows the control held: " + "; ".join(observed_reasons)

    current_grade = None if current_report is None else current_report["grade"]
    delta = engine_remediation.confidence_delta(current_grade, residual_report["grade"])
    delta["statement"] = (
        "the residual run's card grade against the current run's, each as its card document states it where it "
        "verifies, as step 6's report reads it; the control effect's own evidence does not enter either grade yet"
    )
    roi = {
        "schema": engine_remediation.ROI_SCHEMA,
        "scenario": report._scenario_part(scenario, deployment_uuid),
        "option": _option_part(option, document, observed),
        "current": _side(current, current_report),
        "residual": _side(residual, residual_report),
        "line": line,
        "currency": {"code": code, "minor_unit": shown.minor_unit, "rounding": report.ROUNDING},
        "figures": figures,
        "utility_retained": utility_retained(scenario, option.utility_evidence or None),
        "confidence_delta": delta,
        "veto": vetoed,
        "deployment_decision": deployment_decision(scenario),
        "status": SIMULATION_COMPLETED if figures_shown else "not_computed",
        "grade": grade,
        "banner": None if why is None else report.UNKNOWN_BANNER,
        "excluded_from_totals": why is not None,
        "banner_reason": why,
        "integrity": {"verified": not failed, "checks": list(ROI_CHECKS) + [
            f"{side}:{check}" for side in ("current", "residual") for check in report.integrity_checks()
        ], "failed": failed},
        "limitations": list(ROI_LIMITATIONS),
    }
    roi["digest"] = report.digest_of(roi)
    return roi


__all__ = [
    "GROSS_FIGURES",
    "ROI_CHECKS",
    "ROI_LIMITATIONS",
    "VETO_POLICY",
    "OptionRuns",
    "acceptance_lapse",
    "control_held",
    "deployment_decision",
    "record_option",
    "resolve_retest",
    "retest_digest",
    "roi_document",
    "simulate_option",
    "utility_retained",
    "veto",
]
