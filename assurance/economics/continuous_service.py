"""Continuous financial assurance (Economic Exposure E6; ``docs/economics/spec-v1.md``,
section 34): a change event makes the exposure that depends on it stale, names what
must be refreshed, and a refresh an analyst asks for makes a new run, card and
receipt that supersede the stale ones.

- **The dependency map** (:func:`capture`, recorded by step 7b's service with every
  completed exposure run, :class:`~assurance.economics.models.ExposureDependencies`).
  Read BEFORE the run, so a change during it reads as a change: the SPINE claims of
  each type the scenario's templates rest on (:data:`TEMPLATE_CLAIMS`) -- each
  version, its status and whether a retest of it is open --, the input fingerprint of
  each such type and the assurance policy (the scenario's share of the system
  fingerprint, :mod:`assurance.fingerprint`), each effect's asset, each enabling
  finding, each observed effect, the parameter-set version the build read, each feed
  source a figure cites with the version a run reads at the run's as-of date, and the
  engine release.
- **Change -> stale** (:func:`assess`). The map compared with what holds now, for one
  run: every dependency that moved is a reason (:data:`~assurance.economics.models.STALE_REASONS`),
  naming what it was and what it is. A run that depends on nothing that moved stays
  current: a change to a claim, a source, a parameter set or an asset only the other
  scenario rests on leaves this one as it was. Every read applies it -- the report,
  the scenario list, the events route's banner, the scenario document, the receipt's
  route -- so stale is never silent and never totalled as current; a read writes
  nothing. A run with no map is stale (``dependencies_unrecorded``); a fault reading
  what holds now is stale too (``dependencies_unverifiable``): never current by default.
- **The refresh obligation** (:func:`check`, the assurance route's POST and
  ``manage.py check_financial_assurance``). A check records each stale current run
  as a :class:`~assurance.economics.models.ExposureStaleness` with its reasons and
  exactly what to refresh -- the scenario, the parameters, the sources, the claims
  whose SPINE outcome it waits on -- once per set of reasons. Recorded, a run stays
  stale whatever its dependencies do later: only a refresh that stands closes it. A
  check runs no Monte Carlo and imports nothing that does.
- **The refresh** (:func:`prepare_refresh`, :func:`rebuild_body`, :func:`close_obligations`;
  the scenario's refresh route, capped like every Monte Carlo route). Only when an
  analyst asks: the stale scenario version is rebuilt from the parameter set's
  current version as of the refresh date (superseding it), run, carded and, where
  asked, receipted; the obligations of the stale version close only when the new run
  STANDS (:func:`report.may_be_totalled` of its report, which a stale run never is),
  each closure naming SPINE's outcome for the financial claim -- restored,
  contradicted, left Unknown, or (nothing technical having moved) superseded. A run
  that rests on a claim SPINE has not yet re-assessed is stale itself, so a refresh
  made while a retest is open closes nothing.

Nothing is rewritten: a stale run, its card and its receipt stay as recorded and
still verify; a closure says what supersedes them. Nothing here is on a stop path:
it reads SPINE's rows and never writes one, holds no transaction while it reads,
and every row it writes is an economics row, inserted in a transaction of its own.
It imports the probabilistic engine only to read the engine release, inside a
function.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from django.db import IntegrityError, transaction
from django.utils import timezone

from assurance.composition import OFF_ROUTE

from .engine import feeds as feed_rules
from .engine.pack_inputs import SCHEMAS as INDUSTRY_PACKS
from .report import STALE_BANNER
from .models import (
    DEPENDENCIES_SCHEMA,
    SIMULATION_COMPLETED,
    STALE_REASONS,
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EffectFinding,
    ExposureDependencies,
    ExposureRefresh,
    ExposureStaleness,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    ScenarioBuild,
    SimulationResult,
    canonical_digest,
)

#: The SPINE claim types each template's loss rests on: a claim of one of these
#: types falsified, superseded or invalidated makes the scenario's exposure stale
#: (spec, section 34.1). Conservative: a type is listed where its falsification could
#: change how likely or how large the loss is.
TEMPLATE_CLAIMS: dict[str, tuple[str, ...]] = {
    # The agent's reach to move money, and the model and tools that make it up.
    "payment_agent_misuse": ("ai_bom", "effective_access"),
    # Where the data may go, and what can reach another customer's.
    "cross_customer_data_exposure": ("data_boundary", "effective_access"),
    # What the model says: the model, its prompt and its provider.
    "customer_service_ai_misstatement": ("ai_bom",),
    # The workflow's reach, and the model in it.
    "fraud_aml_workflow_failure": ("ai_bom", "effective_access"),
    # The reach the bypass uses, and the agent's composition.
    "agent_approval_bypass": ("ai_bom", "effective_access"),
    # Which provider and model serve, and where.
    "third_party_provider_outage": ("ai_bom", "data_boundary"),
}
#: Every claim type: what a template the table does not list, or a scenario with no
#: effect, rests on (the conservative reading).
ALL_CLAIM_TYPES: tuple[str, ...] = ("ai_bom", "data_boundary", "effective_access")
#: The salient configuration SPINE's system fingerprint carries and no claim family
#: reads (``assurance.fingerprint._SALIENT_METADATA_KEYS`` less the access and BOM
#: facts): followed on its own (``fingerprint_moved``, ``system:unclaimed``) for every
#: run resting on a model, so a change no claim sees is not a change no run sees.
UNCLAIMED_KEYS: tuple[str, ...] = ("generation_config", "prompt_config", "region", "system_prompt", "temperature")
#: The claim statuses that are a pass, for SPINE's outcome on a refresh.
PASSING = frozenset({"verified", "supported", "partially_verified"})
STALE_STATUS = "stale"
CONTRADICTED = "contradicted"
#: The reasons a refresh waits on SPINE for: technical ones. A run stale for one of
#: these closes with SPINE's outcome for the claim (restored, contradicted, Unknown);
#: one stale only for financial or release reasons closes as superseded.
TECHNICAL = frozenset(
    {
        "dependencies_unrecorded",
        "dependencies_unverifiable",
        "claim_superseded",
        "claim_invalidated",
        "claim_status_moved",
        "claim_established",
        "fingerprint_moved",
        "route_moved",
        "asset_changed",
        "finding_changed",
        "evidence_changed",
    }
)
#: What the refresh does, in every obligation.
REFRESH_ACTION = (
    "rebuild the scenario version from the current version of its parameter set, as of the refresh date, "
    "superseding it; run it; issue its Validity Card and, where asked, its receipt. Only the scenario named here "
    "is re-run, and the obligation closes only when the new run stands"
)
#: The SPINE outcomes, as statements.
OUTCOME_STATEMENTS = {
    "restored": "SPINE restores the financial claim: every claim the new run rests on is a pass again",
    "contradicted": "SPINE contradicts the financial claim: a claim the new run rests on is contradicted",
    "unknown": "SPINE leaves the financial claim Unknown: a claim the new run rests on is not a pass",
    "superseded": "nothing technical moved: the new figures supersede the stale ones",
}


class RefreshRefused(ValueError):
    """A refresh that cannot be made, with its code and what to do instead."""

    def __init__(self, code: str, detail: str, status: int = 400):
        super().__init__(code, detail)
        self.code = code
        self.detail = detail
        self.status = status


def _today() -> date:
    """Today's date, UTC: the date a source's freshness is read on. One seam."""
    return timezone.now().date()


def bound_claim_types(scenario: FinancialScenario) -> tuple[str, ...]:
    """The claim types ``scenario`` rests on: those of its effects' templates
    (:data:`TEMPLATE_CLAIMS`); every type where a template is not listed or the
    version has no effect."""
    templates = set(CausalEffect.objects.filter(scenario=scenario).values_list("template_id", flat=True))
    if not templates or any(t not in TEMPLATE_CLAIMS for t in templates):
        return ALL_CLAIM_TYPES
    return tuple(sorted({claim for t in templates for claim in TEMPLATE_CLAIMS[t]}))


def _as_of_of(inputs, build) -> date | None:
    """The run's as-of date, as the card reads it: its build's, else the latest its
    components were computed at."""
    if build is not None:
        return build.as_of
    dates = [c["as_of"] for event in (inputs or {}).get("events", []) for c in event.get("components", [])]
    return date.fromisoformat(max(dates)) if dates else None


def _release() -> dict:
    """The engine release a run's figures and its card rest on, apart from the
    formulas a run names by version (a recorded formula version never changes): the
    run's engine versions and limits, the sensitivity method, the grade and the card
    (``validity_service.release_record``). Imports the engine."""
    from types import SimpleNamespace

    from . import validity_service
    from .engine import scenario_simulation as ss

    # ss.versions reads only the formulas off its input; with no events it names none.
    versions = dict(ss.versions(SimpleNamespace(events=())))
    versions.pop("formulas", None)
    return validity_service.release_record(versions)


# ------------------------------------------------------------------ what holds now


class Now:
    """What holds now for ONE deployment, each part read once and kept for the call:
    SPINE's current claims, open retests and input fingerprints, the policy pin,
    assets, findings and observed effects, parameter-set versions, feed sources and
    the engine release. Reads only, and holds no transaction."""

    def __init__(self, deployment_id, *, today: date | None = None):
        self.deployment_id = deployment_id
        self.today = today or _today()
        self._cache: dict = {}

    def _once(self, key, compute):
        if key not in self._cache:
            self._cache[key] = compute()
        return self._cache[key]

    @property
    def deployment(self):
        from assurance.models import Deployment

        return self._once(
            "deployment",
            lambda: Deployment.objects.prefetch_related("assets__provider__assertions", "declared_components")
            .select_related("data_boundary")
            .get(pk=self.deployment_id),
        )

    @property
    def input_fingerprints(self) -> dict[str, str]:
        from assurance.fingerprint import claim_input_fingerprints

        return self._once("inputs", lambda: claim_input_fingerprints(self.deployment))

    @property
    def policy(self) -> str:
        from assurance.fingerprint import policy_version

        return self._once("policy", lambda: policy_version(self.deployment))

    @property
    def open_retests(self) -> frozenset:
        from assurance.models import RetestRequirement

        return self._once(
            "retests",
            lambda: frozenset(
                RetestRequirement.objects.filter(deployment_id=self.deployment_id, resolved_at__isnull=True)
                .values_list("claim__fingerprint", flat=True)
            ),
        )

    def claims(self, claim_type: str) -> list[dict]:
        """The current claims of ``claim_type``, each as a map records it."""
        from assurance.models import AssuranceClaim

        def read():
            rows = AssuranceClaim.objects.filter(deployment_id=self.deployment_id, claim_type=claim_type).current()
            return [
                {
                    "identity": row.fingerprint,
                    "version": str(row.uuid),
                    "status": row.status,
                    "input_fingerprint": row.input_fingerprint,
                    "system_fingerprint": row.system_fingerprint,
                    "policy_version": row.policy_version,
                    "retest_open": row.fingerprint in self.open_retests,
                }
                for row in sorted(rows, key=lambda c: (c.fingerprint, c.pk))
            ]

        return self._once(("claims", claim_type), read)

    @property
    def system_fingerprint(self) -> str:
        from assurance.fingerprint import compute_system_fingerprint

        return self._once("system", lambda: compute_system_fingerprint(self.deployment))

    def drifted(self, claim: dict, claim_type: str) -> str:
        """Why the state ``claim`` (a current claim, as :meth:`claims` reads it) is
        bound to no longer holds -- by SPINE's own predicate
        (:func:`assurance.fingerprint.claim_state_moved`), its inputs or the policy it
        was judged under -- or ``""``."""
        from types import SimpleNamespace

        from assurance.fingerprint import claim_state_moved

        bound = SimpleNamespace(claim_type=claim_type, input_fingerprint=claim["input_fingerprint"],
                                system_fingerprint=claim["system_fingerprint"])
        # The whole-system fingerprint is read only where SPINE's predicate needs it: a
        # row bound before per-claim fingerprints, or a type with no input table.
        needs_system = not claim["input_fingerprint"] or claim_type not in self.input_fingerprints
        system = self.system_fingerprint if needs_system else ""
        why = []
        if claim_state_moved(bound, system_fp=system, input_fps=self.input_fingerprints):
            why.append("its inputs no longer match the deployment")
        if claim["policy_version"] != self.policy:
            why.append("the assurance policy it was judged under is no longer in force")
        return "; ".join(why)

    def asset(self, asset_uuid: str) -> str | None:
        """The digest of an asset's stable descriptor and whether it is in the graph,
        or ``None`` for one the deployment does not hold."""
        from assurance.fingerprint import _asset_descriptor
        from assurance.graph_refs import retired

        def read():
            found = {str(a.uuid): a for a in self.deployment.assets.all()}
            return {
                key: canonical_digest({"descriptor": _asset_descriptor(a), "in_graph": not retired(a)})
                for key, a in found.items()
            }

        return self._once("assets", read).get(asset_uuid)

    def finding(self, finding_uuid: str) -> dict | None:
        """A finding's status and severity, whether its evidence has expired by SPINE's
        own ageing (:func:`assurance.change.is_stale`: not re-observed within
        ``EVIDENCE_TTL_DAYS``, on SPINE's own clock: a retest is due before it is read
        as current), and whether the deployment's latest scan no longer reports it
        (:func:`assurance.change.change_status` ``cleared``: the absence of a signal,
        never a fix)."""
        from assurance.change import change_status, is_stale
        from assurance.models import Finding

        def read():
            rows = list(Finding.objects.filter(deployment_id=self.deployment_id).only(
                "uuid", "status", "severity", "first_seen", "last_seen"
            ))
            latest = max((row.last_seen for row in rows if row.last_seen is not None), default=None)
            return {
                str(row.uuid): {"status": row.status, "severity": row.severity, "evidence_expired": is_stale(row),
                                "cleared": change_status(row, latest) == "cleared"}
                for row in rows
            }

        return self._once("findings", read).get(finding_uuid)

    def observed(self, outcome_uuid: str) -> dict | None:
        """An observed effect's row: its status, its evidence digest, and SPINE's
        reading of the route it was taken against (:func:`assurance.workflow_chains.route_of`:
        ``current``, ``moved`` or ``unrecorded``; the last two are off-route, not
        evidence about what serves now)."""
        from assurance.models import WorkflowChainOutcome
        from assurance.workflow_chains import route_of

        def read(key=outcome_uuid):
            row = WorkflowChainOutcome.objects.filter(deployment_id=self.deployment_id, uuid=key).first()
            if row is None:
                return None
            return {"status": row.status, "evidence_digest": row.evidence_digest or "",
                    "route": route_of(row, self.serving)}

        return self._once(("observed", outcome_uuid), read)

    @property
    def serving(self) -> str:
        """The deployment's served-route fingerprint now (SPINE's
        :func:`assurance.served_route.serving_route_now`, the route every chain outcome
        is read against, and a part of its system fingerprint)."""
        from assurance.served_route import serving_route_now

        return self._once("serving", lambda: serving_route_now(self.deployment))

    @property
    def serving_routes(self) -> dict[str, str]:
        """Each serving asset's route fingerprint, by the asset's uuid: the assets
        SPINE gives a served route (``served_route.serves_inference``)."""
        from assurance.served_route import route_fingerprint, served_route, serves_inference

        return self._once("routes", lambda: {
            str(a.uuid): route_fingerprint(served_route(a)) for a in self.deployment.assets.all() if serves_inference(a)
        })

    @property
    def unclaimed(self) -> dict[str, str]:
        """The configuration SPINE's system fingerprint carries and no claim reads, by
        asset: each in-graph asset's salient metadata outside every claim family (its
        prompt and generation configuration, temperature, region), as a digest, where
        it has any."""
        from assurance.graph_refs import in_graph

        def read():
            found = {}
            for asset in in_graph(self.deployment.assets.all()):
                metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
                held = {key: metadata[key] for key in UNCLAIMED_KEYS if metadata.get(key) is not None}
                if held:
                    found[str(asset.uuid)] = canonical_digest(held)
            return found

        return self._once("unclaimed", read)

    def parameter_set(self, set_key: str) -> CustomerParameterSet | None:
        return self._once(
            ("set", set_key), lambda: CustomerParameterSet.current(self.deployment_id, set_key)
        )

    def source(self, key: str, as_of: date, parameters=None) -> dict:
        """The state of feed source ``key`` for a run on ``as_of`` whose figures are
        ``parameters`` (its canonical inputs'), as the card reads it
        (``feeds.states_for``: a prefill source aged from the version each figure was
        accepted from, a context source failing closed)."""
        from . import feeds

        # Kept by what the state is read from: the figures that cite the source.
        cited = None if parameters is None else {
            name: parameters[name] for name in feed_rules.referenced_keys(parameters).get(key, [])
        }
        return self._once(
            ("source", key, as_of, None if cited is None else canonical_digest(cited)),
            lambda: feeds.states_for([key], deployment=self.deployment_id, as_of=as_of, parameters=parameters)[key],
        )

    def release(self) -> tuple[str | None, dict | None, str]:
        """``(digest, record, "")`` of the engine release, or ``(None, None, why)``."""

        def read():
            try:
                record = _release()
            except Exception as error:  # noqa: BLE001 - an engine that will not import is a reason, never a raise
                return None, None, type(error).__name__
            return canonical_digest(record), record, ""

        return self._once("release", read)


def _source_entry(state: dict) -> dict:
    used = state.get("used_version") or {}
    return {
        "as_of": state.get("as_of"),
        "used_version": used.get("uuid"),
        "version": used.get("version"),
        "state": state.get("state"),
    }


def capture(scenario: FinancialScenario, inputs, *, now: Now | None = None) -> dict:
    """The dependency map of a run of ``scenario`` on ``inputs`` (its canonical
    inputs), read now: what the run depends on, each part as it stands (spec, section
    34.1). Called before the run; raises on a fault (the caller records no map, and
    the run reads stale)."""
    now = now or Now(scenario.deployment_id)
    types = bound_claim_types(scenario)
    effects = list(CausalEffect.objects.filter(scenario=scenario).order_by("effect_key", "id"))
    links = list(EffectFinding.objects.filter(effect_id__in=[e.pk for e in effects]).order_by("finding", "id"))
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    parameter_set = None
    if build is not None:
        version = CustomerParameterSet.objects.get(pk=build.parameter_set_id)
        parameter_set = {"set_key": version.set_key, "version": version.version, "content_digest": version.content_digest}
    as_of = _as_of_of(inputs, build)
    sources = {}
    for key in sorted(feed_rules.referenced_keys((inputs or {}).get("parameters"))):
        sources[key] = (
            {"as_of": None, "used_version": None, "version": None, "state": feed_rules.MISSING}
            if as_of is None
            else _source_entry(now.source(key, as_of, (inputs or {}).get("parameters")))
        )
    digest, record, why = now.release()
    # A run rests on what serves where its scenario rests on the model's composition
    # (an ai_bom claim type) or an effect is on a serving asset.
    route_bound = "ai_bom" in types or any(e.asset in now.serving_routes for e in effects)
    return {
        "schema": DEPENDENCIES_SCHEMA,
        "scenario": str(scenario.uuid),
        "claim_types": list(types),
        "claims": {claim_type: now.claims(claim_type) for claim_type in types},
        "inputs": {claim_type: now.input_fingerprints.get(claim_type) for claim_type in types},
        "policy": now.policy,
        "route_bound": route_bound,
        "route": {"serving": now.serving, "assets": now.serving_routes},
        "unclaimed": now.unclaimed,
        "build_system_fingerprint": scenario.system_fingerprint or None,
        "assets": {e.asset: now.asset(e.asset) for e in effects},
        "findings": {link.finding: now.finding(link.finding) for link in links},
        "observed_effects": {e.observed_effect: now.observed(e.observed_effect) for e in effects if e.observed_effect},
        "parameter_set": parameter_set,
        "as_of": None if as_of is None else as_of.isoformat(),
        "sources": sources,
        "release": {"digest": digest, "record": record, "unavailable": why or None},
    }


def record_dependencies(result: SimulationResult, dependencies: dict, *, captured_at
                        ) -> ExposureDependencies | None:
    """Record ``dependencies`` as ``result``'s map: the row, or ``None`` where it is
    not an exposure run that completed or a map is recorded already. Every check runs
    before the transaction, which only inserts."""
    if result.remediation_id is not None or result.status != SIMULATION_COMPLETED:
        return None
    row = ExposureDependencies(
        deployment_id=result.deployment_id,
        scenario_id=result.scenario_id,
        simulation=result,
        schema=DEPENDENCIES_SCHEMA,
        dependencies=dependencies,
        dependencies_digest=canonical_digest(dependencies),
        captured_at=captured_at,
    )
    try:
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as refused:
        if isinstance(refused, EconomicsRefused) and refused.code != "duplicate_id":
            raise
        return None
    return row


# ------------------------------------------------------------------ change -> stale


def _reason(code: str, dependency: str, detail: str, *, was=None, now=None, **extra) -> dict:
    return {"code": code, "dependency": dependency, "was": was, "now": now, "detail": detail, **extra}


def _claim_reasons(recorded: dict, now: Now) -> list[dict]:
    from assurance.fingerprint import CLAIM_INPUTS

    found = []
    for claim_type in recorded.get("claim_types", []):
        was = {e["identity"]: e for e in recorded.get("claims", {}).get(claim_type, [])}
        held = {e["identity"]: e for e in now.claims(claim_type)}
        dependency = f"claim:{claim_type}"
        for identity, entry in sorted(was.items()):
            if entry["status"] == STALE_STATUS or entry.get("retest_open"):
                found.append(_reason(
                    "claim_invalidated", dependency,
                    f"SPINE had invalidated the {claim_type} claim when the run was made: a retest of it was due",
                    was=entry["status"],
                ))
            current = held.get(identity)
            if current is None:
                found.append(_reason(
                    "claim_superseded", dependency,
                    f"SPINE holds no current version of the {claim_type} claim the run was bound to",
                    was=entry["version"],
                ))
                continue
            if current["version"] != entry["version"]:
                found.append(_reason(
                    "claim_superseded", dependency,
                    f"SPINE superseded the version of the {claim_type} claim the run was bound to",
                    was=entry["version"], now=current["version"],
                ))
            elif current["status"] != entry["status"]:
                code = "claim_invalidated" if current["status"] == STALE_STATUS else "claim_status_moved"
                found.append(_reason(
                    code, dependency,
                    f"the {claim_type} claim the run rests on moved from {entry['status']} to {current['status']}",
                    was=entry["status"], now=current["status"],
                ))
            if current["retest_open"] and not entry.get("retest_open"):
                found.append(_reason(
                    "claim_invalidated", dependency,
                    f"SPINE opened a retest of the {claim_type} claim the run rests on",
                    was=entry["status"], now=current["status"],
                ))
        for identity in sorted(set(held) - set(was)):
            found.append(_reason(
                "claim_established", dependency,
                f"SPINE established a {claim_type} claim after the run, which the run never read",
                now=held[identity]["version"],
            ))
        # The system state a bound claim rests on moved, by SPINE's own predicate (the
        # one its invalidation acts on), before SPINE's check has run: SPINE decides
        # which claims a change affects, and only a change to one this scenario rests
        # on makes it stale.
        families = ", ".join(CLAIM_INPUTS.get(claim_type, ("the whole system state",)))
        why = [moved for moved in (now.drifted(current, claim_type) for _identity, current in sorted(held.items()))
               if moved]
        # And the input fingerprint recorded with the run, compared itself (review round 1
        # of #168, M2): with no claim of the type derived yet, nothing above would see
        # a change to the inputs the type reads. Per type, so a change to inputs only
        # another type reads leaves this run current.
        recorded_inputs = (recorded.get("inputs") or {}).get(claim_type)
        current_inputs = now.input_fingerprints.get(claim_type)
        if recorded_inputs != current_inputs:
            why.append("its inputs are not the ones recorded with the run")
        if why:
            found.append(_reason(
                "fingerprint_moved", f"inputs:{claim_type}",
                f"the system state the {claim_type} claim type rests on ({families}) moved: {'; '.join(why)}",
                was=recorded_inputs, now=current_inputs,
            ))
    if recorded.get("policy") != now.policy:
        found.append(_reason(
            "fingerprint_moved", "policy", "the assurance policy in force is not the one recorded with the run",
            was=recorded.get("policy"), now=now.policy,
        ))
    return found


def _route_reasons(recorded: dict, now: Now) -> list[dict]:
    """The system state outside every claim family that SPINE's system fingerprint
    carries (review round 1 of #168, H1), for a run resting on what serves (its
    scenario rests on the model's composition, or an effect is on a serving asset):
    the served route of every serving asset -- the route every chain outcome is read
    against -- and the salient configuration no claim reads."""
    if not recorded.get("route_bound"):
        return []
    found = []
    route = recorded.get("route") or {}
    before, after = route.get("assets") or {}, now.serving_routes
    if route.get("serving") != now.serving or before != after:
        changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
        found.append(_reason(
            "route_moved", "route",
            "the served route moved on " + (", ".join(changed) if changed else "the deployment's serving assets"),
            was=route.get("serving"), now=now.serving, changed=changed,
        ))
    before, after = recorded.get("unclaimed") or {}, now.unclaimed
    if before != after:
        changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
        found.append(_reason(
            "fingerprint_moved", "system:unclaimed",
            "configuration no claim reads (prompt, generation, temperature, region) moved on " + ", ".join(changed),
            changed=changed,
        ))
    return found


def _spine_rows_reasons(recorded: dict, now: Now) -> list[dict]:
    found = []
    for asset, digest in sorted((recorded.get("assets") or {}).items()):
        current = now.asset(asset)
        if current != digest:
            found.append(_reason(
                "asset_changed", f"asset:{asset}",
                "the asset an effect is bound to changed or left the graph" if current else "the asset is gone",
                was=digest, now=current,
            ))
    for finding, held in sorted((recorded.get("findings") or {}).items()):
        current = now.finding(finding)
        dependency = f"finding:{finding}"
        if current is None or held is None:
            if current != held:
                found.append(_reason("finding_changed", dependency, "an enabling finding is gone"
                                     if current is None else "an enabling finding appeared"))
            continue
        if (current["status"], current["severity"]) != (held["status"], held["severity"]):
            found.append(_reason(
                "finding_changed", dependency, "an enabling finding's status or severity moved",
                was=f"{held['status']}/{held['severity']}", now=f"{current['status']}/{current['severity']}",
            ))
        # SPINE's evidence ageing (review round 1 of #168, L1): a finding not re-observed
        # within its TTL is due a retest before it is read as current.
        if held.get("evidence_expired"):
            found.append(_reason(
                "finding_changed", dependency,
                "the enabling finding's evidence had expired when the run was made (SPINE's evidence ageing): a "
                "retest was due",
            ))
        elif current.get("evidence_expired"):
            found.append(_reason(
                "finding_changed", dependency,
                "the enabling finding's evidence expired (SPINE's evidence ageing): a retest is due before it is read "
                "as current",
            ))
        # SPINE's change state: a scan that no longer reports the finding (cleared) is
        # the absence of a signal, not a fix -- and one that reports it again moves it too.
        if bool(held.get("cleared")) != bool(current.get("cleared")):
            found.append(_reason(
                "finding_changed", dependency,
                "the deployment's latest scan no longer reports the enabling finding (SPINE's change state cleared: "
                "the absence of a signal, never a fix)" if current.get("cleared")
                else "the deployment's latest scan reports the enabling finding again",
                was="cleared" if held.get("cleared") else "reported",
                now="cleared" if current.get("cleared") else "reported",
            ))
    for outcome, held in sorted((recorded.get("observed_effects") or {}).items()):
        current = now.observed(outcome)
        dependency = f"observed_effect:{outcome}"
        if current is None or held is None:
            if current != held:
                found.append(_reason("evidence_changed", dependency, "the observed effect is gone"
                                     if current is None else "the observed effect appeared"))
            continue
        if (current["status"], current["evidence_digest"]) != (held["status"], held["evidence_digest"]):
            found.append(_reason(
                "evidence_changed", dependency,
                "the observed effect no longer holds what it held when the run was made",
                was=held["status"], now=current["status"],
            ))
        # SPINE reads an outcome bound to a route that no longer serves as off-route:
        # not evidence about what serves now (review round 1 of #168, H1).
        if held.get("route") in OFF_ROUTE:
            found.append(_reason(
                "evidence_changed", dependency,
                "the observed effect was taken against a route that did not serve when the run was made",
                was=held.get("route"), now=current.get("route"),
            ))
        elif current.get("route") in OFF_ROUTE:
            found.append(_reason(
                "evidence_changed", dependency,
                "the observed effect was taken against a route that no longer serves",
                was=held.get("route"), now=current.get("route"),
            ))
    return found


def _set_rows(deployment_id, set_key: str, version: int) -> dict[str, dict]:
    found = CustomerParameterSet.objects.filter(deployment_id=deployment_id, set_key=set_key, version=version).first()
    if found is None:
        return {}
    rows = {}
    for row in FinancialParameter.objects.filter(parameter_set=found).order_by("name", "id"):
        rows[row.name] = {
            "unit": row.unit, "currency": row.currency, "low": row.low, "base": row.base, "high": row.high,
            "source_type": row.source_type, "evidence_ref": row.evidence_ref,
            "effective_date": row.effective_date.isoformat(),
            "fresh_until": row.fresh_until.isoformat() if row.fresh_until else None,
            "distribution": row.distribution,
        }
    rows[":insurance_exclusions"] = {"families": list(found.insurance_exclusions)}
    return rows


def _financial_reasons(recorded: dict, now: Now, parameters=None) -> list[dict]:
    found = []
    held = recorded.get("parameter_set")
    if held is not None:
        current = now.parameter_set(held["set_key"])
        if current is None or current.version != held["version"]:
            before = _set_rows(now.deployment_id, held["set_key"], held["version"])
            after = {} if current is None else _set_rows(now.deployment_id, held["set_key"], current.version)
            changed = sorted(n for n in set(before) | set(after) if before.get(n) != after.get(n))
            names = [n for n in changed if not n.startswith(":")]
            detail = (
                f"version {current.version} of the parameter set {held['set_key']} is current; the run read version "
                f"{held['version']}" if current is not None else f"the parameter set {held['set_key']} is gone"
            )
            detail += f": {', '.join(names)} differ" if names else ": no figure differs, the version moved"
            found.append(_reason(
                "parameter_set_superseded", f"parameter_set:{held['set_key']}", detail,
                was=str(held["version"]), now=None if current is None else str(current.version), changed=names,
            ))
            terms = [n for n in changed if n.startswith(("insurance_", ":insurance_"))]
            if terms:
                found.append(_reason(
                    "contract_terms_changed", f"parameter_set:{held['set_key']}:insurance",
                    f"the insurance and contract terms {', '.join(t.lstrip(':') for t in terms)} changed",
                    was=str(held["version"]), now=None if current is None else str(current.version),
                    changed=[t.lstrip(":") for t in terms],
                ))
    for key, entry in sorted((recorded.get("sources") or {}).items()):
        if entry.get("as_of"):
            then = _source_entry(now.source(key, date.fromisoformat(entry["as_of"]), parameters))
            if then["used_version"] != entry.get("used_version"):
                found.append(_reason(
                    "source_superseded", f"source:{key}",
                    f"a run as of {entry['as_of']} would now read version {then['version']} of {key}, not "
                    f"{entry.get('version')}",
                    was=None if entry.get("version") is None else str(entry["version"]),
                    now=None if then["version"] is None else str(then["version"]),
                ))
        today = now.source(key, now.today, parameters)
        if today.get("state") in feed_rules.DOWNGRADING:
            found.append(_reason(
                "source_stale", f"source:{key}",
                f"{key} is {today.get('state')} as of the day it was read (section 29.5): its newest observation is "
                f"past the source's SLA of {today.get('sla_days')} days, or there is none a run may use",
                was=entry.get("state"), now=today.get("state"),
            ))
    return found


def _release_reasons(recorded: dict, now: Now) -> list[dict]:
    held = recorded.get("release") or {}
    digest, current, why = now.release()
    if digest is None or held.get("digest") is None:
        return [_reason(
            "release_unverifiable", "release",
            f"the engine release could not be read ({why or held.get('unavailable') or 'not recorded'})",
        )]
    if digest == held["digest"]:
        return []
    before = held.get("record") or {}
    moved = sorted(part for part in set(before) | set(current) if before.get(part) != current.get(part))
    return [_reason(
        "release_changed", "release", f"the engine release moved since the run: {', '.join(moved)}",
        was=held["digest"], now=digest, changed=moved,
    )]


def _ordered(reasons: list[dict]) -> list[dict]:
    """Every reason once, by its code, dependency and detail."""
    seen, ordered = set(), []
    for reason in sorted(reasons, key=lambda r: (r["code"], r["dependency"], r["detail"])):
        key = (reason["code"], reason["dependency"], reason["detail"])
        if key not in seen:
            seen.add(key)
            ordered.append(reason)
    return ordered


def live_reasons(result: SimulationResult, *, now: Now | None = None) -> list[dict]:
    """Every dependency of ``result`` that moved since it ran, as reasons (none: it is
    current). Reads only; never raises: a fault reading what holds now is a reason."""
    now = now or Now(result.deployment_id)
    found: list[dict] = []
    try:
        mapped = ExposureDependencies.objects.filter(simulation=result).first()
        if mapped is None:
            found.append(_reason(
                "dependencies_unrecorded", "dependencies",
                "no dependency map was recorded with this run: what it rests on cannot be shown unchanged",
            ))
        else:
            recorded = mapped.dependencies
            found += _claim_reasons(recorded, now)
            found += _route_reasons(recorded, now)
            found += _spine_rows_reasons(recorded, now)
            found += _financial_reasons(recorded, now, (result.inputs or {}).get("parameters"))
            found += _release_reasons(recorded, now)
        later = FinancialScenario.objects.filter(supersedes_id=result.scenario_id).order_by("id").first()
        if later is not None:
            found.append(_reason(
                "scenario_superseded", f"scenario:{result.scenario.uuid}",
                f"scenario version {later.uuid} supersedes the version this run is of", now=str(later.uuid),
            ))
    except Exception as error:  # noqa: BLE001 - a fault reading the dependencies is a reason: never current by default
        found.append(_reason(
            "dependencies_unverifiable", "dependencies",
            f"what the run rests on could not be read now ({type(error).__name__})",
        ))
    return _ordered(found)


def refresh_plan(scenario: FinancialScenario, reasons: list[dict]) -> dict:
    """Exactly what a refresh of ``scenario`` must refresh for ``reasons``: the
    scenario, the parameters, sources, claims, assets, findings and observed effects
    that moved, whether the release did, and whether it waits on SPINE."""

    def named(prefix: str) -> list[str]:
        return sorted({r["dependency"][len(prefix):] for r in reasons if r["dependency"].startswith(prefix)})

    parameters = sorted({name for r in reasons for name in r.get("changed", []) if r["code"] != "release_changed"})
    return {
        "scenario": str(scenario.uuid),
        "action": REFRESH_ACTION,
        "parameters": parameters,
        "sources": named("source:"),
        "claims": sorted(set(named("claim:")) | set(named("inputs:"))),
        "assets": named("asset:"),
        "findings": named("finding:"),
        "observed_effects": named("observed_effect:"),
        "release": any(r["code"] in ("release_changed", "release_unverifiable") for r in reasons),
        "awaits_spine": any(r["code"] in TECHNICAL for r in reasons),
    }


@dataclass
class Freshness:
    """Whether a run is current: its state, every reason it is stale (what moved now,
    and what a check recorded), its obligations and what superseded it."""

    state: str
    reasons: list = field(default_factory=list)
    live: list = field(default_factory=list)
    obligations: list = field(default_factory=list)
    superseded_by: dict | None = None
    not_assessed: str | None = None

    @property
    def stale(self) -> bool:
        return self.state == "stale"

    def banner_reason(self) -> str | None:
        if not self.stale:
            return None
        codes = ", ".join(f"{r['code']} ({r['dependency']})" for r in self.reasons)
        superseded = ""
        if self.superseded_by is not None:
            superseded = f"; superseded by run {self.superseded_by['simulation']}"
        return f"stale: {codes}{superseded}: not current until it is refreshed"

    def unknowns(self) -> list[dict]:
        """The report's ``unknowns`` entries for a stale run: one per reason."""
        return [
            {"kind": "stale", "id": r["code"], "reason": f"{r['dependency']}: {r['detail']}",
             "missing": [r["dependency"]]}
            for r in self.reasons
        ] if self.stale else []

    def summary(self) -> dict:
        """The state and each reason's code and dependency (a list line's)."""
        served = {"state": self.state, "reasons": [{"code": r["code"], "dependency": r["dependency"]}
                                                   for r in self.reasons]}
        if self.superseded_by is not None:
            served["superseded_by"] = self.superseded_by
        if self.not_assessed:
            served["not_assessed"] = self.not_assessed
        return served

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "not_assessed": self.not_assessed,
            "reasons": self.reasons,
            "obligations": self.obligations,
            "superseded_by": self.superseded_by,
            "banner": STALE_BANNER if self.stale else None,
            "banner_reason": self.banner_reason(),
        }


def _closure(row: ExposureRefresh) -> dict:
    receipt = None
    if row.receipt_id is not None:
        receipt = FinancialExposureReceipt.objects.filter(pk=row.receipt_id).values_list("receipt_id", flat=True).first()
    return {
        "uuid": str(row.uuid),
        "scenario": str(FinancialScenario.objects.filter(pk=row.scenario_id).values_list("uuid", flat=True).first()),
        "simulation": str(SimulationResult.objects.filter(pk=row.simulation_id).values_list("uuid", flat=True).first()),
        "receipt_id": receipt,
        "spine_outcome": row.spine_outcome,
        "statement": OUTCOME_STATEMENTS[row.spine_outcome],
        "outcome": row.outcome,
        "author": row.author_username or None,
        "closed_at": row.closed_at.isoformat(),
    }


def _obligation(row: ExposureStaleness, closure: ExposureRefresh | None) -> dict:
    return {
        "uuid": str(row.uuid),
        "detected_at": row.detected_at.isoformat(),
        "reasons": row.reasons,
        "reasons_digest": row.reasons_digest,
        "refresh": row.refresh,
        "state": "open" if closure is None else "closed",
        "closed": None if closure is None else _closure(closure),
    }


def assess(result: SimulationResult, *, now: Now | None = None) -> Freshness:
    """Whether ``result`` is current (spec, section 34.2): stale where any dependency
    moved since it ran (:func:`live_reasons`) or a check recorded it stale; a residual
    or refused run is not assessed (it is never exposure, or has no figures). Reads
    only; never raises."""
    if result.remediation_id is not None:
        return Freshness("not_assessed", not_assessed="a residual run under a remediation option is never exposure")
    if result.status != SIMULATION_COMPLETED:
        return Freshness("not_assessed", not_assessed="a refused run has no figures to be current or stale")
    live = live_reasons(result, now=now)
    obligations, recorded, superseded = [], [], None
    try:
        rows = list(ExposureStaleness.objects.filter(simulation=result).order_by("id"))
        closures = {row.staleness_id: row for row in ExposureRefresh.objects.filter(staleness__in=rows)}
        for row in rows:
            closure = closures.get(row.pk)
            obligations.append(_obligation(row, closure))
            recorded += row.reasons
            if closure is not None and superseded is None:
                superseded = {k: v for k, v in _closure(closure).items() if k in (
                    "scenario", "simulation", "receipt_id", "spine_outcome")}
    except Exception as error:  # noqa: BLE001 - a fault reading the obligations is a reason, never a pass
        live = _ordered(live + [_reason(
            "dependencies_unverifiable", "obligations", f"the obligations could not be read ({type(error).__name__})"
        )])
    reasons = _ordered(live + recorded)
    return Freshness("stale" if reasons else "current", reasons, live, obligations, superseded)


def safe_assess(result: SimulationResult | None, *, now: Now | None = None) -> Freshness | None:
    """:func:`assess`, for a read that must answer whatever happens: ``None`` for no
    result, and stale with ``dependencies_unverifiable`` for a fault."""
    if result is None:
        return None
    try:
        return assess(result, now=now)
    except Exception as error:  # noqa: BLE001 - a read never fails over freshness, and never reads it as current
        reason = _reason("dependencies_unverifiable", "dependencies",
                         f"the run's freshness could not be read ({type(error).__name__})")
        return Freshness("stale", [reason], [reason])


# ------------------------------------------------------------------ the check


def _latest_completed(scenario: FinancialScenario) -> SimulationResult | None:
    return (
        SimulationResult.objects.exposure_runs()
        .filter(scenario=scenario, deployment_id=scenario.deployment_id)
        .order_by("-id")
        .first()
    )


def current_versions(deployment) -> list[FinancialScenario]:
    """Every scenario version of ``deployment`` that no other supersedes."""
    superseding = FinancialScenario.objects.filter(deployment=deployment, supersedes__isnull=False)
    superseded = set(superseding.values_list("supersedes_id", flat=True))
    return [s for s in FinancialScenario.objects.filter(deployment=deployment).order_by("id") if s.pk not in superseded]


def record_staleness(result: SimulationResult, reasons: list[dict], *, scenario=None) -> tuple[ExposureStaleness, bool]:
    """Record ``result`` stale for ``reasons`` with the refresh it owes, once per set
    of reasons: ``(row, created)``. Every check runs before the transaction, which
    only inserts."""
    scenario = scenario or FinancialScenario.objects.get(pk=result.scenario_id)
    digest = canonical_digest(reasons)
    found = ExposureStaleness.objects.filter(simulation=result, reasons_digest=digest).first()
    if found is not None:
        return found, False
    row = ExposureStaleness(
        deployment_id=result.deployment_id,
        scenario=scenario,
        simulation=result,
        reasons=reasons,
        reasons_digest=digest,
        refresh=refresh_plan(scenario, reasons),
    )
    try:
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = ExposureStaleness.objects.filter(simulation=result, reasons_digest=digest).first()
        if found is None:
            raise
        return found, False
    return row, True


def _between_runs() -> None:
    """A seam between the runs a check reads (a test holds a check here, mid-way)."""


def check(deployment, *, today: date | None = None) -> dict:
    """Read every current exposure run of ``deployment`` -- each scenario version no
    other supersedes, its latest completed exposure run -- and record each stale one
    with the refresh it owes (:func:`record_staleness`). Runs no Monte Carlo; reads
    with no transaction held, and each row it records is inserted in a short
    transaction of its own. Returns what it found."""
    now = Now(deployment.pk, today=today)
    runs = []
    recorded = 0
    for scenario in current_versions(deployment):
        result = _latest_completed(scenario)
        if result is None or result.status != SIMULATION_COMPLETED:
            continue
        _between_runs()
        freshness = assess(result, now=now)
        entry = {"scenario": str(scenario.uuid), "simulation": str(result.uuid), "state": freshness.state,
                 "reasons": [{"code": r["code"], "dependency": r["dependency"]} for r in freshness.reasons]}
        # A fault reading what holds now reads stale, and is never recorded: a recorded
        # staleness never lifts, and a transient fault is not a change.
        lasting = [r for r in freshness.live if r["code"] != "dependencies_unverifiable"]
        if lasting:
            row, created = record_staleness(result, lasting, scenario=scenario)
            recorded += created
            entry["obligation"] = str(row.uuid)
        runs.append(entry)
    return {
        "checked": len(runs),
        "stale": sum(1 for run in runs if run["state"] == "stale"),
        "current": sum(1 for run in runs if run["state"] == "current"),
        "obligations_recorded": recorded,
        "runs": runs,
        "statement": "every current exposure run read against what it depends on; each stale one recorded with the "
        "refresh it owes. Nothing was recomputed: a refresh runs only when an analyst asks for it",
    }


def overview(deployment, *, today: date | None = None) -> dict:
    """Every current scenario version's latest exposure run with its freshness, and
    every open obligation of the deployment. Reads only."""
    now = Now(deployment.pk, today=today)
    versions = []
    for scenario in current_versions(deployment):
        result = _latest_completed(scenario)
        freshness = safe_assess(result, now=now)
        versions.append({
            "scenario": str(scenario.uuid),
            "title": scenario.title,
            "simulation": None if result is None else str(result.uuid),
            "freshness": None if freshness is None else freshness.summary(),
        })
    closed = set(ExposureRefresh.objects.filter(deployment=deployment).values_list("staleness_id", flat=True))
    open_rows = [
        row for row in ExposureStaleness.objects.filter(deployment=deployment).order_by("id") if row.pk not in closed
    ]
    return {
        "deployment": str(deployment.uuid),
        "scenarios": versions,
        "open_obligations": [
            {**_obligation(row, None),
             "scenario": str(FinancialScenario.objects.filter(pk=row.scenario_id).values_list("uuid", flat=True).first()),
             "simulation": str(SimulationResult.objects.filter(pk=row.simulation_id).values_list("uuid", flat=True)
                               .first())}
            for row in open_rows
        ],
        "statement": "each current scenario version's latest exposure run, current or stale and why, and every refresh "
        "obligation still open; a run is refreshed only when an analyst asks",
    }


def scenario_freshness(scenario: FinancialScenario, result: SimulationResult | None = None, *,
                       today: date | None = None) -> dict:
    """One run's freshness in full (the version's latest exposure run, or ``result``):
    its dependency map, its state and reasons, its obligations and what superseded it,
    and what a refresh must refresh now. Reads only."""
    result = result if result is not None else _latest_completed(scenario)
    if result is None:
        return {"scenario": str(scenario.uuid), "simulation": None, "freshness": None,
                "statement": "no exposure run is recorded for this scenario version"}
    freshness = safe_assess(result, now=Now(scenario.deployment_id, today=today))
    mapped = ExposureDependencies.objects.filter(simulation=result).first()
    return {
        "scenario": str(scenario.uuid),
        "simulation": str(result.uuid),
        "freshness": freshness.as_dict(),
        "dependencies": None if mapped is None else {
            "schema": mapped.schema,
            "digest": mapped.dependencies_digest,
            "captured_at": mapped.captured_at.isoformat(),
            "map": mapped.dependencies,
        },
        "refresh": refresh_plan(scenario, freshness.reasons) if freshness.stale else None,
        "statement": "what the run rests on, recorded before it ran, compared with what holds now; a stale run is "
        "never totalled as current, and is refreshed only when an analyst asks",
    }


# ------------------------------------------------------------------ the refresh


@dataclass(frozen=True)
class Prepared:
    """What a refresh does: ``mode`` ``"refresh"`` -- rebuild the version (``body``),
    run it, card and receipt it -- or ``"close"`` -- the version's latest run is
    current and obligations of its line are still open (a refresh whose card or
    receipt was not issued, or whose run did not stand): issue what is missing for
    ``stale`` (then the run itself) and close what it can, running nothing. ``stale``
    is the version's latest exposure run, ``obligations`` the open ones of its line."""

    stale: SimulationResult | None
    freshness: Freshness | None
    obligations: tuple
    body: dict | None
    mode: str = "refresh"


def rebuild_body(scenario: FinancialScenario, *, as_of: date, version: int | None = None) -> dict:
    """The build request that rebuilds ``scenario`` from what its build recorded --
    the same effects, attributes and findings -- with its parameter set's CURRENT
    version (or ``version``) and ``as_of``, superseding it. A version the builder did
    not build has no inputs to rebuild from (``refresh_not_rebuildable``)."""
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    document = None if build is None else build.inputs
    if not isinstance(document, dict) or not {"parameter_set", "effects", "findings"} <= set(document):
        raise RefreshRefused(
            "refresh_not_rebuildable",
            "this scenario version was not built by the scenario builder: there is nothing to rebuild it from; build "
            "a new version and simulate it",
        )
    set_key = document["parameter_set"]["set_key"]
    current = CustomerParameterSet.current(scenario.deployment_id, set_key)
    if current is None and version is None:
        raise RefreshRefused("refresh_not_rebuildable", f"the parameter set {set_key} holds no version to rebuild from")
    effects = []
    for effect in document["effects"]:
        attributes = {
            name: {key: value for key, value in held.items() if not (key in ("currency", "fresh_until") and value is None)}
            for name, held in effect["attributes"].items()
        }
        entry = {
            "key": effect["key"], "origin": effect["origin"], "effect_type": effect["effect_type"],
            "asset": effect["asset"], "business_process": effect["business_process"], "attributes": attributes,
        }
        if effect["origin"] == "observed":
            entry["observed_effect"] = effect["observed_effect"]
        effects.append(entry)
    body = {
        "title": scenario.title,
        "parameter_set": {"set_key": set_key, "version": version or current.version},
        "currency": build.currency,
        "as_of": as_of.isoformat(),
        "effects": effects,
        "findings": [{"finding": f, "effect": e, "role": r} for f, e, r in document["findings"]],
        "supersedes": str(scenario.uuid),
    }
    # Rebuilt under the pack it was built under (E7, spec section 37): an industry
    # pack's build names it; a banking build names none, as it never did.
    if document.get("pack") in INDUSTRY_PACKS:
        body["pack"] = document["pack"]
    return body


def lineage(scenario: FinancialScenario) -> list[int]:
    """``scenario`` and every version it supersedes, transitively, newest first: the
    versions a run of ``scenario`` supersedes the exposure of."""
    found, step = [], scenario.pk
    while step is not None and step not in found:
        found.append(step)
        step = FinancialScenario.objects.filter(pk=step).values_list("supersedes_id", flat=True).first()
    return found


def open_obligations(scenario: FinancialScenario) -> list[ExposureStaleness]:
    """Every obligation still open on ``scenario`` and on each version it supersedes
    (:func:`lineage`): a refresh of the latest version closes them all."""
    closed = set(ExposureRefresh.objects.filter(deployment_id=scenario.deployment_id).values_list("staleness_id",
                                                                                                    flat=True))
    return [
        row for row in ExposureStaleness.objects.filter(scenario_id__in=lineage(scenario)).order_by("id")
        if row.pk not in closed
    ]


def latest_of(scenario: FinancialScenario) -> FinancialScenario:
    """The latest version of ``scenario``'s line: following each version's ONE
    successor (``uq_econ_scenario_one_successor``) to the version none supersedes."""
    seen, step = set(), scenario
    while step.pk not in seen:
        seen.add(step.pk)
        later = FinancialScenario.objects.filter(supersedes=step).order_by("id").first()
        if later is None:
            return step
        step = later
    return step


def prepare_refresh(scenario: FinancialScenario, *, as_of: date) -> Prepared:
    """What a refresh of ``scenario`` does, or why it does nothing (spec, section 34.4).

    - A version another supersedes is refused (``scenario_superseded``, 409), naming
      the latest version of its line, which holds its open obligations: refresh that.
    - Its latest exposure run is stale: the run is recorded stale (if it is not yet),
      and the version is rebuilt and run (``"refresh"``).
    - It has no completed exposure run (none, or a refused one), and obligations of its
      line are open: it is rebuilt and run (a refused run is no dead end; a new
      parameter-set version may give the engine what it refused).
    - Its latest run is current and obligations of its line are open (a refresh whose
      card or receipt was not issued, or whose run did not stand): ``"close"`` -- issue
      what is missing and close what the run can, running nothing again (review round 1
      of #168, M1).
    - Otherwise nothing is open and nothing moved: ``exposure_current`` (409) for a
      current run, ``nothing_to_refresh`` (409) for none. Runs nothing."""
    latest = latest_of(scenario)
    if latest.pk != scenario.pk:
        held = open_obligations(latest)
        raise RefreshRefused(
            "scenario_superseded",
            f"scenario version {latest.uuid} supersedes this one: refresh it"
            + (f"; it holds this line's {len(held)} open obligation(s)" if held else ""),
            status=409,
        )
    run = _latest_completed(scenario)
    held = tuple(open_obligations(scenario))
    if run is None or run.status != SIMULATION_COMPLETED:
        if not held:
            raise RefreshRefused("nothing_to_refresh", "this scenario version has no completed exposure run to "
                                 "refresh, and no obligation of its line is open", status=409)
        return Prepared(run, None, held, rebuild_body(scenario, as_of=as_of))
    freshness = assess(run)
    if not freshness.stale:
        if held:
            return Prepared(run, freshness, held, None, mode="close")
        raise RefreshRefused("exposure_current", "its latest exposure run depends on nothing that moved: there is "
                             "no obligation to close, and nothing was run", status=409)
    lasting = [r for r in freshness.live if r["code"] != "dependencies_unverifiable"]
    if lasting:
        record_staleness(run, lasting, scenario=scenario)
    body = rebuild_body(scenario, as_of=as_of)
    return Prepared(run, assess(run), tuple(open_obligations(scenario)), body)


def spine_outcome(reasons: list[dict], dependencies: dict | None) -> tuple[str, dict]:
    """SPINE's outcome for the financial claim a refresh closes, and what SPINE says of
    each claim type the new run rests on: ``superseded`` where nothing technical moved;
    else ``contradicted`` where a claim it rests on is contradicted, ``unknown`` where
    one is not a pass (or there is none), and ``restored`` where every one is."""
    per: dict[str, str] = {}
    for claim_type in (dependencies or {}).get("claim_types", []):
        entries = (dependencies or {}).get("claims", {}).get(claim_type, [])
        statuses = {e["status"] for e in entries}
        if CONTRADICTED in statuses:
            per[claim_type] = "contradicted"
        elif entries and statuses <= PASSING:
            per[claim_type] = "restored"
        else:
            per[claim_type] = "unknown"
    if not any(r["code"] in TECHNICAL for r in reasons):
        return "superseded", per
    if "contradicted" in per.values():
        return "contradicted", per
    if "unknown" in per.values() or not per:
        return "unknown", per
    return "restored", per


def _new_run_stands(result: SimulationResult) -> str | None:
    """Why the new run does not stand yet, or ``None``: its report must be one a total
    may sum (:func:`report.may_be_totalled`), which a stale run never is."""
    from . import report

    built = report.build_report(result)
    if report.may_be_totalled(built):
        return None
    return built.get("banner_reason") or "its report is not one a total may sum"


def close_obligations(result: SimulationResult, card, receipt, *, author
                      ) -> tuple[list[ExposureRefresh], str | None]:
    """Close every open obligation of ``result``'s version and of each version it
    supersedes with ``result`` -- the new run -- its ``card`` and ``receipt`` (or
    none), once the new run STANDS: ``(closures, None)``; or ``([], why)`` and every
    obligation left open. Each closure names SPINE's outcome. Every check runs before
    each transaction, which only inserts."""
    if card is None:
        return [], "the new run has no Validity Card: it is not graded"
    why = _new_run_stands(result)
    if why is not None:
        return [], why
    mapped = ExposureDependencies.objects.filter(simulation=result).first()
    closures = []
    for obligation in open_obligations(FinancialScenario.objects.get(pk=result.scenario_id)):
        outcome, per = spine_outcome(obligation.reasons, None if mapped is None else mapped.dependencies)
        row = ExposureRefresh(
            deployment_id=result.deployment_id,
            staleness=obligation,
            stale_simulation_id=obligation.simulation_id,
            scenario_id=result.scenario_id,
            simulation=result,
            card=card,
            receipt=receipt,
            spine_outcome=outcome,
            outcome={"claims": per, "statement": OUTCOME_STATEMENTS[outcome]},
            author=author,
        )
        try:
            row.check_new()
            with transaction.atomic():
                row.insert_checked()
        except (IntegrityError, EconomicsRefused) as raced:
            if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
                raise
            continue
        closures.append(row)
    return closures, None


def closure_document(row: ExposureRefresh) -> dict:
    return _closure(row)


# ------------------------------------------------------------------ hooks for other reads


def portfolio_exclusion(result: SimulationResult, *, now: Now | None = None) -> dict | None:
    """What a portfolio (E5, spec section 33) says of a member: where its run is stale,
    ``{"code": "stale", "reason": ..., "reasons": [...]}``, else ``None``. A stored
    portfolio reads each member through it (``portfolio.stale_members``); a portfolio
    being totalled leaves a stale member out through its report
    (``report.may_be_totalled``), as ``stale``."""
    freshness = safe_assess(result, now=now)
    if freshness is None or not freshness.stale:
        return None
    return {"code": "stale", "reason": freshness.banner_reason(),
            "reasons": [{"code": r["code"], "dependency": r["dependency"]} for r in freshness.reasons]}


def receipt_headers(receipt: FinancialExposureReceipt) -> dict[str, str]:
    """What a receipt's route says of its run's freshness, in headers beside the
    signed bytes it serves unchanged: the state, the reasons' codes, and the receipt
    and run that supersede it. Never raises: a fault reads stale."""
    try:
        result = SimulationResult.objects.get(pk=receipt.simulation_id)
        freshness = safe_assess(result)
    except Exception:  # noqa: BLE001 - a receipt is always served; its freshness is then not vouched for
        return {"X-Exposure-Freshness": "stale", "X-Exposure-Stale-Reasons": "dependencies_unverifiable"}
    if freshness is None or freshness.state == "not_assessed":
        return {}
    headers = {"X-Exposure-Freshness": freshness.state}
    if freshness.stale:
        headers["X-Exposure-Stale-Reasons"] = ",".join(sorted({r["code"] for r in freshness.reasons}))
    if freshness.superseded_by is not None:
        headers["X-Exposure-Superseded-By-Run"] = freshness.superseded_by["simulation"]
        if freshness.superseded_by.get("receipt_id"):
            headers["X-Exposure-Superseded-By-Receipt"] = freshness.superseded_by["receipt_id"]
    return headers


__all__ = [
    "ALL_CLAIM_TYPES",
    "DEPENDENCIES_SCHEMA",
    "OUTCOME_STATEMENTS",
    "REFRESH_ACTION",
    "STALE_BANNER",
    "STALE_REASONS",
    "TECHNICAL",
    "TEMPLATE_CLAIMS",
    "UNCLAIMED_KEYS",
    "Freshness",
    "Now",
    "Prepared",
    "RefreshRefused",
    "assess",
    "bound_claim_types",
    "capture",
    "check",
    "close_obligations",
    "closure_document",
    "current_versions",
    "latest_of",
    "lineage",
    "live_reasons",
    "open_obligations",
    "overview",
    "portfolio_exclusion",
    "prepare_refresh",
    "rebuild_body",
    "receipt_headers",
    "record_dependencies",
    "record_staleness",
    "refresh_plan",
    "safe_assess",
    "scenario_freshness",
    "spine_outcome",
]
