"""A seeded, realistic-size SPINE corpus, and the instruments that measure it (Phase 5 item 3).

SPINE sits on the critical path of every assessment: claim derivation
(:func:`assurance.claims.derive_claims`), the ripple traversal
(:func:`assurance.ripple.assess_ripple`) and the decision recompute
(:func:`assurance.decision.recompute_decision`). This module builds the world those
paths read -- several deployments, each with its assets, providers, findings and
their evidence, a data boundary, claims re-derived through several versions, retest
obligations, latent conditions (pending, fired, unobservable), evidence recorded
against claims, approved workflows, signed chain outcomes and recorded authority
chains -- and measures what each path costs over it:

- the statements it issues (:class:`Statements`), and each one's EXPLAIN QUERY PLAN;
- the SQLite virtual-machine steps it runs (a deterministic measure of the rows it
  visits: a full scan of a table costs steps in proportion to every row in it);
- its CPU time (``time.process_time``), the one non-deterministic figure, reported
  with its n and never asserted on.

Everything is deterministic. The clock is held (:class:`Clock`), every UUID a model
or the code under test draws comes from a seeded counter (:class:`SeededUUIDs`), and
the engine keys are fixed (:data:`KEYS`), so two builds of the corpus in two
processes write the same rows and the paths over them publish the same bytes -- the
property the golden-output test (``test_spine_paths_publish_what_they_published``)
rests on. Used only by tests; nothing here is imported by the service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import traceback
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone as dj_timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

#: Captured before anything patches them: a model field whose default IS one of
#: these draws from the held clock / the seeded UUIDs while the world is held.
_REAL_UUID4 = _uuid.uuid4
_REAL_NOW = dj_timezone.now

#: The instant the corpus starts at. Fixed, so every timestamp is.
EPOCH = datetime(2026, 3, 2, 9, 0, tzinfo=dt_timezone.utc)

#: Fixed engine keys, so every signature (Ed25519 is deterministic) and key id is
#: the same in every build. Test-only seeds, never a credential.
KEYS = {
    engine: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"spine-corpus|{engine}".encode()).digest())
    for engine in ("achilles", "athena", "achilles-effect")
}

WORKFLOW = "support-update"


class Clock:
    """The held clock: ``now()`` answers the same instant until :meth:`advance`."""

    def __init__(self, at: datetime = EPOCH):
        self.at = at

    def now(self) -> datetime:
        return self.at

    def advance(self, **delta) -> datetime:
        self.at = self.at + timedelta(**delta)
        return self.at


class SeededUUIDs:
    """``uuid.uuid4`` from a counter: the n-th draw is the same in every build."""

    def __init__(self, seed: str = "spine-corpus"):
        self.seed = seed
        self.drawn = 0

    def __call__(self) -> _uuid.UUID:
        self.drawn += 1
        digest = hashlib.sha256(f"{self.seed}|{self.drawn}".encode()).digest()
        return _uuid.UUID(bytes=digest[:16], version=4)


def hold_still(monkeypatch, clock: Clock, uuids: SeededUUIDs, keyring_path) -> None:
    """Hold the world still for a build and its measurements: the clock, every UUID
    drawn, and a keyring that trusts :data:`KEYS`. Undone by ``monkeypatch``."""
    from assurance import observed_outcomes, receipt

    monkeypatch.setattr(dj_timezone, "now", clock.now)
    monkeypatch.setattr(_uuid, "uuid4", uuids)
    monkeypatch.setattr(receipt, "_utc_now", clock.now)
    # A default captured as a function (``default=uuid.uuid4``, ``default=timezone.now``)
    # is the function object itself, so patching the module does not reach it: the
    # field's cached default is replaced for the duration instead.
    for model in apps.get_models():
        for fld in model._meta.concrete_fields:
            if fld.default is _REAL_UUID4:
                monkeypatch.setitem(fld.__dict__, "_get_default", uuids)
            elif fld.default is _REAL_NOW:
                monkeypatch.setitem(fld.__dict__, "_get_default", clock.now)
    keyring_path.write_text(
        json.dumps(
            [
                {"engine": engine, "public_key": base64.b64encode(oc.raw_public_key(key)).decode()}
                for engine, key in KEYS.items()
            ]
        )
    )
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(keyring_path))


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------

#: Tool permission sets the corpus cycles through: reads, writes, code execution,
#: egress, a financial action -- what the access graph and the ripple read.
_TOOL_PERMISSIONS = (
    ["db:read"],
    ["db:write", "db:read"],
    ["exec"],
    ["http:post"],
    ["payments:refund"],
    ["files:read"],
    ["email:send"],
)
_SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Shape:
    """How big one deployment of the corpus is. ``rank`` varies the shape so the
    deployments are not copies of one another."""

    agents: int = 3
    tools: int = 6
    data_stores: int = 2
    findings: int = 16
    versions: int = 3
    claim_evidence: int = 6
    chains: bool = True


@dataclass
class Corpus:
    clock: Clock
    deployments: list = field(default_factory=list)
    admin: object = None


def _user(username, role):
    User = get_user_model()
    return User.objects.create_user(username=username, password=None, role=role)


def _providers():
    """Providers are shared across deployments, as they are in production."""
    from assurance.models import Provider, ProviderAssertion

    made = []
    for name, kind, region in (
        ("corpus-model-co", "model_provider", "us-east-1"),
        ("corpus-gateway", "gateway", "eu-west-1"),
        ("corpus-vectors", "vector_db", "eu-west-1"),
    ):
        provider, created = Provider.objects.get_or_create(name=name, kind=kind, defaults={"region": region})
        if created:
            ProviderAssertion.objects.create(provider=provider, field="region", value=region)
            ProviderAssertion.objects.create(provider=provider, field="trains_on_data", value="no")
        made.append(provider)
    return made


def _assets(dep, rank: int, shape: Shape, providers):
    from assurance.models import Asset

    A = Asset.Classification
    tools = []
    for t in range(shape.tools + rank % 3):
        perms = _TOOL_PERMISSIONS[(t + rank) % len(_TOOL_PERMISSIONS)]
        name = f"tool-{t}"
        tools.append(name)
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name=name, identifier=name,
            classification=(A.APPROVED, A.KNOWN, A.UNMANAGED)[t % 3],
            metadata={"permissions": perms, "server": f"store-{t % shape.data_stores}"},
        )
    for a in range(shape.agents + rank % 2):
        name = f"agent-{a}"
        reach = [tools[(a + k) % len(tools)] for k in range(3)]
        if a == 0:
            reach.append("crm-mcp")
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.AGENT, name=name, identifier=name,
            classification=A.APPROVED if a % 2 == 0 else A.KNOWN,
            metadata={"tools": reach, "identity": f"svc-{a % 2}"},
        )
    for s in range(shape.data_stores):
        name = f"store-{s}"
        Asset.objects.create(deployment=dep, kind=Asset.Kind.DATA_STORE, name=name, identifier=name)
    for s in range(2):
        name = f"svc-{s}"
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.SERVICE_ACCOUNT, name=name, identifier=name, classification=A.APPROVED,
        )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MCP_SERVER, name="crm-mcp", identifier="crm-mcp", classification=A.APPROVED,
        metadata={"permissions": ["customer:update", "customer:read"], "effect_class": "write"},
        assessed_at=EPOCH,
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, name="model-main", identifier="model-main",
        classification=A.APPROVED, provider=providers[0],
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.GATEWAY, name="gateway", identifier="gateway", provider=providers[1],
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.VECTOR_DB, name="vectors", identifier="vectors", provider=providers[2],
    )


#: The finding profile of each rank (``rank % 6``), so the deployments land on
#: different decisions: a critical open; at worst high; only medium and below; every
#: finding closed; every finding accepted (standing, lapsed, outgrown); none at all.
_PROFILES = (
    (("critical", "high", "medium", "low", "info"), "mixed"),
    (("high", "medium", "low", "info"), "mixed"),
    (("medium", "low", "info"), "mixed"),
    (("critical", "high", "medium"), "closed"),
    (("high", "medium", "low"), "accepted"),
    ((), "none"),
)


def _findings(dep, rank: int, shape: Shape, clock: Clock):
    from assurance.models import Evidence, Finding

    severities, profile = _PROFILES[rank % len(_PROFILES)]
    if not severities:
        return
    assets = list(dep.assets.order_by("kind", "name"))
    mixed = (
        Finding.Status.OPEN, Finding.Status.TRIAGED, Finding.Status.CLOSED, Finding.Status.ACCEPTED,
        Finding.Status.REMEDIATING, Finding.Status.INVALIDATED,
    )
    for n in range(shape.findings + 2 * rank):
        severity = severities[(n + rank) % len(severities)]
        if profile == "closed":
            status = (Finding.Status.CLOSED, Finding.Status.FALSE_POSITIVE)[n % 2]
        elif profile == "accepted":
            status = Finding.Status.ACCEPTED
        else:
            status = mixed[n % len(mixed)]
        extra = {}
        if status == Finding.Status.ACCEPTED:
            # Standing, lapsed, and outgrown (accepted at a lower severity than now).
            accepted_at = severity if n % 3 != 2 else "low"
            extra = {"risk_accepted_until": clock.now() + timedelta(days=60 - 50 * (n % 2) - 20 * (n % 3 == 1)),
                     "risk_accepted_severity": accepted_at}
        finding = Finding.objects.create(
            deployment=dep, asset=assets[n % len(assets)], fingerprint=f"corpus-{rank}-{n}",
            finding_type=("excessive_agency", "prompt_injection", "data_exposure")[n % 3],
            title=f"finding {n}", severity=severity, status=status, **extra,
        )
        for e in range(1 + n % 2):
            Evidence.objects.create(
                finding=finding, source=f"engine_scan-{e}",
                classification=("technically_verified", "configuration_verified", "unknown")[(n + e) % 3],
                summary=f"Observed ({n}.{e}).", content_hash=hashlib.sha256(f"{rank}|{n}|{e}".encode()).hexdigest(),
            )


def _claim_evidence(dep, shape: Shape, clock: Clock):
    """Evidence recorded against the deployment's current claims, as an assessor
    records it: independent, signed, naming the claim -- a mix of passes and fails."""
    from assurance import evidence_audit as ea
    from assurance.models import AssuranceClaim, ClaimEvidence
    from assurance.served_route import serving_route_now

    route = serving_route_now(dep)
    claims = list(AssuranceClaim.objects.filter(deployment=dep).current().order_by("claim_type"))
    for n in range(shape.claim_evidence):
        claim = claims[n % len(claims)]
        now = clock.now()
        ea.record_claim_evidence(
            claim,
            outcome=("pass", "pass", "fail")[n % 3],
            origin="independent",
            evidence_class="technically_verified",
            subject_deployment=str(dep.uuid),
            subject_claim_type=claim.claim_type,
            subject_asset="" if claim.asset_id is None else str(claim.asset.uuid),
            subject_route=route,
            subject_inputs=claim.input_fingerprint,
            observed_at=now - timedelta(minutes=2),
            state_check_ref=f"achilles:probe/run-{n}",
            state_checked_at=now - timedelta(minutes=1),
            signer="athena-scan-key-1",
            signature_verified=True,
            content_digest="sha256:" + hashlib.sha256(f"{dep.pk}|{n}".encode()).hexdigest()[:12],
            actor_account="athena-scanner",
            actor_account_kind=ClaimEvidence.AccountKind.SERVICE_ACCOUNT.value,
            actor_device="runner-1",
            actor_organization="Mythos assessor",
            residual_uncertainty=["probe covered read paths only"],
            now=now,
        )
        clock.advance(seconds=5)


def _latent(dep, rank: int, owner, clock: Clock):
    """Declared preconditions on the current claims: pending ones, and -- on some
    deployments -- one that fires and holds its claim."""
    from assurance.latent import declare_condition, evaluate_conditions
    from assurance.models import Asset, AssuranceClaim, LatentCondition

    Kind = LatentCondition.Kind
    access = AssuranceClaim.objects.filter(deployment=dep, claim_type="effective_access").current().get()
    boundary = AssuranceClaim.objects.filter(deployment=dep, claim_type="data_boundary").current().get()
    declare_condition(
        access, kind=Kind.ASSET_APPEARS, subject=f"shadow-tool-{rank}",
        description="The access reading holds only while no shadow tool appears.", declared_by=owner,
    )
    declare_condition(
        boundary, kind=Kind.BOUNDARY_REGION_ADDED, subject="data boundary", expected="ap-south-1",
        description="The boundary reading holds only while ap-south-1 is not approved.", declared_by=owner,
    )
    declare_condition(
        access, kind=Kind.ASSET_BECOMES_UNMANAGED, subject="agent-0",
        description="The access reading holds only while agent-0 stays governed.", declared_by=owner,
    )
    clock.advance(minutes=1)
    evaluate_conditions(dep, now=clock.now())
    if rank % 2 == 1:
        # The named precondition gives way: the condition fires and holds its claim.
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name=f"shadow-tool-{rank}", identifier=f"shadow-tool-{rank}",
            classification=Asset.Classification.UNMANAGED, metadata={"permissions": ["exec"]},
        )
        clock.advance(minutes=1)
        evaluate_conditions(dep, now=clock.now())


def _version(dep, rank: int, v: int, clock: Clock):
    """One change to the deployment's inputs, then a re-derive: the claims resting
    on the change are superseded by a new version."""
    from assurance.claims import derive_claims
    from assurance.invalidation import check_invalidations
    from assurance.models import Asset, DataBoundary

    if v % 3 == 0:
        name = f"tool-v{v}"
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name=name, identifier=name,
            metadata={"permissions": list(_TOOL_PERMISSIONS[(v + rank) % len(_TOOL_PERMISSIONS)])},
        )
    elif v % 3 == 1:
        boundary = DataBoundary.objects.get(deployment=dep)
        boundary.allowed_regions = [*boundary.allowed_regions, f"region-{v}"]
        boundary.save()
    else:
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.MODEL, name=f"model-v{v}", identifier=f"model-v{v}",
        )
    clock.advance(minutes=3)
    check_invalidations(dep, now=clock.now())
    clock.advance(minutes=1)
    derive_claims(dep, now=clock.now())


def churn(dep, v: int, clock: Clock):
    """One change that versions claims without growing the graph: the boundary's
    training approval and a tool's permissions flip back and forth, then a
    re-derive. History accumulates; the deployment's current size does not."""
    from assurance.claims import derive_claims
    from assurance.models import Asset, DataBoundary

    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.training_allowed = not boundary.training_allowed
    boundary.save()
    tool = Asset.objects.get(deployment=dep, kind=Asset.Kind.TOOL, identifier="tool-0")
    tool.metadata = {**tool.metadata, "permissions": ["db:read"] if v % 2 else ["db:read", "files:read"]}
    tool.save(update_fields=["metadata"])
    clock.advance(minutes=2)
    derive_claims(dep, now=clock.now())


def _v4(text: str) -> str:
    """A version-4 UUID in hex, derived from ``text``: an outcome id that is the same
    in every build."""
    return _uuid.UUID(bytes=hashlib.sha256(text.encode()).digest()[:16], version=4).hex


def _sign(dep, status, observed_at, *, engine="achilles", seq=0):
    from assurance import composition as comp
    from assurance import observed_outcomes
    from assurance.models import WorkflowChainOutcome
    from assurance.served_route import served_route_fingerprint

    key = KEYS[engine]
    outcome = oc.build_outcome(
        deployment=str(dep.uuid), workflow=WORKFLOW, status=status, engine=engine, engine_version="1.0.0",
        run_id=f"run-{dep.pk}-{seq}", evidence_digest="sha256:" + "cd" * 32, observed_at=observed_at,
        reason="" if status == oc.HELD else "the run did not establish the chain",
        outcome_id=_v4(f"outcome|{dep.uuid}|{seq}"),
    )
    envelope = oc.sign_outcome(outcome, key)
    return WorkflowChainOutcome.objects.create(
        deployment=dep, workflow=WORKFLOW, status=status, basis=comp.BASIS_DEMONSTRATED,
        observed_at=observed_outcomes._instant(outcome["observed_at"]),
        source=f"{engine} 1.0.0 run {outcome['observer']['run_id']}", outcome_id=outcome["outcome_id"],
        observer_engine=engine, observer_key_id=oc.key_id_for(oc.raw_public_key(key)),
        evidence_digest=outcome["evidence_digest"], envelope=envelope,
        route_fingerprint=served_route_fingerprint(dep),
    )


def _observed_effect(dep, gate_outcome_id, observed_at, seq):
    """An observed effect, verified and recorded the one way one is (``ingest``)."""
    from assurance import observed_outcomes
    from tests.signed_chains import GATE_STATE, _stamp, live_presented

    instant = observed_at.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    evidence = {
        "schema": "mythos.observed-effect/v2",
        "deployment": str(dep.uuid),
        "workflow": WORKFLOW,
        "tool": {"kind": "mcp_server", "identifier": "crm-mcp"},
        "action": "customer:update",
        "action_digest": "ab" * 32,
        "permit_digest": "sha256:" + "ef" * 32,
        "dispatch_id": _v4(f"dispatch|{dep.uuid}|{seq}"),
        "gate_outcome_id": gate_outcome_id,
        "observed": {"provider": "crm-provider", "status_code": 200, "receipt_id": f"rcpt-{seq}",
                     "response_digest": "sha256:" + "12" * 32},
        "observed_at": instant,
        "dispatch": {**GATE_STATE, "dispatched_at": _stamp(observed_at), "presented": live_presented(dep, WORKFLOW)},
    }
    outcome = oc.build_outcome(
        deployment=str(dep.uuid), workflow=WORKFLOW, status=oc.HELD, engine="achilles-effect",
        engine_version="0.1.0", run_id=f"effect-{dep.pk}-{seq}", evidence_digest=oc.evidence_digest_of(evidence),
        observed_at=observed_at, reason="",
        outcome_id=_v4(f"effect|{dep.uuid}|{seq}"),
    )
    envelope = oc.sign_outcome(outcome, KEYS["achilles-effect"])
    rows, refusals = observed_outcomes.ingest(dep, [envelope], evidence=[evidence], now=observed_at + timedelta(seconds=1))
    assert not refusals, refusals
    return rows[0]


def _chains(dep, rank: int, client, clock: Clock):
    """An approved workflow binding the CRM server, a signed permit for it, and the
    authority chain of the effect it produced -- recorded through the routes, as
    an operator records them."""
    from assurance.models import ApprovalVersion, AuthorityEdgeVersion, ServedRouteNote, ToolContract
    from assurance.served_route import note_route

    base = f"/api/assurance/deployments/{dep.uuid}/"
    note_route(dep, now=clock.now())
    entry = {"slug": WORKFLOW, "name": "Support update", "description": "update a customer record",
             "tools": [{"kind": "mcp_server", "identifier": "crm-mcp"}]}
    put = client.put(base + "approved-workflows/", {"workflows": [entry]}, format="json")
    assert put.status_code == 200, put.content
    # The approval, contracts, route and edges as noted an hour before the dispatch.
    earlier = clock.now() - timedelta(hours=1)
    ApprovalVersion.objects.filter(deployment=dep).update(in_force_from=earlier)
    ToolContract.objects.filter(deployment=dep).update(recorded_at=earlier)
    ServedRouteNote.objects.filter(deployment=dep).update(since=earlier)
    AuthorityEdgeVersion._base_manager.filter(deployment=dep).update(noticed_at=earlier)
    clock.advance(minutes=5)
    permit = _sign(dep, oc.HELD, clock.now() - timedelta(minutes=2), seq=0)
    if rank % 3 == 2:
        _sign(dep, oc.VIOLATED, clock.now() - timedelta(minutes=3), seq=1)
    effect = _observed_effect(dep, permit.outcome_id, clock.now() - timedelta(minutes=1), seq=0)
    version = client.get(base + "authority-chains/").json()["approvals_in_force"][WORKFLOW]
    agent = {"kind": "agent", "ref": "agent-0"}
    policy = {"kind": "policy", "ref": WORKFLOW, "version": version}
    mcp = {"kind": "mcp_server", "ref": "crm-mcp"}
    account = {"kind": "service_account", "ref": "svc-0" if rank % 2 == 0 else "svc-1"}
    action = {"kind": "action", "ref": "customer:update"}
    produced = {"kind": "effect", "ref": "customer-record-change"}
    body = {
        "workflow": WORKFLOW,
        "hops": [
            {"from": agent, "relation": "under_policy", "to": policy},
            {"from": policy, "relation": "invokes", "to": mcp},
            {"from": mcp, "relation": "through_identity", "to": account},
            {"from": account, "relation": "performs", "to": action},
            {"from": action, "relation": "produces", "to": produced},
        ],
        "gate_outcome_id": permit.outcome_id,
        "effect_outcome_id": effect.outcome_id,
        "observed_at": (clock.now() - timedelta(minutes=1)).isoformat(),
        "source": "operator",
    }
    posted = client.post(base + "authority-chains/", body, format="json")
    assert posted.status_code == 201, posted.content


def build_deployment(corpus: Corpus, rank: int, shape: Shape | None = None):
    """One deployment of the corpus, built through the code paths production uses."""
    from assurance.claims import derive_claims
    from assurance.decision import recompute_decision
    from assurance.invalidation import check_invalidations
    from assurance.models import DataBoundary, Deployment

    shape = shape or Shape()
    clock = corpus.clock
    User = get_user_model()
    owner = _user(f"corpus-owner-{rank}", User.Roles.ANALYST)
    dep = Deployment.objects.create(name=f"corpus-{rank}", owner=owner)
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"] if rank % 2 == 0 else [],
        training_allowed=rank % 3 == 0,
    )
    _assets(dep, rank, shape, _providers())
    _findings(dep, rank, shape, clock)
    clock.advance(minutes=1)
    derive_claims(dep, now=clock.now())
    for v in range(shape.versions + rank % 2):
        _version(dep, rank, v, clock)
    _claim_evidence(dep, shape, clock)
    _latent(dep, rank, owner, clock)
    if shape.chains and rank % 6 != 1:
        client = APIClient()
        client.force_authenticate(user=corpus.admin)
        _chains(dep, rank, client, clock)
    if rank % 2 == 0:
        # Left with an open retest: an input moved and nothing re-derived since.
        from assurance.models import Asset

        Asset.objects.create(deployment=dep, kind=Asset.Kind.TOOL, name="tool-late", identifier="tool-late",
                             metadata={"permissions": ["db:write"]})
        clock.advance(minutes=1)
        check_invalidations(dep, now=clock.now())
    clock.advance(minutes=1)
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    corpus.deployments.append(dep)
    clock.advance(minutes=10)
    return dep


def build_corpus(clock: Clock, *, deployments: int = 6, shape: Shape | None = None) -> Corpus:
    User = get_user_model()
    corpus = Corpus(clock=clock, admin=_user("corpus-admin", User.Roles.ADMIN))
    for rank in range(deployments):
        build_deployment(corpus, rank, shape)
    return corpus


# ---------------------------------------------------------------------------
# The instruments
# ---------------------------------------------------------------------------


class Statements:
    """Every statement a block issues, with its parameters, in order -- and, with
    ``origins``, the names of the functions on the stack that issued it."""

    def __init__(self, *, origins: bool = False):
        self.issued: list[tuple[str, tuple]] = []
        self.origins: list[frozenset] = []
        self._with_origins = origins

    def __call__(self, execute, sql, params, many, context):
        self.issued.append((sql, tuple(params) if params is not None and not many else ()))
        if self._with_origins:
            self.origins.append(frozenset(frame.name for frame in traceback.extract_stack()))
        return execute(sql, params, many, context)


@dataclass
class Measured:
    result: object
    statements: list
    vm_steps: int
    cpu_seconds: float
    origins: list = field(default_factory=list)


#: The VM steps between two calls of the progress handler: the resolution of the count.
VM_STEP_GRANULE = 100


def measure(fn, *, origins: bool = False) -> Measured:
    """Run ``fn`` once, recording its statements and the SQLite VM steps it ran."""
    connection.ensure_connection()
    raw = connection.connection
    steps = [0]

    def tick():
        steps[0] += 1
        return 0

    recorder = Statements(origins=origins)
    raw.set_progress_handler(tick, VM_STEP_GRANULE)
    try:
        with connection.execute_wrapper(recorder):
            started = time.process_time()
            result = fn()
            cpu = time.process_time() - started
    finally:
        raw.set_progress_handler(None, 0)
    return Measured(
        result=result, statements=recorder.issued, vm_steps=steps[0] * VM_STEP_GRANULE, cpu_seconds=cpu,
        origins=recorder.origins,
    )


def cpu_seconds(fn, *, repeat: int = 5) -> list[float]:
    """``fn``'s CPU time over ``repeat`` runs, with no instrument attached."""
    times = []
    for _ in range(repeat):
        started = time.process_time()
        fn()
        times.append(time.process_time() - started)
    return times


_EXPLAINABLE = ("SELECT", "WITH", "UPDATE", "DELETE")


def plans(statements) -> list[tuple[str, list[str]]]:
    """EXPLAIN QUERY PLAN of every statement that reads a table, as ``(sql, details)``."""
    out = []
    with connection.cursor() as cursor:
        for sql, params in statements:
            if not sql.lstrip().upper().startswith(_EXPLAINABLE):
                continue
            cursor.execute("EXPLAIN QUERY PLAN " + sql, params)
            out.append((sql, [row[-1] for row in cursor.fetchall()]))
    return out


def statement_steps(statements, granule: int = 10) -> list[tuple[str, int, list[str]]]:
    """Each reading statement run again on its own, to the last row: ``(sql, VM steps,
    plan)``. Attributes a path's work to the statement that does it."""
    connection.ensure_connection()
    raw = connection.connection
    out = []
    plan_of = dict(plans(statements))
    with connection.cursor() as cursor:
        for sql, params in statements:
            if not sql.lstrip().upper().startswith(("SELECT", "WITH")):
                continue
            steps = [0]

            def tick():
                steps[0] += 1
                return 0

            raw.set_progress_handler(tick, granule)
            try:
                cursor.execute(sql, params)
                cursor.fetchall()
            finally:
                raw.set_progress_handler(None, 0)
            out.append((sql, steps[0] * granule, plan_of.get(sql, [])))
    return out


def full_scans(statements, tables) -> list[tuple[str, str]]:
    """``(table, sql)`` for every statement whose plan reads one of ``tables`` whole:
    a ``SCAN`` of it (with or without an index -- a full index walk still visits
    every row), rather than a ``SEARCH`` by key."""
    found = []
    for sql, details in plans(statements):
        aliases = _aliases(sql)
        for detail in details:
            if not detail.startswith("SCAN "):
                continue
            name = detail.split()[1]
            table = aliases.get(name, name)
            if table in tables:
                found.append((table, sql))
    return found


def _aliases(sql: str) -> dict[str, str]:
    """Django's subquery aliases (``"assurance_x" U0``) back to their tables."""
    out = {}
    words = sql.replace("(", " ").replace(")", " ").replace(",", " ").split()
    for i, word in enumerate(words[:-1]):
        nxt = words[i + 1]
        if word.startswith('"') and word.endswith('"') and nxt[:1] in ("U", "T", "V") and nxt[1:].isdigit():
            out[nxt] = word.strip('"')
    return out


def per_deployment_tables() -> frozenset[str]:
    """Every table whose rows belong to one deployment: a foreign key to it, or to a
    table that does (a claim's events, a finding's evidence), and the deployments
    table itself."""
    from assurance.models import Deployment

    owned = {Deployment}
    grew = True
    while grew:
        grew = False
        for model in apps.get_models():
            if model in owned:
                continue
            for fld in model._meta.concrete_fields:
                if fld.many_to_one and getattr(fld, "related_model", None) in owned:
                    owned.add(model)
                    grew = True
                    break
    return frozenset(model._meta.db_table for model in owned)


# ---------------------------------------------------------------------------
# What the paths publish, canonically
# ---------------------------------------------------------------------------


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, _uuid.UUID):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"not canonical: {type(value).__name__}")


def canonical(document) -> str:
    """The bytes a golden comparison compares: sorted keys, one form per type."""
    return json.dumps(document, sort_keys=True, indent=1, default=_jsonable, ensure_ascii=False) + "\n"


class _Keys:
    """A row's stable name in place of its autoincrement id: an id depends on every
    row any earlier test committed in the session, a uuid or a username does not."""

    def __init__(self):
        self.cache: dict = {}

    def of(self, model, pk):
        if pk is None:
            return None
        table = self.cache.get(model)
        if table is None:
            names = [f.name for f in model._meta.concrete_fields]
            column = "uuid" if "uuid" in names else ("username" if "username" in names else None)
            if column is None:
                table = {}
            else:
                table = dict(model._base_manager.values_list("pk", column))
            self.cache[model] = table
        return str(table.get(pk, f"{model._meta.label}#?"))


def _row(obj, keys: _Keys) -> dict:
    out = {}
    for fld in obj._meta.concrete_fields:
        if fld.primary_key:
            continue
        value = fld.value_from_object(obj)
        if fld.is_relation:
            value = keys.of(fld.related_model, value)
        out[fld.name] = value
    return out


def stored(dep) -> dict:
    """Every decision and claim row the paths write for ``dep``, in write order."""
    from assurance.models import (
        AssuranceClaim,
        ClaimAuditWeighing,
        ClaimEvent,
        DecisionTransition,
        Deployment,
        LatentCondition,
        RetestRequirement,
    )

    keys = _Keys()
    claims = AssuranceClaim.objects.filter(deployment=dep).order_by("pk")
    return {
        "deployment": _row(Deployment.objects.get(pk=dep.pk), keys),
        "claims": [_row(c, keys) for c in claims],
        "claim_events": [_row(e, keys) for e in ClaimEvent.objects.filter(claim__deployment=dep).order_by("pk")],
        "weighings": [_row(w, keys) for w in ClaimAuditWeighing.objects.filter(claim__deployment=dep).order_by("pk")],
        "retests": [_row(r, keys) for r in RetestRequirement.objects.filter(deployment=dep).order_by("pk")],
        "latent_conditions": [_row(c, keys) for c in LatentCondition.objects.filter(deployment=dep).order_by("pk")],
        "transitions": [_row(t, keys) for t in DecisionTransition.objects.filter(deployment=dep).order_by("pk")],
    }


def _plain(value, keys: _Keys):
    """``value`` -- a decision's parts, as :func:`assurance.decision.read_decision_parts`
    returns them -- as plain data. A row is named by what it is (its model and its
    uuid), not by which of its columns a reader happened to load."""
    import dataclasses
    import enum

    from django.db import models as dj_models

    if isinstance(value, dj_models.Model):
        return {"row": value._meta.label, "key": keys.of(type(value), value.pk)}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {"type": type(value).__name__,
                **{f.name: _plain(getattr(value, f.name), keys) for f in dataclasses.fields(value)}}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _plain(v, keys) for k, v in value.items()}
    if hasattr(value, "_asdict"):
        return {"type": type(value).__name__, **{k: _plain(v, keys) for k, v in value._asdict().items()}}
    if isinstance(value, (list, tuple)):
        return [_plain(v, keys) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(v, keys) for v in value), key=lambda v: json.dumps(v, sort_keys=True, default=str))
    if value is None or isinstance(value, (str, int, float, bool, datetime, _uuid.UUID)):
        return value
    raise TypeError(f"no plain form for {type(value).__name__}")


def _distinct(readings: list) -> list:
    """``readings`` without repeats, in the order first read: a refresh recomputes
    the same parts more than once."""
    seen, out = set(), []
    for reading in readings:
        key = canonical(reading)
        if key not in seen:
            seen.add(key)
            out.append(reading)
    return out


class _RecordedParts:
    """Every :class:`assurance.decision.DecisionParts` a recompute reads while this is
    open, so the golden comparison covers what the decision was computed FROM -- the
    rows each signal holds, and each signal -- not only the decision it came to."""

    def __init__(self):
        self.read: list = []

    def __enter__(self):
        from assurance import decision

        self._real = decision.read_decision_parts

        def recorded(deployment, **kwargs):
            parts = self._real(deployment, **kwargs)
            self.read.append(parts)
            return parts

        decision.read_decision_parts = recorded
        return self

    def __exit__(self, *exc):
        from assurance import decision

        decision.read_decision_parts = self._real
        return False


def run_paths(corpus: Corpus) -> dict:
    """Derivation, traversal and recompute over every deployment of ``corpus``, as the
    routes and the backstop run them, and everything they publish and store."""
    from assurance.claims import derive_claims
    from assurance.decision import current_decision, decision_support, recompute_decision, refresh_stored_decisions
    from assurance.models import Deployment
    from assurance.receipt import build_assurance_receipt
    from assurance.ripple import assess_ripple

    clock = corpus.clock
    published = {}
    for dep in corpus.deployments:
        pk = dep.pk
        clock.advance(minutes=1)
        derived = derive_claims(Deployment.objects.get(pk=pk), now=clock.now())
        ripple = assess_ripple(
            Deployment.objects.prefetch_related("assets__provider__assertions", "findings__asset").get(pk=pk)
        )
        with _RecordedParts() as recorded:
            clock.advance(minutes=1)
            decided = recompute_decision(Deployment.objects.get(pk=pk))
            clock.advance(minutes=1)
            refresh_stored_decisions([pk])
            # And the refresh of a decision another writer left (a rollout): the
            # claim, the watches read, and the decision brought current.
            clock.advance(minutes=1)
            Deployment.objects.filter(pk=pk).update(decision_policy="")
            refresh_stored_decisions([pk])
        clock.advance(minutes=1)
        reading = Deployment.objects.get(pk=pk)
        current_decision(reading)
        support = decision_support(reading)
        receipt = build_assurance_receipt(
            Deployment.objects.prefetch_related("findings__evidence", "assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=pk)
        )
        published[dep.name] = {
            "derive_claims": derived,
            "assess_ripple": ripple,
            "recompute_decision": decided,
            "recompute_read": _distinct([_plain(parts, _Keys()) for parts in recorded.read]),
            "recomputes": len(recorded.read),
            "decision_support": support,
            "assurance_receipt": receipt,
            "stored": stored(dep),
        }
    return published


def each_statement(measured: Measured, tables) -> list[dict]:
    """Every statement of ``measured``, in order: its SQL, the functions that issued
    it, the ``tables`` its plan reads whole, and -- for a read -- the exact VM steps
    it takes run again on its own now. Taken right after the measurement, so the
    steps are of the database as the path read it."""
    connection.ensure_connection()
    raw = connection.connection
    out = []
    with connection.cursor() as cursor:
        for index, (sql, params) in enumerate(measured.statements):
            head = sql.lstrip().upper()
            entry = {"sql": sql, "origins": measured.origins[index] if measured.origins else frozenset(),
                     "scans": [], "steps": None}
            if head.startswith(_EXPLAINABLE):
                cursor.execute("EXPLAIN QUERY PLAN " + sql, params)
                aliases = _aliases(sql)
                for row in cursor.fetchall():
                    detail = row[-1]
                    if detail.startswith("SCAN "):
                        name = detail.split()[1]
                        if aliases.get(name, name) in tables:
                            entry["scans"].append(aliases.get(name, name))
            if head.startswith(("SELECT", "WITH")):
                steps = [0]

                def tick():
                    steps[0] += 1
                    return 0

                raw.set_progress_handler(tick, 1)
                try:
                    cursor.execute(sql, params)
                    cursor.fetchall()
                finally:
                    raw.set_progress_handler(None, 0)
                entry["steps"] = steps[0]
            out.append(entry)
    return out
