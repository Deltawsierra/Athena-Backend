"""No recorded history row is rewritten past its guard: not in bulk, not by an upsert,
not by a fresh instance carrying its key, not by a move.

Every append-only record refuses an update or a delete of a recorded row in its
``save`` and ``delete``; some refuse one in bulk on the queryset too. Two ORM writes
went through none of those, on every append-only record (:mod:`assurance.append_only`):

(a) ``bulk_create(..., update_conflicts=True, update_fields=..., unique_fields=...)`` is
    an upsert, ``INSERT ... ON CONFLICT DO UPDATE``: it rewrote the recorded row holding
    the key, in place. Every record's default queryset now refuses it, with the
    record's own refusal, before any SQL, by keyword, by position, on a filtered
    queryset and through ``abulk_create``. A plain ``bulk_create`` of new rows still
    inserts them, and ``ignore_conflicts=True`` (which drops a row whose key is taken
    and leaves the recorded one exactly as it was) is not refused. The economics
    records already refused every ``bulk_create``, and still do.

(b) A reverse foreign key's ``add(row)`` (bulk, the default) moved a recorded row to
    another parent with an ``UPDATE`` through the base manager; ``set`` adds the same
    way, and on a nullable key ``remove`` and ``clear`` nulled it. Each history key's
    reverse accessor is now gone (``related_name="+"``) where nothing read it, and
    refuses all four where something does (a ``HistoryForeignKey``), while reads
    (``all``, ``filter``, ``count``, a prefetch) and ``create`` work as before.

(c) The base manager stays Django's plain one on EVERY append-only record, the edge
    history's included: the deployment's cascade and removing an operator (a stop,
    ``accounts:user-detail`` DELETE, which nulls every account column naming them) run
    through it. Removing an operator named on a row of every kind is still 204 through
    the real route, nulls exactly those columns and changes nothing else.

(d) A fresh instance carrying a recorded row's key (``Model(pk=<recorded>,
    ...).save()``) passed every non-economics record's ``save``, which checked only
    ``_state.adding``, and Django's save then tried an UPDATE: it overwrote the row.
    Every ``save`` now writes an INSERT and nothing else, as the economics records'
    always did, so it fails on the key (``IntegrityError``), and a save asking for an
    update (``force_update``, ``update_fields``) is refused before any SQL.

(e) A queryset ``update()``, ``bulk_update()`` or ``delete()`` rewrote or removed the
    rows of the seven records whose ``save`` alone refused (``ToolContract``,
    ``AuthorityChain``, ``IdentityEvidence``, ``EffectReconciliationReceipt``, the two
    Achilles records, ``RoleGrant``). Every record's queryset now refuses all three, as
    the approval and edge histories' did; ``RoleGrant`` refuses a row's ``delete`` too.
    No writer used any of them but four test fixtures, which now write through the
    base manager; promoting, demoting and removing an operator (two of them stops)
    still answer through the real routes.

A gate-attested hop citing a version still resolves to what the gate signed after
every one of these is attempted on the rows it reads.

On master the upsert and the moves go through, so those tests fail there; the
economics upsert, the stop and the cascade already held there and are pinned.
(:mod:`assurance.append_only` is imported where a test reads it, so that the rest of
this file runs on master and shows each write going through.)
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta

import pytest
from asgiref.sync import async_to_sync
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, models, transaction
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from accounts.models import RoleGrant
from assurance import gate_approval, observed_effects, recovery_record
from assurance.economics import models as econ
from assurance.models import (
    AchillesScanRefusal,
    AchillesScanResult,
    AchillesScanRewriteRefused,
    ApprovalVersion,
    ApprovalVersionRewriteRefused,
    Asset,
    AssuranceClaim,
    AuthorityChain,
    AuthorityChainRewriteRefused,
    AuthorityEdgeVersion,
    AuthorityEdgeVersionRewriteRefused,
    Deployment,
    EffectReconciliationReceipt,
    EffectReconciliationRewriteRefused,
    Finding,
    IdentityEvidence,
    IdentityEvidenceRewriteRefused,
    RecoveryRecord,
    RecoveryRecordRewriteRefused,
    RepairContract,
    RetestCheck,
    RetestClosureEvidence,
    ToolContract,
    ToolContractRewriteRefused,
)
from assurance.repair_contract import ContractIsAppendOnly
from safety import stops
from tests import repair_contracts
from tests.test_an_observed_effect_proves_the_produces_hop import TOKEN
from tests.test_economics_records import _fx, _index, _scenario, _source
from tests.test_spine_authority_chain import WF, _world
from tests.test_the_gate_attests_the_approval_it_read import _chain, _reading, _record

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
NOW = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)

#: Every append-only record and the refusal it rewrites are refused with. The answer
#: key: a test below finds every model that is append-only by its guard or its
#: docstring, and holds that set to this one plus the three below.
APPEND_ONLY = {
    RoleGrant: ValueError,
    RepairContract: ContractIsAppendOnly,
    ToolContract: ToolContractRewriteRefused,
    AuthorityChain: AuthorityChainRewriteRefused,
    ApprovalVersion: ApprovalVersionRewriteRefused,
    AuthorityEdgeVersion: AuthorityEdgeVersionRewriteRefused,
    IdentityEvidence: IdentityEvidenceRewriteRefused,
    EffectReconciliationReceipt: EffectReconciliationRewriteRefused,
    AchillesScanResult: AchillesScanRewriteRefused,
    AchillesScanRefusal: AchillesScanRewriteRefused,
    RecoveryRecord: RecoveryRecordRewriteRefused,
    **{
        model: econ.EconomicsRewriteRefused
        for model in (
            econ.FinancialSource, econ.FinancialSourceTrustRaise, econ.ModelInventoryEntry, econ.FinancialScenario,
            econ.ScenarioReview, econ.SensitiveOverride, econ.OverrideApproval, econ.OverrideRevocation,
            econ.FXObservation, econ.CostIndexObservation, econ.FinancialSourceFetch, econ.FinancialSourceRecords,
            econ.CustomerParameterSet, econ.FinancialParameter, econ.LossEvent, econ.LossComponent,
            econ.ScenarioBuild, econ.CausalEffect, econ.EffectFinding, econ.FigureNormalization,
            econ.FinancialNormalizationPolicy, econ.SimulationResult, econ.FinancialValidityCard,
            econ.FinancialExposureReceipt, econ.SimulationCharts, econ.RemediationOption,
            econ.ExposureDependencies, econ.ExposureStaleness, econ.ExposureRefresh, econ.CorrelationGroup,
            econ.PortfolioResult,
        )
    },
}

#: Documented as append-only (or as history) with no guard to get past: rows a writer
#: rewrites by design (a claim's status and windows), or ones nothing refuses at all.
#: Not this change's to guard; listed so a new one is not missed.
DOCUMENTED_NOT_GUARDED = {
    AssuranceClaim: "a claim version's status and windows are rewritten by design (supersede, lifecycle)",
    RetestClosureEvidence: "documented append-only; nothing refuses a rewrite of it at all",
    RetestCheck: "documented append-only; nothing refuses a rewrite of it at all",
}

#: Every history key whose reverse accessor something reads: it reads, and never moves.
GUARDED = {
    (ApprovalVersion, "deployment"): "approval_versions",
    (ApprovalVersion, "declared_by"): "declared_approval_versions",
    (RepairContract, "finding"): "repair_contracts",
    (AchillesScanResult, "deployment"): "achilles_scan_results",
    (AchillesScanRefusal, "deployment"): "achilles_scan_refusals",
    (econ.FinancialScenario, "supersedes"): "superseded_by",
    (econ.ScenarioReview, "scenario"): "reviews",
    (econ.OverrideApproval, "override"): "approvals",
    (econ.OverrideRevocation, "override"): "revocations",
    (econ.FXObservation, "source"): "fx_observations",
    (econ.CostIndexObservation, "source"): "cost_index_observations",
}

#: Every reverse accessor this change removed, by the key it belonged to: nothing read
#: it, and it moved a recorded row.
REMOVED = {
    (ToolContract, "deployment"): "tool_contracts",
    (ToolContract, "asset"): "tool_contracts",
    (AuthorityChain, "deployment"): "authority_chains",
    (AuthorityChain, "recorded_by"): "authority_chains",
    (AuthorityEdgeVersion, "deployment"): "authority_edge_versions",
    (IdentityEvidence, "deployment"): "identity_evidence",
    (EffectReconciliationReceipt, "deployment"): "effect_reconciliations",
    (econ.FinancialSource, "deployment"): "financial_sources",
    (econ.FinancialSource, "recorded_by"): "economics_sources_recorded",
    (econ.FinancialSourceTrustRaise, "from_version"): "trust_raises",
    (econ.FinancialSourceTrustRaise, "requested_by"): "economics_trust_raises_requested",
    (econ.FinancialSourceTrustRaise, "approved_by"): "economics_trust_raises_approved",
    (econ.FinancialSourceTrustRaise, "withdrawn_by"): "economics_trust_raises_withdrawn",
    (econ.ModelInventoryEntry, "recorded_by"): "economics_inventory_recorded",
    (econ.FinancialScenario, "deployment"): "financial_scenarios",
    (econ.FinancialScenario, "author"): "economics_scenarios_authored",
    (econ.ScenarioReview, "reviewer"): "economics_reviews",
    (econ.SensitiveOverride, "scenario"): "sensitive_overrides",
    (econ.SensitiveOverride, "requested_by"): "economics_overrides_requested",
    (econ.OverrideApproval, "approver"): "economics_override_approvals",
    (econ.OverrideRevocation, "revoked_by"): "economics_override_revocations",
    (econ.CustomerParameterSet, "author"): "economics_parameter_sets_authored",
    (econ.RemediationOption, "author"): "economics_remediation_options_authored",
    (econ.ExposureRefresh, "author"): "economics_refreshes_authored",
    (econ.CorrelationGroup, "author"): "economics_correlation_groups_authored",
}


# ------------------------------------------------------------------ the world


class World:
    """Two deployments, the people, a finding and an asset, and one recorded row of
    every append-only record whose row a test can write through its own writer."""

    def __init__(self):
        self.dep = Deployment.objects.create(name="history-kept")
        self.other = Deployment.objects.create(name="history-elsewhere")
        self.leaver = User.objects.create_user(username="leaver", password="x", role="admin")
        self.alice = User.objects.create_user(username="alice", password="x", role="admin")
        self.bob = User.objects.create_user(username="bob", password="x", role="admin")
        # Promoted by nobody: the economics rules read the leaver's, alice's and bob's
        # grants, so the grant recorded here is someone else's.
        self.grantee = User.objects.create_user(username="grantee", password="x", role="analyst")
        self.finding = self._finding("fp-kept")
        self.asset = Asset.objects.create(deployment=self.dep, kind=Asset.Kind.MCP_SERVER, name="crm", identifier="crm-mcp")
        # A recovery step is the first of its own incident's, so each built one is
        # derived and its build reads nothing (the imposter is built inside a capture).
        self.incidents = {n: self._finding(f"fp-incident-{n}") for n in range(1, 10)}
        self.rows = {}
        for model, (build, _field, _value) in RECORDS.items():
            self.rows[model] = build(self, 1)
            self.rows[model].save()
        self.rows.update(self._economics())

    def _finding(self, fingerprint, deployment=None):
        return Finding.objects.create(
            deployment=deployment or self.dep, fingerprint=fingerprint, finding_type="sql_injection",
            title="SQLi", severity="critical",
        )

    def _economics(self):
        source = _source(recorded_by=self.leaver)
        scenario = _scenario(self.dep, self.leaver, title="theirs to write")
        theirs = _scenario(self.dep, self.alice, title="someone else's")
        asked = econ.SensitiveOverride.objects.create(
            scenario=scenario, subject="revenue_per_hour", reason="customer-confirmed", requested_by=self.leaver
        )
        approved = econ.SensitiveOverride.objects.create(
            scenario=theirs, subject="x", reason="y", requested_by=self.bob
        )
        return {
            econ.FinancialSource: source,
            econ.FXObservation: _fx(source),
            econ.CostIndexObservation: _index(source),
            econ.ModelInventoryEntry: econ.ModelInventoryEntry.objects.create(
                model_id="m", version="1", owner="o", intended_use="u", limitations="l", recorded_by=self.leaver
            ),
            econ.FinancialScenario: _scenario(self.dep, self.leaver, title="revised", supersedes=scenario),
            econ.ScenarioReview: econ.ScenarioReview.objects.create(
                scenario=theirs, reviewer=self.leaver, verdict="approved"
            ),
            econ.SensitiveOverride: asked,
            econ.OverrideApproval: econ.OverrideApproval.objects.create(override=approved, approver=self.leaver),
            econ.OverrideRevocation: asked.revoke(by=self.leaver, reason="approved in error"),
        }

    def another(self, model):
        """A new parent of ``model``'s kind, to move a row to."""
        n = User.objects.count() + Deployment.objects.count()
        if model is Deployment:
            return Deployment.objects.create(name=f"elsewhere-{n}")
        if model is User:
            return User.objects.create_user(username=f"someone-{n}", password="x")
        if model is Finding:
            return self._finding(f"fp-{n}")
        if model is Asset:
            return Asset.objects.create(deployment=self.dep, kind=Asset.Kind.MCP_SERVER, name=f"a{n}", identifier=f"a{n}")
        if model is econ.FinancialSource:
            return _source(source_key=f"source-{n}")
        if model is econ.FinancialScenario:
            return _scenario(self.dep, self.alice, title=f"another {n}")
        if model is econ.SensitiveOverride:
            return econ.SensitiveOverride.objects.create(
                scenario=_scenario(self.dep, self.alice, title=f"another {n}"), subject="x", reason="y",
                requested_by=self.alice,
            )
        raise AssertionError(model)


def _role_grant(w, n):
    return RoleGrant(
        account_pk=w.grantee.pk, account_username="grantee", role="analyst", granted_at=NOW - timedelta(days=30 - n)
    )


def _repair_contract(w, n):
    return RepairContract(
        finding=w.finding, version=n, prohibited_effect=repair_contracts.EFFECT,
        preserved_behaviours=list(repair_contracts.BEHAVIOURS), agreed_by=w.leaver,
    )


def _tool_contract(w, n):
    return ToolContract(
        deployment=w.dep, asset=w.asset, tool_kind="mcp_server", tool_identifier="crm-mcp", digest=f"{n:02x}" * 32,
        contract={"identifier": "crm-mcp", "n": n},
    )


def _authority_chain(w, n):
    return AuthorityChain(
        deployment=w.dep, workflow="refund", effect=f"refund-{n}", hops=[{"from": "a", "relation": "r", "to": "b"}],
        digest="sha256:" + f"{n:02x}" * 32, recorded_by=w.leaver,
    )


def _approval_version(w, n):
    return ApprovalVersion(
        deployment=w.dep, workflow="refund", digest=f"{n:02x}" * 32, tools=[["mcp_server", "crm-mcp", "c0" * 32]],
        in_force_from=NOW + timedelta(n), declared_by=w.leaver,
    )


def _edge_version(w, n):
    return AuthorityEdgeVersion(
        deployment=w.dep, kind="invokes", source=str(w.asset.uuid), target=f"tool-{n}", in_force=True,
        noticed_at=NOW + timedelta(n),
    )


def _identity_evidence(w, n):
    return IdentityEvidence(
        deployment=w.dep, kind="authentication", outcome_id=f"identity-{n}", observer_engine="athena",
        observer_key_id="k1", evidence_digest="sha256:" + "e1" * 32, envelope={"payloadType": "x"},
        document={"n": n}, replay_key=f"replay-{n}", principal="svc-x", witness="mythos", observed_at=NOW,
    )


def _reconciliation(w, n):
    return EffectReconciliationReceipt(
        deployment=w.dep, receipt_id=f"receipt-{n}", dispatch_id="dispatch-1", attempt=n, gate_outcome_id="gate-1",
        workflow="refund", answer="applied", conclusion="produced", provider="crm", read_at=NOW,
        observer_key_id="k1", envelope_digest="sha256:" + "f1" * 32, envelope={"payloadType": "x"},
    )


def _scan_result(w, n):
    return AchillesScanResult(
        deployment=w.dep, outcome_id=f"scan-outcome-{n}", scan_id=f"scan-{n}", release="r1",
        observer_engine="achilles", observer_key_id="k1", evidence_digest="sha256:" + "a2" * 32,
        scan_status="completed", observed_at=NOW, envelope={"payloadType": "x"}, document={"scan": n},
    )


def _scan_refusal(w, n):
    return AchillesScanRefusal(deployment=w.dep, code="tampered", reason=f"the signed digest does not match ({n})")


def _recovery_record(w, n, finding=None):
    finding = finding or w.incidents[n]
    links = {
        "incident": str(finding.uuid), "evidence": [], "permits": [], "receipts": [], "decision": None,
        "repair_contract": None, "closure_evidence": None, "unknowns": [], "gaps": [], "restrictions": [],
        "uncertainty": [],
    }
    return recovery_record.draft(finding, version=1, links=links, recorded_by=w.leaver, recorded_at=NOW)


#: Every append-only record outside economics: an unsaved row of it (the n-th, so
#: several can be written), the column an upsert would rewrite, and what to.
RECORDS = {
    RoleGrant: (_role_grant, "role", "admin"),
    RepairContract: (_repair_contract, "prohibited_effect", "nothing"),
    ToolContract: (_tool_contract, "digest", "ff" * 32),
    AuthorityChain: (_authority_chain, "digest", "sha256:" + "ff" * 32),
    ApprovalVersion: (_approval_version, "digest", "ff" * 32),
    AuthorityEdgeVersion: (_edge_version, "in_force", False),
    IdentityEvidence: (_identity_evidence, "principal", "someone-else"),
    EffectReconciliationReceipt: (_reconciliation, "answer", "not_applied"),
    AchillesScanResult: (_scan_result, "scan_status", "aborted"),
    AchillesScanRefusal: (_scan_refusal, "reason", "nothing was refused"),
    # Not `state`: every derived field is refused at save unless derived, before the key is.
    RecoveryRecord: (_recovery_record, "recorded_at", NOW - timedelta(days=1)),
}

ECONOMICS_ROWS = (
    econ.FinancialSource, econ.FXObservation, econ.CostIndexObservation, econ.ModelInventoryEntry,
    econ.FinancialScenario, econ.ScenarioReview, econ.SensitiveOverride, econ.OverrideApproval,
    econ.OverrideRevocation,
)


@pytest.fixture
def world():
    return World()


def _stored(row):
    """Every column of ``row`` as stored, read past every refusal (the base manager)."""
    return type(row)._base_manager.filter(pk=row.pk).values().get()


def _counts():
    return {model: model._base_manager.count() for model in APPEND_ONLY}


def _label(model):
    return model.__name__


# ------------------------------------------------- the inventory, and every guard on it


def _save_refuses_a_recorded_row(model):
    save = getattr(model, "save")
    if save is models.Model.save:
        return False
    source = inspect.getsource(save)
    return "insert_only(" in source or ("not self._state.adding" in source and "raise " in source)


def test_every_append_only_record_is_in_the_inventory_and_refuses_an_upsert():
    from assurance.append_only import HistoryQuerySet

    found = {
        model
        for model in apps.get_models()
        if isinstance(model._default_manager.all(), HistoryQuerySet)
        or _save_refuses_a_recorded_row(model)
        or "append-only" in (model.__doc__ or "").lower()
    }
    assert found == set(APPEND_ONLY) | set(DOCUMENTED_NOT_GUARDED)
    for model, refusal in APPEND_ONLY.items():
        rows = model._default_manager.all()
        assert model._default_manager is model.objects, model
        assert isinstance(rows, HistoryQuerySet), model
        assert rows.refused is refusal, model


def test_every_append_only_records_base_manager_stays_djangos_plain_one():
    """The deployment's cascade and removing an operator (a stop) write through it: an
    append-only base manager would refuse the stop's SET_NULL. The edge history's too,
    whose only writer through it is the cascade."""
    for model in APPEND_ONLY:
        assert model._meta.base_manager_name is None, model
        assert type(model._base_manager) is models.Manager, model
        assert type(model._base_manager.all()) is models.QuerySet, model
    assert type(AuthorityEdgeVersion._base_manager) is models.Manager
    assert type(ApprovalVersion._base_manager) is models.Manager


# ------------------------------------------------------------------ (a) the upsert


UPSERTS = {
    "by keyword": lambda model, objs, field: model.objects.bulk_create(
        objs, update_conflicts=True, unique_fields=["id"], update_fields=[field]
    ),
    "by position": lambda model, objs, field: model.objects.bulk_create(objs, None, False, True, [field], ["id"]),
    "on a filtered queryset": lambda model, objs, field: model.objects.filter(pk__in=[o.pk for o in objs]).bulk_create(
        objs, update_conflicts=True, unique_fields=["id"], update_fields=[field]
    ),
    "asynchronously": lambda model, objs, field: async_to_sync(model.objects.all().abulk_create)(
        objs, update_conflicts=True, unique_fields=["id"], update_fields=[field]
    ),
}


@pytest.mark.parametrize("form", list(UPSERTS))
@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_an_upsert_of_a_recorded_row_is_refused_and_changes_nothing(world, model, form):
    _build, field, value = RECORDS[model]
    row = world.rows[model]
    before, counts = _stored(row), _counts()
    forged = model._base_manager.get(pk=row.pk)
    setattr(forged, field, value)

    with CaptureQueriesContext(connection) as sql, pytest.raises(APPEND_ONLY[model]) as refused:
        UPSERTS[form](model, [forged], field)

    assert "never rewritten" in str(refused.value) or "never edited" in str(refused.value)
    assert sql.captured_queries == [], "refused before any SQL, so the caller's transaction stays usable"
    assert _stored(row) == before
    assert _counts() == counts


@pytest.mark.parametrize("model", ECONOMICS_ROWS, ids=_label)
def test_an_economics_upsert_is_refused_with_every_bulk_create_and_changes_nothing(world, model):
    row = world.rows[model]
    before = _stored(row)
    forged = model._base_manager.get(pk=row.pk)
    for form, upsert in UPSERTS.items():
        with CaptureQueriesContext(connection) as sql, pytest.raises(econ.EconomicsRefused) as refused:
            upsert(model, [forged], "uuid")
        assert refused.value.code == "bulk_create_refused", form
        assert sql.captured_queries == [], form
        assert _stored(row) == before, form


def test_every_economics_record_refuses_an_upsert_before_any_sql():
    """Those whose rows this file does not build: the refusal reads nothing and writes
    nothing, whatever is asked."""
    for model, refusal in APPEND_ONLY.items():
        if refusal is not econ.EconomicsRewriteRefused:
            continue
        with CaptureQueriesContext(connection) as sql, pytest.raises(econ.EconomicsRefused) as refused:
            model.objects.bulk_create([model(pk=1)], update_conflicts=True, unique_fields=["id"], update_fields=["uuid"])
        assert refused.value.code == "bulk_create_refused", model
        assert sql.captured_queries == [], model


@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_a_plain_bulk_create_of_new_rows_still_inserts_them(world, model):
    """Appending is untouched: the edge history notes its changes this way."""
    build, _field, _value = RECORDS[model]
    row = world.rows[model]
    before = _stored(row)
    made = model.objects.bulk_create([build(world, 2), build(world, 3)])
    assert len(made) == 2 and all(r.pk is not None for r in made)
    assert model._base_manager.filter(pk__in=[r.pk for r in made]).count() == 2
    assert _stored(row) == before


@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_ignore_conflicts_drops_a_taken_key_and_rewrites_nothing(world, model):
    """Not refused: a row whose key is taken is dropped, the recorded row stays exactly
    as it was, and a new row beside it is inserted."""
    build, field, value = RECORDS[model]
    row = world.rows[model]
    before, count = _stored(row), model._base_manager.count()
    forged = model._base_manager.get(pk=row.pk)
    setattr(forged, field, value)
    model.objects.bulk_create([forged, build(world, 4)], ignore_conflicts=True)
    assert _stored(row) == before
    assert model._base_manager.count() == count + 1


# --------------------------------------------------------- (b) the reverse-key move


def _history_keys(model):
    return [f for f in model._meta.get_fields() if f.concrete and f.many_to_one]


def test_no_history_key_has_a_reverse_manager_that_moves_a_recorded_row():
    from assurance.append_only import HistoryForeignKey

    guarded = {}
    for model in APPEND_ONLY:
        assert not any(f.many_to_many for f in model._meta.get_fields() if f.concrete), model
        for field in _history_keys(model):
            if field.remote_field.hidden:
                assert not isinstance(field, HistoryForeignKey), (model, field.name)
                continue
            assert isinstance(field, HistoryForeignKey), (model, field.name, "a reverse accessor that moves rows")
            accessor = field.remote_field.accessor_name
            descriptor = getattr(field.related_model, accessor)
            assert type(descriptor) is HistoryForeignKey.related_accessor_class, (model, field.name)
            guarded[(model, field.name)] = accessor
    assert guarded == GUARDED


@pytest.mark.parametrize(
    ("key", "accessor"), list(REMOVED.items()), ids=[f"{model.__name__}.{name}" for model, name in REMOVED]
)
def test_a_removed_reverse_accessor_is_gone(key, accessor):
    model, name = key
    field = model._meta.get_field(name)
    assert field.remote_field.hidden and field.remote_field.related_name == "+"
    assert not hasattr(field.related_model, accessor)


def _moves(world, model, name, row):
    """Every way a reverse accessor moves ``row``, by its key ``name``: to another
    parent (``add``, bulk or not, ``set``, ``aadd``), and off its own (``remove`` and
    ``clear``, which a nullable key's accessor has)."""
    field = model._meta.get_field(name)
    accessor = GUARDED.get((model, name)) or REMOVED[(model, name)]
    parent = getattr(row, name)
    elsewhere = world.another(field.related_model)
    yield "add", lambda: getattr(elsewhere, accessor).add(row)
    yield "add one by one", lambda: getattr(elsewhere, accessor).add(row, bulk=False)
    yield "set", lambda: getattr(elsewhere, accessor).set([row])
    yield "aadd", lambda: async_to_sync(getattr(elsewhere, accessor).aadd)(row)
    if field.null and parent is not None:
        yield "remove", lambda: getattr(parent, accessor).remove(row)
        yield "clear", lambda: getattr(parent, accessor).clear()
        yield "clear one by one", lambda: getattr(parent, accessor).clear(bulk=False)


MOVABLE = [
    key for key in [*GUARDED, *REMOVED] if key[0] in RECORDS or key[0] in ECONOMICS_ROWS
]


@pytest.mark.parametrize("key", MOVABLE, ids=lambda k: f"{k[0].__name__}.{k[1]}")
def test_a_recorded_row_is_never_moved_by_a_reverse_accessor(world, key):
    model, name = key
    row = world.rows[model]
    before = _stored(row)
    for how, move in _moves(world, model, name, row):
        if key in GUARDED:
            with CaptureQueriesContext(connection) as sql, pytest.raises(APPEND_ONLY[model], match="never moved by"):
                move()
            assert sql.captured_queries == [], how
        else:
            with pytest.raises(AttributeError):
                move()
        assert _stored(row) == before, how


@pytest.mark.parametrize("key", [k for k in GUARDED if k in MOVABLE], ids=lambda k: f"{k[0].__name__}.{k[1]}")
def test_a_guarded_reverse_accessor_still_reads(world, key):
    model, name = key
    accessor = GUARDED[key]
    row = world.rows[model]
    parent = getattr(row, name)
    rows = getattr(parent, accessor)
    assert row in list(rows.all())
    assert rows.filter(pk=row.pk).count() == 1
    fetched = type(parent)._base_manager.prefetch_related(accessor).get(pk=parent.pk)
    with CaptureQueriesContext(connection) as sql:
        assert row in list(getattr(fetched, accessor).all())
    assert sql.captured_queries == [], "the prefetch serves the read"


def test_a_guarded_reverse_accessor_still_appends_a_new_row(world):
    made = world.dep.achilles_scan_refusals.create(code="tampered", reason="a new refusal")
    assert made.deployment_id == world.dep.pk
    assert world.dep.achilles_scan_refusals.filter(pk=made.pk).exists()


def test_the_repair_contracts_route_still_reads_them_through_the_accessor(world):
    """``finding.repair_contracts`` is read (and prefetched) to serve the contracts."""
    contract = world.rows[RepairContract]
    client = APIClient()
    client.force_authenticate(user=world.alice)
    answer = client.get(f"/api/assurance/findings/{world.finding.uuid}/repair-contracts/")
    assert answer.status_code == 200, answer.content
    assert contract.content_digest in answer.content.decode()


# ------------------------------------------------------------- (c) the stop


def test_removing_an_operator_nulls_every_history_column_naming_them_and_nothing_else(world):
    """Removing an operator is a stop. Named on a recorded row of every kind this file
    builds, the real route answers 204, removes the account, and the one change each
    row takes is the column naming them nulled: every other column of every row, and
    the number of rows of every append-only record, stay as they were."""
    assert stops.STOP_ROUTES["accounts:user-detail"] == {"DELETE": stops.always}
    leaver = world.leaver
    named = {}
    for model, row in world.rows.items():
        for field in _history_keys(model):
            if field.related_model is User and getattr(row, field.attname) == leaver.pk:
                named.setdefault(model, []).append(field.attname)
    assert set(named) >= {
        ApprovalVersion, AuthorityChain, RepairContract, RecoveryRecord, econ.FinancialSource, econ.ModelInventoryEntry,
        econ.FinancialScenario, econ.ScenarioReview, econ.SensitiveOverride, econ.OverrideApproval,
        econ.OverrideRevocation,
    }, named
    before = {model: _stored(row) for model, row in world.rows.items()}
    counts = _counts()

    client = APIClient()
    client.force_authenticate(user=world.alice)
    client.raise_request_exception = False
    answer = client.delete(f"/api/accounts/users/{leaver.pk}/")

    assert answer.status_code == 204, answer.content
    assert not User.objects.filter(pk=leaver.pk).exists()
    for model, row in world.rows.items():
        nulled = {column: None for column in named.get(model, [])}
        assert _stored(row) == {**before[model], **nulled}, model
    assert _counts() == counts


def test_the_deployments_cascade_still_takes_its_history_and_only_its_own(world):
    """Every key here keeps its cascade, accessor or none: the deployment's delete
    takes its rows (through the base manager) and no other deployment's."""
    elsewhere = {}
    for model, (build, _field, _value) in RECORDS.items():
        row = build(world, 6)
        if model is RepairContract:
            row.finding = world._finding("fp-elsewhere", deployment=world.other)
        elif model is RecoveryRecord:
            row = _recovery_record(world, 6, world._finding("fp-incident-elsewhere", deployment=world.other))
        elif hasattr(row, "deployment_id"):
            row.deployment = world.other
        if model is ToolContract:
            row.asset = Asset.objects.create(deployment=world.other, kind=Asset.Kind.MCP_SERVER, name="crm", identifier="x")
        row.save()
        elsewhere[model] = (row, _stored(row))
    gone = {model: row.pk for model, row in world.rows.items() if getattr(row, "deployment_id", 0) == world.dep.pk}
    gone[RepairContract] = world.rows[RepairContract].pk
    gone[RecoveryRecord] = world.rows[RecoveryRecord].pk
    assert set(gone) >= set(RECORDS) - {RoleGrant}

    world.dep.delete()

    for model, pk in gone.items():
        assert not model._base_manager.filter(pk=pk).exists(), model
    for model, (row, stored) in elsewhere.items():
        assert _stored(row) == stored, model


# --------------------------------------------- the gate-attested hop still resolves


@pytest.fixture
def service(monkeypatch):
    """The observed-effect service (as in the produces-hop tests)."""
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def test_a_gate_attested_hop_still_resolves_after_every_upsert_and_move_is_attempted(service):
    """The version the gate read and signed, and the edges the graph hops read, are
    attacked by upsert and by move: each is refused, nothing changes, and the chain
    still reads proven, citing that version."""
    dep, client, permit, _ = _world()
    reading = _reading(dep)
    row, _evidence = _record(service, dep, permit, schema="v4", reading=reading)
    version = ApprovalVersion.objects.get(pk=int(reading["version"]))
    edges = list(AuthorityEdgeVersion.objects.filter(deployment=dep))
    assert edges
    before = (_stored(version), [_stored(e) for e in edges])
    elsewhere = Deployment.objects.create(name="elsewhere")
    someone = User.objects.create_user(username="someone", password="x")

    forged = ApprovalVersion._base_manager.get(pk=version.pk)
    forged.digest, forged.tools = "c3" * 32, [["mcp_server", "crm-mcp", "f0" * 32]]
    flipped = list(AuthorityEdgeVersion._base_manager.filter(pk__in=[e.pk for e in edges]))
    for edge in flipped:
        edge.in_force = not edge.in_force
    refused = {
        "the version upserted": (
            ApprovalVersionRewriteRefused,
            lambda: ApprovalVersion.objects.bulk_create(
                [forged], update_conflicts=True, unique_fields=["id"], update_fields=["digest", "tools"]
            ),
        ),
        "the version moved to another deployment": (
            ApprovalVersionRewriteRefused, lambda: elsewhere.approval_versions.add(version)
        ),
        "the version set on another deployment": (
            ApprovalVersionRewriteRefused, lambda: elsewhere.approval_versions.set([version])
        ),
        "the version given another declarer": (
            ApprovalVersionRewriteRefused, lambda: someone.declared_approval_versions.add(version)
        ),
        "the edges upserted": (
            AuthorityEdgeVersionRewriteRefused,
            lambda: AuthorityEdgeVersion.objects.bulk_create(
                flipped, update_conflicts=True, unique_fields=["id"], update_fields=["in_force"]
            ),
        ),
        "the edges moved to another deployment": (AttributeError, lambda: elsewhere.authority_edge_versions),
    }
    for why, (refusal, attempt) in refused.items():
        with pytest.raises(refusal):
            attempt()
        assert (_stored(version), [_stored(e) for e in edges]) == before, why

    chain = _chain(client, dep, permit, row)

    policy, invokes = _hops(chain)["under_policy"], _hops(chain)["invokes"]
    assert _codes(policy) == ["approval_attested_in_force_at_dispatch"], policy
    assert "contract_attested_in_force_at_dispatch" in _codes(invokes), invokes
    assert f"version {version.id}" in str(policy)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    status, body = gate_approval.approval_in_force(dep, WF, tools=True)
    assert status == 200 and body["version"] == reading["version"] and body["digest"] == reading["digest"]


# ------------------------------------- (d) a fresh instance carrying a recorded key


@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_a_fresh_instance_carrying_a_recorded_key_never_overwrites_it(world, model):
    build, field, value = RECORDS[model]
    row = world.rows[model]
    before, counts = _stored(row), _counts()

    def imposter():
        made = build(world, 7)
        made.pk = row.pk
        setattr(made, field, value)
        return made

    with pytest.raises(IntegrityError), transaction.atomic():
        imposter().save()
    assert _stored(row) == before
    for asked in ({"force_update": True}, {"update_fields": [field]}):
        with CaptureQueriesContext(connection) as sql, pytest.raises(APPEND_ONLY[model]):
            imposter().save(**asked)
        assert sql.captured_queries == [], asked
    assert _stored(row) == before
    assert _counts() == counts


@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_a_new_row_is_still_written_by_save_and_create(world, model):
    build, _field, _value = RECORDS[model]
    saved = build(world, 8)
    saved.save()
    assert saved.pk is not None and model._base_manager.filter(pk=saved.pk).exists()
    fields = build(world, 9)
    created = model.objects.create(
        **{f.attname: getattr(fields, f.attname) for f in model._meta.concrete_fields if not f.primary_key}
    )
    assert model._base_manager.filter(pk=created.pk).exists()


# -------------------------------------------------------- (e) a rewrite in bulk


BULK_WRITES = {
    "update": lambda model, row, forged, field, value: model.objects.filter(pk=row.pk).update(**{field: value}),
    "update everything": lambda model, row, forged, field, value: model.objects.update(**{field: value}),
    "bulk_update": lambda model, row, forged, field, value: model.objects.bulk_update([forged], [field]),
    "delete": lambda model, row, forged, field, value: model.objects.filter(pk=row.pk).delete(),
    "delete everything": lambda model, row, forged, field, value: model.objects.all().delete(),
}


@pytest.mark.parametrize("write", list(BULK_WRITES))
@pytest.mark.parametrize("model", list(RECORDS), ids=_label)
def test_a_bulk_rewrite_or_delete_is_refused_and_changes_nothing(world, model, write):
    _build, field, value = RECORDS[model]
    row = world.rows[model]
    before, counts = _stored(row), _counts()
    forged = model._base_manager.get(pk=row.pk)
    setattr(forged, field, value)

    with CaptureQueriesContext(connection) as sql, pytest.raises(APPEND_ONLY[model]):
        BULK_WRITES[write](model, row, forged, field, value)

    assert sql.captured_queries == [], "refused before any SQL, so the caller's transaction stays usable"
    assert _stored(row) == before
    assert _counts() == counts


def test_a_recorded_role_grant_is_never_deleted_one_at_a_time(world):
    grant = world.rows[RoleGrant]
    before = _stored(grant)
    with pytest.raises(ValueError, match="never deleted"):
        grant.delete()
    assert _stored(grant) == before


def _set_role(by, account, role):
    client = APIClient()
    client.force_authenticate(user=by)
    client.raise_request_exception = False
    return client.patch(f"/api/accounts/users/{account.pk}/set_role/", {"role": role}, format="json")


def test_promoting_demoting_and_removing_an_operator_still_answer_and_never_rewrite_a_grant(world):
    """A promotion appends a grant through its writer (``RoleGrant.record``, an INSERT);
    a demotion (a stop) and a removal (a stop) write none and answer through the real
    routes, and every recorded grant stays as it was."""
    assert stops.STOP_ROUTES["accounts:user-set-role"]["PATCH"] is not None
    admin = world.alice
    grants = list(RoleGrant._base_manager.order_by("id").values())

    promoted = _set_role(admin, world.grantee, "admin")
    assert promoted.status_code == 200, promoted.content
    after = list(RoleGrant._base_manager.order_by("id").values())
    assert after[: len(grants)] == grants and len(after) == len(grants) + 1
    assert (after[-1]["account_pk"], after[-1]["role"], after[-1]["granted_by_pk"]) == (
        world.grantee.pk, "admin", admin.pk
    )

    demoted = _set_role(admin, world.grantee, "viewer")
    assert demoted.status_code == 200, demoted.content
    assert list(RoleGrant._base_manager.order_by("id").values()) == after

    client = APIClient()
    client.force_authenticate(user=admin)
    client.raise_request_exception = False
    removed = client.delete(f"/api/accounts/users/{world.grantee.pk}/")
    assert removed.status_code == 204, removed.content
    assert not User.objects.filter(pk=world.grantee.pk).exists()
    assert list(RoleGrant._base_manager.order_by("id").values()) == after
