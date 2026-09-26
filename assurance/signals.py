"""Populate the assurance system of record when a scan completes (Phase 0.1b).

Phase 0.1 built the data model and an explicit ``ingest_scan`` callable. This
wires it in: when a ``PentestScan`` transitions to *completed* with an engine
response, its findings are ingested into structured Finding + Evidence rows.

Two deliberate safety choices keep this off the delicate scan path:

- **On commit, not inline.** Ingestion is scheduled with
  ``transaction.on_commit``, so it runs *after* the scan's transaction commits
  and never lengthens or contends with it. A side effect that matters here: in
  the test suite, where each test runs in a transaction that is rolled back,
  on-commit callbacks are discarded — so this signal is inert during the
  existing pentest/engagement tests and cannot interfere with them. It runs in
  production (and in transactional tests) only.
- **Never fatal.** The whole ingest is wrapped: an ingestion error is logged and
  swallowed, so recording a finding never breaks scan completion.

Disable entirely with ``ASSURANCE_INGEST_ON_COMPLETE = False``.

It also holds the backstop that keeps the stored decision current when a decision
input is written by something other than the API -- the Django admin, a shell, a
management command (see :func:`schedule_decision_refresh`).
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, DatabaseError, connections, transaction
from django.db.models import QuerySet
from django.db.models.signals import post_delete, post_migrate, post_save, pre_delete, pre_save
from django.dispatch import receiver

# Plain constants; the models module is loaded before `AppConfig.ready` imports
# this one, so importing them here changes no loading order.
from .models import DECISION_OWNED_FIELDS, LATENT_HOLDING_STATES, LATENT_UNREAD_STATES

logger = logging.getLogger(__name__)


@receiver(post_save, sender="pentest.PentestScan", dispatch_uid="assurance_ingest_on_complete")
def ingest_completed_scan(sender, instance, created, update_fields=None, **kwargs):
    """Ingest a scan's findings once it is marked completed.

    Fires only on the completion transition (a save that touches ``status``,
    which ``PentestScan.mark_completed`` does), for a completed scan that has an
    engine response. ``ingest_scan`` is idempotent, so a later save of the same
    completed scan re-ingests harmlessly rather than duplicating."""
    if not getattr(settings, "ASSURANCE_INGEST_ON_COMPLETE", True):
        return
    # Local imports: keep app loading order independent of import side effects.
    from pentest.models import PentestScan

    if created:
        return
    if instance.status != PentestScan.STATUS_COMPLETED:
        return
    # Only on the save that set the status (mark_completed uses update_fields);
    # a full save with update_fields=None also qualifies.
    if update_fields is not None and "status" not in update_fields:
        return
    if not instance.engine_response:
        return

    scan_pk = instance.pk

    def _do_ingest():
        from .ingest import ingest_scan

        try:
            ingest_scan(instance)
        except Exception:  # recording findings must never break completion
            logger.exception("assurance ingestion failed for scan %s", scan_pk)

    transaction.on_commit(_do_ingest)


@receiver(post_save, sender="assurance.Finding", dispatch_uid="assurance_auto_dispatch_finding")
def auto_dispatch_finding(sender, instance, created, update_fields=None, **kwargs):
    """Auto-dispatch a finding to its deployment's connectors once it is recorded
    (commercial spine, automated-dispatch policy).

    Inert by default and gated at every layer: it only ever *schedules* the
    dispatch (on commit, so it never lengthens the finding's transaction and is
    discarded in the rolled-back test transactions), and the scheduled work is a
    no-op unless the deployment has an admin-enabled
    :class:`~assurance.models.DispatchPolicy` the finding qualifies for AND at least
    one connector binding. With no policy — the default for every deployment —
    nothing happens. The dispatch itself is idempotent (a finding is never pushed to
    the same connector twice) and resilient (a connector error is recorded, never
    raised). Disable entirely with ``ASSURANCE_AUTO_DISPATCH_ENABLED = False``."""
    if not getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True):
        return
    from .dispatch import schedule_finding_dispatch

    schedule_finding_dispatch(instance)


def _has_column(using, table, column) -> bool:
    """Whether ``table`` exists in the database behind ``using`` and has ``column``.

    The catalogue is asked whether the table exists BEFORE the table is described.
    Describing a missing table is a failing query on PostgreSQL (``SELECT * FROM
    <table> LIMIT 1``), and a failed query aborts the transaction it ran in: a
    ``flush`` inside ``atomic()`` reached this probe with the assurance tables
    migrated away, the error was swallowed below, and the whole block -- the flush
    included -- was silently rolled back at COMMIT. The probe also runs in its own
    savepoint, so a describe that fails for any other reason takes only the
    savepoint with it, never the caller's transaction.
    """
    connection = connections[using or DEFAULT_DB_ALIAS]
    try:
        with transaction.atomic(using=connection.alias), connection.cursor() as cursor:
            if table not in connection.introspection.table_names(cursor):
                return False
            description = connection.introspection.get_table_description(cursor, table)
    except DatabaseError:
        return False
    return any(col.name == column for col in description)


@receiver(post_migrate, dispatch_uid="assurance_restore_fired_holds")
def restore_the_holds_fired_conditions_keep(sender, using=None, apps=None, **kwargs):
    """Put back the hold each FIRED latent condition keeps on its claim, wherever
    something removed it (:func:`assurance.latent.restore_fired_holds`).

    The upgrade from the release before this one: its re-derive left a fired
    condition on the version it closed and read the new version back to a pass,
    resolving the retest. 0038 carries the condition to the claim's current version,
    where it holds it again -- but the claim row still read VERIFIED, no retest was
    open, and the stored decision, recomputed here, read READY until some later
    write happened to evaluate the condition. Connected BEFORE the recompute below,
    so the decisions it recomputes read the hold as it is put back; each restore
    also schedules its deployment's refresh, as any write to a claim does.

    Keyed on the data, like the receivers below: a condition whose hold is in place
    is not touched, so an unrelated ``migrate`` writes nothing. It reads no condition
    again and writes no decision column itself.
    """
    if not _the_decision_columns_are_migrated(sender, using, apps):
        return
    from .latent import deployments_with_a_lifted_hold, restore_fired_holds
    from .models import Deployment

    for deployment in Deployment.objects.filter(pk__in=deployments_with_a_lifted_hold()).order_by("pk"):
        restore_fired_holds(deployment)


@receiver(post_migrate, dispatch_uid="assurance_recompute_after_demotion")
def recompute_decisions_computed_under_another_rule(sender, using=None, apps=None, **kwargs):
    """Recompute every stored decision with chain outcomes under it that was never
    computed under the signed-outcome rule (``decision_keyring`` NULL).

    Keyed on the DATA, not on the migration plan. It used to fire only when the
    plan just applied contained the marker migration -- and Django sends
    ``post_migrate`` only after a whole plan succeeds, so a ``migrate`` that
    failed on a later migration recorded the marker as applied and the re-run's
    plan no longer contained it: the recompute was skipped for good. A NULL
    stamp is still NULL on the re-run. Rows already stamped are not touched, so
    an unrelated ``migrate`` moves no decision; only this app's signal, and only
    for the database the decision rule reads.
    """
    if not _the_decision_columns_are_migrated(sender, using, apps):
        return
    from django.db.models import Q

    from .decision import _current_policy_pin, recompute_decision
    from .models import Deployment, WorkflowChainOutcome

    deployment_ids = WorkflowChainOutcome.objects.values_list("deployment_id", flat=True).distinct()
    for deployment in Deployment.objects.filter(pk__in=deployment_ids, decision_keyring__isnull=True):
        recompute_decision(deployment)
    # And every stored decision computed under other rules: a release that moved
    # the policy pin moved what the same inputs imply (Deployment.decision_policy).
    # Keyed on the data like the keyring stamp, so a migrate that failed part-way
    # leaves them marked for the next.
    stale = Deployment.objects.filter(decision__isnull=False).filter(
        Q(decision_policy__isnull=True) | ~Q(decision_policy=_current_policy_pin())
    )
    for deployment in stale.order_by("pk"):
        recompute_decision(deployment)


def _the_decision_columns_are_migrated(sender, using, apps) -> bool:
    """Whether a ``post_migrate`` from ``sender`` on ``using`` finds this app's
    decision columns in place to be read and recomputed: only this app's signal,
    only the database the decision rule reads, and only a schema at the stamp.

    `post_migrate` fires after EVERY migrate, including one that leaves this app
    below the migration adding the stamp (a rollback, a staged upgrade): the column
    is not there to query, and every such migrate crashed in the receivers. The
    migration state the signal hands over says whether it is -- asked of the model,
    not of the recorder table, which a run with no migrations applied
    (`--nomigrations`, a fresh syncdb) never creates.
    """
    if getattr(sender, "name", None) != "assurance":
        return False
    if using not in (None, DEFAULT_DB_ALIAS):
        return False
    from .models import Deployment

    if apps is not None:
        try:
            state = apps.get_model("assurance", "Deployment")
        except LookupError:
            return False
        names = {f.name for f in state._meta.get_fields()}
        return _DECISION_COLUMNS_ADDED_LAST <= names
    # `flush` sends post_migrate with no migration state at all, so there is
    # nothing to ask but the database itself -- and a flush of a database left
    # below the stamp crashed on the column here.
    return all(_has_column(using, Deployment._meta.db_table, c) for c in _DECISION_COLUMNS_ADDED_LAST)


#: The decision columns the refresh writes that later migrations added. A recompute
#: writes every one of them, so a schema missing any is one it cannot run against --
#: a staged upgrade stopped between the stamp and the accepted-risk expiry has the
#: first and not the second, and asking only for the first let the receivers crash.
_DECISION_COLUMNS_ADDED_LAST = frozenset({"decision_keyring", "decision_valid_until", "decision_policy"})


@receiver(post_migrate, dispatch_uid="assurance_repair_decisions_behind_their_log")
def repair_decisions_behind_their_log(sender, using=None, apps=None, **kwargs):
    """Bring every deployment whose stored decision is behind its own transition
    log (``decision_revision`` below the log's latest revision) up to it.

    Such a row is legacy data only -- the stale full save before ``Deployment.save``
    stopped writing the decision columns, or ``loaddata`` of a fixture dumped
    before its log moved -- and it was repaired only by the next recompute of that
    deployment, which might never come. Every read now publishes what the log
    records (``revision.hold_to_its_log``); this brings the rows themselves level
    at the upgrade, so no read is left to do it.

    The repair every read makes, ``revision.bring_up_to_its_log``: through the one
    writer, under the row lock, the no-op move TO the decision the log records --
    the operator's pause as the log records it -- and nothing new recorded. Not a
    recompute: a ``migrate`` decides nothing. It runs wherever the schema is
    upgraded, which need not be where the outcome keyring is installed, and a
    recompute there recorded a decision computed without the keyring as the next
    transition. A row level with or ahead of its log is not touched -- not even
    locked -- so an unrelated ``migrate`` moves no decision. Keyed on the data, like
    the receiver above, so a re-run after a failed ``migrate`` still finds what it
    has not repaired.
    """
    if not _the_decision_columns_are_migrated(sender, using, apps):
        return
    from django.db.models import F

    from .models import Deployment
    from .revision import bring_up_to_its_log, logged_head

    behind = (
        Deployment.objects.annotate(**logged_head())
        .filter(logged_revision__gt=F("decision_revision"))
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    for pk in behind:
        bring_up_to_its_log(pk)


# ---------------------------------------------------------------------------
# The backstop: a decision input written anywhere refreshes the stored decision
# ---------------------------------------------------------------------------
#
# Every API route that writes a decision input refreshes the stored decision in
# the same transaction as the write (`views._refresh_stored_decision`). Nothing
# made anything else do so. An admin who re-opened a critical finding, a shell
# session that marked a scan's evidence incomplete, a management command that
# re-derived the claims -- each changed what decision-support computed live and
# left the receipt, the bundle and the dispatch fence reading the decision from
# before. These receivers are the net under every writer that did not refresh:
# a write to any model the decision is computed from schedules one refresh of
# that deployment's stored decision for when its transaction commits.
#
# What it cannot see: `QuerySet.update()` and `bulk_create()` send no signals.
# The routes that use them refresh explicitly, and the meta-test over every
# mutating route (tests/test_every_write_route_keeps_the_decision_current.py)
# holds them to it.

#: Every model the decision is computed from, and the chain of foreign keys from a
#: row of it to the deployment whose decision it feeds. Held against the queries
#: `compute_decision` actually issues by
#: test_the_backstop_watches_every_table_the_decision_reads, so a new input cannot
#: be added to the rule without being added here.
DECISION_INPUTS = {
    "assurance.Finding": ("deployment",),
    # A finding's evidence class is the weakest of its evidence rows.
    "assurance.Evidence": ("finding", "deployment"),
    "assurance.AssuranceClaim": ("deployment",),
    "assurance.RetestRequirement": ("deployment",),
    # Observed components, and whether each was assessed: the coverage cap.
    "assurance.Asset": ("deployment",),
    # The declared baseline the coverage cap is measured against.
    "assurance.DeclaredComponent": ("deployment",),
    "assurance.ApprovedWorkflow": ("deployment",),
    "assurance.WorkflowChainOutcome": ("deployment",),
    # A declared precondition a current claim rests on that nobody can read now --
    # unobservable, or its evaluation failed -- holds the decision back.
    "assurance.LatentCondition": ("deployment",),
}

def _deployments_serving_through(instance) -> set:
    """The deployments with a component that resolves to this provider: the route
    each serves names the provider and reads its region (assurance.served_route)."""
    from .models import Asset

    if instance.pk is None:
        return set()
    return set(
        Asset.objects.filter(provider_id=instance.pk).values_list("deployment_id", flat=True).distinct()
    )


#: Inputs the decision reads that belong to no one deployment, and how to find the
#: deployments a write to one reaches. A provider is shared: its name and region are
#: fields of the served route (P2.2), which every chain outcome is compared with, so
#: renaming it moves the route of every deployment serving through it -- and the
#: decision of each, with no write to any of them.
DECISION_FANOUT_INPUTS = {
    "assurance.Provider": _deployments_serving_through,
}

#: Where a fan-out row's deployments are kept between pre_delete and post_delete:
#: by post_delete the components that resolved to it have been set to none.
_PRIOR_FANOUT = "_assurance_decision_prior_fanout"


def _fanout_input_saved(sender, instance, raw=False, using=None, **kwargs):
    if raw:
        return
    for deployment_id in DECISION_FANOUT_INPUTS[instance._meta.label](instance):
        schedule_decision_refresh(deployment_id, using=using)


def _fanout_input_deleting(sender, instance, **kwargs):
    instance.__dict__[_PRIOR_FANOUT] = DECISION_FANOUT_INPUTS[instance._meta.label](instance)


def _fanout_input_deleted(sender, instance, using=None, **kwargs):
    for deployment_id in instance.__dict__.pop(_PRIOR_FANOUT, set()):
        schedule_decision_refresh(deployment_id, using=using)


#: For a model the decision reads only some columns of: those columns. A save that
#: names none of them in ``update_fields`` cannot move the decision -- a finding's
#: remediation workflow and its assignee are saved on every move and read by
#: nothing the decision computes. Pinned by
#: test_the_decision_reads_no_finding_column_but_these.
DECISION_COLUMNS = {
    # An accepted finding is read for when its acceptance ends and the severity it
    # was given at (`decision.accepted_risk_signal`): narrowing that severity alone
    # took an acceptance from standing to outgrown and scheduled nothing.
    "assurance.Finding": frozenset(
        {"deployment", "deployment_id", "status", "severity", "risk_accepted_until", "risk_accepted_severity"}
    ),
    # Not `last_evaluated_at`, which every evaluation writes: a refresh it scheduled
    # would evaluate again, and write it again.
    "assurance.LatentCondition": frozenset(
        {"deployment", "deployment_id", "claim", "claim_id", "state"}
    ),
}

#: For a model the decision reads only some ROWS of: the column that says which, and
#: the values it reads. A row written whole in none of them cannot move the decision
#: when it is first written -- declaring a watch writes a PENDING one. A whole save of
#: an existing row is refreshed whatever it holds (`_remember_prior_deployment`
#: notes the row's deployment first), so a row moved OUT of such a state is too. A
#: condition is read unread, and FIRED, which holds its claim whatever the claim reads.
DECISION_ROWS = {
    "assurance.LatentCondition": ("state", LATENT_UNREAD_STATES | LATENT_HOLDING_STATES),
}

#: The Deployment columns that are the refresh's output rather than an input to
#: it. The refresh writes the decision columns with a QuerySet update, which sends
#: no signal, and `Deployment.save` refuses to write them at all
#: (`models.DECISION_OWNED_FIELDS`); what remains is a save that touches only
#: `updated_at`, which moves nothing either.
_DECISION_OWN_FIELDS = DECISION_OWNED_FIELDS | {"updated_at"}


def writes_a_decision_input(instance, update_fields) -> bool:
    """Whether saving ``instance`` with ``update_fields`` can change what its
    deployment's decision is computed from. A save that names no field
    (``update_fields=None``) writes every column, so it can -- unless the row is
    one the decision does not read (`DECISION_ROWS`)."""
    label = instance._meta.label
    if label == "assurance.Deployment":
        # `evidence_incomplete`, `last_complete_scan_at` and the reported
        # `check_coverage` are inputs the deployment row carries itself. Its
        # decision columns are the refresh's output, not an input.
        return update_fields is None or not set(update_fields) <= _DECISION_OWN_FIELDS
    if label not in DECISION_INPUTS:
        return False
    if update_fields is None:
        rows = DECISION_ROWS.get(label)
        return rows is None or getattr(instance, rows[0]) in rows[1]
    columns = DECISION_COLUMNS.get(label)
    return columns is None or bool(columns & set(update_fields))


#: Where a row's deployment is kept between pre_save and post_save when the save
#: could move the row to another deployment -- which moves TWO decisions.
_PRIOR = "_assurance_decision_prior_deployment"

#: The connection attribute that de-duplicates scheduled refreshes per transaction.
_PENDING = "_assurance_decision_refresh_pending"


def decision_deployment_id(instance, *, stored: bool = False):
    """The pk of the deployment whose decision ``instance`` feeds, or ``None``.

    ``stored`` asks the database rather than the instance: the deployment the row
    belongs to as last saved, which is the one a save that changes the foreign key
    moves the row away from.
    """
    chain = DECISION_INPUTS[instance._meta.label]
    if stored:
        if instance.pk is None:
            return None
        return (
            type(instance)._default_manager.filter(pk=instance.pk)
            .values_list("__".join(chain), flat=True)
            .first()
        )
    return _follow(instance, chain)


def _follow(instance, chain):
    field = instance._meta.get_field(chain[0])
    if len(chain) == 1:
        return getattr(instance, field.attname)
    if field.is_cached(instance):
        related = getattr(instance, field.name)
        return None if related is None else _follow(related, chain[1:])
    related_pk = getattr(instance, field.attname)
    if related_pk is None:
        return None
    # One narrow query rather than loading the parent: an ingest saves an evidence
    # row per finding, and this runs on each.
    return (
        field.related_model._default_manager.filter(pk=related_pk)
        .values_list("__".join(chain[1:]), flat=True)
        .first()
    )


class _RefreshAfterCommit:
    """One deployment's stored-decision refresh, run when its transaction commits.

    A class rather than a closure so a test can find it among the commit hooks and
    ask which deployment it is for.
    """

    __slots__ = ("deployment_id", "pending")

    def __init__(self, deployment_id, pending):
        self.deployment_id = deployment_id
        self.pending = pending

    def __call__(self):
        # Out of the pending set first: a test harness that runs commit hooks
        # without ending the transaction must be able to schedule this deployment
        # again for a later write.
        if self.pending is not None:
            self.pending.discard(self.deployment_id)
        from .decision import refresh_stored_decisions

        try:
            refresh_stored_decisions([self.deployment_id])
        except Exception:  # the write it follows has already committed
            # Raised here, it would propagate out of COMMIT into a caller whose
            # write succeeded -- an API route that already refreshed inside its own
            # transaction would answer 500 for a write that stands, and its client
            # would retry it -- and it would drop every commit hook queued after
            # this one. Logged at ERROR instead, naming the deployment and what the
            # failure leaves behind: its stored decision was NOT brought current,
            # so the receipt and the dispatch fence may be publishing one its
            # inputs no longer support. An integrity error here is not noise; it
            # is how a torn revision showed itself, and the only way it did.
            logger.exception(
                "stored decision refresh failed after commit for deployment %s; its "
                "stored decision was not refreshed and may no longer match its inputs",
                self.deployment_id,
            )


def schedule_decision_refresh(deployment_id, *, using=None) -> None:
    """Refresh ``deployment_id``'s stored decision once the current transaction
    commits -- once, however many of its inputs the transaction wrote.

    Coalesced per deployment per transaction: an ingest that writes a thousand
    findings refreshes once, not a thousand times. The de-duplication is keyed on
    the connection's list of commit hooks, which Django replaces on commit, on
    rollback and on a savepoint rollback -- so a refresh registered inside a
    savepoint that was rolled back (and so discarded with it) is never mistaken
    for one still pending. Outside a transaction (autocommit) the write has already
    committed, and the refresh runs now.

    Only the default database: it is the one the decision rule reads, as the
    upgrade receiver above already assumes.
    """
    using = using or DEFAULT_DB_ALIAS
    if deployment_id is None or using != DEFAULT_DB_ALIAS:
        return
    connection = connections[using]
    pending = None
    if connection.in_atomic_block:
        hooks = connection.run_on_commit
        state = getattr(connection, _PENDING, None)
        if state is None or state[0] is not hooks:
            state = (hooks, set())
            setattr(connection, _PENDING, state)
        pending = state[1]
        if deployment_id in pending:
            return
        pending.add(deployment_id)
    transaction.on_commit(_RefreshAfterCommit(deployment_id, pending), using=using)


def _remember_prior_deployment(sender, instance, raw=False, update_fields=None, **kwargs):
    """Before a save that could move a row to another deployment, note the one it
    is leaving: that deployment's decision moves too."""
    if raw or instance._state.adding or instance.pk is None:
        return
    head = instance._meta.get_field(DECISION_INPUTS[instance._meta.label][0])
    if update_fields is not None and not ({head.name, head.attname} & set(update_fields)):
        # A save that does not write the foreign key cannot move the row. This is
        # every save an ingest makes, so it costs them nothing.
        return
    instance.__dict__[_PRIOR] = decision_deployment_id(instance, stored=True)


def _decision_input_saved(sender, instance, raw=False, using=None, update_fields=None, **kwargs):
    prior = instance.__dict__.pop(_PRIOR, None)
    if raw:
        # `loaddata`: fixtures are restored as they were dumped, stored decision
        # included, and a fixture's rows need not arrive parents first.
        return
    if prior is None and not writes_a_decision_input(instance, update_fields):
        return
    current = decision_deployment_id(instance)
    for deployment_id in {prior, current} - {None}:
        schedule_decision_refresh(deployment_id, using=using)


def _decision_input_deleted(sender, instance, using=None, origin=None, **kwargs):
    from .models import Deployment

    # Deleting a deployment cascades to every input it has; there is no decision
    # left to refresh, and asking each cascaded row for its deployment would cost
    # a query per evidence row.
    if isinstance(origin, Deployment) or (isinstance(origin, QuerySet) and origin.model is Deployment):
        return
    schedule_decision_refresh(decision_deployment_id(instance), using=using)


@receiver(post_save, sender="assurance.Deployment", dispatch_uid="assurance_decision_backstop_deployment")
def _deployment_saved(sender, instance, raw=False, using=None, update_fields=None, **kwargs):
    """The deployment row carries inputs of its own: ``evidence_incomplete``,
    ``last_complete_scan_at`` and the reported ``check_coverage``."""
    if raw:
        return
    if not writes_a_decision_input(instance, update_fields):
        # The refresh's own write. Without this guard every refresh would schedule
        # the next one.
        return
    schedule_decision_refresh(instance.pk, using=using)


@receiver(post_save, sender="assurance.Deployment", dispatch_uid="assurance_route_noted_at_creation")
def _note_the_route_a_new_deployment_starts_with(sender, instance, created=False, raw=False, **kwargs):
    """A deployment starts with the route nothing serves, and the record says so from
    the moment it exists -- so a run against it before any component is recorded binds
    to that, rather than to nothing because no note was ever taken. Never raises
    (:func:`assurance.served_route.note_route_quietly`), and no stop path creates one."""
    if raw or not created:
        return
    from .served_route import note_route_quietly

    note_route_quietly(instance, now=instance.created_at)


for _label in DECISION_INPUTS:
    pre_save.connect(
        _remember_prior_deployment, sender=_label, dispatch_uid=f"assurance_decision_backstop_pre:{_label}"
    )
    post_save.connect(
        _decision_input_saved, sender=_label, dispatch_uid=f"assurance_decision_backstop_save:{_label}"
    )
    post_delete.connect(
        _decision_input_deleted, sender=_label, dispatch_uid=f"assurance_decision_backstop_delete:{_label}"
    )


# ---------------------------------------------------------------------------
# Latent conditions (Phase 2 item 9): what the decision does not read, but a
# declared condition does.
# ---------------------------------------------------------------------------
#
# The data boundary and a provider's profile reach the decision only through the
# claims re-derived from them -- until someone declares a latent condition on one.
# Then a write to it is the change the condition watches for, and the deployment
# it is declared on is brought current after the write commits: the refresh above
# evaluates the conditions first (`decision.refresh_stored_decisions`). This is how
# every writer brings them current -- the API routes schedule it too, and only a
# data boundary route evaluates its own deployment inline -- so a write to a
# provider that twenty deployments watch no longer evaluates and locks all twenty
# inside its own transaction. Every live condition counts, not only a pending one:
# a fired or unobservable condition is read again by the refresh.

_PRIOR_PROVIDER_NAME = "_assurance_latent_prior_provider_name"


def _provider_name_as_stored(instance):
    """The provider name ``instance`` carried as last saved: a Provider's own, or
    the provider a ProviderAssertion belonged to."""
    if instance._state.adding or instance.pk is None:
        return None
    if instance._meta.label == "assurance.Provider":
        field = "name"
    else:
        field = "provider__name"
    return type(instance)._default_manager.filter(pk=instance.pk).values_list(field, flat=True).first()


def _provider_name(instance):
    if instance._meta.label == "assurance.Provider":
        return instance.name
    provider = getattr(instance, "provider", None)
    return None if provider is None else provider.name


def _remember_prior_provider_name(sender, instance, raw=False, **kwargs):
    if raw:
        return
    instance.__dict__[_PRIOR_PROVIDER_NAME] = _provider_name_as_stored(instance)


def _schedule_watching(deployment_ids, using) -> None:
    for deployment_id in deployment_ids:
        schedule_decision_refresh(deployment_id, using=using)


def _provider_profile_written(sender, instance, raw=False, using=None, **kwargs):
    from .latent import deployments_watching_provider

    before = instance.__dict__.pop(_PRIOR_PROVIDER_NAME, None)
    if raw:
        return
    _schedule_watching(deployments_watching_provider(before, _provider_name(instance)), using)


def _data_boundary_written(sender, instance, raw=False, using=None, **kwargs):
    from .latent import deployments_watching_boundary

    if raw:
        return
    _schedule_watching(deployments_watching_boundary(instance.deployment_id), using)


for _label in DECISION_FANOUT_INPUTS:
    post_save.connect(_fanout_input_saved, sender=_label, dispatch_uid=f"assurance_decision_fanout_save:{_label}")
    pre_delete.connect(
        _fanout_input_deleting, sender=_label, dispatch_uid=f"assurance_decision_fanout_pre_delete:{_label}"
    )
    post_delete.connect(
        _fanout_input_deleted, sender=_label, dispatch_uid=f"assurance_decision_fanout_delete:{_label}"
    )


for _label in ("assurance.Provider", "assurance.ProviderAssertion"):
    pre_save.connect(
        _remember_prior_provider_name, sender=_label, dispatch_uid=f"assurance_latent_pre:{_label}"
    )
    post_save.connect(_provider_profile_written, sender=_label, dispatch_uid=f"assurance_latent_save:{_label}")
    post_delete.connect(_provider_profile_written, sender=_label, dispatch_uid=f"assurance_latent_delete:{_label}")
post_save.connect(
    _data_boundary_written, sender="assurance.DataBoundary", dispatch_uid="assurance_latent_save:DataBoundary"
)
post_delete.connect(
    _data_boundary_written, sender="assurance.DataBoundary", dispatch_uid="assurance_latent_delete:DataBoundary"
)
