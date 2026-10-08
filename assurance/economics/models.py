"""The Economic Exposure records (phase E0): sources, the model inventory, and the
scenario, review and override records the separation rules are enforced on.

These are ``assurance`` models: :mod:`assurance.models` imports this module, so
Django files them under the ``assurance`` app and they migrate in
``assurance/migrations/``. Nothing uses them yet -- no route, command or signal
writes or reads one in this phase. ``docs/economics/spec-v1.md`` (section 6)
names each model's permitted writers for the steps that add them.

The rules themselves are pure functions in :mod:`assurance.economics.engine.governance`;
each model calls them on save and refuses a write with the rule's code
(:class:`EconomicsRefused`). Every model here is APPEND-ONLY, as the assurance
history is: a recorded row is never edited or deleted (:class:`EconomicsRewriteRefused`),
its queryset refuses a bulk update, delete or create, and a row goes only with its
deployment (the foreign key's cascade, which Django runs through the base manager).
A change is a new row: a new version of a source, a new revision of an inventory
entry, a scenario that supersedes another.

People are named as :class:`assurance.models.ClaimEvent` names them: an account
foreign key, nulled if the account is removed, and the account's username written
once with the row and never cleared, so attribution outlives the account.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Max, Q
from django.utils import timezone

from .engine import governance
from .engine.provenance import LicenseClass, TrustTier


class EconomicsRewriteRefused(ValueError):
    """A recorded economics row was asked to change or go away. The records are
    append-only: a change is a NEW row, and the one before it stays."""


class EconomicsRefused(ValueError):
    """A write one of the governance rules refuses. ``code`` is the rule's code
    (:data:`assurance.economics.engine.governance.REFUSALS`)."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{code}: {governance.REFUSALS[code]}")


class SeparationOfDutiesRefused(EconomicsRefused):
    """An author reviewing their own scenario, a requester approving their own
    override, a second approval from the same person, or an override read as in
    force without two different approvers."""


class SourceNotUsableForProduction(EconomicsRefused):
    """A production run asked to use a source whose license nobody has reviewed."""


class AppendOnlyQuerySet(models.QuerySet):
    """Refuses every bulk write: a recorded row is never rewritten or deleted, and a
    new one is written through ``save``, where its model's checks run."""

    def update(self, **kwargs):
        raise EconomicsRewriteRefused("Economics records are never rewritten; record a new row.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise EconomicsRewriteRefused("Economics records are never rewritten; record a new row.")

    def delete(self):
        raise EconomicsRewriteRefused("Economics records are never deleted; they go with their deployment.")

    delete.queryset_only = True

    def bulk_create(self, objs, *args, **kwargs):
        raise EconomicsRefused("bulk_create_refused")


class _AppendOnly(models.Model):
    """The append-only discipline every model here shares. A subclass states its
    checks in :meth:`check_new`, which runs before the row is first written."""

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        abstract = True

    def check_new(self) -> None:
        """Refuse (raise :class:`EconomicsRefused`) a row the rules do not allow,
        and fill in what the row records about itself when it is written."""

    def save(self, *args, **kwargs):
        if not self._state.adding or kwargs.get("force_update") or kwargs.get("update_fields") is not None:
            raise EconomicsRewriteRefused(
                f"A recorded {self._meta.verbose_name} is history and is never rewritten; record a new row."
            )
        self.check_new()
        # An INSERT, never an UPDATE: a new instance carrying a recorded row's
        # primary key fails rather than overwriting that row.
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise EconomicsRewriteRefused(f"A recorded {self._meta.verbose_name} is history and is never deleted.")


def _username(account) -> str:
    return (getattr(account, "username", "") or "")[:150]


def _refuse(refusal: str | None, error=EconomicsRefused) -> None:
    if refusal is not None:
        raise error(refusal)


# ---------------------------------------------------------------------------
# FinancialSource -- one version of one data source a figure rests on
# ---------------------------------------------------------------------------


class FinancialSourceQuerySet(AppendOnlyQuerySet):
    def usable_for_production(self):
        """The versions a production run may use: those whose license class someone
        has reviewed. ``unreviewed`` (the default) is never among them."""
        reviewed = [c.value for c in LicenseClass if governance.production_use_refusal(c.value) is None]
        return self.filter(license_class__in=reviewed)


class FinancialSource(_AppendOnly):
    """One version of one data source: who publishes it, which dataset, where it was
    read from, on what terms, how far it is trusted, when it was retrieved, and the
    hash of the snapshot taken (specification, sections 10 and 15).

    ``source_key`` is the source's identity across versions; ``version`` counts from
    1 and is assigned on save when it is not given. A changed snapshot, license class
    or trust tier is a new version, and the older one stays as the record of what an
    earlier run read. In this phase every source is a committed fixture snapshot; no
    feed writes one.

    ``deployment`` is the tenant: empty for a platform-wide source (an official
    statistics series, a public price list), set for one customer's own data, which
    no other deployment's scenario may read.

    ``license_class`` defaults to ``unreviewed``, and an unreviewed source is never
    used by a production run: :meth:`check_usable_for_production` refuses it, and
    :meth:`FinancialSourceQuerySet.usable_for_production` leaves it out.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        "assurance.Deployment",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="financial_sources",
    )
    source_key = models.SlugField(max_length=200)
    version = models.PositiveIntegerField()
    provider = models.CharField(max_length=200)
    dataset = models.CharField(max_length=200)
    # Where it was read from: a URL or an API endpoint. Blank for a customer file.
    url = models.URLField(max_length=2048, blank=True)
    license_class = models.CharField(
        max_length=32, choices=[(c.value, c.value) for c in LicenseClass], default=LicenseClass.UNREVIEWED.value
    )
    trust_tier = models.CharField(
        max_length=32, choices=[(t.value, t.value) for t in TrustTier], default=TrustTier.UNVERIFIED.value
    )
    retrieved_at = models.DateTimeField()
    # "sha256:" + 64 hex over the snapshot's bytes, as the platform's other digests.
    snapshot_hash = models.CharField(max_length=71)
    schema_version = models.CharField(max_length=64)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_sources_recorded",
    )
    recorded_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    objects = FinancialSourceQuerySet.as_manager()

    class Meta:
        ordering = ["source_key", "version", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["source_key", "version"],
                condition=Q(deployment__isnull=True),
                name="uq_econ_source_platform_version",
            ),
            models.UniqueConstraint(
                fields=["deployment", "source_key", "version"],
                condition=Q(deployment__isnull=False),
                name="uq_econ_source_tenant_version",
            ),
            models.CheckConstraint(condition=Q(version__gte=1), name="ck_econ_source_version_positive"),
        ]
        indexes = [models.Index(fields=["deployment", "source_key"], name="assurance_econ_source_key")]

    def check_new(self) -> None:
        _refuse(governance.snapshot_hash_refusal(self.snapshot_hash))
        if self.version is None:
            earlier = FinancialSource._base_manager.filter(
                deployment_id=self.deployment_id, source_key=self.source_key
            ).aggregate(latest=Max("version"))["latest"]
            self.version = (earlier or 0) + 1
        if self.recorded_by_id is not None and not self.recorded_by_username:
            self.recorded_by_username = _username(self.recorded_by)

    def production_use_refusal(self) -> str | None:
        return governance.production_use_refusal(self.license_class)

    def check_usable_for_production(self) -> None:
        """Raise :class:`SourceNotUsableForProduction` unless a production run may
        use this version. Called by the run before it reads the source."""
        _refuse(self.production_use_refusal(), SourceNotUsableForProduction)

    def __str__(self) -> str:
        return f"{self.source_key} v{self.version} ({self.license_class})"


# ---------------------------------------------------------------------------
# ModelInventoryEntry -- the model inventory (specification, section 26)
# ---------------------------------------------------------------------------


class ModelInventoryEntry(_AppendOnly):
    """One financial model release registered in the inventory: its id and version,
    the accountable owner, what it is for, what it must not be used for, and when it
    retires (an open date until one is set).

    A change to a registered release -- a new owner, a narrowed intended use, a
    retirement date -- is a new ``revision`` of the same ``(model_id, version)``,
    assigned on save; the highest revision is the entry in force. A change to the
    model itself is a new ``version``.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    model_id = models.SlugField(max_length=200)
    version = models.CharField(max_length=64)
    revision = models.PositiveIntegerField()
    # The accountable owner: a named person or function, not an account, so the
    # entry keeps an owner when an account is removed.
    owner = models.CharField(max_length=200)
    intended_use = models.TextField()
    limitations = models.TextField()
    retirement_date = models.DateField(null=True, blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_inventory_recorded",
    )
    recorded_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["model_id", "version", "revision"]
        verbose_name_plural = "model inventory entries"
        constraints = [
            models.UniqueConstraint(fields=["model_id", "version", "revision"], name="uq_econ_inventory_revision"),
            models.CheckConstraint(condition=Q(revision__gte=1), name="ck_econ_inventory_revision_positive"),
        ]

    def check_new(self) -> None:
        _refuse(
            governance.inventory_refusal(
                model_id=self.model_id,
                version=self.version,
                owner=self.owner,
                intended_use=self.intended_use,
                limitations=self.limitations,
            )
        )
        if self.revision is None:
            earlier = ModelInventoryEntry._base_manager.filter(
                model_id=self.model_id, version=self.version
            ).aggregate(latest=Max("revision"))["latest"]
            self.revision = (earlier or 0) + 1
        if self.recorded_by_id is not None and not self.recorded_by_username:
            self.recorded_by_username = _username(self.recorded_by)

    def __str__(self) -> str:
        return f"{self.model_id} {self.version} r{self.revision}"


# ---------------------------------------------------------------------------
# FinancialScenario, ScenarioReview -- a reviewer is never the author
# ---------------------------------------------------------------------------


class FinancialScenario(_AppendOnly):
    """A causal loss scenario's identity and authorship: which deployment, which
    system state, which effect its loss follows from, and who wrote it.

    Only what the separation rules need, and the references into SPINE that bind it
    (specification, section 15). Parameters, components, results and the grade come
    with the scenario builder and the engine, in later steps.

    SPINE is referenced, never copied (section 16): ``system_fingerprint`` as an
    assurance claim binds to a system state, ``causal_effect`` as the receipt names
    an effect (``sha256:`` + hex), both checked against
    :data:`~assurance.economics.engine.governance.REFERENCE_FORMS` and blank until
    known. A revised scenario is a new row that ``supersedes`` this one, in the same
    deployment.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        "assurance.Deployment", on_delete=models.CASCADE, related_name="financial_scenarios"
    )
    title = models.CharField(max_length=255)
    system_fingerprint = models.CharField(max_length=64, blank=True)
    causal_effect = models.CharField(max_length=71, blank=True)
    supersedes = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="superseded_by"
    )
    # Null when a machine drafted the scenario; see ScenarioReview.
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_scenarios_authored",
    )
    author_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "id"]
        indexes = [models.Index(fields=["deployment"], name="assurance_econ_scenario_dep")]

    @property
    def author_person(self) -> governance.Person:
        return governance.Person(id=self.author_id, username=self.author_username)

    def check_new(self) -> None:
        if self.system_fingerprint:
            _refuse(governance.spine_reference_refusal("system_fingerprint", self.system_fingerprint))
        if self.causal_effect:
            _refuse(governance.spine_reference_refusal("effect", self.causal_effect))
        if self.supersedes_id is not None and self.supersedes.deployment_id != self.deployment_id:
            raise EconomicsRefused("cross_tenant_reference")
        if self.author_id is not None and not self.author_username:
            self.author_username = _username(self.author)

    def __str__(self) -> str:
        return f"scenario {self.title}"


class ScenarioReview(_AppendOnly):
    """One person's review of one scenario. The reviewer is never the scenario's
    author (``author_reviews_own_scenario``): checked when the review is written,
    against the author's account and the username recorded with the scenario, so a
    removed author's scenario is still theirs. A scenario a machine drafted (no
    author) may be reviewed by any named person."""

    class Verdict(models.TextChoices):
        APPROVED = "approved", "Approved"
        RETURNED = "returned", "Returned to the author"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="reviews")
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_reviews",
    )
    reviewer_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    verdict = models.CharField(max_length=16, choices=Verdict.choices)
    note = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]

    def check_new(self) -> None:
        if self.reviewer_id is not None and not self.reviewer_username:
            self.reviewer_username = _username(self.reviewer)
        reviewer = governance.Person(id=self.reviewer_id, username=self.reviewer_username)
        _refuse(governance.review_refusal(self.scenario.author_person, reviewer), SeparationOfDutiesRefused)

    def __str__(self) -> str:
        return f"{self.verdict} review of scenario {self.scenario_id}"


# ---------------------------------------------------------------------------
# SensitiveOverride, OverrideApproval -- two different approvers
# ---------------------------------------------------------------------------


class SensitiveOverride(_AppendOnly):
    """A request to override something in a scenario -- a parameter, a computed
    value -- that is sensitive enough to need two approvers.

    Recording the request puts nothing in force. It is in force only once two
    different named people, neither of them the requester, have approved it
    (:meth:`approval_refusal`, ``override_needs_two_approvers``), and that is read
    from the approvals each time it is asked, never stored.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="sensitive_overrides")
    # What is overridden: a parameter's or a value's name.
    subject = models.CharField(max_length=200)
    reason = models.TextField()
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_overrides_requested",
    )
    requested_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    requested_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]

    @property
    def requester(self) -> governance.Person:
        return governance.Person(id=self.requested_by_id, username=self.requested_by_username)

    def approvers(self) -> list[governance.Person]:
        """Everyone who has approved it, as the approvals name them, read now."""
        return [
            governance.Person(id=account_id, username=username)
            for account_id, username in OverrideApproval._base_manager.filter(override_id=self.pk)
            .order_by("id")
            .values_list("approver_id", "approver_username")
        ]

    def approval_refusal(self) -> str | None:
        """``None`` when the override is in force; otherwise why it is not."""
        return governance.override_refusal(self.requester, self.approvers())

    @property
    def in_force(self) -> bool:
        return self.approval_refusal() is None

    def check_in_force(self) -> None:
        """Raise :class:`SeparationOfDutiesRefused` unless the override is in force.
        Called by whatever would apply it, before it does."""
        _refuse(self.approval_refusal(), SeparationOfDutiesRefused)

    def check_new(self) -> None:
        if self.requested_by_id is not None and not self.requested_by_username:
            self.requested_by_username = _username(self.requested_by)
        _refuse(
            governance.override_request_refusal(self.requester, self.subject, self.reason),
            SeparationOfDutiesRefused,
        )

    def __str__(self) -> str:
        return f"sensitive override of {self.subject} on scenario {self.scenario_id}"


class OverrideApproval(_AppendOnly):
    """One person's approval of one sensitive override. The requester never
    approves their own override, and nobody approves the same override twice
    (checked on save, and by a unique constraint for two writes racing)."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    override = models.ForeignKey(SensitiveOverride, on_delete=models.CASCADE, related_name="approvals")
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_override_approvals",
    )
    approver_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    approved_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["override", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["override", "approver"],
                condition=Q(approver__isnull=False),
                name="uq_econ_override_one_approval_each",
            ),
        ]

    def check_new(self) -> None:
        if self.approver_id is not None and not self.approver_username:
            self.approver_username = _username(self.approver)
        approver = governance.Person(id=self.approver_id, username=self.approver_username)
        override = self.override
        _refuse(
            governance.approval_refusal(override.requester, override.approvers(), approver),
            SeparationOfDutiesRefused,
        )

    def __str__(self) -> str:
        return f"approval of override {self.override_id}"
