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
deployment. A change is a new row: a new version of a source, a new revision of an
inventory entry, a scenario that supersedes another.

The refusals guard the ORM paths code is written against, not the table. The base
manager, ``Model.save`` called directly, a plain ``QuerySet(model)``, raw SQL and a
migration all write past them (spec, section 10). The base manager MUST stay
Django's plain one -- never set ``Meta.base_manager_name`` here -- because it is the
path the two writes from outside economics take: removing an operator, a stop,
nulls the account columns, and deleting a deployment cascades its rows away.

People are named as :class:`assurance.models.ClaimEvent` names them: an account
foreign key, nulled if the account is removed, and the account's username. The
username is ALWAYS the account's own, written from the account when the row is
written and never taken from the caller; a review, an override request and an
approval are refused without an account. So a username with no account is only
ever read on a row whose account was removed after it was written.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Max, Q
from django.utils import timezone

from .engine import governance
from .engine.provenance import LicenseClass, TrustTier

_LICENSE_CODES = [c.value for c in LicenseClass]
_TRUST_CODES = [t.value for t in TrustTier]


class EconomicsRewriteRefused(ValueError):
    """A recorded economics row was asked to change or go away. The records are
    append-only: a change is a NEW row, and the one before it stays."""


class EconomicsRefused(ValueError):
    """A write one of the governance rules refuses. ``code`` is the rule's code
    (:data:`assurance.economics.engine.governance.REFUSALS`); ``detail`` names the
    field, where one does."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {governance.REFUSALS[code]}{suffix}")


class SeparationOfDutiesRefused(EconomicsRefused):
    """An author of any version reviewing a scenario, a review, request or approval
    with no account behind it, a requester approving their own override, a second
    approval from the same person, or an override read as in force without two
    different approvers."""


class SourceNotUsableForProduction(EconomicsRefused):
    """A production run asked to use a source whose license nobody has reviewed, or
    another deployment's source."""


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


def _signed_in(account) -> governance.Person:
    """The person a row is written by: the account and the account's OWN username,
    or nobody. Whatever username the caller put on the row is not read."""
    if account is None or account.pk is None:
        return governance.Person()
    return governance.Person(id=account.pk, username=(account.get_username() or "")[:150])


def _refuse(refusal: str | None, error=EconomicsRefused, detail: str = "") -> None:
    if refusal is not None:
        raise error(refusal, detail)


def _require_text(**fields) -> None:
    for name, value in fields.items():
        _refuse(governance.required_text_refusal(value), detail=name)


# ---------------------------------------------------------------------------
# FinancialSource -- one version of one data source a figure rests on
# ---------------------------------------------------------------------------


class FinancialSourceQuerySet(AppendOnlyQuerySet):
    def usable_for_production(self, deployment):
        """The versions a production run for ``deployment`` may use: the
        platform-wide sources and that deployment's own, and only those whose
        license class someone has reviewed. ``unreviewed`` (the default) is never
        among them, and another deployment's source never is. ``deployment=None``
        is a run for no deployment: platform-wide sources only."""
        reviewed = [c for c in _LICENSE_CODES if governance.production_use_refusal(c) is None]
        tenant = Q(deployment__isnull=True)
        if deployment is not None:
            tenant |= Q(deployment=deployment)
        return self.filter(tenant, license_class__in=reviewed)


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
    no other deployment's run may read. A platform-wide source is never licensed or
    trusted as ``customer`` data. Keys are per tenant: a deployment's source may use
    the key of a platform-wide one, and a run names a source by key AND deployment.

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
        max_length=32, choices=[(c, c) for c in _LICENSE_CODES], default=LicenseClass.UNREVIEWED.value
    )
    trust_tier = models.CharField(
        max_length=32, choices=[(t, t) for t in _TRUST_CODES], default=TrustTier.UNVERIFIED.value
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
        # The checks below touch no column a cascade or a SET_NULL writes, so no
        # stop's write can trip them.
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
            models.CheckConstraint(condition=Q(license_class__in=_LICENSE_CODES), name="ck_econ_source_license_class"),
            models.CheckConstraint(condition=Q(trust_tier__in=_TRUST_CODES), name="ck_econ_source_trust_tier"),
            models.CheckConstraint(
                condition=Q(deployment__isnull=False)
                | ~(Q(license_class=LicenseClass.CUSTOMER.value) | Q(trust_tier=TrustTier.CUSTOMER.value)),
                name="ck_econ_source_customer_has_tenant",
            ),
        ]
        indexes = [models.Index(fields=["deployment", "source_key"], name="assurance_econ_source_key")]

    def check_new(self) -> None:
        _require_text(
            source_key=self.source_key, provider=self.provider, dataset=self.dataset, schema_version=self.schema_version
        )
        _refuse(governance.code_refusal(self.license_class, _LICENSE_CODES), detail="license_class")
        _refuse(governance.code_refusal(self.trust_tier, _TRUST_CODES), detail="trust_tier")
        if self.deployment_id is None and (
            self.license_class == LicenseClass.CUSTOMER.value or self.trust_tier == TrustTier.CUSTOMER.value
        ):
            raise EconomicsRefused("customer_source_without_tenant")
        _refuse(governance.snapshot_hash_refusal(self.snapshot_hash), detail="snapshot_hash")
        if self.version is None:
            earlier = FinancialSource._base_manager.filter(
                deployment_id=self.deployment_id, source_key=self.source_key
            ).aggregate(latest=Max("version"))["latest"]
            self.version = (earlier or 0) + 1
        self.recorded_by_username = _signed_in(self.recorded_by).username

    def production_use_refusal(self, deployment) -> str | None:
        """``None`` when a production run for ``deployment`` may use this version;
        otherwise why not."""
        refusal = governance.production_use_refusal(self.license_class)
        if refusal is not None:
            return refusal
        if self.deployment_id is not None and self.deployment_id != getattr(deployment, "pk", deployment):
            return "cross_tenant_reference"
        return None

    def check_usable_for_production(self, deployment) -> None:
        """Raise :class:`SourceNotUsableForProduction` unless a production run for
        ``deployment`` may use this version. Called by the run before it reads it."""
        _refuse(self.production_use_refusal(deployment), SourceNotUsableForProduction)

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
        self.recorded_by_username = _signed_in(self.recorded_by).username

    def __str__(self) -> str:
        return f"{self.model_id} {self.version} r{self.revision}"


# ---------------------------------------------------------------------------
# FinancialScenario, ScenarioReview -- a reviewer authored no version
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
    :data:`~assurance.economics.engine.governance.REFERENCE_FORMS` -- for their form
    only -- and blank until known. A revised scenario is a new row that
    ``supersedes`` this one, in the same deployment; the versions it supersedes,
    transitively, are all its versions for the review rule.
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
    # Null when a machine drafted the version; see ScenarioReview.
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

    @classmethod
    def authors_of(cls, scenario_id) -> list[governance.Person]:
        """The author of every version of a scenario, as STORED: the version
        ``scenario_id`` names and each one it supersedes, transitively, read through
        the base manager so nothing in memory stands in for a row."""
        authors: list[governance.Person] = []
        seen: set = set()
        step = scenario_id
        while step is not None and step not in seen:
            seen.add(step)
            row = (
                cls._base_manager.filter(pk=step)
                .values_list("author_id", "author_username", "supersedes_id")
                .first()
            )
            if row is None:
                break
            author_id, username, step = row
            authors.append(governance.Person(id=author_id, username=username))
        return authors

    def check_new(self) -> None:
        _require_text(title=self.title)
        if self.system_fingerprint:
            _refuse(
                governance.spine_reference_refusal("system_fingerprint", self.system_fingerprint),
                detail="system_fingerprint",
            )
        if self.causal_effect:
            _refuse(governance.spine_reference_refusal("effect", self.causal_effect), detail="causal_effect")
        if self.supersedes_id is not None:
            stored = FinancialScenario._base_manager.filter(pk=self.supersedes_id).values_list(
                "deployment_id", flat=True
            )
            if list(stored) != [self.deployment_id]:
                raise EconomicsRefused("cross_tenant_reference", "supersedes")
        self.author_username = _signed_in(self.author).username

    def __str__(self) -> str:
        return f"scenario {self.title}"


class ReviewVerdict(models.TextChoices):
    APPROVED = "approved", "Approved"
    RETURNED = "returned", "Returned to the author"


class ScenarioReview(_AppendOnly):
    """One person's review of one scenario version.

    Written only by a signed-in account. The reviewer authored NO version of the
    scenario -- neither the one reviewed nor any it supersedes, transitively
    (``author_reviews_own_scenario``) -- matched on the account and on each
    version's recorded username, so a removed author is still the author. A line of
    versions none of which names an author (all machine-drafted) is not reviewable
    (``author_not_named``): a person authors a version first."""

    Verdict = ReviewVerdict

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
        constraints = [
            models.CheckConstraint(condition=Q(verdict__in=ReviewVerdict.values), name="ck_econ_review_verdict"),
        ]

    def check_new(self) -> None:
        _refuse(governance.code_refusal(self.verdict, self.Verdict.values), detail="verdict")
        reviewer = _signed_in(self.reviewer)
        self.reviewer_username = reviewer.username
        authors = FinancialScenario.authors_of(self.scenario_id)
        _refuse(governance.review_refusal(authors, reviewer), SeparationOfDutiesRefused)

    def __str__(self) -> str:
        return f"{self.verdict} review of scenario {self.scenario_id}"


# ---------------------------------------------------------------------------
# SensitiveOverride, OverrideApproval -- two different approvers
# ---------------------------------------------------------------------------


class SensitiveOverride(_AppendOnly):
    """A request to override something in a scenario -- a parameter, a computed
    value -- that is sensitive enough to need two approvers. Written only by a
    signed-in account.

    Recording the request puts nothing in force. It is in force only once two
    different people, neither of them the requester, have approved it
    (:meth:`approval_refusal`, ``override_needs_two_approvers``), and that is read
    from the stored rows each time it is asked, never stored.
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

    @classmethod
    def requester_of(cls, override_id) -> governance.Person:
        """Who asked for the override, as STORED."""
        row = (
            cls._base_manager.filter(pk=override_id).values_list("requested_by_id", "requested_by_username").first()
        )
        return governance.Person(id=row[0], username=row[1]) if row else governance.Person()

    @classmethod
    def approvers_of(cls, override_id) -> list[governance.Person]:
        """Everyone who has approved the override, as the stored approvals name them."""
        return [
            governance.Person(id=account_id, username=username)
            for account_id, username in OverrideApproval._base_manager.filter(override_id=override_id)
            .order_by("id")
            .values_list("approver_id", "approver_username")
        ]

    def approvers(self) -> list[governance.Person]:
        return self.approvers_of(self.pk)

    def approval_refusal(self) -> str | None:
        """``None`` when the override is in force; otherwise why it is not. Read
        from the stored rows, never from this instance's fields."""
        return governance.override_refusal(self.requester_of(self.pk), self.approvers_of(self.pk))

    @property
    def in_force(self) -> bool:
        return self.approval_refusal() is None

    def check_in_force(self) -> None:
        """Raise :class:`SeparationOfDutiesRefused` unless the override is in force.
        Called by whatever would apply it, before it does."""
        _refuse(self.approval_refusal(), SeparationOfDutiesRefused)

    def check_new(self) -> None:
        requester = _signed_in(self.requested_by)
        self.requested_by_username = requester.username
        _refuse(
            governance.override_request_refusal(requester, self.subject, self.reason),
            SeparationOfDutiesRefused,
        )

    def __str__(self) -> str:
        return f"sensitive override of {self.subject} on scenario {self.scenario_id}"


class OverrideApproval(_AppendOnly):
    """One person's approval of one sensitive override, written only by a signed-in
    account. The requester never approves their own override, and nobody approves
    the same override twice (checked on save, and by a unique constraint for two
    writes racing)."""

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
        approver = _signed_in(self.approver)
        self.approver_username = approver.username
        _refuse(
            governance.approval_refusal(
                SensitiveOverride.requester_of(self.override_id),
                SensitiveOverride.approvers_of(self.override_id),
                approver,
            ),
            SeparationOfDutiesRefused,
        )

    def __str__(self) -> str:
        return f"approval of override {self.override_id}"
