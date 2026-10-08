"""The Economic Exposure records: sources, the model inventory, and the scenario,
review and override records the separation rules are enforced on (phase E0); and
the FX and cost-index observations read from a source's snapshot (phase E1).

These are ``assurance`` models: :mod:`assurance.models` imports this module, so
Django files them under the ``assurance`` app and they migrate in
``assurance/migrations/``. Nothing serves them yet -- no route, command or signal
writes or reads one; the observations are written only by the snapshot loader an
operator runs (:mod:`assurance.economics.snapshots`). ``docs/economics/spec-v1.md``
(section 6) names each model's permitted writers.

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
from decimal import Context as DecimalContext
from decimal import Decimal, DecimalException

from django.conf import settings
from django.db import models, transaction
from django.db.models import F, Max, Q
from django.utils import timezone

from .engine import cost_index, formulas, fx, governance, money, parameters
from .engine import parameter_set as pset
from .engine import loss as engine_loss
from .engine.provenance import LicenseClass, SourceType, TrustTier

_LICENSE_CODES = [c.value for c in LicenseClass]
_TRUST_CODES = [t.value for t in TrustTier]
_RATE_TYPE_CODES = [t.value for t in fx.RateType]

#: What every refusal code means: the governance rules' (phase E0), the money,
#: FX and cost-index engine's (phase E1), and the scenario engine's (parameters,
#: formulas, loss events and the parameter set). A code two publish means the same.
_REFUSAL_TEXT = {**parameters.REFUSALS, **money.REFUSALS, **governance.REFUSALS}


class EconomicsRewriteRefused(ValueError):
    """A recorded economics row was asked to change or go away. The records are
    append-only: a change is a NEW row, and the one before it stays."""


class EconomicsRefused(ValueError):
    """A write one of the governance rules refuses, or one the money or scenario
    engine refuses. ``code`` is the rule's code
    (:data:`assurance.economics.engine.governance.REFUSALS`,
    :data:`assurance.economics.engine.money.REFUSALS` for an observation, or
    :data:`assurance.economics.engine.parameters.REFUSALS` for a parameter, a
    parameter set or a loss component); ``detail`` names the field, where one does."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {_REFUSAL_TEXT[code]}{suffix}")


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
        is a run for no deployment: platform-wide sources only. A synthetic source
        is never among them, whatever its licence."""
        reviewed = [c for c in _LICENSE_CODES if governance.production_use_refusal(c) is None]
        tenant = Q(deployment__isnull=True)
        if deployment is not None:
            tenant |= Q(deployment=deployment)
        return self.filter(tenant, license_class__in=reviewed, synthetic=False)


class FinancialSource(_AppendOnly):
    """One version of one data source: who publishes it, which dataset, where it was
    read from, on what terms, how far it is trusted, when it was retrieved, and the
    hash of the snapshot taken (specification, sections 10 and 15).

    ``source_key`` is the source's identity across versions; ``version`` counts from
    1 and is assigned on save when it is not given. A changed snapshot, license class
    or trust tier is a new version, and the older one stays as the record of what an
    earlier run read. In this phase every source is a committed fixture snapshot; no
    feed writes one. A source's FX and cost-index observations hang off its version
    (``fx_observations``, ``cost_index_observations``) and go with it.

    ``deployment`` is the tenant: empty for a platform-wide source (an official
    statistics series, a public price list), set for one customer's own data, which
    no other deployment's run may read. A platform-wide source is never licensed or
    trusted as ``customer`` data. Keys are per tenant: a deployment's source may use
    the key of a platform-wide one, and a run names a source by key AND deployment.

    ``license_class`` defaults to ``unreviewed``, and an unreviewed source is never
    used by a production run: :meth:`check_usable_for_production` refuses it, and
    :meth:`FinancialSourceQuerySet.usable_for_production` leaves it out.

    ``synthetic`` marks made-up test data, such as the committed fixture snapshot
    (set by :func:`assurance.economics.snapshots.register_snapshot` from the
    snapshot's own flag). A synthetic source is never used by a production run,
    whatever its licence (``synthetic_source``), and is never trusted above
    ``unverified`` (refused on save, and a check constraint).
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
    # Made-up test data: never used by a production run, never trusted above unverified.
    synthetic = models.BooleanField(default=False)
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
            models.CheckConstraint(
                condition=Q(synthetic=False) | Q(trust_tier=TrustTier.UNVERIFIED.value),
                name="ck_econ_source_synthetic_unverified",
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
        if self.synthetic is not False and self.trust_tier != TrustTier.UNVERIFIED.value:
            raise EconomicsRefused("synthetic_source", "trust_tier")
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
        refusal = governance.production_use_refusal(self.license_class, synthetic=self.synthetic)
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


# ---------------------------------------------------------------------------
# FXObservation, CostIndexObservation -- what a source's snapshot holds (E1)
# ---------------------------------------------------------------------------

#: Each decimal column's exact capacity: digits in all, and digits after the
#: point. Django keeps a decimal on SQLite (this service's database) to 15
#: significant digits, so no column holds more, and a value a column cannot hold
#: EXACTLY is refused (``value_precision``), never rounded to fit.
RATE_DIGITS, RATE_PLACES = 15, 9
INDEX_DIGITS, INDEX_PLACES = 15, 6


def _fits(value: Decimal, digits: int, places: int) -> bool:
    """Whether a column of ``digits`` digits, ``places`` of them after the point,
    holds ``value`` exactly."""
    try:
        held = value.quantize(Decimal(1).scaleb(-places), context=DecimalContext(prec=digits))
    except (DecimalException, TypeError, AttributeError):
        return False
    return held == value


def _engine_refusal(build):
    """Build the engine's object for a row, and refuse the row with the engine's
    code if the engine refuses it."""
    try:
        return build()
    except money.MoneyRefused as refused:
        raise EconomicsRefused(refused.code, refused.detail) from None


class FXObservation(_AppendOnly):
    """One exchange rate read from a source version's snapshot: ``1 base = rate
    quote``, its rate type (``reference``, ``mid``, ``bid`` or ``ask``), its provider,
    when it was observed, the date it is the rate for, and the snapshot hash
    (specification, section 15).

    The pure contract is :class:`assurance.economics.engine.fx.FXRate`, and a row is
    refused on save unless it makes one -- a rate that is not a ``Decimal`` (a float),
    NaN or Infinity, zero or negative; a code the currency table does not hold, or
    one with no minor unit; a pair of one code; an unknown rate type; a naive
    instant -- with the engine's code. It is refused too unless its
    ``source_snapshot_hash`` is its source version's own (``snapshot_hash_mismatch``),
    and unless the column holds its rate exactly (``value_precision``).

    It goes with its source, which goes with its deployment. A corrected rate is a
    new snapshot: a new source version, and new rows."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    source = models.ForeignKey(FinancialSource, on_delete=models.CASCADE, related_name="fx_observations")
    base_currency = models.CharField(max_length=3)
    quote_currency = models.CharField(max_length=3)
    rate = models.DecimalField(max_digits=RATE_DIGITS, decimal_places=RATE_PLACES)
    rate_type = models.CharField(max_length=16, choices=[(t, t) for t in _RATE_TYPE_CODES])
    provider = models.CharField(max_length=200)
    observed_at = models.DateTimeField()
    effective_date = models.DateField()
    # "sha256:" + 64 hex: the snapshot the rate was read from, equal to its source's.
    source_snapshot_hash = models.CharField(max_length=71)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["source", "provider", "base_currency", "quote_currency", "rate_type", "effective_date", "id"]
        verbose_name = "FX observation"
        constraints = [
            models.UniqueConstraint(
                fields=["source", "provider", "base_currency", "quote_currency", "rate_type", "effective_date"],
                name="uq_econ_fx_observation",
            ),
            models.CheckConstraint(condition=Q(rate__gt=0), name="ck_econ_fx_rate_positive"),
            models.CheckConstraint(condition=Q(rate_type__in=_RATE_TYPE_CODES), name="ck_econ_fx_rate_type"),
            models.CheckConstraint(condition=~Q(base_currency=F("quote_currency")), name="ck_econ_fx_pair"),
        ]
        indexes = [
            models.Index(fields=["base_currency", "quote_currency", "effective_date"], name="assurance_econ_fx_pair_day")
        ]

    def as_engine(self) -> fx.FXRate:
        """The row as the engine reads it, with its source version named."""
        source = self.source if self.source_id is not None else None
        return fx.FXRate(
            base=self.base_currency,
            quote=self.quote_currency,
            rate=self.rate,
            rate_type=self.rate_type,
            provider=self.provider,
            observed_at=self.observed_at,
            effective_date=self.effective_date,
            source_snapshot_hash=self.source_snapshot_hash,
            source_key=source.source_key if source else "",
            source_version=source.version if source else None,
        )

    def check_new(self) -> None:
        _engine_refusal(self.as_engine)
        if not _fits(self.rate, RATE_DIGITS, RATE_PLACES):
            raise EconomicsRefused("value_precision", f"rate {self.rate}")
        stored = FinancialSource._base_manager.filter(pk=self.source_id).values_list("snapshot_hash", flat=True)
        if list(stored) != [self.source_snapshot_hash]:
            raise EconomicsRefused("snapshot_hash_mismatch")

    def __str__(self) -> str:
        return f"{self.base_currency}/{self.quote_currency} {self.rate} {self.rate_type} on {self.effective_date}"


class CostIndexObservation(_AppendOnly):
    """One published value of one cost-index series, read from a source version's
    snapshot: series id, geography, category, the base its values are expressed on
    (``2020-03=100``), period (a month, ``YYYY-MM``), value, and the date that
    vintage was published (specification, sections 13 and 15).

    The pure contract is :class:`assurance.economics.engine.cost_index.IndexPoint`,
    and a row is refused on save unless it makes one -- a value that is not a
    ``Decimal``, NaN, zero or negative; a malformed period; a vintage published
    before its period began (``date_inversion``) -- with the engine's code; unless
    the column holds its value exactly (``value_precision``); and unless its series
    is the one geography, category and base it already is in this source
    (``index_series_mismatch``), so a ratio never divides one base by another. It
    goes with its source."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    source = models.ForeignKey(FinancialSource, on_delete=models.CASCADE, related_name="cost_index_observations")
    series_id = models.CharField(max_length=100)
    geography = models.CharField(max_length=32)
    category = models.CharField(max_length=200)
    base = models.CharField(max_length=64)
    period = models.CharField(max_length=7)
    value = models.DecimalField(max_digits=INDEX_DIGITS, decimal_places=INDEX_PLACES)
    vintage_date = models.DateField()
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["source", "series_id", "period", "vintage_date", "id"]
        verbose_name = "cost index observation"
        constraints = [
            models.UniqueConstraint(
                fields=["source", "series_id", "period", "vintage_date"], name="uq_econ_cost_index_observation"
            ),
            models.CheckConstraint(condition=Q(value__gt=0), name="ck_econ_cost_index_positive"),
        ]

    def as_engine(self) -> cost_index.IndexPoint:
        """The row as the engine reads it, with its source version and snapshot named."""
        source = self.source if self.source_id is not None else None
        return cost_index.IndexPoint(
            series_id=self.series_id,
            geography=self.geography,
            category=self.category,
            base=self.base,
            period=self.period,
            value=self.value,
            vintage_date=self.vintage_date,
            source_snapshot_hash=source.snapshot_hash if source else "",
            source_key=source.source_key if source else "",
            source_version=source.version if source else None,
        )

    def check_new(self) -> None:
        _engine_refusal(self.as_engine)
        if not _fits(self.value, INDEX_DIGITS, INDEX_PLACES):
            raise EconomicsRefused("value_precision", f"value {self.value}")
        other = (
            CostIndexObservation._base_manager.filter(source_id=self.source_id, series_id=self.series_id)
            .exclude(geography=self.geography, category=self.category, base=self.base)
            .exists()
        )
        if other:
            raise EconomicsRefused("index_series_mismatch", self.series_id)

    def __str__(self) -> str:
        return f"{self.series_id} {self.period} = {self.value} (vintage {self.vintage_date})"


# ---------------------------------------------------------------------------
# CustomerParameterSet, FinancialParameter, LossEvent, LossComponent: the
# scenario parameters, loss events and components (spec, sections 14 to 20)
# ---------------------------------------------------------------------------

_UNIT_CODES = [u.value for u in parameters.Unit]
_SOURCE_TYPE_CODES = [t.value for t in SourceType]
_COMPONENT_FAMILY_CODES = sorted(formulas.COMPONENT_FAMILIES)
_COMPONENT_STATUS_CODES = [formulas.ESTIMATED, formulas.UNKNOWN]
#: The width of every key column (a set key, an event key, a component key).
_KEY_MAX = 100


def _key(value, field: str) -> None:
    """A key: text, not blank, at most :data:`_KEY_MAX` characters."""
    _refuse(governance.required_text_refusal(value), detail=field)
    if len(value) > _KEY_MAX:
        raise EconomicsRefused("field_malformed", f"{field} is longer than {_KEY_MAX}")


class CustomerParameterSet(_AppendOnly):
    """One version of one deployment's customer parameter set: the customer's own
    figures, the thirty variables of :data:`~assurance.economics.engine.pset.VARIABLES`
    with their units, the per-family insurance sublimits and the excluded
    families (specification, section 14; spec, section 19).

    Deployment-scoped and versioned: ``set_key`` names the set within its
    deployment (``bank_prod_2026q4``, as the specification's scenario request
    names one), ``version`` counts from 1 per deployment and key and is assigned on
    save, and the highest version is the current one. A change is a new version;
    no version is edited. ``author`` is the signed-in account that recorded it,
    with its own username (null only for a version a machine recorded, which no
    route does in this phase).

    A version's figures are its :class:`FinancialParameter` rows, written with it
    in one transaction by :meth:`record`. ``variable_count`` and ``content_digest``
    are taken from the validated document before any row is written; nothing may
    add a parameter to a recorded version (``parameter_set_sealed``), and
    :meth:`intact` re-reads the rows and compares their digest.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor (related_name "+"), here and on every foreign key of the
    # scenario records: a related manager's add(), set(), remove() and clear() write
    # through the base manager's update, past the append-only refusals, and could
    # move a recorded row to another parent, even another deployment's. The rows
    # are read by filtering, and the cascade from the deployment still reaches them.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    set_key = models.SlugField(max_length=_KEY_MAX)
    version = models.PositiveIntegerField()
    schema_version = models.CharField(max_length=64, default=pset.SCHEMA_VERSION)
    # The excluded families, sorted: the one part of a version that is not a parameter.
    insurance_exclusions = models.JSONField(default=list, blank=True)
    variable_count = models.PositiveIntegerField()
    # "sha256:" + 64 hex over the version's canonical document.
    content_digest = models.CharField(max_length=71)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_parameter_sets_authored",
    )
    author_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "set_key", "version", "id"]
        # No check below names the author column, which removing an operator nulls.
        constraints = [
            models.UniqueConstraint(fields=["deployment", "set_key", "version"], name="uq_econ_parameter_set_version"),
            models.CheckConstraint(condition=Q(version__gte=1), name="ck_econ_parameter_set_version_positive"),
            models.CheckConstraint(condition=Q(variable_count__gte=1), name="ck_econ_parameter_set_not_empty"),
        ]
        indexes = [models.Index(fields=["deployment", "set_key"], name="assurance_econ_pset_key")]

    @classmethod
    def record(cls, deployment, set_key: str, document, *, author=None) -> CustomerParameterSet:
        """Record the next version of ``deployment``'s set ``set_key`` from
        ``document`` (:func:`~assurance.economics.engine.pset.parse_document`),
        with every parameter it holds, in one transaction. Refused whole, with the
        engine's code, or written whole."""
        _engine_refusal(lambda: pset.check_set_key(set_key))
        content = _engine_refusal(lambda: pset.parse_document(document))
        rows = content.parameters()
        with transaction.atomic():
            version = cls.objects.create(
                deployment=deployment,
                set_key=set_key,
                insurance_exclusions=list(content.exclusions),
                variable_count=len(rows),
                content_digest=content.digest(),
                author=author,
            )
            for parameter in rows:
                FinancialParameter.from_engine(parameter, parameter_set=version).save()
        return version

    @classmethod
    def current(cls, deployment, set_key: str) -> CustomerParameterSet | None:
        """The highest recorded version of ``deployment``'s set ``set_key``."""
        return cls.objects.filter(deployment=deployment, set_key=set_key).order_by("-version").first()

    def check_new(self) -> None:
        _engine_refusal(lambda: pset.check_set_key(self.set_key))
        if self.schema_version != pset.SCHEMA_VERSION:
            raise EconomicsRefused("code_unrecognised", "schema_version")
        exclusions = self.insurance_exclusions
        if not isinstance(exclusions, list):
            raise EconomicsRefused("field_malformed", "insurance_exclusions is not a list")
        for family in exclusions:
            if not isinstance(family, str) or family not in formulas.CASH_FAMILIES:
                raise EconomicsRefused("loss_family_unrecognised", f"insurance_exclusions {family!r}")
        if len(set(exclusions)) != len(exclusions):
            raise EconomicsRefused("duplicate_id", "insurance_exclusions names a family twice")
        self.insurance_exclusions = sorted(exclusions)
        if type(self.variable_count) is not int or self.variable_count < 1:
            raise EconomicsRefused("field_missing", "variables: a version holds at least one variable")
        _refuse(governance.snapshot_hash_refusal(self.content_digest), detail="content_digest")
        if self.version is None:
            earlier = CustomerParameterSet._base_manager.filter(
                deployment_id=self.deployment_id, set_key=self.set_key
            ).aggregate(latest=Max("version"))["latest"]
            self.version = (earlier or 0) + 1
        self.author_username = _signed_in(self.author).username

    def parameter_rows(self) -> list[FinancialParameter]:
        """The version's parameters, as stored."""
        return list(FinancialParameter._base_manager.filter(parameter_set_id=self.pk).order_by("name", "id"))

    def content(self, rows: list[FinancialParameter] | None = None) -> pset.ParameterSetContent:
        """The version's content, read back from its rows."""
        rows = self.parameter_rows() if rows is None else rows
        return _engine_refusal(
            lambda: pset.content_of([row.as_engine() for row in rows], self.insurance_exclusions)
        )

    def intact(self, rows: list[FinancialParameter] | None = None) -> bool:
        """Whether the stored rows are exactly the version that was recorded: as many
        as it was recorded with, and the same digest."""
        rows = self.parameter_rows() if rows is None else rows
        return len(rows) == self.variable_count and self.content(rows).digest() == self.content_digest

    def as_dict(self, *, current_version: int | None = None) -> dict:
        """The version as the parameter-set API serves it."""
        rows = self.parameter_rows()
        content = self.content(rows)

        def entry(parameter: parameters.Parameter, schema: dict) -> dict:
            row = parameter.as_dict()
            del row["name"]
            return {**schema, **row}

        return {
            "set_key": self.set_key,
            "version": self.version,
            "current": current_version is not None and self.version == current_version,
            "schema": self.schema_version,
            "author": self.author_username or None,
            "recorded_at": self.recorded_at.isoformat(),
            "content_digest": self.content_digest,
            "intact": len(rows) == self.variable_count and content.digest() == self.content_digest,
            "variables": {
                name: entry(p, pset.VARIABLES[name].as_dict()) for name, p in content.variables.items()
            },
            "insurance_sublimits": {
                family: entry(p, {"unit": parameters.Unit.MONEY.value}) for family, p in content.sublimits.items()
            },
            "insurance_exclusions": list(content.exclusions),
        }

    def __str__(self) -> str:
        return f"parameter set {self.set_key} v{self.version}"


class FinancialParameter(_AppendOnly):
    """One financial parameter: a name, a unit, a ``source_type``, a low, base and
    high value (a decimal string in the one spelling; money in ``currency``), the
    evidence it rests on, the date it holds from and, where its source says, the
    last date it is fresh (specification, section 15).

    It belongs to exactly one parent (``parent_required``, and a check
    constraint): a scenario version, or a customer parameter-set version, whose
    deployment is its tenant. A parameter-set version's parameters are its
    variables, each with the unit its schema gives (``unit_mismatch``), and none is
    added after the version is recorded (``parameter_set_sealed``). Every row is
    refused on save unless it makes an engine
    :class:`~assurance.economics.engine.parameters.Parameter`, with the engine's
    code; its values are stored in the one decimal spelling, never as a float.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    parameter_set = models.ForeignKey(
        CustomerParameterSet, on_delete=models.CASCADE, null=True, blank=True, related_name="+"
    )
    name = models.CharField(max_length=_KEY_MAX)
    unit = models.CharField(max_length=32, choices=[(u, u) for u in _UNIT_CODES])
    source_type = models.CharField(max_length=32, choices=[(t, t) for t in _SOURCE_TYPE_CODES])
    # Blank for a quantity; the ISO 4217 code of a money parameter.
    currency = models.CharField(max_length=3, blank=True)
    # Decimal strings in the one spelling (spec, section 12.6): exact at any width,
    # where a decimal column on SQLite keeps 15 significant digits.
    low = models.TextField()
    base = models.TextField()
    high = models.TextField()
    evidence_ref = models.CharField(max_length=pset.EVIDENCE_REF_MAX)
    effective_date = models.DateField()
    fresh_until = models.DateField(null=True, blank=True)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.CheckConstraint(
                condition=(Q(scenario__isnull=False) & Q(parameter_set__isnull=True))
                | (Q(scenario__isnull=True) & Q(parameter_set__isnull=False)),
                name="ck_econ_parameter_one_parent",
            ),
            models.UniqueConstraint(
                fields=["scenario", "name"], condition=Q(scenario__isnull=False), name="uq_econ_parameter_scenario_name"
            ),
            models.UniqueConstraint(
                fields=["parameter_set", "name"],
                condition=Q(parameter_set__isnull=False),
                name="uq_econ_parameter_set_name",
            ),
            models.CheckConstraint(condition=Q(unit__in=_UNIT_CODES), name="ck_econ_parameter_unit"),
            models.CheckConstraint(condition=Q(source_type__in=_SOURCE_TYPE_CODES), name="ck_econ_parameter_source_type"),
        ]

    @classmethod
    def from_engine(cls, parameter: parameters.Parameter, *, scenario=None, parameter_set=None) -> FinancialParameter:
        """An unsaved row holding ``parameter``, for ``scenario`` or ``parameter_set``."""
        return cls(
            scenario=scenario,
            parameter_set=parameter_set,
            name=parameter.name,
            unit=parameter.unit.value,
            source_type=parameter.source_type.value,
            currency=parameter.currency or "",
            low=parameters.Parameter.text(parameter.low),
            base=parameters.Parameter.text(parameter.base),
            high=parameters.Parameter.text(parameter.high),
            evidence_ref=parameter.evidence_ref,
            effective_date=parameter.effective_date,
            fresh_until=parameter.fresh_until,
        )

    @classmethod
    def deployment_of(cls, pk) -> int | None:
        """The deployment a stored parameter belongs to, through its parent."""
        row = (
            cls._base_manager.filter(pk=pk)
            .values_list("scenario__deployment_id", "parameter_set__deployment_id")
            .first()
        )
        if row is None:
            return None
        return row[0] if row[0] is not None else row[1]

    def as_engine(self) -> parameters.Parameter:
        """The row as the engine reads it, its uuid as the parameter's id."""
        unit = parameters.check_unit(self.unit)
        if unit in parameters.MONEY_UNITS:

            def value(text, point):
                return money.Money(money.parse_decimal(text, f"{self.name} {point}"), self.currency)

        else:
            if self.currency:
                raise parameters.ParameterRefused("unit_mismatch", f"{self.name} is {unit}, a quantity, with a currency")

            def value(text, point):
                return money.parse_decimal(text, f"{self.name} {point}")

        return parameters.Parameter(
            name=self.name,
            unit=unit,
            source_type=self.source_type,
            low=value(self.low, "low"),
            base=value(self.base, "base"),
            high=value(self.high, "high"),
            evidence_ref=self.evidence_ref,
            effective_date=self.effective_date,
            fresh_until=self.fresh_until,
            parameter_id=str(self.uuid),
        )

    def check_new(self) -> None:
        if (self.scenario_id is None) == (self.parameter_set_id is None):
            raise EconomicsRefused("parent_required")
        if self.effective_date is None:
            raise EconomicsRefused("date_malformed", f"{self.name} has no effective_date")
        if isinstance(self.evidence_ref, str) and len(self.evidence_ref) > pset.EVIDENCE_REF_MAX:
            raise EconomicsRefused("field_malformed", f"{self.name} evidence_ref is longer than its column")
        if isinstance(self.name, str) and len(self.name) > _KEY_MAX:
            raise EconomicsRefused("field_malformed", f"a parameter name is longer than {_KEY_MAX}")
        engine = _engine_refusal(self.as_engine)
        # Stored in the one spelling: "1.10" and "1.1" are one value, written once.
        self.low, self.base, self.high = (parameters.Parameter.text(engine.at(p)) for p in parameters.POINTS)
        if self.parameter_set_id is not None:
            expected = _engine_refusal(lambda: pset.variable_unit(self.name))
            if engine.unit is not expected:
                raise EconomicsRefused("unit_mismatch", f"the parameter set's {self.name} is {expected}")
            sealed = CustomerParameterSet._base_manager.filter(pk=self.parameter_set_id).values_list(
                "variable_count", flat=True
            )
            held = FinancialParameter._base_manager.filter(parameter_set_id=self.parameter_set_id).count()
            if not sealed or held >= sealed[0]:
                raise EconomicsRefused("parameter_set_sealed", f"set version {self.parameter_set_id}")
        parent = (
            FinancialParameter._base_manager.filter(scenario_id=self.scenario_id)
            if self.scenario_id is not None
            else FinancialParameter._base_manager.filter(parameter_set_id=self.parameter_set_id)
        )
        if parent.filter(name=self.name).exists():
            raise EconomicsRefused("duplicate_id", f"parameter {self.name!r} twice in one parent")

    def __str__(self) -> str:
        return f"parameter {self.name} ({self.unit})"


class LossEvent(_AppendOnly):
    """One causal loss event of a scenario version: the scenario that creates a
    financial consequence (specification, sections 6 and 15). Its key is unique
    within the scenario (``duplicate_id``), its effect is named as SPINE names one
    (``sha256:`` + hex, checked for form), and every component of it is in its
    ``currency``. Components are :class:`LossComponent` rows."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor: see CustomerParameterSet.deployment.
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    event_key = models.SlugField(max_length=_KEY_MAX)
    currency = models.CharField(max_length=3)
    effect = models.CharField(max_length=71, blank=True)
    business_process = models.CharField(max_length=200, blank=True)
    trigger = models.CharField(max_length=200, blank=True)
    correlation_group = models.CharField(max_length=_KEY_MAX, blank=True)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]
        constraints = [models.UniqueConstraint(fields=["scenario", "event_key"], name="uq_econ_loss_event_key")]

    def check_new(self) -> None:
        _key(self.event_key, "event_key")
        _engine_refusal(lambda: money.check_reporting_currency(self.currency, "event currency"))
        if self.effect:
            _refuse(governance.spine_reference_refusal("effect", self.effect), detail="effect")
        if LossEvent._base_manager.filter(scenario_id=self.scenario_id, event_key=self.event_key).exists():
            raise EconomicsRefused("duplicate_id", f"event {self.event_key!r} twice in one scenario")

    def deployment_id_of(self) -> int | None:
        return FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("deployment_id", flat=True).first()

    def as_engine(self) -> engine_loss.LossEvent:
        """The event as the engine reads it, its components recomputed from the rows
        they cite."""
        rows = LossComponent._base_manager.filter(loss_event_id=self.pk).order_by("id")
        return _engine_refusal(
            lambda: engine_loss.LossEvent(self.event_key, self.currency, tuple(row.as_engine() for row in rows))
        )

    def __str__(self) -> str:
        return f"loss event {self.event_key}"


class LossComponent(_AppendOnly):
    """One component of one loss event: its loss family (or ``market_value``), the
    formula id and version that computes it, the as-of date, and the parameters it
    cites, by formula input (specification, section 15).

    The amounts are never taken from the caller. On save, the row's formula is
    evaluated from the cited parameters, as stored, and the status, currency, low,
    base and high, or the unknown reason and the missing inputs, are written from
    that result: a component is ``unknown``, with no amount, when an input is not
    cited. Every cited parameter is a recorded one (``parameter_not_found``) of the
    event's own deployment (``cross_tenant_reference``): the scenario's, or one of
    the deployment's parameter sets. Stored components are gross of insurance
    (``insurance_treatment``, a check constraint); insurance is applied once, when
    an event is assessed.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor: see CustomerParameterSet.deployment.
    loss_event = models.ForeignKey(LossEvent, on_delete=models.CASCADE, related_name="+")
    component_key = models.SlugField(max_length=_KEY_MAX)
    family = models.CharField(max_length=32, choices=[(f, f) for f in _COMPONENT_FAMILY_CODES])
    formula_id = models.CharField(max_length=64)
    formula_version = models.PositiveIntegerField()
    as_of = models.DateField()
    # {formula input name: the cited FinancialParameter's uuid}
    cited_parameters = models.JSONField(default=dict)
    status = models.CharField(max_length=16, choices=[(s, s) for s in _COMPONENT_STATUS_CODES], editable=False)
    currency = models.CharField(max_length=3, blank=True, editable=False)
    low = models.TextField(blank=True, editable=False)
    base = models.TextField(blank=True, editable=False)
    high = models.TextField(blank=True, editable=False)
    unknown_reason = models.CharField(max_length=32, blank=True, editable=False)
    missing_inputs = models.JSONField(default=list, editable=False)
    insurance_treatment = models.CharField(max_length=16, default=formulas.GROSS, editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["loss_event", "id"]
        constraints = [
            models.UniqueConstraint(fields=["loss_event", "component_key"], name="uq_econ_loss_component_key"),
            models.CheckConstraint(condition=Q(family__in=_COMPONENT_FAMILY_CODES), name="ck_econ_component_family"),
            models.CheckConstraint(condition=Q(status__in=_COMPONENT_STATUS_CODES), name="ck_econ_component_status"),
            models.CheckConstraint(condition=Q(insurance_treatment=formulas.GROSS), name="ck_econ_component_gross"),
        ]

    def _bindings(self, deployment_id) -> dict[str, parameters.Parameter]:
        cited = self.cited_parameters
        if not isinstance(cited, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in cited.items()):
            raise EconomicsRefused("field_malformed", "cited_parameters maps a formula input to a parameter's uuid")
        wanted = {}
        for name, value in cited.items():
            try:
                wanted[name] = uuid.UUID(value)
            except ValueError:
                raise EconomicsRefused("parameter_not_found", f"{name}: {value!r}") from None
        rows = {row.uuid: row for row in FinancialParameter._base_manager.filter(uuid__in=list(wanted.values()))}
        bindings = {}
        for name, key in wanted.items():
            row = rows.get(key)
            if row is None:
                raise EconomicsRefused("parameter_not_found", f"{name}: {key}")
            if FinancialParameter.deployment_of(row.pk) != deployment_id:
                raise EconomicsRefused("cross_tenant_reference", f"{name} cites another deployment's parameter")
            bindings[name] = _engine_refusal(row.as_engine)
        return bindings

    def _evaluate(self):
        event = LossEvent._base_manager.filter(pk=self.loss_event_id).values_list("currency", "scenario_id").first()
        if event is None:
            raise EconomicsRefused("parameter_not_found", "the component's loss event is not recorded")
        currency, scenario_id = event
        deployment_id = FinancialScenario._base_manager.filter(pk=scenario_id).values_list(
            "deployment_id", flat=True
        ).first()
        bindings = self._bindings(deployment_id)
        component = _engine_refusal(
            lambda: formulas.evaluate(
                self.component_key, self.family, self.formula_id, self.formula_version, bindings, as_of=self.as_of
            )
        )
        if component.currency is not None and component.currency != currency:
            raise EconomicsRefused(
                "currency_mismatch", f"the component is in {component.currency}; its event is in {currency}"
            )
        return component

    def as_engine(self) -> formulas.LossComponent:
        """The component recomputed from the rows it cites."""
        return self._evaluate()

    def check_new(self) -> None:
        _key(self.component_key, "component_key")
        if LossComponent._base_manager.filter(
            loss_event_id=self.loss_event_id, component_key=self.component_key
        ).exists():
            raise EconomicsRefused("duplicate_id", f"component {self.component_key!r} twice in one event")
        component = self._evaluate()
        estimated = component.status == formulas.ESTIMATED
        self.status = component.status
        self.currency = component.currency or ""
        self.low, self.base, self.high = (
            (parameters.Parameter.text(component.at(p)) for p in parameters.POINTS) if estimated else ("", "", "")
        )
        self.unknown_reason = component.unknown_reason or ""
        self.missing_inputs = list(component.missing)
        self.insurance_treatment = formulas.GROSS

    def __str__(self) -> str:
        return f"{self.family} component {self.component_key} ({self.status})"
