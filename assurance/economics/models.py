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

import base64
import binascii
import hashlib
import json
import re
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
#: The codes a stored simulation result is refused with on save (spec, section 25.6).
SIMULATION_RECORD_REFUSALS = {
    "result_malformed": (
        "a simulation result names its seed (a whole number from 0 to 2^64 - 1, as text), its draws, its "
        "digests, and either a completed record or a refusal code, never both; no number in it is a float"
    ),
    "digest_mismatch": (
        "a simulation result's input digest is the SHA-256 of its canonical inputs, and its result digest the "
        "SHA-256 of its canonical record"
    ),
}
_REFUSAL_TEXT.update(SIMULATION_RECORD_REFUSALS)
#: The codes a Validity Card or a Financial Exposure Receipt row is refused with on
#: save (spec, section 26.6).
CARD_RECORD_REFUSALS = {
    "card_record_malformed": (
        "a Validity Card row holds the card of its own simulation result: an object naming that result's scenario "
        "and the grade the row names, with no float in it, its digest the card's, and its sensitivity analysis the "
        "one its digest names"
    ),
    "receipt_record_malformed": (
        "a receipt row holds a schema-valid mythos.financial-exposure-receipt/v1 document naming its own card, "
        "scenario and tenant, and the DSSE envelope signed over exactly that document; and it receipts a scenario's "
        "own run, never a residual run under a remediation option, which is not the scenario's exposure"
    ),
}
_REFUSAL_TEXT.update(CARD_RECORD_REFUSALS)
#: The code a stored chart series is refused with on save (spec, section 27.4).
CHARTS_RECORD_REFUSALS = {
    "charts_record_malformed": (
        "a chart-series row holds the series of its own completed simulation result: an object naming that "
        "result's scenario, seed, draws, input digest and outcomes digest, with no float in it and its digest the "
        "series'"
    ),
}
_REFUSAL_TEXT.update(CHARTS_RECORD_REFUSALS)
#: The codes a remediation option row is refused with on save (spec, section 28).
REMEDIATION_RECORD_REFUSALS = {
    "remediation_record_malformed": (
        "a remediation option row holds its option's document in the one spelling, held to every rule of its form; "
        "its digest the document's for its scenario version; and its title, currency, days and citations the "
        "document's"
    ),
    "remediation_option_held": (
        "a scenario version holds ONE remediation option: another option is a new scenario version that supersedes "
        "it, append-only"
    ),
}
_REFUSAL_TEXT.update(REMEDIATION_RECORD_REFUSALS)
#: The codes a stored portfolio result, or a correlation group version, is refused
#: with on save (spec, section 31).
PORTFOLIO_RECORD_REFUSALS = {
    "portfolio_record_malformed": (
        "a portfolio result names its seed (a whole number from 0 to 2^64 - 1, as text), its draws, its reporting "
        "currency and valuation date, its digests, and either a completed record of its own inputs, seed and draws "
        "or a refusal code, never both; no number in it is a float"
    ),
    "group_record_malformed": (
        "a correlation group version names a key of 1 to 60 lowercase letters, digits, '-' and '_', a strength from "
        "0.000001 to 10 in its one spelling, a source type, its evidence (1 to 500 characters), and 2 to 50 of its "
        "deployment's scenario versions, in order, each once"
    ),
}
_REFUSAL_TEXT.update(PORTFOLIO_RECORD_REFUSALS)


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


class EngineRefused(EconomicsRefused):
    """A write the probabilistic engine refuses (a stated distribution): its code
    and meaning are the engine's, which this module never imports at load time
    (spec, section 23.10), so the meaning travels with the refusal."""

    def __init__(self, code: str, meaning: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        ValueError.__init__(self, f"{code}: {meaning}{suffix}")


class SeparationOfDutiesRefused(EconomicsRefused):
    """An author of any version reviewing a scenario, a review, request or approval
    with no account behind it, a requester approving their own override, a second
    approval from the same person, or an override read as in force without two
    different approvers."""


class SourceNotUsableForProduction(EconomicsRefused):
    """A production run asked to use a source whose license nobody has reviewed, a
    synthetic source, another deployment's source, or (a run that
    :func:`runs_in_production`) a source still trusted as ``unverified``."""


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

    def _insert_checked(self) -> None:
        """Insert a new row of a scenario build whose checks :func:`check_build_rows`
        already ran, whole, before the build's transaction: an INSERT, never an
        UPDATE, and nothing read. Any other row is refused."""
        if not self._state.adding or getattr(self, "_build_checked", None) is not _CHECKED:
            raise EconomicsRewriteRefused("A build's rows are checked whole before any is written.")
        super().save(force_insert=True)

    def _insert_as_checked(self) -> None:
        """An INSERT of a row its own class checked whole just before (a
        :class:`SimulationResult`, by :meth:`SimulationResult.insert_checked`):
        never an UPDATE, and nothing read."""
        super().save(force_insert=True)

    def _mark_checked(self) -> None:
        """Record that every check of this new row ran on exactly its present values
        (:meth:`CustomerParameterSet.check_rows`)."""
        self._checked_as = _checked_state(self)

    def _insert_as_marked(self) -> None:
        """An INSERT of a row marked checked (:meth:`_mark_checked`), unchanged since:
        never an UPDATE, and nothing read or computed. A row not checked, or changed
        since its check, is refused."""
        if not self._state.adding or getattr(self, "_checked_as", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A parameter-set version is checked whole, then inserted unchanged.")
        super().save(force_insert=True)


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


#: The deployment environments (``assurance.models.Deployment.Environment``, spelled
#: here: that module imports this one) whose runs are not production runs. Every
#: other -- ``production``, the default, and ``other``, which says nothing of whether
#: the system serves customers -- is held as production.
NON_PRODUCTION_ENVIRONMENTS = ("dev", "staging")


#: Set on a :class:`FinancialSource` instance by :meth:`FinancialSourceTrustRaise.approve`
#: alone (through :func:`_raised_version`), never from anything a caller passes: the
#: one way an ``authoritative`` version is recorded. ``check_new`` refuses one without
#: it (``second_person_required``), so a plain save, the snapshot loader and any other
#: writer through the model never record that tier.
_SECOND_ADMIN_APPROVED = object()


def runs_in_production(deployment) -> bool:
    """Whether a run for ``deployment`` (a deployment, its primary key, or ``None``)
    is a production run, which never relies on a source still at trust tier
    ``unverified`` (``source_unverified``; the owner's decision of 12 Oct 2026).

    The deployment's STORED environment decides, never the caller's object: a run
    for a deployment recorded as ``dev`` or ``staging`` is not a production run and
    keeps the gate as it was (licence, synthetic data, tenancy). Anything else is:
    a deployment in ``production`` (the default) or ``other``, one that is not
    recorded, and a run for no deployment (``None``, platform-wide sources only). So
    the rule is off only where a deployment is recorded as non-production."""
    if deployment is None:
        return True
    model = FinancialSource._meta.get_field("deployment").related_model
    environment = (
        model._base_manager.filter(pk=getattr(deployment, "pk", deployment)).values_list("environment", flat=True).first()
    )
    return environment not in NON_PRODUCTION_ENVIRONMENTS


class FinancialSourceQuerySet(AppendOnlyQuerySet):
    def usable_for_production(self, deployment):
        """The versions a production run for ``deployment`` may use: the
        platform-wide sources and that deployment's own, and only those whose
        license class someone has reviewed. ``unreviewed`` (the default) is never
        among them, and another deployment's source never is. ``deployment=None``
        is a run for no deployment: platform-wide sources only. A synthetic source
        is never among them, whatever its licence. Where the run is a production
        one (:func:`runs_in_production`), a source still trusted as ``unverified``
        (the default) is not among them either."""
        reviewed = [c for c in _LICENSE_CODES if governance.production_use_refusal(c) is None]
        tenant = Q(deployment__isnull=True)
        if deployment is not None:
            tenant |= Q(deployment=deployment)
        usable = self.filter(tenant, license_class__in=reviewed, synthetic=False)
        if runs_in_production(deployment):
            trusted = [t for t in _TRUST_CODES if governance.production_trust_refusal(t) is None]
            usable = usable.filter(trust_tier__in=trusted)
        return usable


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

    ``trust_tier`` defaults to ``unverified``, and a production run -- one for a
    deployment not recorded as ``dev`` or ``staging`` (:func:`runs_in_production`)
    -- never relies on an unverified source either (``source_unverified``; the
    owner's decision of 12 Oct 2026). A version's tier never changes: a higher tier
    is a new version, recorded by :class:`FinancialSourceTrustRaise` (spec, section
    6.1) -- an admin raises a tier, only upward and only from the latest version,
    through the trust-raise routes or ``manage.py raise_source_trust``, and
    ``authoritative`` needs a second admin's approval through the signed-in route.
    The new version copies every field but the tier, and names the admin who
    completed the raise as ``recorded_by``; it reads the observations its snapshot
    was registered with (``snapshots.fx_book``). No version is recorded at
    ``authoritative`` without the marker that approval sets
    (``second_person_required``): not a plain save, and not the snapshot loader,
    which refuses a file stating it and records any lower tier as stated.

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
        if (
            governance.needs_second_person(self.trust_tier)
            and getattr(self, "_second_admin", None) is not _SECOND_ADMIN_APPROVED
        ):
            raise EconomicsRefused(
                "second_person_required",
                "an authoritative version is recorded only by approving a raise: "
                "POST /api/assurance/economics/trust-raises/<uuid>/approve/",
            )
        _refuse(governance.snapshot_hash_refusal(self.snapshot_hash), detail="snapshot_hash")
        if self.version is None:
            earlier = FinancialSource._base_manager.filter(
                deployment_id=self.deployment_id, source_key=self.source_key
            ).aggregate(latest=Max("version"))["latest"]
            self.version = (earlier or 0) + 1
        self.recorded_by_username = _signed_in(self.recorded_by).username

    def _stored_for_the_gate(self) -> tuple | None:
        """What the gate reads of this version, from the STORED row and never from
        this object: ``(license_class, synthetic, deployment_id, trust_tier,
        source_key, version)``, or ``None`` for a row that is not stored. A row is
        never rewritten, so a field changed on the object in hand is not the source's:
        reading it would let an in-memory edit pass the gate."""
        if self.pk is None:
            return None
        return (
            FinancialSource._base_manager.filter(pk=self.pk)
            .values_list("license_class", "synthetic", "deployment_id", "trust_tier", "source_key", "version")
            .first()
        )

    def production_use_refusal(self, deployment) -> str | None:
        """``None`` when a production run for ``deployment`` may use this version;
        otherwise why not, read from the STORED row. A row that is not stored is
        refused (``cross_tenant_reference``), as :func:`snapshots._tenant_sources`
        refuses one. A run that :func:`runs_in_production` also never relies on a
        version still trusted as ``unverified`` (``source_unverified``): only a new
        version at a tier above it is usable."""
        return self._refusal(self._stored_for_the_gate(), deployment)

    @staticmethod
    def _refusal(stored: tuple | None, deployment) -> str | None:
        if stored is None:
            return "cross_tenant_reference"
        license_class, synthetic, tenant, trust_tier, _key, _version = stored
        refusal = governance.production_use_refusal(license_class, synthetic=synthetic)
        if refusal is not None:
            return refusal
        if tenant is not None and tenant != getattr(deployment, "pk", deployment):
            return "cross_tenant_reference"
        if runs_in_production(deployment):
            return governance.production_trust_refusal(trust_tier)
        return None

    def check_usable_for_production(self, deployment) -> None:
        """Raise :class:`SourceNotUsableForProduction` unless a production run for
        ``deployment`` may use this version, as stored. Called by the run before it
        reads it. The refusal names the source: its key, version and trust tier, as
        stored."""
        stored = self._stored_for_the_gate()
        if stored is None:
            detail = "a source that is not stored"
        else:
            detail = f"source {stored[4]} v{stored[5]}, trust tier {stored[3]}"
        _refuse(self._refusal(stored, deployment), SourceNotUsableForProduction, detail)

    def __str__(self) -> str:
        return f"{self.source_key} v{self.version} ({self.license_class})"


# ---------------------------------------------------------------------------
# FinancialSourceTrustRaise -- raising a source's trust tier (12 Oct 2026)
# ---------------------------------------------------------------------------


class TrustRaiseState(models.TextChoices):
    PENDING = "pending", "Pending a second admin's approval"
    DONE = "done", "Done: the new version is recorded"
    WITHDRAWN = "withdrawn", "Withdrawn by an admin"
    EXPIRED = "expired", "Expired: not approved within the time a request waits"


class TrustRaiseChannel(models.TextChoices):
    """How a raise, or its withdrawal, arrived."""

    API = governance.SIGNED_IN_CHANNEL, "The signed-in route"
    COMMAND = "command", "manage.py raise_source_trust, the account's password typed at a terminal"


#: Every (from, to) pair a raise may record: strictly upward in the trust order.
_RAISE_PAIRS = [
    (low.value, high.value)
    for position, low in enumerate(governance.TRUST_ORDER)
    for high in governance.TRUST_ORDER[position + 1 :]
]


def _upward_pairs() -> Q:
    (first_low, first_high), *rest = _RAISE_PAIRS
    condition = Q(from_tier=first_low, to_tier=first_high)
    for low, high in rest:
        condition |= Q(from_tier=low, to_tier=high)
    return condition


def _is_admin(account) -> bool:
    """Whether ``account`` is a stored, active admin account: role admin, or a
    superuser, as the assurance API's writes read it (``assurance.views._is_admin``),
    read from the account itself and never from anything the caller says."""
    if account is None or getattr(account, "pk", None) is None:
        return False
    if getattr(account, "is_active", False) is not True:
        return False
    return bool(getattr(account, "is_superuser", False) or getattr(account, "is_admin", False))


def require_trust_admin(account) -> None:
    """Refuse (``admin_required``) anyone but an admin: the one check every raise,
    approval and withdrawal makes first, whichever way it arrives (a route or the
    command)."""
    _refuse(governance.trust_raise_admin_refusal(_is_admin(account)))


def _channel(channel) -> str:
    """``channel`` if it is one this record knows (``code_unrecognised`` otherwise)."""
    _refuse(governance.code_refusal(channel, TrustRaiseChannel.values), detail="channel")
    return channel


def _requester_is_admin(row) -> bool:
    """Whether the admin who requested ``row`` is still an active admin, read from the
    account's STORED row now. An account removed since is not; nor is a name."""
    if row.requested_by_id is None:
        return False
    accounts = FinancialSourceTrustRaise._meta.get_field("requested_by").related_model
    return _is_admin(accounts._base_manager.filter(pk=row.requested_by_id).first())


def _stored_source(pk) -> dict | None:
    """What a raise reads of a source version, from the STORED row (never from an
    object in hand, whose fields a caller may have changed in memory)."""
    return (
        FinancialSource._base_manager.filter(pk=pk)
        .values(
            "pk", "deployment_id", "source_key", "version", "provider", "dataset", "url", "license_class",
            "trust_tier", "retrieved_at", "snapshot_hash", "schema_version", "synthetic",
        )
        .first()
    )


def _named(stored: dict) -> str:
    """A source version as a message names it: its key and version number, never a
    database key."""
    return f"source {stored['source_key']} v{stored['version']}"


def _superseded(stored: dict) -> bool:
    """Whether a newer version of ``stored``'s source (the same tenant and key) has
    been recorded."""
    return FinancialSource._base_manager.filter(
        deployment_id=stored["deployment_id"], source_key=stored["source_key"], version__gt=stored["version"]
    ).exists()


def _expire_if_due(row) -> bool:
    """For a locked, pending ``row``: whether it has expired by the service's clock
    (``trust_raise_expiry_refusal``), and if so its one transition, to ``expired``,
    made here -- a single conditional write, only while it is still pending."""
    if governance.trust_raise_expiry_refusal(row.requested_at, timezone.now()) is None:
        return False
    moved = FinancialSourceTrustRaise._base_manager.filter(pk=row.pk, state=TrustRaiseState.PENDING).update(
        state=TrustRaiseState.EXPIRED
    )
    if moved != 1:
        raise EconomicsRefused("trust_raise_not_pending", "it moved while it was found expired")
    return True


def _expired_detail(row) -> str:
    expired = row.requested_at + governance.TRUST_RAISE_EXPIRES_AFTER
    return f"requested {row.requested_at:%Y-%m-%d %H:%M} UTC, expired {expired:%Y-%m-%d %H:%M} UTC; request it again"


def _raised_version(stored: dict, to_tier: str, by, *, second_admin: bool = False) -> FinancialSource:
    """A NEW version of ``stored``'s source: every field as stored but the tier, and
    ``recorded_by`` the admin who completed the raise. Saved through
    :class:`FinancialSource`'s own checks, so its invariants hold here too (a
    synthetic source stays unverified, ``customer`` needs a tenant).

    Its version number is PINNED to the one after the version raised, never the next
    free one: a version recorded meanwhile -- a snapshot an operator registered
    between the superseded check and this insert, which PostgreSQL's READ COMMITTED
    lets happen -- collides with it on the unique constraint (IntegrityError,
    answered 409, nothing written), rather than being superseded by a copy of the
    older snapshot. ``second_admin`` (from :meth:`FinancialSourceTrustRaise.approve`
    only) carries the marker an ``authoritative`` version needs."""
    raised = FinancialSource(
        deployment_id=stored["deployment_id"],
        source_key=stored["source_key"],
        version=stored["version"] + 1,
        provider=stored["provider"],
        dataset=stored["dataset"],
        url=stored["url"],
        license_class=stored["license_class"],
        trust_tier=to_tier,
        retrieved_at=stored["retrieved_at"],
        snapshot_hash=stored["snapshot_hash"],
        schema_version=stored["schema_version"],
        synthetic=stored["synthetic"],
        recorded_by=by,
    )
    if second_admin:
        raised._second_admin = _SECOND_ADMIN_APPROVED
    raised.save()
    return raised


class FinancialSourceTrustRaise(_AppendOnly):
    """One raise of one source's trust tier (the owner's decisions of 12 Oct 2026, and
    of review round 1 of #155; spec, section 6.1).

    A version's tier never changes, so a raise records a NEW version of the source
    (:func:`_raised_version`) and this record of who raised it, why, when and through
    which channel. Only an admin raises a tier (``admin_required``); only upward
    (:data:`~assurance.economics.engine.governance.TRUST_ORDER`, ``trust_not_raised``);
    and only from the latest version of the source (``source_superseded``).

    Below ``authoritative`` one admin raises in one step (:meth:`request`): the new
    version and this record, ``done``, with the requester as the approver, are
    written together. ``authoritative`` needs two people: the request is recorded
    ``pending`` and no version is written; a DIFFERENT admin approves it through the
    signed-in route (:meth:`approve`; ``second_person_required`` for the same person
    or for the operator's command), while the requester is still an active admin
    (``requester_no_longer_admin``), which records the version; or any admin
    withdraws it (:meth:`withdraw`), and the record names who did. A request not
    approved within :data:`~assurance.economics.engine.governance.TRUST_RAISE_EXPIRES_AFTER`
    of its request (30 days) has expired (``trust_raise_expired``): found at approve
    time, lazily, and moved to ``expired`` in its one transition; a read shows it
    ``expired`` without writing (:meth:`current_state`), and it is not withdrawn.
    Nothing else records an ``authoritative`` version: :class:`FinancialSource`
    refuses one without the marker only :meth:`approve` sets.

    The record is append-only but for its ONE state transition, from ``pending`` to
    ``done``, ``withdrawn`` or ``expired``, which is a single conditional write (only
    while it is still pending) made by :meth:`approve` or :meth:`withdraw` and nothing
    else.

    People are named as every economics record names them: the account, nulled if it
    is removed, and the account's own username, which outlives it. No check
    constraint touches an account column, so removing an operator (a stop) is never
    refused by a raise. It waits only for an approval or withdrawal already in flight,
    for that transaction's few milliseconds: on the raise row's lock and its foreign
    keys' on PostgreSQL, on the database's write lock on SQLite, as behind any write.
    """

    State = TrustRaiseState
    Channel = TrustRaiseChannel

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    from_version = models.ForeignKey(FinancialSource, on_delete=models.CASCADE, related_name="trust_raises")
    # The version the raise recorded: empty until it is done.
    to_version = models.OneToOneField(
        FinancialSource, on_delete=models.CASCADE, null=True, blank=True, related_name="raised_by"
    )
    from_tier = models.CharField(max_length=32, choices=[(t, t) for t in _TRUST_CODES])
    to_tier = models.CharField(max_length=32, choices=[(t, t) for t in _TRUST_CODES])
    reason = models.TextField()
    state = models.CharField(max_length=16, choices=State.choices, default=State.PENDING)
    # How the request arrived (and, below the top tier, the raise it completed).
    channel = models.CharField(max_length=16, choices=Channel.choices)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_trust_raises_requested",
    )
    requested_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    requested_at = models.DateTimeField(default=timezone.now)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_trust_raises_approved",
    )
    approved_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    withdrawn_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_trust_raises_withdrawn",
    )
    withdrawn_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    withdrawn_via = models.CharField(max_length=16, choices=Channel.choices, blank=True, default="")

    class Meta:
        ordering = ["from_version", "id"]
        # None of these touches an account column, which removing an operator (a
        # stop) nulls.
        constraints = [
            models.CheckConstraint(condition=Q(state__in=TrustRaiseState.values), name="ck_econ_trust_raise_state"),
            models.CheckConstraint(
                condition=Q(channel__in=TrustRaiseChannel.values), name="ck_econ_trust_raise_channel"
            ),
            models.CheckConstraint(condition=_upward_pairs(), name="ck_econ_trust_raise_upward"),
            models.CheckConstraint(condition=~Q(requested_by_username=""), name="ck_econ_trust_raise_requester"),
            models.CheckConstraint(
                condition=(
                    (
                        Q(state=TrustRaiseState.PENDING)
                        & Q(to_version__isnull=True, approved_at__isnull=True, withdrawn_at__isnull=True)
                        & Q(approved_by_username="", withdrawn_by_username="", withdrawn_via="")
                    )
                    | (
                        Q(state=TrustRaiseState.DONE)
                        & Q(to_version__isnull=False, approved_at__isnull=False, withdrawn_at__isnull=True)
                        & ~Q(approved_by_username="")
                        & Q(withdrawn_by_username="", withdrawn_via="")
                    )
                    | (
                        Q(state=TrustRaiseState.EXPIRED)
                        & Q(to_version__isnull=True, approved_at__isnull=True, withdrawn_at__isnull=True)
                        & Q(approved_by_username="", withdrawn_by_username="", withdrawn_via="")
                    )
                    | (
                        Q(state=TrustRaiseState.WITHDRAWN)
                        & Q(to_version__isnull=True, approved_at__isnull=True, withdrawn_at__isnull=False)
                        & Q(approved_by_username="")
                        & ~Q(withdrawn_by_username="")
                        & Q(withdrawn_via__in=TrustRaiseChannel.values)
                    )
                ),
                name="ck_econ_trust_raise_state_fields",
            ),
        ]
        indexes = [models.Index(fields=["from_version", "state"], name="assurance_econ_raise_state")]

    # -- writing -------------------------------------------------------------------

    def check_new(self) -> None:
        """A raise is inserted ``pending`` (a tier that needs a second person) or
        ``done`` (one that does not, with its new version, the requester its
        approver), never ``withdrawn``; by an admin; through a channel this record
        knows; for a reason; upward from the STORED tier of a source version that is
        the latest of its key. So no write through the ORM records a raise to
        ``authoritative`` as done without a second admin's :meth:`approve`. A pending
        request's ``requested_at``, from which it expires, is the service's clock at
        insert, whatever the row carried."""
        requester = _signed_in(self.requested_by)
        self.requested_by_username = requester.username
        self.withdrawn_by_username = ""
        require_trust_admin(self.requested_by)
        _channel(self.channel)
        _refuse(governance.trust_raise_reason_refusal(self.reason), detail="reason")
        stored = _stored_source(self.from_version_id)
        if stored is None:
            raise EconomicsRefused("cross_tenant_reference", "a source that is not stored")
        self.from_tier = stored["trust_tier"]
        _refuse(
            governance.trust_raise_refusal(
                self.from_tier,
                self.to_tier,
                synthetic=stored["synthetic"],
                has_tenant=stored["deployment_id"] is not None,
            ),
            detail="to_tier",
        )
        two_people = governance.needs_second_person(self.to_tier)
        if two_people and self.state != TrustRaiseState.PENDING:
            raise EconomicsRefused("second_person_required", "a raise to this tier is requested, then approved")
        if not two_people and self.state != TrustRaiseState.DONE:
            raise EconomicsRefused("trust_raise_not_pending", "a raise below authoritative is done in one step")
        if two_people:
            if self.to_version_id is not None or self.approved_by_id is not None or self.approved_at is not None:
                raise EconomicsRefused("second_person_required", "a request names no version or approver")
            if _superseded(stored):
                raise EconomicsRefused("source_superseded", _named(stored))
            self.approved_by_username = ""
            # Its expiry counts from here, by the service's clock: never a time the
            # caller put on the row, which could postpone it.
            self.requested_at = timezone.now()
            return
        # One step: the requester is the approver, and the version is the next one
        # of the same source, at the new tier, with nothing recorded after it.
        self.approved_by = self.requested_by
        self.approved_by_username = requester.username
        raised = (
            FinancialSource._base_manager.filter(pk=self.to_version_id)
            .values_list("deployment_id", "source_key", "version", "trust_tier")
            .first()
        )
        expected = (stored["deployment_id"], stored["source_key"], stored["version"] + 1, self.to_tier)
        if raised != expected or _superseded({**stored, "version": stored["version"] + 1}):
            raise EconomicsRefused("source_superseded", _named(stored))
        if self.approved_at is None:
            self.approved_at = timezone.now()

    @classmethod
    def request(cls, source, to_tier, reason, *, by, channel) -> FinancialSourceTrustRaise:
        """Raise ``source`` (a version, or its primary key) to ``to_tier`` for
        ``reason``, as the admin ``by``, arriving through ``channel`` (``api``: the
        signed-in route; ``command``: the operator's command, the account's password
        typed at a terminal).

        Below ``authoritative``: the new version and a ``done`` record, written in
        one transaction. ``authoritative``: a ``pending`` record and no version, for
        a different admin to :meth:`approve` through the signed-in route. Refused
        (:class:`EconomicsRefused`, nothing written) for anyone but an admin, a
        channel this record does not know, a blank or overlong reason, a tier this
        platform does not know, one that is not above the version's own, a synthetic
        source, ``customer`` on a platform-wide source, or a version that is not the
        latest of its source."""
        require_trust_admin(by)
        _channel(channel)
        _refuse(governance.trust_raise_reason_refusal(reason), detail="reason")
        _refuse(governance.code_refusal(to_tier, _TRUST_CODES), detail="to_tier")
        pk = getattr(source, "pk", source)
        with transaction.atomic():
            stored = _stored_source(pk)
            if stored is None:
                raise EconomicsRefused("cross_tenant_reference", "a source that is not stored")
            _refuse(
                governance.trust_raise_refusal(
                    stored["trust_tier"],
                    to_tier,
                    synthetic=stored["synthetic"],
                    has_tenant=stored["deployment_id"] is not None,
                ),
                detail="to_tier",
            )
            if _superseded(stored):
                raise EconomicsRefused("source_superseded", _named(stored))
            if governance.needs_second_person(to_tier):
                return cls.objects.create(
                    from_version_id=pk, to_tier=to_tier, reason=reason, requested_by=by, channel=channel
                )
            raised = _raised_version(stored, to_tier, by)
            return cls.objects.create(
                from_version_id=pk,
                to_version=raised,
                to_tier=to_tier,
                reason=reason,
                state=TrustRaiseState.DONE,
                channel=channel,
                requested_by=by,
                requested_at=raised.recorded_at,
                approved_by=by,
                approved_at=raised.recorded_at,
            )

    def approve(self, *, by, channel) -> FinancialSourceTrustRaise:
        """Approve this pending raise as ``by``: an admin other than its requester,
        signed in to the route (``channel`` ``api``; the operator's command never
        approves, ``second_person_required``). Records the new version and moves the
        record to ``done``, in one transaction.

        Atomic and single-use. The raise's row is locked first and everything after
        is read under that lock: that it is still pending (``trust_raise_not_pending``
        -- approved or withdrawn meanwhile), that it has not expired
        (``trust_raise_expired``: 30 days after its request by the service's clock,
        never a time a caller sent; found here, lazily, the request moves to
        ``expired`` in its one transition, which is committed, and nothing else is
        recorded), that ``by`` is not its requester
        (``second_person_required``), that the requester is still an active admin
        (``requester_no_longer_admin``), and that its version is still the latest of
        its source (``source_superseded``). So two approvals at once give exactly one
        version: the second waits on the lock and finds the raise done. A version
        recorded meanwhile by anything else collides with the one this records (its
        number is pinned, :func:`_raised_version`), and nothing is written.

        The lock is ``select_for_update``, which holds the row on PostgreSQL. SQLite
        ignores it and serialises the whole transaction instead: it takes the
        database's write lock at BEGIN IMMEDIATE, so a second approval waits there.
        The transaction is a few reads and three writes, milliseconds; it reads and
        writes nothing a stop reads."""
        _refuse(governance.trust_raise_approval_channel_refusal(channel))
        require_trust_admin(by)
        approver = _signed_in(by)
        with transaction.atomic():
            row = FinancialSourceTrustRaise.objects.select_for_update().filter(pk=self.pk).first()
            if row is None:
                raise EconomicsRefused("trust_raise_not_pending", "a raise that is not stored")
            if row.state == TrustRaiseState.EXPIRED:
                raise EconomicsRefused("trust_raise_expired", _expired_detail(row))
            if row.state != TrustRaiseState.PENDING:
                raise EconomicsRefused("trust_raise_not_pending", f"it is {row.state}")
            expired = _expire_if_due(row)
            if not expired:
                self._record_approval(row, by, approver)
        if expired:
            # The request moved to expired, and that transition is committed; the
            # approval is refused and nothing else is recorded.
            raise EconomicsRefused("trust_raise_expired", _expired_detail(row))
        return FinancialSourceTrustRaise.objects.get(pk=self.pk)

    @staticmethod
    def _record_approval(row, by, approver) -> None:
        """The approval of the locked, pending, unexpired ``row``, inside approve()'s
        transaction: the checks read under the lock, the new version, and the record's
        one transition to ``done``."""
        requester = governance.Person(id=row.requested_by_id, username=row.requested_by_username)
        _refuse(governance.trust_raise_approval_refusal(requester, approver))
        _refuse(governance.trust_raise_requester_refusal(_requester_is_admin(row)))
        stored = _stored_source(row.from_version_id)
        if stored is None:
            raise EconomicsRefused("source_superseded", "a source version that is not stored")
        if _superseded(stored):
            raise EconomicsRefused("source_superseded", _named(stored))
        _refuse(
            governance.trust_raise_refusal(
                stored["trust_tier"],
                row.to_tier,
                synthetic=stored["synthetic"],
                has_tenant=stored["deployment_id"] is not None,
            ),
            detail="to_tier",
        )
        raised = _raised_version(stored, row.to_tier, by, second_admin=True)
        # The one transition this record makes, and only from pending.
        moved = FinancialSourceTrustRaise._base_manager.filter(pk=row.pk, state=TrustRaiseState.PENDING).update(
            state=TrustRaiseState.DONE,
            to_version=raised,
            approved_by=by,
            approved_by_username=approver.username,
            approved_at=raised.recorded_at,
        )
        if moved != 1:
            raise EconomicsRefused("trust_raise_not_pending", "it moved while being approved")

    def withdraw(self, *, by, channel) -> FinancialSourceTrustRaise:
        """Withdraw this pending raise as ``by``, any active admin, through
        ``channel``. Nothing else changes: no version is written, and the record
        stays, ``withdrawn``, naming who withdrew it, when and through which channel.
        Cancelling a request for more trust is never harder than granting it. An
        expired request (by the service's clock) is not pending
        (``trust_raise_not_pending``), and the refusal writes nothing: it is never
        approved either, and only an approval moves it to ``expired``."""
        require_trust_admin(by)
        _channel(channel)
        withdrawer = _signed_in(by)
        with transaction.atomic():
            row = FinancialSourceTrustRaise.objects.select_for_update().filter(pk=self.pk).first()
            if row is None:
                raise EconomicsRefused("trust_raise_not_pending", "a raise that is not stored")
            if row.state != TrustRaiseState.PENDING:
                raise EconomicsRefused("trust_raise_not_pending", f"it is {row.state}")
            if governance.trust_raise_expiry_refusal(row.requested_at, timezone.now()) is not None:
                raise EconomicsRefused("trust_raise_not_pending", f"it is expired: {_expired_detail(row)}")
            moved = FinancialSourceTrustRaise._base_manager.filter(pk=row.pk, state=TrustRaiseState.PENDING).update(
                state=TrustRaiseState.WITHDRAWN,
                withdrawn_at=timezone.now(),
                withdrawn_by=by,
                withdrawn_by_username=withdrawer.username,
                withdrawn_via=channel,
            )
            if moved != 1:
                raise EconomicsRefused("trust_raise_not_pending", "it moved while being withdrawn")
        return FinancialSourceTrustRaise.objects.get(pk=self.pk)

    # -- reading -------------------------------------------------------------------

    @property
    def expires_at(self):
        """When this request expires if it is still pending then: a raise that needs a
        second person only; ``None`` for one done in one step."""
        if not governance.needs_second_person(self.to_tier):
            return None
        return self.requested_at + governance.TRUST_RAISE_EXPIRES_AFTER

    def current_state(self, now=None) -> str:
        """The state as it stands at ``now`` (the service's clock): ``expired`` for a
        request still stored pending past its time, which approve() would move there.
        Computed on read; nothing is written."""
        if self.state == TrustRaiseState.PENDING and governance.trust_raise_expiry_refusal(
            self.requested_at, now or timezone.now()
        ):
            return TrustRaiseState.EXPIRED.value
        return self.state

    def as_dict(self) -> dict:
        """The record as the routes answer it: the source, both versions, the
        tiers, the reason, the channel, and who did what when, by their recorded
        usernames."""

        def version(source):
            if source is None:
                return None
            return {
                "uuid": str(source.uuid),
                "version": source.version,
                "trust_tier": source.trust_tier,
                "recorded_by": source.recorded_by_username or None,
                "recorded_at": source.recorded_at.isoformat(),
            }

        source = self.from_version
        return {
            "uuid": str(self.uuid),
            "state": self.current_state(),
            "channel": self.channel,
            "source_key": source.source_key,
            "deployment": str(source.deployment.uuid) if source.deployment_id is not None else None,
            "from_version": version(source),
            "to_version": version(self.to_version),
            "from_tier": self.from_tier,
            "to_tier": self.to_tier,
            "needs_second_person": governance.needs_second_person(self.to_tier),
            "reason": self.reason,
            "requested_by": self.requested_by_username or None,
            "requested_at": self.requested_at.isoformat(),
            "approved_by": self.approved_by_username or None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "withdrawn_by": self.withdrawn_by_username or None,
            "withdrawn_at": self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            "withdrawn_via": self.withdrawn_via or None,
        }

    def __str__(self) -> str:
        return f"{self.state} raise to {self.to_tier} ({self.uuid})"


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
    only -- and blank until known. The scenario builder records the deployment's
    system fingerprint when it builds a version (spec, section 24.6); where it could
    not compute one it records none, and why, in ``system_fingerprint_unavailable``
    -- never both. A version with neither was recorded before the builder recorded
    one, or by another writer. A revised scenario is a new row that ``supersedes``
    this one, in the same deployment; the versions it supersedes, transitively, are
    all its versions for the review rule.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        "assurance.Deployment", on_delete=models.CASCADE, related_name="financial_scenarios"
    )
    title = models.CharField(max_length=255)
    system_fingerprint = models.CharField(max_length=64, blank=True)
    # Why the builder recorded no system fingerprint (blank where it recorded one, or
    # where the version was recorded before the builder recorded any).
    system_fingerprint_unavailable = models.TextField(blank=True, default="")
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
            if self.system_fingerprint_unavailable:
                raise EconomicsRefused(
                    "field_malformed",
                    "system_fingerprint_unavailable: a version records its system fingerprint or why it has none, "
                    "never both",
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


def _read_as(row, read_as):
    """``(source, named, held_by)`` for an observation ``row``: the version that holds
    it, the version its provenance names, and that holder's version number when it is
    not the one named. ``read_as`` is the version of the same source a run asked for
    (:func:`assurance.economics.snapshots.fx_book`): a raised version holds no rows of
    its own and reads those the loader registered under the same snapshot hash, so
    the provenance names the version the gate checked AND the version holding the
    rows. Without ``read_as``, the row's own version is named, as before."""
    source = row.source if row.source_id is not None else None
    if read_as is None or source is None or read_as.pk == source.pk:
        return source, source, None
    return source, read_as, source.version


def _engine_refusal(build):
    """Build the engine's object for a row, and refuse the row with the engine's
    code if the engine refuses it (a stated distribution's with the probabilistic
    engine's code and meaning, which travel with the refusal)."""
    try:
        return build()
    except pset.StatedDistributionRefused as refused:
        raise EngineRefused(refused.code, refused.meaning, refused.detail) from None
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

    def as_engine(self, read_as=None) -> fx.FXRate:
        """The row as the engine reads it, with its source version named: the row's own,
        or ``read_as``, the version of the same source a run asked for when this row is
        held by another (:func:`_read_as`)."""
        source, named, held_by = _read_as(self, read_as)
        return fx.FXRate(
            base=self.base_currency,
            quote=self.quote_currency,
            rate=self.rate,
            rate_type=self.rate_type,
            provider=self.provider,
            observed_at=self.observed_at,
            effective_date=self.effective_date,
            source_snapshot_hash=self.source_snapshot_hash,
            source_key=named.source_key if named else "",
            source_version=named.version if named else None,
            observations_version=held_by,
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

    def as_engine(self, read_as=None) -> cost_index.IndexPoint:
        """The row as the engine reads it, with its source version and snapshot named:
        the row's own version, or ``read_as`` (:func:`_read_as`)."""
        source, named, held_by = _read_as(self, read_as)
        return cost_index.IndexPoint(
            series_id=self.series_id,
            geography=self.geography,
            category=self.category,
            base=self.base,
            period=self.period,
            value=self.value,
            vintage_date=self.vintage_date,
            source_snapshot_hash=source.snapshot_hash if source else "",
            source_key=named.source_key if named else "",
            source_version=named.version if named else None,
            observations_version=held_by,
            provider=source.provider if source else "",
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
# FinancialSourceFetch -- one fetch of one live feed (MVP step 10)
# ---------------------------------------------------------------------------

FETCH_RECORDED = "recorded"
FETCH_UNCHANGED = "unchanged"
FETCH_REFUSED = "refused"
FETCH_OUTCOMES = (FETCH_RECORDED, FETCH_UNCHANGED, FETCH_REFUSED)


def fetch_codes() -> frozenset[str]:
    """Every code a refused fetch may record: the feed adapters' and the fetch's
    (:data:`assurance.economics.engine.feeds.FEED_REFUSALS`), the money engine's for a
    value the observation contract refuses, and the governance rules' for a version
    the store refuses."""
    from .engine.feeds import FEED_REFUSALS

    return frozenset(FEED_REFUSALS) | frozenset(money.REFUSALS) | frozenset(governance.REFUSALS)


class FinancialSourceFetch(_AppendOnly):
    """One fetch of one feed source by ``manage.py fetch_financial_source`` (spec,
    section 29): which source, as known on which date, when it was asked, and what
    came of it -- ``recorded`` (a new source version, whose snapshot hash is the
    response's normalised payload hash), ``unchanged`` (the payload was one already
    recorded: no new version, and the version that holds it named), or ``refused``
    (nothing recorded but this row, and the refusal's CODE, never its text, which
    could quote the answer).

    A fetch refused before anything is sent -- no key, live fetching switched off,
    an unknown source, a date it cannot ask for -- writes nothing at all, not even
    this. A feed source is platform-wide, so a fetch names no deployment, and no
    account: removing an operator, a stop, never writes one. Append-only."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    source_key = models.SlugField(max_length=200)
    as_of = models.DateField()
    requested_at = models.DateTimeField(default=timezone.now)
    outcome = models.CharField(max_length=16, choices=[(o, o) for o in FETCH_OUTCOMES])
    # The refusal's code: blank unless the fetch was refused.
    code = models.CharField(max_length=64, blank=True, default="")
    # "sha256:" + 64 hex: the normalised payload's hash, where an answer was read.
    payload_hash = models.CharField(max_length=71, blank=True, default="")
    # The version recorded, or the one already holding the payload; none when refused.
    source = models.ForeignKey(FinancialSource, on_delete=models.CASCADE, null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["source_key", "requested_at", "id"]
        verbose_name = "financial source fetch"
        constraints = [
            models.CheckConstraint(condition=Q(outcome__in=FETCH_OUTCOMES), name="ck_econ_fetch_outcome"),
            models.CheckConstraint(
                condition=(Q(outcome=FETCH_REFUSED) & ~Q(code="") & Q(source__isnull=True))
                | (Q(outcome__in=(FETCH_RECORDED, FETCH_UNCHANGED)) & Q(code="") & Q(source__isnull=False)),
                name="ck_econ_fetch_outcome_fields",
            ),
        ]
        indexes = [models.Index(fields=["source_key", "requested_at"], name="assurance_econ_fetch_key")]

    def check_new(self) -> None:
        _require_text(source_key=self.source_key)
        _refuse(governance.code_refusal(self.outcome, FETCH_OUTCOMES), detail="outcome")
        refused = self.outcome == FETCH_REFUSED
        if refused != (self.source_id is None) or refused != bool(self.code):
            raise EconomicsRefused("code_unrecognised", "a refused fetch has a code and no version; any other, both not")
        if refused:
            _refuse(governance.code_refusal(self.code, fetch_codes()), detail="code")
        if self.payload_hash:
            _refuse(governance.snapshot_hash_refusal(self.payload_hash), detail="payload_hash")
        if self.source_id is not None:
            stored = (
                FinancialSource._base_manager.filter(pk=self.source_id)
                .values_list("deployment_id", "source_key", "snapshot_hash")
                .first()
            )
            if stored is None or stored[0] is not None or stored[1] != self.source_key:
                raise EconomicsRefused("cross_tenant_reference", "a fetch names a platform-wide version of its source")
            if stored[2] != self.payload_hash:
                raise EconomicsRefused("snapshot_hash_mismatch")

    def __str__(self) -> str:
        return f"{self.source_key} as of {self.as_of}: {self.outcome}{f' ({self.code})' if self.code else ''}"


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
    :meth:`intact` re-reads the rows and compares their digest. A row may state the
    distribution it draws from in a simulation, and the version may hold the
    scenario's ``frequency`` (spec, section 19.2); each stated distribution is
    checked against its row's figures by the simulation's own test before anything
    is written.
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
        engine's code, or written whole.

        Every check of the version and of each row -- the ones a save runs, a
        stated distribution's test against its row's figures included -- runs
        BEFORE the transaction (:meth:`check_rows`), which then only inserts: on
        SQLite, a stop's write waits for the inserts alone, never for a check. A
        version raced to the same number is stopped by the unique constraint
        (``IntegrityError``), and nothing is written."""
        _engine_refusal(lambda: pset.check_set_key(set_key))
        content = _engine_refusal(lambda: pset.parse_document(document))
        parameters_ = content.parameters()
        version = cls(
            deployment=deployment,
            set_key=set_key,
            insurance_exclusions=list(content.exclusions),
            variable_count=len(parameters_),
            content_digest=content.digest(),
            author=author,
        )
        rows = [
            FinancialParameter.from_engine(
                parameter, parameter_set=version, distribution=content.distributions.get(parameter.name)
            )
            for parameter in parameters_
        ]
        cls.check_rows(version, rows)
        with transaction.atomic():
            version._insert_as_marked()
            for row in rows:
                row._insert_as_marked()
        return version

    @classmethod
    def check_rows(cls, version: CustomerParameterSet, rows: list[FinancialParameter]) -> None:
        """Run every check a save of the new ``version`` and of each of its ``rows``
        runs, against the version itself where a save reads the stored rows, and
        mark each as checked: :meth:`_AppendOnly._insert_as_marked` then inserts it
        only as it was checked. Reads only the latest version number recorded."""
        if not version._state.adding or any(not row._state.adding for row in rows):
            raise EconomicsRewriteRefused("A parameter-set version writes new rows only.")
        version.check_new()
        if len(rows) != version.variable_count:
            raise EconomicsRefused("parameter_set_sealed", f"{len(rows)} rows for {version.variable_count}")
        names: set[str] = set()
        for row in rows:
            if row.parameter_set is not version or row.scenario_id is not None:
                raise EconomicsRefused("parent_required")
            engine = row._check_form()
            expected = _engine_refusal(lambda row=row: pset.variable_unit(row.name))
            if engine.unit is not expected:
                raise EconomicsRefused("unit_mismatch", f"the parameter set's {row.name} is {expected}")
            if row.name in names:
                raise EconomicsRefused("duplicate_id", f"parameter {row.name!r} twice in one parent")
            if row.derived_from:
                raise EconomicsRefused("parameter_not_found", f"{row.name} is derived from a parameter of another parent")
            names.add(row.name)
        for row in (version, *rows):
            row._mark_checked()

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
        """The version's content, read back from its rows, with the distributions
        they state as stored."""
        rows = self.parameter_rows() if rows is None else rows
        return _engine_refusal(
            lambda: pset.content_of(
                [row.as_engine() for row in rows],
                self.insurance_exclusions,
                {row.name: row.distribution for row in rows if row.distribution is not None},
            )
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
            return {**schema, **row, "distribution": content.distributions.get(parameter.name)}

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
            pset.FREQUENCY: None
            if content.frequency is None
            else entry(content.frequency, {"unit": parameters.Unit.COUNT.value, "meaning": "events a year"}),
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
    # The distribution the parameter states, if any (spec, section 25.1): a step-7a
    # catalogue id, its version and its native parameters as decimal strings
    # ({"id": "lognormal", "version": 1, "params": {"mu": "9.2", "sigma": "0.8"}}).
    # Null: the parameter states none, and the simulation's rule decides.
    distribution = models.JSONField(null=True, blank=True)
    # The parameters a derived one was taken across, by uuid, each of the same parent:
    # the scenario builder's larger-loss value of an event's attribute cites every
    # effect attribute it was taken across (spec, section 24.5). Empty otherwise.
    derived_from = models.JSONField(default=list, blank=True)
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
    def from_engine(
        cls, parameter: parameters.Parameter, *, scenario=None, parameter_set=None, distribution=None
    ) -> FinancialParameter:
        """An unsaved row holding ``parameter``, for ``scenario`` or ``parameter_set``,
        stating ``distribution`` (a stated distribution's stored form) or none."""
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
            distribution=distribution,
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

    def stated_distribution(self):
        """The distribution the row states, read by the simulation's catalogue, or
        ``None``. Imports the probabilistic engine (and numpy) only when called."""
        if self.distribution is None:
            return None
        from .engine import scenario_simulation

        try:
            return scenario_simulation.parse_stated(self.distribution, f"{self.name}.distribution")
        except scenario_simulation.ScenarioSimulationRefused as refused:
            raise EngineRefused(refused.code, scenario_simulation.REFUSALS[refused.code], refused.detail) from None

    def checked_distribution(self, engine: parameters.Parameter) -> dict:
        """The stated distribution, refused unless step 7a's catalogue builds it
        for this parameter (its unit, and for an expert range its own source
        type) and it holds the parameter's own figures (spec, section 25.1), in
        its stored form. A derived parameter states none: it draws from what it
        was derived from."""
        from .engine import distributions, scenario_simulation

        stated = self.stated_distribution()
        if self.derived_from:
            code = "derived_malformed"
            raise EngineRefused(code, scenario_simulation.REFUSALS[code], f"{self.name} states a distribution")
        try:
            # A scenario's frequency, or the one a parameter set states for the
            # scenarios built from it: a count distribution, by the frequency's rule.
            if self.name == scenario_simulation.FREQUENCY_PARAMETER:
                scenario_simulation.resolve_frequency(engine, stated)
            else:
                scenario_simulation.check_stated(stated, engine)
        except scenario_simulation.ScenarioSimulationRefused as refused:
            raise EngineRefused(refused.code, scenario_simulation.REFUSALS[refused.code], refused.detail) from None
        except distributions.DistributionRefused as refused:
            raise EngineRefused(refused.code, distributions.REFUSALS[refused.code], refused.detail) from None
        except money.MoneyRefused as refused:
            raise EconomicsRefused(refused.code, refused.detail) from None
        return stated.as_json()

    def _check_form(self) -> parameters.Parameter:
        """The checks that read nothing stored: the row as its own values make it,
        which it returns, as the engine reads it."""
        if self.effective_date is None:
            raise EconomicsRefused("date_malformed", f"{self.name} has no effective_date")
        if isinstance(self.evidence_ref, str) and len(self.evidence_ref) > pset.EVIDENCE_REF_MAX:
            raise EconomicsRefused("field_malformed", f"{self.name} evidence_ref is longer than its column")
        if isinstance(self.name, str) and len(self.name) > _KEY_MAX:
            raise EconomicsRefused("field_malformed", f"a parameter name is longer than {_KEY_MAX}")
        derived = self.derived_from
        if not isinstance(derived, list) or not all(isinstance(x, str) for x in derived):
            raise EconomicsRefused("field_malformed", f"{self.name} derived_from is a list of parameters' uuids")
        if len(set(derived)) != len(derived) or str(self.uuid) in derived:
            raise EconomicsRefused("duplicate_id", f"{self.name} derived_from names a parameter twice, or itself")
        engine = _engine_refusal(self.as_engine)
        # Stored in the one spelling: "1.10" and "1.1" are one value, written once.
        self.low, self.base, self.high = (parameters.Parameter.text(engine.at(p)) for p in parameters.POINTS)
        if self.distribution is not None:
            self.distribution = self.checked_distribution(engine)
        return engine

    def check_new(self) -> None:
        if (self.scenario_id is None) == (self.parameter_set_id is None):
            raise EconomicsRefused("parent_required")
        engine = self._check_form()
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
        if self.derived_from and parent.filter(uuid__in=self.derived_from).count() != len(self.derived_from):
            raise EconomicsRefused("parameter_not_found", f"{self.name} is derived from a parameter of another parent")

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

    def _check_form(self) -> None:
        _key(self.event_key, "event_key")
        _engine_refusal(lambda: money.check_reporting_currency(self.currency, "event currency"))
        if self.effect:
            _refuse(governance.spine_reference_refusal("effect", self.effect), detail="effect")

    def check_new(self) -> None:
        self._check_form()
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

    def _cited(self) -> dict[str, uuid.UUID]:
        """``cited_parameters`` read: formula input to the cited parameter's uuid."""
        cited = self.cited_parameters
        if not isinstance(cited, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in cited.items()):
            raise EconomicsRefused("field_malformed", "cited_parameters maps a formula input to a parameter's uuid")
        wanted = {}
        for name, value in cited.items():
            try:
                wanted[name] = uuid.UUID(value)
            except ValueError:
                raise EconomicsRefused("parameter_not_found", f"{name}: {value!r}") from None
        return wanted

    def _bindings(self, deployment_id) -> dict[str, parameters.Parameter]:
        wanted = self._cited()
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
        return self._compute(self._bindings(deployment_id), currency)

    def _compute(self, bindings, currency):
        """The component the row's formula makes of ``bindings``, in ``currency``."""
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
        self._record(self._evaluate())

    def _record(self, component) -> None:
        """Write what the formula made into the row: never the caller's amounts."""
        estimated = component.status == formulas.ESTIMATED
        self.status = component.status
        self.currency = component.currency or ""
        self.low, self.base, self.high = (
            tuple(parameters.Parameter.text(component.at(p)) for p in parameters.POINTS) if estimated else ("", "", "")
        )
        self.unknown_reason = component.unknown_reason or ""
        self.missing_inputs = list(component.missing)
        self.insurance_treatment = formulas.GROSS

    def __str__(self) -> str:
        return f"{self.family} component {self.component_key} ({self.status})"


# ---------------------------------------------------------------------------
# ScenarioBuild, CausalEffect, EffectFinding: the causal graph a built scenario
# rests on (spec, section 24). Written by the scenario builder only.
# ---------------------------------------------------------------------------

#: An effect's origin and a finding's role, spelled here and not imported: this
#: module is on Django's load path, and the builder's template module is kept off
#: it (spec, section 2). ``tests/test_economics_builder.py`` pins them equal to
#: :class:`assurance.economics.engine.templates.Origin` and ``FindingRole``.
EFFECT_ORIGINS = ("observed", "hypothetical")
FINDING_ROLES = ("prerequisite", "amplifier", "alternate_path")
#: The width of an effect key: an attribute is stored as a scenario parameter named
#: ``<effect key>.<attribute>``, which fits the parameter's name column.
EFFECT_KEY_MAX = 60
_UUID_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _uuid_text(value, field: str) -> None:
    """A SPINE row named by its uuid, as the edge history names a node: lowercase and
    hyphenated, checked for form only (resolved by the builder, in the deployment)."""
    _refuse(governance.spine_reference_refusal("node", value), detail=field)


class ScenarioBuild(_AppendOnly):
    """How one scenario version was built: the deployment, the customer
    parameter-set version it read, its currency and as-of date, the builder, the
    grouping key and the template pack, and the CONTENT DIGEST of everything it was
    built from (spec, section 24). The digest is unique per deployment, so the same
    inputs never build a second scenario: a rebuild returns this one, and two builds
    racing are refused by the constraint (409), not duplicated."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    scenario = models.OneToOneField(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    parameter_set = models.ForeignKey(CustomerParameterSet, on_delete=models.CASCADE, related_name="+")
    # "sha256:" + 64 hex over the build's canonical inputs.
    build_digest = models.CharField(max_length=71)
    builder_version = models.CharField(max_length=100)
    grouping_version = models.CharField(max_length=100)
    pack = models.CharField(max_length=100)
    currency = models.CharField(max_length=3)
    as_of = models.DateField()
    # The canonical inputs the digest is taken over, kept whole.
    inputs = models.JSONField()
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "id"]
        constraints = [
            models.UniqueConstraint(fields=["deployment", "build_digest"], name="uq_econ_build_digest"),
        ]

    def _check_form(self) -> None:
        _refuse(governance.snapshot_hash_refusal(self.build_digest), detail="build_digest")
        _require_text(
            builder_version=self.builder_version, grouping_version=self.grouping_version, pack=self.pack
        )
        _engine_refusal(lambda: money.check_reporting_currency(self.currency, "build currency"))
        if self.as_of is None:
            raise EconomicsRefused("date_malformed", "the build has no as_of date")

    def check_new(self) -> None:
        self._check_form()
        scenario = FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("deployment_id", flat=True)
        if list(scenario) != [self.deployment_id]:
            raise EconomicsRefused("cross_tenant_reference", "scenario")
        pset_tenant = CustomerParameterSet._base_manager.filter(pk=self.parameter_set_id).values_list(
            "deployment_id", flat=True
        )
        if list(pset_tenant) != [self.deployment_id]:
            raise EconomicsRefused("cross_tenant_reference", "parameter_set")
        # A second build of the same digest is not looked for here: the builder reads
        # the one recorded and returns it, and two builds racing past that read are
        # refused by the unique constraint, which no check made before it can be.

    def __str__(self) -> str:
        return f"build {self.build_digest} of scenario {self.scenario_id}"


class CausalEffect(_AppendOnly):
    """One effect of a built scenario version, the node its loss follows from (spec,
    section 24; specification, section 6): a SPINE observed effect, named by its
    row's uuid with the digest its signature covers, or a hypothetical effect an
    analyst declared. It is bound to an asset of the deployment (a node, by uuid) and
    to a business process, has a type, the time it occurred when it was observed,
    and the template it was assigned to.

    THE INVARIANT, held here and in the database: an effect is in exactly ONE loss
    event of its scenario version. ``loss_event`` is one foreign key, not null; an
    effect key is unique within the scenario, and so is a SPINE observation (a
    unique constraint each), so neither one effect nor one observation can be put
    in two events; and every row of one SPINE effect (``spine_effect``) in a
    scenario is in one event and declared one way, checked on save
    (``duplicate_id``). Its attributes are the scenario's financial parameters named
    ``<effect_key>.<attribute>``."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    loss_event = models.ForeignKey(LossEvent, on_delete=models.CASCADE, related_name="+")
    effect_key = models.SlugField(max_length=EFFECT_KEY_MAX)
    origin = models.CharField(max_length=16, choices=[(c, c) for c in EFFECT_ORIGINS])
    # An observed effect: its WorkflowChainOutcome's uuid, and the evidence digest its
    # signature covers (the observation). Blank for a hypothetical effect.
    observed_effect = models.CharField(max_length=36, blank=True)
    observation = models.CharField(max_length=71, blank=True)
    # The effect as the receipt names one (workflow and tool): blank when unknown.
    spine_effect = models.CharField(max_length=71, blank=True)
    effect_type = models.CharField(max_length=64)
    asset = models.CharField(max_length=36)
    business_process = models.CharField(max_length=64)
    # When it was observed, from the SPINE row; null for a hypothetical effect.
    occurred_at = models.DateTimeField(null=True, blank=True)
    template_id = models.CharField(max_length=100)
    template_version = models.PositiveIntegerField()
    # Every template that covers the effect, [[id, version], ...], in precedence order.
    in_scope_of = models.JSONField(default=list)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]
        constraints = [
            models.UniqueConstraint(fields=["scenario", "effect_key"], name="uq_econ_effect_key"),
            models.UniqueConstraint(
                fields=["scenario", "observation"], condition=~Q(observation=""), name="uq_econ_effect_observation"
            ),
            models.CheckConstraint(condition=Q(origin__in=EFFECT_ORIGINS), name="ck_econ_effect_origin"),
            models.CheckConstraint(
                condition=(Q(origin="observed") & ~Q(observation="") & ~Q(observed_effect=""))
                | (Q(origin="hypothetical") & Q(observation="") & Q(observed_effect="")),
                name="ck_econ_effect_observed_has_observation",
            ),
        ]

    def _check_form(self) -> None:
        _refuse(governance.required_text_refusal(self.effect_key), detail="effect_key")
        if len(self.effect_key) > EFFECT_KEY_MAX:
            raise EconomicsRefused("field_malformed", f"effect_key is longer than {EFFECT_KEY_MAX}")
        _refuse(governance.code_refusal(self.origin, EFFECT_ORIGINS), detail="origin")
        _require_text(effect_type=self.effect_type, business_process=self.business_process, template_id=self.template_id)
        _uuid_text(self.asset, "asset")
        if self.origin == "observed":
            _uuid_text(self.observed_effect, "observed_effect")
            _refuse(governance.spine_reference_refusal("effect", self.observation), detail="observation")
        elif self.observed_effect or self.observation:
            raise EconomicsRefused("field_malformed", "a hypothetical effect names no observed effect")
        if self.spine_effect:
            _refuse(governance.spine_reference_refusal("effect", self.spine_effect), detail="spine_effect")

    def check_new(self) -> None:
        self._check_form()
        event = LossEvent._base_manager.filter(pk=self.loss_event_id).values_list("scenario_id", flat=True)
        if list(event) != [self.scenario_id]:
            raise EconomicsRefused("cross_tenant_reference", "the effect's loss event is another scenario's")
        mine = CausalEffect._base_manager.filter(scenario_id=self.scenario_id)
        if mine.filter(effect_key=self.effect_key).exists():
            raise EconomicsRefused("duplicate_id", f"effect {self.effect_key!r} twice in one scenario")
        if self.observation and mine.filter(observation=self.observation).exists():
            raise EconomicsRefused("duplicate_id", f"observation {self.observation} in two effects of one scenario")
        if self.spine_effect:
            same = mine.filter(spine_effect=self.spine_effect)
            if same.exclude(loss_event_id=self.loss_event_id).exists():
                raise EconomicsRefused("duplicate_id", f"SPINE effect {self.spine_effect} in two loss events")
            if same.exclude(
                effect_type=self.effect_type, asset=self.asset, business_process=self.business_process
            ).exists():
                raise EconomicsRefused("duplicate_id", f"SPINE effect {self.spine_effect} declared two ways")

    def attribute_rows(self) -> list[FinancialParameter]:
        """The effect's attributes, as stored: the scenario's parameters named
        ``<effect_key>.<attribute>``."""
        prefix = f"{self.effect_key}."
        return [
            row
            for row in FinancialParameter._base_manager.filter(
                scenario_id=self.scenario_id, name__startswith=prefix
            ).order_by("name", "id")
            if row.name[len(prefix):] and "." not in row.name[len(prefix):]
        ]

    def __str__(self) -> str:
        return f"{self.origin} effect {self.effect_key} ({self.effect_type})"


class EffectFinding(_AppendOnly):
    """One finding enabling one effect of a built scenario version, as a
    prerequisite, an amplifier or an alternate path (specification, section 6:
    Finding ENABLES Effect). The finding is named by its uuid; the builder resolves it
    in the scenario's own deployment. A finding enables an effect once (a unique
    constraint); findings that enable one effect join that effect's ONE event, and add
    no component to it."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor: see CustomerParameterSet.deployment.
    effect = models.ForeignKey(CausalEffect, on_delete=models.CASCADE, related_name="+")
    finding = models.CharField(max_length=36)
    role = models.CharField(max_length=16, choices=[(c, c) for c in FINDING_ROLES])
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["effect", "id"]
        constraints = [
            models.UniqueConstraint(fields=["effect", "finding"], name="uq_econ_effect_finding"),
            models.CheckConstraint(condition=Q(role__in=FINDING_ROLES), name="ck_econ_effect_finding_role"),
        ]

    def _check_form(self) -> None:
        _uuid_text(self.finding, "finding")
        _refuse(governance.code_refusal(self.role, FINDING_ROLES), detail="role")

    def check_new(self) -> None:
        self._check_form()
        if EffectFinding._base_manager.filter(effect_id=self.effect_id, finding=self.finding).exists():
            raise EconomicsRefused("duplicate_id", f"finding {self.finding} enables one effect twice")

    def __str__(self) -> str:
        return f"finding {self.finding} {self.role} of effect {self.effect_id}"


# ---------------------------------------------------------------------------
# SimulationResult -- one Monte Carlo run of one scenario version (step 7b)
# ---------------------------------------------------------------------------

#: A simulation result's status.
SIMULATION_COMPLETED = "completed"
SIMULATION_REFUSED = "refused"
SIMULATION_STATUSES = (SIMULATION_COMPLETED, SIMULATION_REFUSED)
_SEED = re.compile(r"0|[1-9][0-9]{0,19}")
_MAX_SEED = 2**64 - 1


def canonical_digest(document) -> str:
    """``sha256:`` and the SHA-256 of a document's canonical JSON: sorted keys, no
    whitespace, ASCII, no NaN (the simulation engine's form, written here without
    importing it)."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _has_float(value) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_float(item) for item in value)
    return False


def _checked_state(row) -> tuple:
    """Every column value of ``row``, as checked: an insert after the check must
    write exactly these."""
    return tuple(json.dumps(field.value_from_object(row), sort_keys=True, default=str) for field in row._meta.concrete_fields)


class SimulationResultQuerySet(AppendOnlyQuerySet):
    """The append-only queryset, and the ONE place the exposure filter is written
    (spec, section 28): a scenario's own runs are its exposure; a residual run under
    a remediation option never is."""

    def exposure_runs(self):
        """The runs that are a scenario's exposure: none under a remediation option.
        Every reader of exposure -- the results route, the scenario document, the
        events banner, any total -- reads through this."""
        return self.filter(remediation__isnull=True)

    def residual_runs(self):
        """The residual runs under a remediation option: never exposure."""
        return self.filter(remediation__isnull=False)


class SimulationResult(_AppendOnly):
    """One Monte Carlo run of one scenario version (spec, section 25.6): the seed and
    the draws; the canonical inputs and their digest; every version the figures rest
    on (the formulas, the twins, the distributions, the sampler, numpy); the
    summaries and the whole record as decimal strings, and the record's digest; or,
    where the run was refused, the refusal's code. And when it ran, and for how long.

    Append-only like every economics record, and IDEMPOTENT: one row per scenario
    version, input digest, seed and draws (``uq_econ_simulation_inputs``). The
    service returns the row already recorded for the same inputs and never runs or
    writes a second; two runs racing past that read are refused by the constraint,
    and the later returns the first's row. Nothing in it is a float: every figure is
    a decimal string (``result_malformed``), and both digests are recomputed on save
    (``digest_mismatch``). It has no account column, so removing an operator, a stop,
    never writes it, and it goes with its deployment."""

    objects = SimulationResultQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    # 0 to 2^64 - 1, as text: wider than a signed 64-bit column, and never a double.
    seed = models.CharField(max_length=20)
    draws = models.PositiveIntegerField()
    severe_percentile = models.CharField(max_length=32)
    input_digest = models.CharField(max_length=71)
    result_digest = models.CharField(max_length=71, blank=True)
    status = models.CharField(max_length=16, choices=[(s, s) for s in SIMULATION_STATUSES])
    refusal_code = models.CharField(max_length=64, blank=True)
    refusal_detail = models.TextField(blank=True)
    # The canonical inputs the input digest is taken over, kept whole.
    inputs = models.JSONField()
    versions = models.JSONField()
    # The scenario's, each event's and each component's figures, as the record holds them.
    summaries = models.JSONField(null=True, blank=True)
    # The whole record the result digest is taken over.
    record = models.JSONField(null=True, blank=True)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()
    duration_ms = models.PositiveIntegerField()
    recorded_at = models.DateTimeField(default=timezone.now)
    # A residual run (spec, section 28): the remediation option whose control effect it
    # applies, named in its canonical inputs too. Null for the scenario as it is. A
    # residual run is never the scenario's exposure: the results route and the
    # scenario document serve only runs with none, and the ROI route serves this one.
    remediation = models.ForeignKey(
        "RemediationOption", on_delete=models.CASCADE, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["scenario", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scenario", "input_digest", "seed", "draws"], name="uq_econ_simulation_inputs"
            ),
            models.CheckConstraint(condition=Q(status__in=SIMULATION_STATUSES), name="ck_econ_simulation_status"),
            models.CheckConstraint(
                condition=(Q(status=SIMULATION_COMPLETED) & ~Q(result_digest="") & Q(refusal_code=""))
                | (Q(status=SIMULATION_REFUSED) & Q(result_digest="") & ~Q(refusal_code="")),
                name="ck_econ_simulation_outcome",
            ),
        ]

    @staticmethod
    def summaries_of(record) -> dict:
        """The figures a completed record holds: the scenario's and each event's,
        with their components'."""
        return {"scenario": record["scenario"], "events": record["events"]}

    def check_new(self) -> None:
        tenant = FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("deployment_id", flat=True)
        if list(tenant) != [self.deployment_id]:
            raise EconomicsRefused("cross_tenant_reference", "scenario")
        if not isinstance(self.seed, str) or not _SEED.fullmatch(self.seed) or int(self.seed) > _MAX_SEED:
            raise EconomicsRefused("result_malformed", f"seed {self.seed!r}")
        if type(self.draws) is not int or self.draws < 1:
            raise EconomicsRefused("result_malformed", f"draws {self.draws!r}")
        _require_text(severe_percentile=self.severe_percentile)
        _refuse(governance.snapshot_hash_refusal(self.input_digest), detail="input_digest")
        for name, document in (
            ("inputs", self.inputs),
            ("versions", self.versions),
            ("summaries", self.summaries),
            ("record", self.record),
        ):
            if _has_float(document):
                raise EconomicsRefused("result_malformed", f"{name} holds a float")
        if canonical_digest(self.inputs) != self.input_digest:
            raise EconomicsRefused("digest_mismatch", "input_digest")
        if self.status == SIMULATION_COMPLETED:
            _refuse(governance.snapshot_hash_refusal(self.result_digest), detail="result_digest")
            if self.refusal_code or not isinstance(self.record, dict):
                raise EconomicsRefused("result_malformed", "a completed result holds a record and no refusal")
            if canonical_digest(self.record) != self.result_digest:
                raise EconomicsRefused("digest_mismatch", "result_digest")
            held = (self.record.get("input_digest"), self.record.get("seed"), self.record.get("simulations"))
            if held != (self.input_digest, self.seed, self.draws) or self.summaries != self.summaries_of(self.record):
                raise EconomicsRefused("result_malformed", "the record is not this result's")
        elif self.status == SIMULATION_REFUSED:
            if not self.refusal_code or self.result_digest or self.record is not None or self.summaries is not None:
                raise EconomicsRefused("result_malformed", "a refused result holds a refusal code and no figures")
        else:
            raise EconomicsRefused("result_malformed", f"status {self.status!r}")
        if self.started_at is None or self.finished_at is None or self.finished_at < self.started_at:
            raise EconomicsRefused("date_inversion", "a result finishes after it starts")
        # A residual run names its option in its column and in its inputs, the same
        # one, of its own scenario version; any other run names none in either.
        block = self.inputs.get("remediation") if isinstance(self.inputs, dict) else None
        if self.remediation_id is None:
            if block is not None:
                raise EconomicsRefused("result_malformed", "a run whose inputs name a remediation option is residual")
        else:
            option = list(
                RemediationOption._base_manager.filter(pk=self.remediation_id).values_list(
                    "scenario_id", "uuid", "option_digest"
                )
            )
            named = (block.get("option"), block.get("option_digest")) if isinstance(block, dict) else None
            if len(option) != 1 or option[0][0] != self.scenario_id or named != (str(option[0][1]), option[0][2]):
                raise EconomicsRefused("result_malformed", "a residual run's inputs name its own option, of its scenario")
        if SimulationResult._base_manager.filter(
            scenario_id=self.scenario_id, input_digest=self.input_digest, seed=self.seed, draws=self.draws
        ).exists():
            raise EconomicsRefused("duplicate_id", "a result of the same inputs, seed and draws is recorded")
        self._result_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this result, whose :meth:`check_new` ran on exactly these values
        just before, inside the caller's transaction: an INSERT, never an UPDATE,
        and nothing read, so the transaction holds only the write (spec, section
        25.6). A run that raced past the check is stopped by the unique
        constraint. Any other row, or one changed since its check, is refused."""
        if not self._state.adding or getattr(self, "_result_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A simulation result is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"simulation of scenario {self.scenario_id}, seed {self.seed}, {self.draws} draws: {self.status}"


# ---------------------------------------------------------------------------
# FinancialValidityCard, FinancialExposureReceipt -- one simulation result graded,
# carded and receipted (step 8)
# ---------------------------------------------------------------------------

#: The confidence grades a card names (the owner's specification, section 8).
CARD_GRADES = ("A", "B", "C", "D", "Unknown")


def card_digest(card) -> str:
    """The digest a receipt names for a Validity Card: ``sha256:`` over the card's
    canonical JSON as ``mythos_core.exposure_receipt.card_digest_of`` writes it
    (sorted keys, no whitespace, UTF-8, no NaN), computed here without importing
    it, so loading the models loads no part of the receipt module."""
    text = json.dumps(card, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class FinancialValidityCard(_AppendOnly):
    """The Financial Exposure Validity Card of ONE simulation result (spec, section
    26.4; the owner's specification, sections 8 and 15): every field of the owner's
    table, each from the stored result, the scenario version's rows and the
    sensitivity analysis made on the run's own draws, or saying it has no data;
    the confidence grade with its reason; and what was read when the card was
    issued (the review status, the inventory entry, the findings' status, the
    deployment's system fingerprint where the scenario version records none), kept
    as issued.

    Append-only like every economics record, and IDEMPOTENT: one card per
    simulation result (a one-to-one key). The sensitivity analysis is stored with
    it, and the card names its digest. Nothing in it is a float; the card's digest
    is recomputed on save (``card_record_malformed``). No account column, so removing an
    operator never writes it; it goes with its deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    simulation = models.OneToOneField(SimulationResult, on_delete=models.CASCADE, related_name="+")
    schema = models.CharField(max_length=100)
    confidence_grade = models.CharField(max_length=16, choices=[(g, g) for g in CARD_GRADES])
    grade_version_digest = models.CharField(max_length=71)
    card = models.JSONField()
    card_digest = models.CharField(max_length=71)
    # The sensitivity analysis the card's most sensitive variables and evidence mix
    # are read from; null where the run was refused and nothing was analysed.
    sensitivity = models.JSONField(null=True, blank=True)
    sensitivity_digest = models.CharField(max_length=71, blank=True)
    issued_at = models.DateTimeField()
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]
        constraints = [
            models.CheckConstraint(condition=Q(confidence_grade__in=CARD_GRADES), name="ck_econ_card_grade"),
            models.CheckConstraint(
                condition=(Q(sensitivity__isnull=True) & Q(sensitivity_digest=""))
                | (Q(sensitivity__isnull=False) & ~Q(sensitivity_digest="")),
                name="ck_econ_card_sensitivity_digest",
            ),
        ]

    def check_new(self) -> None:
        simulation = SimulationResult._base_manager.filter(pk=self.simulation_id).values_list(
            "scenario_id", "deployment_id"
        )
        if list(simulation) != [(self.scenario_id, self.deployment_id)]:
            raise EconomicsRefused("cross_tenant_reference", "the card's simulation is another scenario's")
        scenario = FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("uuid", flat=True)
        if not isinstance(self.card, dict) or [str(u) for u in scenario] != [self.card.get("scenario_id")]:
            raise EconomicsRefused("card_record_malformed", "the card names another scenario")
        if self.card.get("confidence_grade") != self.confidence_grade or self.confidence_grade not in CARD_GRADES:
            raise EconomicsRefused("card_record_malformed", "the card's grade is not the row's")
        _require_text(schema=self.schema)
        _refuse(governance.snapshot_hash_refusal(self.grade_version_digest), detail="grade_version_digest")
        for name, document in (("card", self.card), ("sensitivity", self.sensitivity)):
            if _has_float(document):
                raise EconomicsRefused("card_record_malformed", f"the {name} holds a float")
        if card_digest(self.card) != self.card_digest:
            raise EconomicsRefused("card_record_malformed", "card_digest is not the card's")
        if self.sensitivity is None:
            if self.sensitivity_digest:
                raise EconomicsRefused("card_record_malformed", "a digest of no sensitivity analysis")
        elif canonical_digest(self.sensitivity) != self.sensitivity_digest:
            raise EconomicsRefused("card_record_malformed", "sensitivity_digest is not the analysis's")
        if self.issued_at is None:
            raise EconomicsRefused("card_record_malformed", "the card says when it was issued")
        if FinancialValidityCard._base_manager.filter(simulation_id=self.simulation_id).exists():
            raise EconomicsRefused("duplicate_id", "a card of this simulation result is recorded")
        self._card_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this card, whose :meth:`check_new` ran on exactly these values just
        before, inside the caller's transaction: an INSERT and nothing read (as
        :meth:`SimulationResult.insert_checked`)."""
        if not self._state.adding or getattr(self, "_card_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A Validity Card is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"validity card of simulation {self.simulation_id}: grade {self.confidence_grade}"


class FinancialExposureReceipt(_AppendOnly):
    """The signed Financial Exposure Receipt of ONE simulation result and its card
    (spec, section 26.5): the ``mythos.financial-exposure-receipt/v1`` document
    ``mythos_core.exposure_receipt`` built, and the DSSE envelope signed over it.

    Append-only like every economics record, and IDEMPOTENT: one receipt per
    simulation result, and per card (one-to-one keys), so the same result returns
    the same row. On save, the envelope's payload must be exactly the document's
    canonical bytes, and the document must name this row's card, scenario and
    tenant (``receipt_record_malformed``). No account column; it goes with its
    deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    simulation = models.OneToOneField(SimulationResult, on_delete=models.CASCADE, related_name="+")
    card = models.OneToOneField(FinancialValidityCard, on_delete=models.CASCADE, related_name="+")
    receipt_id = models.CharField(max_length=32)
    document = models.JSONField()
    envelope = models.JSONField()
    key_id = models.CharField(max_length=128)
    generated_at = models.DateTimeField()
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]

    def check_new(self) -> None:
        card = FinancialValidityCard._base_manager.filter(pk=self.card_id).values_list(
            "simulation_id", "scenario_id", "deployment_id", "card_digest"
        )
        card = list(card)
        if not card or card[0][:3] != (self.simulation_id, self.scenario_id, self.deployment_id):
            raise EconomicsRefused("cross_tenant_reference", "the receipt's card is another result's")
        residual = SimulationResult._base_manager.filter(pk=self.simulation_id).values_list("remediation_id", flat=True)
        if any(option is not None for option in residual):
            raise EconomicsRefused(
                "receipt_record_malformed", "a residual run under a remediation option is not receipted: not exposure"
            )
        try:
            # Imported on use, never at load: the models' import loads no part of
            # the receipt module (spec, section 26.7).
            from mythos_core import exposure_receipt as core
            from mythos_core.outcome import canonical_bytes

            document = core.validate_receipt(dict(self.document))
            payload = canonical_bytes(document)
        except Exception as error:  # noqa: BLE001 - every fault of the document is this row's refusal
            raise EconomicsRefused("receipt_record_malformed", f"{type(error).__name__}: {error}") from None
        scenario = FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("uuid", flat=True)
        # The tenant is the deployment (a Deployment IS the tenant boundary).
        deployments = self._meta.get_field("deployment").related_model._base_manager
        deployment = deployments.filter(pk=self.deployment_id).values_list("uuid", flat=True)
        named = (
            document["scenario_id"],
            document["tenant_id"],
            document["receipt_id"],
            document["validity_card"]["digest"],
        )
        expected = (
            str(next(iter(scenario), "")),
            str(next(iter(deployment), "")),
            self.receipt_id,
            card[0][3],
        )
        if named != expected:
            raise EconomicsRefused("receipt_record_malformed", "the document names another scenario, tenant, id or card")
        envelope = self.envelope
        try:
            signatures = envelope["signatures"]
            (signature,) = signatures
            sig = signature["sig"]
            # Core's signature form: the 88-character base64 of a 64-byte Ed25519
            # signature, as its verifier reads one, checked before anything is stored.
            ok = (
                set(envelope) == {"payloadType", "payload", "signatures"}
                and envelope["payloadType"] == core.RECEIPT_PAYLOAD_TYPE
                and base64.b64decode(envelope["payload"], validate=True) == payload
                and isinstance(signatures, list)
                and isinstance(signature, dict)
                and set(signature) == {"keyid", "sig"}
                and isinstance(signature["keyid"], str)
                and signature["keyid"] == self.key_id
                and isinstance(sig, str)
                and len(sig) == core.SIGNATURE_B64_LENGTH
                and len(base64.b64decode(sig, validate=True)) == 64
            )
        except (TypeError, KeyError, ValueError, binascii.Error):
            ok = False
        if not ok:
            raise EconomicsRefused(
                "receipt_record_malformed", "the envelope is not one well-formed signature over exactly the document"
            )
        if FinancialExposureReceipt._base_manager.filter(
            Q(simulation_id=self.simulation_id) | Q(card_id=self.card_id)
        ).exists():
            raise EconomicsRefused("duplicate_id", "a receipt of this simulation result is recorded")
        self._receipt_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this receipt, checked just before on exactly these values: an
        INSERT and nothing read."""
        if not self._state.adding or getattr(self, "_receipt_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A receipt is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"exposure receipt {self.receipt_id} of simulation {self.simulation_id}"


# ---------------------------------------------------------------------------
# SimulationCharts -- one simulation result's chart-ready series (step 6)
# ---------------------------------------------------------------------------


class SimulationCharts(_AppendOnly):
    """The chart-ready series of ONE completed simulation result (spec, section
    27.4): for each line of the scenario, the exceedance curve at fixed
    probabilities and a histogram, made on the run's own draws
    (``engine.charts.series``), so the report never runs a simulation to draw them.

    Append-only like every economics record, and IDEMPOTENT: one series per result
    (a one-to-one key). Nothing in it is a float, and its digest is recomputed on
    save (``charts_record_malformed``). No account column, so removing an operator
    never writes it; it goes with its deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    scenario = models.ForeignKey(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    simulation = models.OneToOneField(SimulationResult, on_delete=models.CASCADE, related_name="+")
    schema = models.CharField(max_length=100)
    charts = models.JSONField()
    charts_digest = models.CharField(max_length=71)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]

    def check_new(self) -> None:
        simulation = list(
            SimulationResult._base_manager.filter(pk=self.simulation_id).values_list(
                "scenario_id", "deployment_id", "status", "seed", "draws", "input_digest", "record"
            )
        )
        if len(simulation) != 1 or simulation[0][:2] != (self.scenario_id, self.deployment_id):
            raise EconomicsRefused("cross_tenant_reference", "the series' simulation is another scenario's")
        _, _, status, seed, draws, input_digest, record = simulation[0]
        if status != SIMULATION_COMPLETED or not isinstance(record, dict):
            raise EconomicsRefused("charts_record_malformed", "a refused run has no draws to chart")
        scenario = FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("uuid", flat=True)
        charts = self.charts
        if not isinstance(charts, dict) or charts.get("schema") != self.schema:
            raise EconomicsRefused("charts_record_malformed", "the series is not an object of its schema")
        named = (charts.get("scenario_id"), charts.get("seed"), charts.get("draws"), charts.get("input_digest"),
                 charts.get("outcomes_sha256"))
        if named != (*[str(u) for u in scenario], seed, draws, input_digest, record.get("outcomes_sha256")):
            raise EconomicsRefused("charts_record_malformed", "the series is not this result's")
        _require_text(schema=self.schema)
        if _has_float(charts):
            raise EconomicsRefused("charts_record_malformed", "the series holds a float")
        if canonical_digest(charts) != self.charts_digest:
            raise EconomicsRefused("charts_record_malformed", "charts_digest is not the series'")
        if SimulationCharts._base_manager.filter(simulation_id=self.simulation_id).exists():
            raise EconomicsRefused("duplicate_id", "a series of this simulation result is recorded")
        self._charts_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this series, whose :meth:`check_new` ran on exactly these values just
        before, inside the caller's transaction: an INSERT and nothing read (as
        :meth:`SimulationResult.insert_checked`)."""
        if not self._state.adding or getattr(self, "_charts_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A chart series is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"chart series of simulation {self.simulation_id}"


# ---------------------------------------------------------------------------
# RemediationOption -- one remediation option of a scenario version (step 13)
# ---------------------------------------------------------------------------


class RemediationOption(_AppendOnly):
    """ONE remediation option of ONE scenario version (spec, section 28; the owner's
    specification, section 21 and the ``MitigationOption`` of section 15): what it
    costs to implement and to run for a year, how long it takes, what it depends on
    (text, or SPINE ids, never copies), its control effect (a frequency reduction
    and/or a magnitude reduction, each a ratio with a low, base and high and a source,
    acting on every component or on the families or components it names), the retest
    an observed control effect was observed in, and the evidence that legitimate use
    survives, if any. Its document is held to every rule of its form on save, in its
    one spelling, and its digest is the document's for its scenario version: the
    residual run names that digest in its canonical inputs.

    Append-only like every economics record, and ONE per scenario version (a
    one-to-one key, and ``remediation_option_held``): another option is a new
    version. It names its author as a scenario does: the account, nulled if the
    account is removed (a stop), and the account's own username, kept. It goes with
    its deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessors: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    scenario = models.OneToOneField(FinancialScenario, on_delete=models.CASCADE, related_name="+")
    title = models.CharField(max_length=255)
    # The option as engine.remediation.parse_option holds it, in its one spelling.
    document = models.JSONField()
    option_digest = models.CharField(max_length=71)
    currency = models.CharField(max_length=3)
    time_to_implement_days = models.PositiveIntegerField()
    # The retest record a control effect was observed in, and the one cited for
    # utility retained, each by its digest (engine.remediation.RETEST_CITATION_SCHEMA);
    # blank where none is cited.
    observed_by = models.CharField(max_length=71, blank=True)
    utility_evidence = models.CharField(max_length=71, blank=True)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_remediation_options_authored",
    )
    author_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scenario", "id"]

    def option(self):
        """The option the stored document states, as the engine reads it."""
        from .engine import remediation as engine_remediation

        return engine_remediation.parse_option(self.document)

    def check_new(self) -> None:
        from .engine import remediation as engine_remediation

        scenario = list(FinancialScenario._base_manager.filter(pk=self.scenario_id).values_list("deployment_id", "uuid"))
        if not scenario or scenario[0][0] != self.deployment_id:
            raise EconomicsRefused("cross_tenant_reference", "the option's scenario is another deployment's")
        try:
            option = engine_remediation.parse_option(self.document)
        except (engine_remediation.RemediationRefused, parameters.ParameterRefused, money.MoneyRefused) as refused:
            raise EconomicsRefused("remediation_record_malformed", f"{refused.code}: {refused.detail}") from None
        if dict(option.document) != self.document:
            raise EconomicsRefused("remediation_record_malformed", "the document is not in its one spelling")
        if engine_remediation.option_digest(str(scenario[0][1]), option.document) != self.option_digest:
            raise EconomicsRefused("remediation_record_malformed", "option_digest is not the document's")
        held = (self.title, self.currency, self.time_to_implement_days, self.observed_by, self.utility_evidence)
        stated = (option.title, option.currency, option.time_to_implement_days, option.observed_by or "",
                  option.utility_evidence or "")
        if held != stated:
            raise EconomicsRefused("remediation_record_malformed", "a column is not the document's")
        built = ScenarioBuild._base_manager.filter(scenario_id=self.scenario_id).values_list("currency", flat=True)
        for currency in built:
            if currency != self.currency:
                raise EconomicsRefused(
                    "currency_mismatch", f"the option costs {self.currency}; the scenario is built in {currency}"
                )
        if RemediationOption._base_manager.filter(scenario_id=self.scenario_id).exists():
            raise EconomicsRefused("remediation_option_held", f"scenario {scenario[0][1]}")
        self.author_username = _signed_in(self.author).username
        self._option_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this option, checked just before on exactly these values: an INSERT
        and nothing read (as :meth:`SimulationResult.insert_checked`)."""
        if not self._state.adding or getattr(self, "_option_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A remediation option is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"remediation option {self.title}"


# ---------------------------------------------------------------------------
# CorrelationGroup -- one authored version of one correlation group (E5)
# ---------------------------------------------------------------------------

#: A correlation group's key; its strength's floor and ceiling (the portfolio
#: engine's ``STRENGTH_MIN`` and ``STRENGTH_MAX``, held equal by a test: the engine
#: imports numpy, so it is not imported here); how many scenario versions it names;
#: and its evidence's longest.
GROUP_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,59}")
GROUP_STRENGTH_MIN = Decimal("0.000001")
GROUP_STRENGTH_MAX = Decimal(10)
GROUP_MAX_SCENARIOS = 50
GROUP_MAX_EVIDENCE = 500
_SCENARIO_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class CorrelationGroup(_AppendOnly):
    """One version of one correlation group of a deployment (spec, section 31.3; the
    section-28 audit's T4): its key, its STRENGTH (the variance of the group's
    common driver, as decimal text in its one spelling), the source that strength
    rests on and its evidence, and the scenario versions in it, recorded by an
    account at a time. A portfolio names the versions it draws with, by uuid, and
    records each with its author and time: a group is never supplied anonymously in
    a portfolio request.

    Append-only like every economics record: a changed group is a new version of its
    key (1, 2, ...: ``uq_econ_group_version``), never an edit. It names its author as
    a scenario does: the account, nulled if the account is removed (a stop), and the
    account's own username, kept. It goes with its deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    key = models.CharField(max_length=60)
    # One more than its key's latest in its deployment, assigned on save.
    version = models.PositiveIntegerField(editable=False)
    strength = models.CharField(max_length=32)
    source_type = models.CharField(max_length=32, choices=[(t, t) for t in _SOURCE_TYPE_CODES])
    evidence_ref = models.TextField()
    # The scenario versions' uuids, in order, each once.
    scenarios = models.JSONField()
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="economics_correlation_groups_authored",
    )
    author_username = models.CharField(max_length=150, blank=True, default="", editable=False)
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "key", "version"]
        constraints = [
            models.UniqueConstraint(fields=["deployment", "key", "version"], name="uq_econ_group_version"),
        ]

    def as_dict(self) -> dict:
        """The group version as a portfolio's inputs record it."""
        return {
            "uuid": str(self.uuid),
            "group": self.key,
            "version": self.version,
            "strength": self.strength,
            "source_type": self.source_type,
            "evidence_ref": self.evidence_ref,
            "scenarios": list(self.scenarios),
            "author": self.author_username or None,
            "recorded_at": self.recorded_at.isoformat(),
        }

    def check_new(self) -> None:
        deployments = self._meta.get_field("deployment").related_model._base_manager
        if not deployments.filter(pk=self.deployment_id).exists():
            raise EconomicsRefused("cross_tenant_reference", "the group's deployment is not recorded")
        if not isinstance(self.key, str) or not GROUP_KEY.fullmatch(self.key):
            raise EconomicsRefused("group_record_malformed", f"key {self.key!r}")
        try:
            strength = money.parse_decimal(self.strength, "strength")
        except money.MoneyRefused:
            strength = None
        if strength is None or money.decimal_text(strength) != self.strength or not (
            GROUP_STRENGTH_MIN <= strength <= GROUP_STRENGTH_MAX
        ):
            raise EconomicsRefused("group_record_malformed", f"strength {self.strength!r}")
        if self.source_type not in _SOURCE_TYPE_CODES:
            raise EconomicsRefused("group_record_malformed", f"source type {self.source_type!r}")
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref.strip() or len(
            self.evidence_ref
        ) > GROUP_MAX_EVIDENCE:
            raise EconomicsRefused("group_record_malformed", "evidence_ref")
        named = self.scenarios
        if (
            not isinstance(named, list) or not 2 <= len(named) <= GROUP_MAX_SCENARIOS
            or any(not isinstance(s, str) or not _SCENARIO_UUID.fullmatch(s) for s in named)
            or named != sorted(set(named))
        ):
            raise EconomicsRefused("group_record_malformed", "scenarios")
        held = FinancialScenario._base_manager.filter(deployment_id=self.deployment_id, uuid__in=named).count()
        if held != len(named):
            raise EconomicsRefused("cross_tenant_reference", "a scenario the group names is not its deployment's")
        latest = CorrelationGroup._base_manager.filter(deployment_id=self.deployment_id, key=self.key).aggregate(
            latest=Max("version")
        )["latest"]
        self.version = (latest or 0) + 1
        self.author_username = _signed_in(self.author).username

    def __str__(self) -> str:
        return f"correlation group {self.key} v{self.version}"


# ---------------------------------------------------------------------------
# PortfolioResult -- one deployment's scenarios aggregated from their draws (E5)
# ---------------------------------------------------------------------------


class PortfolioResult(_AppendOnly):
    """One portfolio of a deployment's scenarios, aggregated from their draws (spec,
    section 31): the seed and the draws; the canonical inputs -- each scenario
    included with its stored result's digests, its grade and its normalisation into
    the reporting currency, each scenario excluded with its reason, the correlation
    groups with their strengths and sources, the shared events counted once, every
    version and limit -- and their digest; the record of the figures and its digest,
    or the refusal's code.

    Append-only like every economics record, and IDEMPOTENT on its inputs: one row
    per deployment, input digest, seed and draws (``uq_econ_portfolio_inputs``); the
    same inputs return the row already recorded and never draw a second. Every check
    runs before the transaction, which only inserts. Nothing in it is a float, and
    both digests are recomputed on save (``portfolio_record_malformed``,
    ``digest_mismatch``). No account column: removing an operator, a stop, never
    writes it, and it goes with its deployment."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # No reverse accessor: see CustomerParameterSet.deployment.
    deployment = models.ForeignKey("assurance.Deployment", on_delete=models.CASCADE, related_name="+")
    # 0 to 2^64 - 1, as text: wider than a signed 64-bit column, and never a double.
    seed = models.CharField(max_length=20)
    draws = models.PositiveIntegerField()
    severe_percentile = models.CharField(max_length=32)
    reporting_currency = models.CharField(max_length=3)
    valuation_date = models.DateField()
    input_digest = models.CharField(max_length=71)
    result_digest = models.CharField(max_length=71, blank=True)
    status = models.CharField(max_length=16, choices=[(s, s) for s in SIMULATION_STATUSES])
    refusal_code = models.CharField(max_length=64, blank=True)
    refusal_detail = models.TextField(blank=True)
    # The canonical inputs the input digest is taken over, kept whole.
    inputs = models.JSONField()
    # The whole record the result digest is taken over; null for a refusal.
    record = models.JSONField(null=True, blank=True)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()
    duration_ms = models.PositiveIntegerField()
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "input_digest", "seed", "draws"], name="uq_econ_portfolio_inputs"
            ),
            models.CheckConstraint(condition=Q(status__in=SIMULATION_STATUSES), name="ck_econ_portfolio_status"),
            models.CheckConstraint(
                condition=(Q(status=SIMULATION_COMPLETED) & ~Q(result_digest="") & Q(refusal_code=""))
                | (Q(status=SIMULATION_REFUSED) & Q(result_digest="") & ~Q(refusal_code="")),
                name="ck_econ_portfolio_outcome",
            ),
        ]

    def check_new(self) -> None:
        deployments = self._meta.get_field("deployment").related_model._base_manager
        tenant = list(deployments.filter(pk=self.deployment_id).values_list("uuid", flat=True))
        if len(tenant) != 1:
            raise EconomicsRefused("cross_tenant_reference", "the portfolio's deployment is not recorded")
        if not isinstance(self.seed, str) or not _SEED.fullmatch(self.seed) or int(self.seed) > _MAX_SEED:
            raise EconomicsRefused("portfolio_record_malformed", f"seed {self.seed!r}")
        if type(self.draws) is not int or self.draws < 1:
            raise EconomicsRefused("portfolio_record_malformed", f"draws {self.draws!r}")
        _require_text(severe_percentile=self.severe_percentile)
        _engine_refusal(lambda: money.check_reporting_currency(self.reporting_currency, "reporting currency"))
        if self.valuation_date is None:
            raise EconomicsRefused("portfolio_record_malformed", "the portfolio has no valuation date")
        _refuse(governance.snapshot_hash_refusal(self.input_digest), detail="input_digest")
        for name, document in (("inputs", self.inputs), ("record", self.record)):
            if _has_float(document):
                raise EconomicsRefused("portfolio_record_malformed", f"{name} holds a float")
        if not isinstance(self.inputs, dict) or self.inputs.get("deployment") != str(tenant[0]):
            raise EconomicsRefused("portfolio_record_malformed", "the inputs name another deployment")
        held = (self.inputs.get("reporting_currency"), self.inputs.get("valuation_date"),
                self.inputs.get("severe_percentile"))
        if held != (self.reporting_currency, self.valuation_date.isoformat(), self.severe_percentile):
            raise EconomicsRefused("portfolio_record_malformed", "the inputs are not this row's")
        if canonical_digest(self.inputs) != self.input_digest:
            raise EconomicsRefused("digest_mismatch", "input_digest")
        if self.status == SIMULATION_COMPLETED:
            _refuse(governance.snapshot_hash_refusal(self.result_digest), detail="result_digest")
            if self.refusal_code or not isinstance(self.record, dict):
                raise EconomicsRefused("portfolio_record_malformed", "a completed portfolio holds a record, no refusal")
            if canonical_digest(self.record) != self.result_digest:
                raise EconomicsRefused("digest_mismatch", "result_digest")
            named = (self.record.get("input_digest"), self.record.get("seed"), self.record.get("simulations"),
                     self.record.get("reporting_currency"))
            if named != (self.input_digest, self.seed, self.draws, self.reporting_currency):
                raise EconomicsRefused("portfolio_record_malformed", "the record is not this portfolio's")
        elif self.status == SIMULATION_REFUSED:
            if not self.refusal_code or self.result_digest or self.record is not None:
                raise EconomicsRefused("portfolio_record_malformed", "a refused portfolio holds a code and no figures")
        else:
            raise EconomicsRefused("portfolio_record_malformed", f"status {self.status!r}")
        if self.started_at is None or self.finished_at is None or self.finished_at < self.started_at:
            raise EconomicsRefused("date_inversion", "a portfolio finishes after it starts")
        if PortfolioResult._base_manager.filter(
            deployment_id=self.deployment_id, input_digest=self.input_digest, seed=self.seed, draws=self.draws
        ).exists():
            raise EconomicsRefused("duplicate_id", "a portfolio of the same inputs, seed and draws is recorded")
        self._portfolio_checked = _checked_state(self)

    def insert_checked(self) -> None:
        """Insert this portfolio, whose :meth:`check_new` ran on exactly these values
        just before, inside the caller's transaction: an INSERT and nothing read (as
        :meth:`SimulationResult.insert_checked`)."""
        if not self._state.adding or getattr(self, "_portfolio_checked", None) != _checked_state(self):
            raise EconomicsRewriteRefused("A portfolio result is checked whole, then inserted unchanged.")
        self._insert_as_checked()

    def __str__(self) -> str:
        return f"portfolio of deployment {self.deployment_id}, seed {self.seed}, {self.draws} draws: {self.status}"


# ---------------------------------------------------------------------------
# A scenario build's rows: every check before its transaction, then only writes
# ---------------------------------------------------------------------------

_CHECKED = object()


class BuildRows:
    """Every row one scenario build writes (spec, section 24.6), made BEFORE its
    transaction: the scenario version, its build record, its parameters (each
    effect's attributes, then each event's larger-loss values), its loss events,
    effects, finding links and components, and the parameter-set rows those
    components cite, as read before.

    :func:`check_build_rows` runs every row's checks -- the ones :meth:`check_new`
    runs on a save -- against the build itself and what was recorded before it, and
    computes each component from the parameters it cites; :func:`insert_checked_rows`
    then only writes. So the build's transaction holds no read and computes nothing:
    on SQLite, a stop's write waits for the lock no longer than the inserts take
    (``test_a_builds_transaction_only_writes``). The database's constraints hold
    inside it as on any write."""

    def __init__(self, *, scenario, build, parameters, events, effects, links, components, set_parameters):
        self.scenario = scenario
        self.build = build
        self.parameters = list(parameters)
        self.events = list(events)
        self.effects = list(effects)
        self.links = list(links)
        self.components = list(components)
        # The parameter-set version's rows, by uuid: what a component may cite of it.
        self.set_parameters = dict(set_parameters)
        self._checked = None

    def in_order(self) -> list:
        """Every row, each after every row it refers to."""
        return [
            self.scenario, self.build, *self.parameters, *self.events, *self.effects, *self.links, *self.components
        ]


#: The only records a scenario build writes.
_BUILD_ROW_MODELS = (
    FinancialScenario, ScenarioBuild, FinancialParameter, LossEvent, CausalEffect, EffectFinding, LossComponent
)


def check_build_rows(rows: BuildRows) -> None:
    """Run every check of every row of ``rows`` -- the checks a save runs, each
    reading the build's own rows where a save reads the stored ones -- and compute
    every component. Refused with the same codes; reads only what was recorded
    before the build (the scenario it supersedes)."""
    scenario = rows.scenario
    for row in rows.in_order():
        if not row._state.adding:
            raise EconomicsRewriteRefused("A build writes new rows only.")
    scenario.check_new()  # its one read: the version it supersedes, recorded before
    build = rows.build
    build._check_form()
    if build.scenario is not scenario or build.deployment_id != scenario.deployment_id:
        raise EconomicsRefused("cross_tenant_reference", "scenario")
    if build.parameter_set.deployment_id != scenario.deployment_id:
        raise EconomicsRefused("cross_tenant_reference", "parameter_set")

    held: dict[str, FinancialParameter] = {}
    names: set[str] = set()
    for row in rows.parameters:
        if row.scenario is not scenario or row.parameter_set_id is not None:
            raise EconomicsRefused("parent_required")
        row._check_form()
        if row.name in names:
            raise EconomicsRefused("duplicate_id", f"parameter {row.name!r} twice in one parent")
        names.add(row.name)
        missing = [cited for cited in row.derived_from if cited not in held]
        if missing:
            raise EconomicsRefused("parameter_not_found", f"{row.name} is derived from a parameter of another parent")
        held[str(row.uuid)] = row
    for row in rows.set_parameters.values():
        if row.parameter_set_id != build.parameter_set.pk:
            raise EconomicsRefused("cross_tenant_reference", f"{row.name} is not the build's parameter set's")

    event_keys: set[str] = set()
    events = {id(event): event for event in rows.events}
    for event in rows.events:
        if event.scenario is not scenario:
            raise EconomicsRefused("cross_tenant_reference", "the event is another scenario's")
        event._check_form()
        if event.event_key in event_keys:
            raise EconomicsRefused("duplicate_id", f"event {event.event_key!r} twice in one scenario")
        event_keys.add(event.event_key)

    effect_keys: set[str] = set()
    observations: set[str] = set()
    spines: dict[str, tuple] = {}
    for effect in rows.effects:
        if effect.scenario is not scenario or id(effect.loss_event) not in events:
            raise EconomicsRefused("cross_tenant_reference", "the effect's loss event is another scenario's")
        effect._check_form()
        if effect.effect_key in effect_keys:
            raise EconomicsRefused("duplicate_id", f"effect {effect.effect_key!r} twice in one scenario")
        effect_keys.add(effect.effect_key)
        if effect.observation:
            if effect.observation in observations:
                raise EconomicsRefused("duplicate_id", f"observation {effect.observation} in two effects of one scenario")
            observations.add(effect.observation)
        if effect.spine_effect:
            declared = (effect.effect_type, effect.asset, effect.business_process)
            event_id, first = spines.setdefault(effect.spine_effect, (id(effect.loss_event), declared))
            if event_id != id(effect.loss_event):
                raise EconomicsRefused("duplicate_id", f"SPINE effect {effect.spine_effect} in two loss events")
            if first != declared:
                raise EconomicsRefused("duplicate_id", f"SPINE effect {effect.spine_effect} declared two ways")

    effects = {id(effect) for effect in rows.effects}
    pairs: set[tuple] = set()
    for link in rows.links:
        if id(link.effect) not in effects:
            raise EconomicsRefused("cross_tenant_reference", "the finding's effect is another scenario's")
        link._check_form()
        if (id(link.effect), link.finding) in pairs:
            raise EconomicsRefused("duplicate_id", f"finding {link.finding} enables one effect twice")
        pairs.add((id(link.effect), link.finding))

    citable = {**held, **rows.set_parameters}
    components: set[tuple] = set()
    for component in rows.components:
        event = component.loss_event
        if id(event) not in events:
            raise EconomicsRefused("cross_tenant_reference", "the component's event is another scenario's")
        _key(component.component_key, "component_key")
        if (id(event), component.component_key) in components:
            raise EconomicsRefused("duplicate_id", f"component {component.component_key!r} twice in one event")
        components.add((id(event), component.component_key))
        bindings = {}
        for name, key in component._cited().items():
            row = citable.get(str(key))
            if row is None:
                raise EconomicsRefused("parameter_not_found", f"{name}: {key}")
            bindings[name] = _engine_refusal(row.as_engine)
        component._record(component._compute(bindings, event.currency))
    for row in rows.in_order():
        row._build_checked = _CHECKED
    rows._checked = _CHECKED


def insert_checked_rows(rows: BuildRows) -> None:
    """Write ``rows``, which :func:`check_build_rows` checked whole: inserts only,
    each row after the rows it refers to, and nothing read or computed. Rows not
    checked so are refused, and nothing is written."""
    if rows._checked is not _CHECKED:
        raise EconomicsRewriteRefused("A build's rows are checked whole before any is written.")
    for row in rows.in_order():
        if not isinstance(row, _BUILD_ROW_MODELS):
            raise EconomicsRewriteRefused(f"A build writes no {type(row).__name__}.")
        row._insert_checked()
