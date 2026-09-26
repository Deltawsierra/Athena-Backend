"""Serializers for the assurance system-of-record API.

Read-heavy: the engine owns most finding fields, so the API exposes them
read-only and allows a human to change only the workflow fields (a finding's
status and owner). Secrets never appear here — the engine already redacts its
responses, and the API surfaces structured columns, not raw target material.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from .change import CHANGE_LABELS, age_days, change_status, is_stale
from .composition import EVIDENCE_LABELS, evidence_kind
from .receipt import finding_receipt
from .models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    ClaimEvent,
    DataBoundary,
    DeclaredComponent,
    Deployment,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
    RemediationEvent,
    RetestRequirement,
    Unknown,
    WorkflowChainOutcome,
    evidence_strength,
)

User = get_user_model()


def _owner_field() -> serializers.SlugRelatedField:
    """Owner as a **username**, read and write, rather than the raw user id a
    ModelSerializer would emit — a bare integer in the owner column is
    meaningless to a reader and to the dashboard."""
    return serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all(),
        allow_null=True,
        required=False,
    )


class EvidenceSerializer(serializers.ModelSerializer):
    classification_label = serializers.CharField(
        source="get_classification_display", read_only=True
    )

    class Meta:
        model = Evidence
        fields = [
            "uuid",
            "classification",
            "classification_label",
            "summary",
            "source",
            "content_hash",
            "created_at",
        ]
        read_only_fields = fields


class RemediationEventSerializer(serializers.ModelSerializer):
    """One attributed step in a finding's remediation workflow (Phase 2.3),
    read-only — events are written only through ``assurance.remediation`` so every
    move is validated and attributed."""

    from_state_label = serializers.CharField(source="get_from_state_display", read_only=True)
    to_state_label = serializers.CharField(source="get_to_state_display", read_only=True)
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)

    class Meta:
        model = RemediationEvent
        fields = [
            "uuid",
            "from_state",
            "from_state_label",
            "to_state",
            "to_state_label",
            "actor",
            "note",
            "created_at",
        ]
        read_only_fields = fields


class FindingSerializer(serializers.ModelSerializer):
    evidence = EvidenceSerializer(many=True, read_only=True)
    evidence_class = serializers.CharField(read_only=True)
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    # The asset this finding concerns, once discovery has attached it (Phase 1.1).
    asset_uuid = serializers.UUIDField(source="asset.uuid", read_only=True, allow_null=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    owner = _owner_field()
    # Remediation workflow (Phase 2.3): the human process axis, read-only here.
    # `remediation_state` moves only through the admin-gated, attributed transition
    # action (never a raw PATCH), so the state machine is always enforced; likewise
    # `assignee` is set through the assign action. Both are distinct from the
    # security disposition (`status`), which alone says whether the risk is live.
    remediation_state_label = serializers.CharField(
        source="get_remediation_state_display", read_only=True
    )
    assignee = serializers.CharField(source="assignee.username", read_only=True, allow_null=True)
    # Change intelligence + evidence expiration (spine, EXPOSE). Derived from the
    # existing first_seen/last_seen against the deployment's latest scan, which the
    # viewset supplies via serializer context ("latest_seen" / "now") in one query.
    change_status = serializers.SerializerMethodField()
    change_label = serializers.SerializerMethodField()
    age_days = serializers.SerializerMethodField()
    stale = serializers.SerializerMethodField()
    # Assurance receipt (spine, EXPOSE): a recomputable digest binding this finding
    # to its evidence hashes. Integrity/provenance, not proof the conclusion is
    # true — the evidence class carries how strongly it is known.
    receipt = serializers.SerializerMethodField()
    # What this status must not be read as, where the status has a wrong reading
    # worth naming. Served from the model's one table so the API and the dashboard
    # cannot each invent their own caveat -- a CONTAINED finding that a report
    # renders as "being fixed", or an INVALIDATED one it renders as an incident, is
    # the whole reason these states were added.
    status_must_not_imply = serializers.SerializerMethodField()
    # The disposition's own words. Without it a consumer has only the slug, and
    # the only way to render "contained" as anything a reader understands is to
    # write a label of its own -- which is how two surfaces end up disagreeing
    # about a state that exists *because* its wrong reading is easy. The caveat
    # beside it is served from the same table for the same reason.
    status_label = serializers.CharField(source="get_status_display", read_only=True)

    def get_status_must_not_imply(self, obj) -> str | None:
        return Finding.MUST_NOT_IMPLY.get(obj.status)

    class Meta:
        model = Finding
        fields = [
            "uuid",
            "deployment_uuid",
            "finding_type",
            "title",
            "severity",
            "confidence",
            "cvss_score",
            "cvss_vector",
            "status",
            "status_label",
            "status_must_not_imply",
            "risk_accepted_until",
            "owner",
            "assignee",
            "remediation_state",
            "remediation_state_label",
            "impact",
            "business_impact",
            "recommendation",
            "control_mapping",
            "location",
            "retest_required",
            "evidence_class",
            "evidence",
            "asset_uuid",
            "asset_name",
            "change_status",
            "change_label",
            "age_days",
            "stale",
            "receipt",
            "first_seen",
            "last_seen",
        ]
        # Only the human workflow fields are writable; everything else is the
        # engine's truth and is refreshed by ingestion, so it stays read-only.
        read_only_fields = [
            f
            for f in fields
            if f not in ("status", "risk_accepted_until", "owner", "business_impact")
        ]

    def validate(self, attrs):
        """An accepted risk names when its acceptance ends (owner decision Q6).

        Accepting a risk is a decision to carry it for a stated time. Without an
        end it was indistinguishable from fixing it -- the decision left the
        finding out entirely -- so an acceptance must name one, in the future, and
        any other status clears it: an expiry on a risk nobody accepted would say
        a decision was made that was not.
        """
        status = attrs.get("status", getattr(self.instance, "status", None))
        if status != Finding.Status.ACCEPTED:
            if attrs.get("risk_accepted_until") is not None:
                raise serializers.ValidationError(
                    {"risk_accepted_until": "Only an accepted risk has an acceptance to end."}
                )
            attrs["risk_accepted_until"] = None
            return attrs
        if (
            "risk_accepted_until" not in attrs
            and self.instance is not None
            and self.instance.status == Finding.Status.ACCEPTED
        ):
            # Already accepted, and this change leaves the acceptance alone: an
            # owner or impact edit is not a new acceptance, so it is not judged as
            # one. Judging it refused reassigning a finding whose acceptance had
            # lapsed or never named an end -- which the decision already holds at
            # NEEDS_MORE_EVIDENCE until someone accepts it again with an end.
            return attrs
        until = attrs.get("risk_accepted_until")
        if until is None:
            raise serializers.ValidationError(
                {"risk_accepted_until": "Accepting a risk needs the date its acceptance ends."}
            )
        if until <= timezone.now():
            raise serializers.ValidationError(
                {"risk_accepted_until": "An acceptance cannot end in the past."}
            )
        attrs["risk_accepted_until"] = until
        return attrs

    def _latest_seen(self, obj):
        return (self.context.get("latest_seen") or {}).get(obj.deployment_id)

    def get_change_status(self, obj) -> str:
        return change_status(obj, self._latest_seen(obj))

    def get_change_label(self, obj) -> str:
        return CHANGE_LABELS.get(self.get_change_status(obj), "")

    def get_age_days(self, obj):
        return age_days(obj, self.context.get("now"))

    def get_stale(self, obj) -> bool:
        return is_stale(obj, self.context.get("now"))

    def get_receipt(self, obj) -> dict:
        return finding_receipt(obj)


class AssetSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    classification_label = serializers.CharField(
        source="get_classification_display", read_only=True
    )
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    # The provider this asset resolves to, by uuid — the stable join key the
    # dashboard uses to link an asset to that provider's full assurance profile.
    # `provider` (the raw pk) is meaningless across origins; the name is not a
    # key. The uuid is how the asset graph draws its edge to the provider node.
    provider_uuid = serializers.UUIDField(source="provider.uuid", read_only=True, allow_null=True)
    provider_name = serializers.CharField(source="provider.name", read_only=True, allow_null=True)
    finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Asset
        fields = [
            "uuid",
            "deployment_uuid",
            "kind",
            "kind_label",
            "name",
            "identifier",
            "classification",
            "classification_label",
            "provider",
            "provider_uuid",
            "provider_name",
            "finding_count",
            "metadata",
            "first_seen",
            "last_seen",
        ]
        read_only_fields = fields


class ProviderAssertionSerializer(serializers.ModelSerializer):
    field_label = serializers.CharField(source="get_field_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    source_label = serializers.CharField(source="get_source_display", read_only=True)
    provider = serializers.SlugRelatedField(
        slug_field="uuid", queryset=Provider.objects.all()
    )
    provider_name = serializers.CharField(source="provider.name", read_only=True)
    updated_by = serializers.CharField(source="updated_by.username", read_only=True, allow_null=True)

    class Meta:
        model = ProviderAssertion
        fields = [
            "uuid",
            "provider",
            "provider_name",
            "field",
            "field_label",
            "value",
            "evidence_class",
            "evidence_class_label",
            "source",
            "source_label",
            "notes",
            "updated_by",
            "updated_at",
        ]
        read_only_fields = ["uuid", "provider_name", "updated_by", "updated_at"]

    def validate(self, attrs):
        """One assertion per field per provider — the profile holds a single
        value for each fact, updated in place rather than duplicated."""
        provider = attrs.get("provider") or getattr(self.instance, "provider", None)
        field = attrs.get("field") or getattr(self.instance, "field", None)
        if provider is not None and field is not None:
            qs = ProviderAssertion.objects.filter(provider=provider, field=field)
            if self.instance is not None:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError(
                    {"field": f"This provider already has a '{field}' assertion; edit it instead."}
                )
        return attrs


class ProviderProfileAssertionSerializer(serializers.ModelSerializer):
    """The read-only view of an assertion as it appears *inside* a provider's
    profile (its provider is implied by the parent)."""

    field_label = serializers.CharField(source="get_field_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    source_label = serializers.CharField(source="get_source_display", read_only=True)

    class Meta:
        model = ProviderAssertion
        fields = [
            "uuid",
            "field",
            "field_label",
            "value",
            "evidence_class",
            "evidence_class_label",
            "source",
            "source_label",
            "notes",
            "updated_at",
        ]
        read_only_fields = fields


class ProviderSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    assertions = ProviderProfileAssertionSerializer(many=True, read_only=True)
    # The honest headline for the whole profile: how many facts are recorded and
    # the *weakest* evidence among them, so a profile is never read as stronger
    # than its softest claim.
    profile = serializers.SerializerMethodField()

    class Meta:
        model = Provider
        fields = [
            "uuid",
            "name",
            "kind",
            "kind_label",
            "region",
            "notes",
            "evidence_class",
            "assertions",
            "profile",
        ]
        # Identity and the declared fields are admin-writable (enforced in the
        # view); uuid and the derived views are read-only.
        read_only_fields = ["uuid", "kind_label", "assertions", "profile"]

    def get_profile(self, obj) -> dict:
        classes = [a.evidence_class for a in obj.assertions.all()]
        weakest = max(classes, key=evidence_strength) if classes else None
        return {"declared_fields": len(classes), "weakest_evidence": weakest}


class UnknownSerializer(serializers.ModelSerializer):
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    impact_label = serializers.CharField(
        source="get_deployment_impact_display", read_only=True
    )
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    finding_uuid = serializers.UUIDField(source="finding.uuid", read_only=True, allow_null=True)
    owner = _owner_field()

    class Meta:
        model = Unknown
        fields = [
            "uuid",
            "deployment_uuid",
            "finding_uuid",
            "subject",
            "question",
            "why_it_matters",
            "evidence_needed",
            "deployment_impact",
            "impact_label",
            "status",
            "status_label",
            "source",
            "owner",
            "notes",
            "review_by",
            "first_seen",
            "last_seen",
        ]
        # A derived Unknown's substance is machine-owned and refreshed on
        # re-derive; a human works only the disposition fields.
        read_only_fields = [
            f
            for f in fields
            if f not in ("status", "owner", "notes", "review_by", "deployment_impact")
        ]


class DataBoundarySerializer(serializers.ModelSerializer):
    """The approved data boundary a human declares (Phase 1.4). Write-only shape:
    the assessment (approved-vs-actual) is computed and returned by the view, not
    stored here.

    Every field is optional (each maps to a model field with a default), so the
    view can drive both a true-replace PUT (it fills the fields the body omits from
    the model defaults) and a merge PATCH (``partial=True`` skips the omitted
    fields). The serializer only validates and shapes what is supplied; which
    omitted-field semantics apply is the view's decision."""

    class Meta:
        model = DataBoundary
        fields = ["allowed_regions", "training_allowed", "third_party_sharing_allowed", "notes"]

    def validate_allowed_regions(self, value):
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            raise serializers.ValidationError("allowed_regions must be a list of strings.")
        # Drop blanks and dedupe while preserving order.
        seen: list[str] = []
        for v in value:
            v = v.strip()
            if v and v not in seen:
                seen.append(v)
        return seen


class DeclaredComponentSerializer(serializers.ModelSerializer):
    """One component the customer declares their AI system is built from (SPINE
    Stage 3). The write shape is the declaration; ``uuid`` and the kind label are
    read-only for the dashboard."""

    kind_label = serializers.CharField(source="get_kind_display", read_only=True)

    class Meta:
        model = DeclaredComponent
        fields = ["uuid", "kind", "kind_label", "name", "identifier", "provider_name", "note"]
        read_only_fields = ["uuid", "kind_label"]

    def validate_name(self, value):
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("A declared component needs a name.")
        return value


class ApprovedWorkflowSerializer(serializers.ModelSerializer):
    """One approved business workflow — the unit the compositional assurance graph
    is scoped to (:mod:`assurance.composition`).

    The write shape is the DECLARATION: which workflows the customer has approved.
    That set is what lets the rule refuse its central silent zero -- "a deployment
    with fifty approved workflows and one chain, held, is not ready" only works if
    something knows the fifty.

    NO HAND-WRITTEN FIELD VALIDATORS, deliberately. The first draft of this class
    carried ``validate_slug`` and ``validate_name`` rejecting empty and
    whitespace-only values; both were removed once they were actually exercised,
    because the model fields already refuse every case they claimed to catch --
    ``slug`` is a :class:`~django.db.models.SlugField` and ``name`` a
    non-blank ``CharField``, so DRF derives ``allow_blank=False`` and trims before
    checking. A validator whose branch no input can reach reads as a control and
    enforces nothing, which is the exact shape this module's neighbours exist to
    refuse. What does the refusing is pinned by tests, so it cannot quietly go away
    if a field's type changes.
    """

    #: Who approved it, and when. The model keeps ``approved_by`` "for
    #: provenance" and nothing could read it back, which makes provenance a field
    #: the database holds and no reader can see -- a record kept for an audit that
    #: cannot reach it. Read-only: the approver is whoever made the request, not
    #: whoever the body says.
    approved_by = serializers.SerializerMethodField()
    approved_at = serializers.DateTimeField(source="created_at", read_only=True)

    class Meta:
        model = ApprovedWorkflow
        fields = [
            "uuid",
            "slug",
            "name",
            "description",
            "approved_by",
            "approved_at",
        ]
        read_only_fields = ["uuid"]

    def get_approved_by(self, obj) -> str | None:
        """The approver's username, or ``None`` when the account is gone.

        ``approved_by`` is ``SET_NULL``, so this really can be ``None``, and
        ``None`` means *the approver's account was deleted* -- not *nobody
        approved it*. The approval stands either way, which is why the FK does not
        cascade.
        """
        return obj.approved_by.username if obj.approved_by_id else None


class WorkflowChainOutcomeSerializer(serializers.ModelSerializer):
    """What one exercise of one workflow's authority-to-effect chain established.

    A REPORT AT AN INSTANT, not a standing declaration, and the difference decides
    the write shape: outcomes are appended, never replaced.
    :mod:`assurance.composition` picks the newest verdict per workflow and counts
    what a re-run superseded, so a replace-on-write would leave exactly one outcome
    per workflow and make supersession unreachable -- the rule would keep its logic
    and lose its input.

    ``workflow`` is a free slug on purpose. It is NOT validated against the
    approved set, because an outcome for a workflow nobody approved is exactly what
    :attr:`~assurance.composition.Composition.workflows_unapproved` exists to
    count; refusing it here would make that counter unreachable and this serializer
    the place the platform stopped noticing shadow workflows.

    ``observed_at`` may be omitted, and omitting it means *recency unknown* --
    which :func:`~assurance.composition.compose` handles explicitly, by treating an
    undated outcome as unable to supersede anything and impossible to supersede.
    A naive instant would break the rule's comparison, and does not need rejecting
    here: ``USE_TZ`` is on, so DRF's ``enforce_timezone`` makes an offset-less
    instant aware in the current zone before validation returns. A guard for it was
    written and then removed for being unreachable; the conversion is pinned by
    ``test_naive_observed_at_is_made_aware_rather_than_reaching_the_rule`` instead,
    so turning ``USE_TZ`` off fails a test rather than reaching the rule with a
    datetime it cannot compare.

    ``basis`` may be omitted, and omitting it means the record does not say what the
    row rests on -- which is exactly what every row written before the column
    existed says. It is NOT defaulted to ``attested``: a default that names an
    attester is a default that invents one, and a poster who did not make that
    claim should not have it made for them. It may not be ``demonstrated``, which
    only a verified signed outcome can establish (see ``validate_basis``).

    ``evidence_kind`` is derived, never posted: what kind of evidence the row is
    follows from who signed it (:func:`assurance.composition.evidence_kind`). A row
    Achilles signed is an ``authorization_check`` -- the gate authorized the
    workflow's action at dispatch, which shows the authority chain resolves and not
    that the effect happened -- and nothing yet records an ``observed_effect``.
    """

    status_label = serializers.CharField(source="get_status_display", read_only=True)
    basis_label = serializers.CharField(source="get_basis_display", read_only=True)
    #: When the outcome was RECORDED here, which is not when the chain was
    #: exercised. ``observed_at`` is the exercise; this is the write. A campaign
    #: replaying a month of history posts outcomes whose ``observed_at`` is old and
    #: whose ``recorded_at`` is now, and a reader who cannot see both cannot tell
    #: fresh measurement from backfill.
    recorded_at = serializers.DateTimeField(source="created_at", read_only=True)

    #: Whether this row's ``demonstrated`` is backed by a verified signed outcome.
    #: A reader deciding what the graph rests on should not have to infer it from
    #: which evidence columns happen to be blank.
    signed = serializers.SerializerMethodField()
    #: The basis the composition rule relies on for this row, which is ``basis``
    #: except where ``basis`` says demonstrated and no envelope verifies now --
    #: then attested. Published beside the column because the column alone let a
    #: row read ``basis: demonstrated, signed: false`` while the graph counted it
    #: attested: two answers about one row, and the more flattering one on it.
    basis_in_force = serializers.SerializerMethodField()
    #: What kind of evidence the row is, beside what it rests on. ``signed: true``
    #: with ``basis_in_force: demonstrated`` read as an effect somebody watched
    #: happen, and for an Achilles row it is a permit check: the reader could not
    #: tell the two apart from anything on the row.
    evidence_kind = serializers.SerializerMethodField()
    evidence_kind_label = serializers.SerializerMethodField()
    # Whether the row was taken against the route serving now: `current`, `moved`
    # or `unrecorded` (assurance.composition.CHAIN_ROUTES). Read-only, and never
    # the stored binding itself: that is a fingerprint, and what a reader needs is
    # whether it is the one serving.
    route = serializers.SerializerMethodField()

    class Meta:
        model = WorkflowChainOutcome
        fields = [
            "uuid",
            "workflow",
            "status",
            "status_label",
            "basis",
            "basis_label",
            "basis_in_force",
            "evidence_kind",
            "evidence_kind_label",
            "route",
            "observed_at",
            "recorded_at",
            "source",
            "note",
            "signed",
            "outcome_id",
            "observer_engine",
            "observer_key_id",
            "evidence_digest",
        ]
        read_only_fields = [
            "uuid",
            "status_label",
            "outcome_id",
            "observer_engine",
            "observer_key_id",
            "evidence_digest",
        ]

    def _basis_in_force(self, obj) -> str:
        """One verification per row, whichever field asks first, against one
        keyring read per serialisation rather than one per row."""
        cached = getattr(obj, "_basis_in_force", None)
        if cached is None:
            from . import observed_outcomes

            context = self.context
            if "chain_keyring" not in context:
                context["chain_keyring"] = observed_outcomes.trusted_keyring()
            cached = observed_outcomes.basis_in_force(
                obj, context["chain_keyring"], deployment_uuid=context.get("deployment_uuid")
            )
            obj._basis_in_force = cached
        return cached

    def get_basis_in_force(self, obj) -> str:
        return self._basis_in_force(obj)

    def get_evidence_kind(self, obj) -> str:
        # From the basis IN FORCE, never the column: a row whose signature no
        # longer verifies is attested, and the engine it names vouches for nothing.
        return evidence_kind(self._basis_in_force(obj), obj.observer_engine)

    def get_evidence_kind_label(self, obj) -> str:
        return EVIDENCE_LABELS[self.get_evidence_kind(obj)]

    def get_route(self, obj) -> str:
        """Compared with the route serving now, read once per serialisation and
        deployment rather than once per row."""
        from .served_route import served_route_fingerprint
        from .workflow_chains import route_of

        serving = self.context.setdefault("serving_routes", {})
        if obj.deployment_id not in serving:
            serving[obj.deployment_id] = served_route_fingerprint(obj.deployment)
        return route_of(obj, serving[obj.deployment_id])

    def get_signed(self, obj) -> bool:
        return (
            obj.basis == WorkflowChainOutcome.Basis.DEMONSTRATED
            and self._basis_in_force(obj) == WorkflowChainOutcome.Basis.DEMONSTRATED
        )

    def validate_basis(self, value):
        """``demonstrated`` means a run produced this outcome, and a POST is not a
        run. It used to be accepted here, which let the one field built to tell a
        measurement from an assertion be set by an assertion: fifty typed-in
        ``held`` rows marked demonstrated composed to READY with nothing exercised.
        A demonstrated outcome arrives only as a signed envelope an engine produced,
        through ``chain-outcomes/observed``."""
        if value == WorkflowChainOutcome.Basis.DEMONSTRATED:
            raise serializers.ValidationError(
                "demonstrated is recorded only from a verified signed outcome; post "
                "the engine's envelope to chain-outcomes/observed. An operator's own "
                "record is attested."
            )
        return value

    def validate_observed_at(self, value):
        """An observation cannot be dated after the moment it is recorded.

        Signed ingest already refuses a future ``observed_at``; this route did not,
        and recency is what decides which outcome stands. A typed-in row dated 2099
        would be the newest thing ever said about its workflow for seventy years.
        The same skew allowance as signed ingest, so the two doors agree about what
        "now" means."""
        from .observed_outcomes import MAX_CLOCK_SKEW

        if value is not None and value > timezone.now() + MAX_CLOCK_SKEW:
            raise serializers.ValidationError(
                f"observed_at {value.isoformat()} is in the future; an outcome is "
                "recorded after it is observed, not before"
            )
        return value


class ClaimEventSerializer(serializers.ModelSerializer):
    """One attributed step in an assurance claim's lifecycle (SPINE), read-only —
    events are written only through ``assurance.claims`` (a derive or an attributed
    transition), so every move is validated and attributed."""

    from_status_label = serializers.CharField(source="get_from_status_display", read_only=True)
    to_status_label = serializers.CharField(source="get_to_status_display", read_only=True)
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)

    class Meta:
        model = ClaimEvent
        fields = [
            "uuid",
            "from_status",
            "from_status_label",
            "to_status",
            "to_status_label",
            "actor",
            "note",
            "created_at",
        ]
        read_only_fields = fields


class RetestRequirementSerializer(serializers.ModelSerializer):
    """An open/closed retest obligation on a claim (SPINE Phase 2), read-only —
    obligations are written only through ``assurance.invalidation`` (a change opens
    one) and ``assurance.claims.derive_claims`` (a rebinding re-derivation resolves
    one), so every one is machine-attributed and never hand-edited into a dishonest
    state. Exposes uuids (never pks), the actor's username (null = the machine), and
    the timestamps — mirroring ``ClaimEventSerializer``."""

    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    claim_uuid = serializers.UUIDField(source="claim.uuid", read_only=True)
    claim_type = serializers.CharField(source="claim.claim_type", read_only=True)
    claim_type_label = serializers.CharField(
        source="claim.get_claim_type_display", read_only=True
    )
    resolving_claim_uuid = serializers.UUIDField(
        source="resolving_claim.uuid", read_only=True, allow_null=True
    )
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)
    is_open = serializers.BooleanField(read_only=True)

    class Meta:
        model = RetestRequirement
        fields = [
            "uuid",
            "deployment_uuid",
            "claim_uuid",
            "claim_type",
            "claim_type_label",
            "resolving_claim_uuid",
            "reason",
            "triggering_system_fingerprint",
            "actor",
            "is_open",
            "opened_at",
            "resolved_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AssuranceClaimSerializer(serializers.ModelSerializer):
    """A version-bound, falsifiable assurance claim (SPINE), read-only. Every field
    is machine-derived or moved through the attributed transition action; the API
    never lets a claim be hand-edited into a dishonest state. Human-readable labels
    ride alongside the raw enums, and ``is_stale`` is surfaced so a consumer sees an
    expired claim as expired."""

    claim_type_label = serializers.CharField(source="get_claim_type_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    assessment_label = serializers.SerializerMethodField()
    environment_label = serializers.CharField(source="get_environment_display", read_only=True)
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    asset_uuid = serializers.UUIDField(source="asset.uuid", read_only=True, allow_null=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    human_owner = serializers.CharField(
        source="human_owner.username", read_only=True, allow_null=True
    )
    superseded_by = serializers.UUIDField(
        source="superseded_by.uuid", read_only=True, allow_null=True
    )
    is_stale = serializers.BooleanField(read_only=True)

    class Meta:
        model = AssuranceClaim
        fields = [
            "uuid",
            "deployment_uuid",
            "asset_uuid",
            "asset_name",
            "claim_type",
            "claim_type_label",
            "statement",
            "fingerprint",
            "system_fingerprint",
            "policy_version",
            "environment",
            "environment_label",
            "status",
            "status_label",
            "evidence_class",
            "evidence_class_label",
            "confidence",
            "vendor_asserted",
            "assessment",
            "assessment_label",
            "supporting_summary",
            "contradicting_summary",
            "invalidation_conditions",
            "superseded_by",
            "human_owner",
            "receipt_digest",
            "is_stale",
            "valid_from",
            "valid_to",
            "verified_at",
            "expiration",
            "first_seen",
            "last_seen",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_assessment_label(self, obj) -> str | None:
        # None-safe: an unassessed deployment has no decision, and an absent
        # decision is never read as "ready".
        return obj.get_assessment_display() if obj.assessment else None


class DeploymentSerializer(serializers.ModelSerializer):
    decision_label = serializers.CharField(source="get_decision_display", read_only=True)
    finding_count = serializers.IntegerField(read_only=True)

    def to_representation(self, instance):
        # The deployment list and detail publish the stored decision, as the
        # receipt does; reconciled first with the keyring in force, or a
        # withdrawn key's READY stood here while the receipt said otherwise.
        # `current_decision` refreshes `instance`, so the decision, its label and
        # its revision below are all the reconciled ones.
        from .decision import current_decision

        current_decision(instance)
        return super().to_representation(instance)

    class Meta:
        model = Deployment
        fields = [
            "uuid",
            "name",
            "environment",
            "decision",
            "decision_label",
            # The monotonic revision this decision was written at. Served because
            # the revision fence was unreachable over HTTP: a consumer could read a
            # decision and had no way to tell a fresh one from one superseded
            # between its read and its action.
            "decision_revision",
            "description",
            "finding_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
