"""Read-focused API over the assurance system of record.

Findings, deployments, assets, and providers are exposed for the dashboard to
query. Findings are read-only except for the human workflow fields (status,
owner, business_impact) — the engine owns the rest and ingestion keeps it
current. Access follows the project's existing per-user ownership model: a caller
sees the deployments and findings tied to scans they can see (admins see all),
matching how ``pentest`` already scopes visibility.
"""

from __future__ import annotations

import logging
import uuid as uuidlib

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Count, Exists, OuterRef
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from django.db import transaction

from config.parsers import SafeJSONParser

from .access import assess_effective_access
from .bom import build_ai_bom
from .bom_drift import assess_bom_drift, record_bom_drift_findings
from .boundary import assess_boundary
from . import observability, observed_outcomes
from .bundle import assurance_bundle
from .claims import IllegalClaimTransition, apply_claim_transition, derive_claims
from .invalidation import check_invalidations as run_invalidation_check
from .latent import (
    LatentConditionRefused,
    condition_view,
    declare_condition,
    deployments_watching_boundary,
    deployments_watching_provider,
    fire_due_conditions,
    latent_posture,
    withdraw_condition,
)
from .business_impact import build_business_impact
from .capability import assess_capabilities
from .compliance import build_compliance_map
from .data_lifecycle import assess_data_lifecycle
from .coverage import coverage_manifest
from .decision import current_decision, decision_support, recompute_decision
from .revalidation import plan_revalidation
from .revision import logged_head
from .incident import assemble_incident_pack
from .metadata_logging import assess_metadata_logging
from .operational import assess_operational
from .operational_risk import assess_operational_risk
from .personal_context import assess_personal_context
from .training_reuse import assess_training_reuse
from .packs import UnknownPack, apply_pack, list_packs
from .roi import build_executive_summary
from .route import build_route_map
from .served_route import note_route_quietly, routes_for_outcomes
from .models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    ConnectorBinding,
    DataBoundary,
    DeclaredComponent,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
    LatentCondition,
    PostureBinding,
    Provider,
    ProviderAssertion,
    RetestRequirement,
    Unknown,
    WorkflowChainOutcome,
)
from .chain_registry import ChainBirthRefused, register_birth, registry_posture
from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

from .receipt import (
    NOT_SIGNED_OVER,
    NOT_SIGNED_OVER_REASON,
    NotAnEnvelope,
    build_assurance_receipt,
    deployment_receipt,
    envelope_over,
    signable_receipt,
    unsigned_reason_for,
)
from .vendor_packet import build_vendor_packet, packet_candidates
from .workflow_chains import (
    composition_decision_signal,
    composition_for,
    composition_payload,
    read_chain_provenance,
)
from .ripple import assess_ripple
from .remediation import IllegalTransition, apply_transition, assign
from .vendor import assess_vendors
from .serializers import (
    ApprovedWorkflowSerializer,
    AssetSerializer,
    AssuranceClaimSerializer,
    ClaimEventSerializer,
    DataBoundarySerializer,
    DeclaredComponentSerializer,
    DeploymentSerializer,
    FindingSerializer,
    ProviderAssertionSerializer,
    ProviderSerializer,
    RemediationEventSerializer,
    RetestRequirementSerializer,
    UnknownSerializer,
    WorkflowChainOutcomeSerializer,
)

User = get_user_model()


def _is_privileged(user) -> bool:
    """Who may *read* the whole assurance graph: admins and analysts. Other
    authenticated users see only their own (the read model is intentionally
    broad; writes are separately restricted to admins by ``_require_admin``)."""
    return bool(
        getattr(user, "is_superuser", False)
        or getattr(user, "is_admin", False)
        or getattr(user, "is_analyst", False)
    )


def _is_admin(user) -> bool:
    """Who may *write* to the assurance system of record. ``is_admin`` already
    includes superusers; analysts and below may read but not mutate."""
    return bool(getattr(user, "is_superuser", False) or getattr(user, "is_admin", False))


def _require_admin(request) -> None:
    """Gate a mutating action to admins. A write changes the shared system of
    record (a decision, a disposition), so it is admin-only even though reads are
    open — a non-admin gets a clean 403, not a silent success."""
    if not _is_admin(request.user):
        raise PermissionDenied("Changing the assurance record requires an admin role.")


def _rows_from_body(data, *, key: str, single_allowed: bool):
    """The rows a request body carries, as ``(rows, was_a_single_object)``.

    A body is a list of rows, or an object with ``key`` holding that list, or --
    when ``single_allowed`` -- one row on its own. Anything else is a 400 from
    here, and the alternative is not hypothetical: nine body shapes used to
    return 500.

    ``request.data.get(key, [])`` is an ``AttributeError`` on ``null``, a number,
    a bool or a string. And ``key not in request.data`` on a string is a
    SUBSTRING test, so the body ``"outcomes"`` routed as a batch and died on
    ``request.data["outcomes"]`` two frames later while ``"hello"`` routed as a
    single object and 400'd correctly -- two JSON strings, two code paths, one of
    them a 500.
    """
    if isinstance(data, list):
        return data, False
    if isinstance(data, dict):
        if key in data:
            rows = data[key]
            if not isinstance(rows, list):
                # `{"workflows": {...}}` and `{"workflows": null}` already reach
                # the serializer and 400 honestly; keep that, rather than
                # inventing a second error message for the same mistake.
                return rows, False
            return rows, False
        if single_allowed:
            return [data], True
        # Not "no rows": an object that does not carry the list is a body this
        # route cannot read, and a true-replace reading it as empty cleared the
        # whole set -- `PUT {"a": 1}` lifted every approved workflow's floor. An
        # empty set is said on purpose, as `[]` or `{key: []}`.
    raise ValidationError(
        {
            key: (
                f"Send a list of rows, or an object with a {key!r} list"
                + (", or one row on its own" if single_allowed else "")
                + f". Got {type(data).__name__}."
            )
        }
    )


def _refresh_stored_decision(deployment) -> None:
    """Recompute and persist the deployment's decision after an input to it moved:
    its findings, its claims, its declared architecture or its chains.

    The receipt and the bundle read the STORED decision, and only scan ingest and
    the recompute route refreshed it. So a workflow set or a chain outcome written
    over HTTP changed what decision-support computed live while the receipt kept
    reporting the decision from before -- a signed violation left a stored READY
    in place, read by every surface that trusts the record. Keeps an operator's
    failsafe pause as the LOCKED row holds it, not as this request first read it.

    Call it INSIDE the transaction that made the write, after the write. Called
    after that transaction committed, it left a window in which another reader saw
    the new input beside the old decision under one revision, and a refresh that
    failed there (a lock timeout) left the write standing and the decision stale
    for good -- a signed outcome cannot be posted twice to try again. Inside, the
    two commit together or neither does.

    A declared latent condition the write made true fires first (it marks its claim
    STALE and opens a retest), so the decision refreshed here reads it. The route the
    write left serving is noted beside it, so a run after it binds to it.
    """
    fire_due_conditions(deployment)
    note_route_quietly(deployment)
    recompute_decision(deployment)


def _fire_conditions(deployment_ids, actor) -> None:
    """Fire the declared latent conditions a write to something outside the
    decision's own inputs made true -- the data boundary, a provider's profile --
    on each deployment named, and refresh the decision of each where one fired.
    Call it inside the write's transaction."""
    for deployment in Deployment.objects.filter(pk__in=set(deployment_ids)).order_by("pk"):
        if fire_due_conditions(deployment, actor=actor):
            _refresh_stored_decision(deployment)


def _composition_payload(deployment) -> dict:
    """The deployment's live composition, in the shape the decision route publishes.

    The ingest routes below return this beside every read and every write, so an
    operator who declares an approved set or records an outcome is told in the same
    response what it did to the compositional assurance graph -- rather than
    writing, getting a 200, and having to go and ask a second endpoint whether
    anything changed. A write that reports only itself is how a set that fails to
    close scope looks exactly like one that closes it.

    The shape comes from :func:`assurance.workflow_chains.composition_payload`,
    which :func:`assurance.decision.decision_support` also uses. That keeps the two
    payloads the same SHAPE; it is the transaction below, not the shared builder,
    that keeps them the same ANSWER. An earlier version of this docstring claimed
    the builder alone meant "the two answers cannot drift", and that was false: the
    builder cannot drift, the answers demonstrably did, and only in the reassuring
    direction. Both halves are needed and both are here.

    ``signal`` is what the chains currently carry: these routes make no decision,
    so they have no failsafe to null it under. Whether the deployment is paused,
    and therefore whether that signal reached the decision at all, is the decision
    route's answer to give.
    """
    # ONE TRANSACTION, because `composition_for` takes TWO reads -- the outcomes,
    # then the approved set -- and an unfenced pair can describe a state the
    # database was never in. Measured on the unfenced version, against a writer
    # looping a cycle in which EVERY committed state was `not_recommended` or
    # `needs_more_evidence` and none was ever ready: 18 of 187 reads (9.6%)
    # published `signal: "ready"`, explanation and all. The fabricated answer is
    # the reassuring one, which is how this defect always presents.
    #
    # `decision.decision_support` has had this fence from the start, for the same
    # reason, and reading through it 372 times against the same writer fabricated
    # nothing. One line is the difference.
    #
    # The provenance census joins them inside the same fence. It is a THIRD read,
    # and leaving it outside would publish a census of one moment beside a
    # composition of another -- the same tear this comment is about, in the field
    # whose whole job is to say what the composition rests on.
    with transaction.atomic():
        composition = composition_for(deployment)
        provenance = read_chain_provenance(deployment)
    return composition_payload(
        composition,
        signal=composition_decision_signal(composition),
        provenance=provenance,
    )


# Form-encoded bodies send booleans as strings, and ``bool("false")`` is ``True``.
# These map a declared paused flag honestly so a request to LIFT a failsafe pause
# is never misread as a request to hold it.
_TRUE_STRINGS = frozenset({"true", "1", "yes", "on"})
_FALSE_STRINGS = frozenset({"false", "0", "no", "off", ""})


def _parse_paused(raw, default: bool) -> bool:
    """Parse the failsafe ``paused`` flag from a request body. Absent → ``default``
    (preserve current state). A real bool → itself. A string → mapped
    case-insensitively (``true/1/yes/on`` → True, ``false/0/no/off/""`` → False).
    Anything else raises ``ValidationError`` (HTTP 400) — a safety-relevant control
    on the failsafe path must never be guessed."""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        token = raw.strip().lower()
        if token in _TRUE_STRINGS:
            return True
        if token in _FALSE_STRINGS:
            return False
    raise ValidationError(
        {"paused": "Must be a boolean (true/false, 1/0, yes/no, on/off)."}
    )


def _valid_uuid(value: str) -> str | None:
    """A well-formed UUID string, or None. A malformed ``?deployment=`` filter
    must not reach the ORM as a raw string — that raises a Django ValidationError
    DRF does not catch, surfacing as a 500 instead of an empty result set."""
    try:
        return str(uuidlib.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


# Keys that must never be accepted into a binding's plaintext ``endpoint`` — the
# credential rides only in the encrypted column, set via the ``secret`` field.
_SECRETISH_ENDPOINT_KEYS = frozenset(
    {"token", "secret", "password", "secret_ciphertext", "credential", "api_key", "apikey"}
)


def _parse_bool_field(raw):
    """Parse a boolean from JSON/form input; returns ``(ok, value)``."""
    if isinstance(raw, bool):
        return True, raw
    if isinstance(raw, str):
        token = raw.strip().lower()
        if token in _TRUE_STRINGS:
            return True, True
        if token in _FALSE_STRINGS:
            return True, False
    return False, None


def _apply_credential_binding_write(binding, data):
    """Apply a per-tenant credential-binding write (connector or posture) from
    request data onto ``binding``, in place. Returns an error string on bad input,
    or ``None`` on success. The secret is WRITE-ONLY: it is accepted under
    ``secret``, encrypted immediately, and refused outright when no encryption key
    is configured (so a binding never silently persists an unusable/plaintext
    credential). A secret is never accepted inside ``endpoint``."""
    from .crypto import encryption_available

    if "endpoint" in data:
        endpoint = data.get("endpoint")
        if endpoint in (None, ""):
            endpoint = {}
        if not isinstance(endpoint, dict):
            return "endpoint must be an object of non-secret config fields."
        leaked = _SECRETISH_ENDPOINT_KEYS.intersection(k.lower() for k in endpoint)
        if leaked:
            return (
                "endpoint must not carry a credential "
                f"({', '.join(sorted(leaked))}); send it as write-only 'secret'."
            )
        binding.endpoint = dict(endpoint)
    if "enabled" in data:
        ok, value = _parse_bool_field(data.get("enabled"))
        if not ok:
            return "enabled must be a boolean."
        binding.enabled = value
    if "secret" in data:
        secret = data.get("secret")
        if secret:
            if not isinstance(secret, str):
                return "secret must be a string."
            if not encryption_available():
                return (
                    "No encryption key is configured (ASSURANCE_CREDENTIAL_KEY), so "
                    "a credential cannot be stored and the binding would be inert. "
                    "Configure a key before setting a secret."
                )
            binding.set_secret(secret)
        else:
            # An explicit empty secret clears the stored credential.
            binding.set_secret(None)
    return None


def _credential_binding_state(binding) -> dict:
    """The safe, JSON view of a credential binding — never the secret VALUE, only
    whether one is on file (``has_secret``) and whether the binding is operational.
    Used for both connector and posture bindings."""
    target_field = binding._target_field
    return {
        target_field: getattr(binding, target_field),
        "uuid": str(binding.uuid),
        "bound": True,
        "enabled": binding.enabled,
        "endpoint": binding.endpoint or {},
        "has_secret": binding.has_secret,
        "operational": binding.is_operational(),
        "updated_at": binding.updated_at.isoformat() if binding.updated_at else None,
    }


def _dispatch_policy_state(policy) -> dict:
    """The JSON view of a deployment's dispatch policy. ``None`` → the honest
    default: no policy, so auto-dispatch is off."""
    if policy is None:
        return {
            "configured": False,
            "enabled": False,
            "min_severity": None,
            "on_blocking_decision": False,
            "detail": "no dispatch policy configured; auto-dispatch is off for this deployment",
        }
    return {
        "configured": True,
        "enabled": policy.enabled,
        "min_severity": policy.min_severity,
        "on_blocking_decision": policy.on_blocking_decision,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


def _dispatch_attempt_state(attempt) -> dict:
    """The JSON view of a dispatch attempt — the auditable record of what was and
    was not sent. Carries no secret; ``detail`` is a human-readable line only."""
    return {
        "uuid": str(attempt.uuid),
        "finding": str(attempt.finding.uuid),
        "connector": attempt.connector,
        "outcome": attempt.outcome,
        "trigger": attempt.trigger,
        "detail": attempt.detail,
        "external_ref": attempt.external_ref or None,
        "attempts": attempt.attempts,
        "created_at": attempt.created_at.isoformat() if attempt.created_at else None,
        "updated_at": attempt.updated_at.isoformat() if attempt.updated_at else None,
    }


class DeploymentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = DeploymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    #: How many eligible findings `vendor_packet_candidates` returns at most.
    #: Matches REST_FRAMEWORK PAGE_SIZE, because a custom @action returning a bare
    #: Response does not pass through DEFAULT_PAGINATION_CLASS and so silently
    #: opts out of the bound the rest of the API keeps.
    CANDIDATE_PAGE_SIZE = 50

    def get_queryset(self):
        qs = Deployment.objects.all().annotate(
            finding_count=Count("findings"),
            # Lets the serializer reconcile the decision it publishes without a
            # query per row for a deployment whose stamp is current.
            has_chain_outcomes=Exists(WorkflowChainOutcome.objects.filter(deployment=OuterRef("pk"))),
        )
        if self.action != "recompute":
            # The head of each row's transition log, read with the row: what the
            # serializer holds a row behind its log to (`current_decision`),
            # without a query per row. Not on the route that pauses: it publishes
            # nothing off the row it loads -- `recompute_decision` reads the
            # decision in force under the row lock -- and nothing added for a
            # read may add a way for a pause to fail.
            qs = qs.annotate(**logged_head())
        user = self.request.user
        if _is_privileged(user):
            return qs
        # Own deployments, or deployments whose findings came from the user's scans.
        return qs.filter(owner=user).distinct()

    @action(detail=False, methods=["post"], url_path="check")
    def check(self, request):
        """Every assurance stream, across every deployment the caller can see.

        The per-deployment routes are the right shape for a dashboard, which asks
        one question at a time. They are the wrong shape for anything assessing
        the engine as a whole — a benchmark scoring recall across a portfolio, an
        export, an auditor's snapshot — which needs the verdicts Athena currently
        stands behind, consistently, in one read. Assembling that from the
        separate routes is not just slow: an ingest between two of them yields a
        bundle where a claim has been invalidated by drift the drift stream does
        not carry, and the inconsistency is indistinguishable from an engine that
        failed to invalidate.

        Read-only and computed: it creates nothing, recomputes nothing, and
        reports only what the owning modules already decided. Scoped exactly like
        the deployment list, so it can never widen what a caller may see.

        An optional ``deployments`` list of names narrows the portfolio; a name
        the caller cannot see is simply absent from the result rather than
        refused, because the request says nothing about whether such a deployment
        exists. ``deployments_assessed`` names what was actually read, so an
        empty portfolio is distinguishable from a portfolio of clean deployments
        — five empty streams otherwise read as "nothing failed".

        Any other key in the body is ignored. Callers driving this from a harness
        send their own bookkeeping (a scenario profile, a run id); that is theirs
        to track and nothing Athena should pretend to interpret.
        """
        queryset = self.get_queryset()
        names = request.data.get("deployments") if isinstance(request.data, dict) else None
        if names is not None:
            if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                raise ValidationError({"deployments": "must be a list of deployment names"})
            queryset = queryset.filter(name__in=names)
        return Response(assurance_bundle(queryset))

    @action(detail=False, methods=["get"], url_path="latency")
    def latency(self, request):
        """The p50/p95 latency table this worker process has accumulated.

        The rule is to measure before optimising, and the measurement has to be
        reachable: the recorder lives in this process, while the thing that drives
        a realistic workload -- a Minotaur campaign against the live stack -- is on
        the other side of HTTP. Without this route the only baseline available
        would be one taken from a test, which measures fixtures.

        Admin-only. The component names are the internal derivation steps in the
        order they run -- a map of the assessment pipeline -- which is the same
        reason the other structural reads are privileged. No deployment, no
        finding, no claim, no verdict: only step names and durations.

        The table is **per worker process**, and the response says so. Under a
        multi-worker WSGI server two consecutive requests can land on different
        workers and report different tables; that is the honest answer, because a
        p95 averaged across workers would hide a single slow one. A reader taking a
        baseline should hold the worker count in mind, which they cannot do if the
        response implies a single global table.

        ``samples`` travels with every row: a p95 over three observations is not a
        p95, and a reader has to be able to see that rather than be told it. An
        unmeasured table is an empty list, never zeroes -- a zero in a latency
        column reads as "instant" when it means "never measured".
        """
        _require_admin(request)
        rows = observability.latency_table()
        return Response(
            {
                "engine": observability.ENGINE,
                "tracing": observability.status(),
                "components": rows,
                "measured": bool(rows),
                "scope": "worker_process",
            }
        )

    @action(detail=True, methods=["post"])
    def recompute(self, request, uuid=None):
        """Recompute the deployment's six-state decision from its live findings.
        Accepts an optional ``paused`` flag (the operator failsafe state), which
        overrides to "Deployment paused". Admin-only: it mutates the record.

        A routine recompute must NOT silently clear an operator's failsafe pause:
        ``paused`` defaults to the deployment's *current* paused state, so a
        recompute preserves an existing "Deployment paused" unless the caller
        explicitly passes ``paused=false`` to lift it. (The ingest path guards
        this the same way; the manual path used to default to False and clear it.)"""
        _require_admin(request)
        deployment = self.get_object()
        # Absent -> None: keep whatever the LOCKED row says. Reading "currently
        # paused" here, before the lock, let a pause committed meanwhile be lifted.
        if not isinstance(request.data, dict):
            raise ValidationError({"paused": "Send an object, optionally with a boolean 'paused'."})
        raw_paused = request.data.get("paused")
        paused = None if raw_paused is None else _parse_paused(raw_paused, False)
        decision = recompute_decision(deployment, paused=paused)
        # Commercial spine: if the decision has entered a blocking state and this
        # deployment's policy opts into it, auto-dispatch its qualifying findings.
        # Inert-by-default and never fatal — a dispatch error must not break a
        # decision recompute — so it runs on commit and is wrapped.
        self._maybe_dispatch_on_blocking_decision(deployment)
        return Response({"decision": decision, "decision_label": deployment.get_decision_display()})

    def _maybe_dispatch_on_blocking_decision(self, deployment) -> None:
        """Schedule the blocking-decision dispatch on commit, wrapped so it can
        never break the recompute. A no-op unless the deployment has an enabled
        policy that opts into the decision trigger and the decision is blocking."""
        deployment_pk = deployment.pk

        def _run():
            try:
                from .dispatch import dispatch_for_blocking_decision

                fresh = Deployment.objects.get(pk=deployment_pk)
                dispatch_for_blocking_decision(fresh)
            except Exception:  # dispatch must never break a recompute
                logging.getLogger(__name__).exception(
                    "blocking-decision dispatch failed for deployment %s", deployment_pk
                )

        transaction.on_commit(_run)

    @action(detail=True, methods=["get"])
    def receipt(self, request, uuid=None):
        """The deployment's assurance receipt (spine, EXPOSE): a single
        recomputable digest over its findings' evidence hashes. A read — open to
        any authenticated operator, like the rest of the assurance reads — that
        lets an auditor verify the evidence is unaltered without trusting this
        server. It attests integrity, not that the conclusions are true."""
        deployment = Deployment.objects.prefetch_related("findings__evidence").get(pk=self.get_object().pk)
        return Response(deployment_receipt(deployment))

    @action(detail=True, methods=["get"], url_path="assurance-receipt")
    def assurance_receipt(self, request, uuid=None):
        """The deployment's full, versioned **Assurance Receipt** (commercial
        spine): the roadmap tuple — system, receipt version, policy, evidence
        root, result, per-assessment digests — as one deterministic, portable,
        signable payload (see :func:`assurance.receipt.build_assurance_receipt`
        and its ``RECEIPT_SCHEMA``).

        A read — open to any authenticated operator, like the rest of the
        assurance reads — and computed, never stored. It is the standardised,
        machine-readable superset of the bare ``receipt`` action, which stays as
        it was for existing callers.

        It attests integrity and provenance — that this is the assurance state
        that was recorded, unaltered — never that the conclusions are true or the
        system is secure. The dict is the canonical payload the engine signs; this
        backend does not sign."""
        deployment = (
            Deployment.objects.prefetch_related(
                "findings__evidence", "assets__provider__assertions"
            )
            .select_related("data_boundary")
            .get(pk=self.get_object().pk)
        )
        return Response(build_assurance_receipt(deployment))

    @action(detail=True, methods=["get"], url_path="signed-assurance-receipt")
    def signed_assurance_receipt(self, request, uuid=None):
        """The Assurance Receipt in a **signed DSSE envelope**, or an honest
        statement of why it is not signed.

        ``assurance-receipt`` returns the canonical payload and stays exactly as it
        was for existing callers; this is the signed surface beside it.

        WHAT COMES BACK IS CHECKED against what went out, before anything is
        called signed. Not the signature -- that needs the keyring and is the
        auditor's job -- but the weaker question this route can answer and was not
        asking: is the thing the engine returned an envelope at all, does it carry a
        signature, and does it contain the bytes we sent? ``signed: true`` used to
        mean only "the call did not raise", so ``{}``, a signature list of length
        zero, and an envelope attesting a different decision were all served as
        signed, beside a receipt that said otherwise. See
        :func:`assurance.receipt.envelope_over`.

        WHAT IS SIGNED is the receipt's signable projection
        (:func:`assurance.receipt.signable_receipt`), not the payload
        ``assurance-receipt`` serves. The full payload carries a ``computed_at``
        wall clock and its own ``signed: false`` self-report, and signing those
        would produce an envelope whose signed bytes deny their own signature and
        that differs on every read of an unchanged deployment. Both groups are
        already outside ``digest``, so the signed copy and the unsigned one carry
        the SAME digest and are checkably the same assurance state. ``receipt`` in
        this response is exactly the bytes that were signed -- serving a different
        document beside an envelope is the mismatch this route exists to prevent --
        and ``not_signed_over`` names what was left out and why.

        Signed on read, not stored. The projection is deterministic over stable
        content, so signing at read time yields the same envelope for the same
        state and there is nothing to go stale. Storing it would buy offline
        retention and introduce a class of bug this project has spent the quarter
        removing: a stored signature over an older assurance state, served beside a
        current receipt, is a signature that vouches for something other than what
        the reader is looking at.

        FAILS OPEN ABOUT ITS OWN FAILURE, never about the signature. When the
        engine cannot sign -- unreachable, no key, no keyring -- the response is
        200 with ``signed: false`` and the engine's own reason, and NO envelope.
        That is deliberate on both counts: a 500 would make an unsigned receipt
        indistinguishable from a broken server, and an envelope with an empty
        signature list would be a receipt that looks signed, which is worse than
        one that says it is not.

        What a verified signature establishes: this is the assurance state
        athena-backend recorded, unaltered since the engine signed it. Not that the
        assessment is correct or the system safe -- the receipt carries a
        ``needs_more_evidence`` result or a ``vendor_asserted`` claim at its true
        strength, and a valid signature over a weak claim is a valid signature over
        a weak claim.

        Verification is the auditor's job and is done OFFLINE, against the keyring
        the engine publishes, with ``tools/verify_receipt.py``. This route does not
        verify what it just asked to be signed; a checker that trusted the signer's
        own report would establish only that the engine agrees with itself.
        """
        deployment = (
            Deployment.objects.prefetch_related(
                "findings__evidence", "assets__provider__assertions"
            )
            .select_related("data_boundary")
            .get(pk=self.get_object().pk)
        )
        payload = signable_receipt(build_assurance_receipt(deployment))
        # One dict, spread into both branches, so the two answers can never drift
        # into different shapes. `signed` here is the OUTER, authoritative answer:
        # the projection deliberately drops the receipt's own `signed` field, and
        # a reader must have exactly one place to look.
        base = {
            "receipt": payload,
            # Derived from the constant, never restated. A literal that happened
            # to agree would hide a later divergence for exactly as long as it
            # kept agreeing, and the constant exists so "the route, the tests and
            # any future second signer cannot disagree about what was signed".
            "not_signed_over": {
                "fields": [field for field in NOT_SIGNED_OVER],
                "why": NOT_SIGNED_OVER_REASON,
            },
        }

        try:
            client = CyberEngineClient.from_settings()
            envelope = envelope_over(payload, client.sign_assurance_receipt(payload))
        except (EngineError, RuntimeError, NotAnEnvelope) as exc:
            # RuntimeError is from_settings' own refusal when the engine is not
            # configured at all. Both are "this deployment cannot sign", and the
            # reader needs to know which -- a missing setting and an engine with no
            # key are different things to go and fix.
            #
            # NotAnEnvelope is the third: the engine answered, and what it answered
            # is not an envelope over what we sent. That reads as unsigned for the
            # same reason the other two do -- there is no signature on this receipt
            # -- and NOT as a 500, because the receipt itself is still correct and
            # still worth reading. `signed: true` used to be set on the sole
            # condition that the call did not raise, so an empty dict, a signature
            # list of length zero, and an envelope attesting a DIFFERENT decision
            # were all served as signed. See `envelope_over`.
            # `str(exc)` used to go straight into `reason`. An EngineError message
            # carries the engine's own words -- reproduced against an unresolvable
            # host, it read:
            #
            #     Engine unreachable: HTTPConnectionPool(host='cyberengine.internal',
            #     port=8443) ... Failed to resolve 'cyberengine.internal'
            #
            # and a 500 from the engine carried up to 500 characters of its body:
            # source paths, a key path, an upstream address. This route is
            # IsAuthenticated, so that went to every reader, and none of it was ever
            # on the signed route. The message belongs in the log; the reason is said
            # in our own words. See `unsigned_reason_for`.
            logging.getLogger(__name__).warning(
                "assurance receipt for deployment %s could not be signed (%s): %s",
                deployment.uuid,
                type(exc).__name__,
                exc,
            )
            return Response(
                {**base, "signed": False, "reason": unsigned_reason_for(exc), "envelope": None}
            )

        return Response(
            {
                **base,
                "signed": True,
                "reason": None,
                "envelope": envelope,
                "verify": (
                    "verify offline against the engine's published keyring "
                    "(GET /api/assurance/keyring) with tools/verify_receipt.py. "
                    "A keyring taken from the same place as the receipt proves "
                    "only that they agree with each other."
                ),
            }
        )

    @action(detail=True, methods=["get"], url_path="vendor-packet-candidates")
    def vendor_packet_candidates(self, request, uuid=None):
        """Which of this deployment's findings a **vendor-coordination packet** can
        be built for (Phase 2 item 10).

        The packet route lives on the finding, and it REFUSES a finding that
        implicates no third party. Without this list a caller has to discover that
        by trying, one finding at a time, and a 409 is a poor way to learn which
        door to knock on. So the eligible set is its own read.

        Membership is exactly :func:`assurance.vendor_packet.packet_candidates`:
        read off the asset -> provider edge, never inferred from a title or a
        finding type. One function, called by both routes, so the list and the
        refusal can never disagree about who is eligible.

        ``total`` is the deployment's whole finding count beside the eligible one,
        because "three of forty implicate a vendor" and "three of three" are
        different situations and a bare list of three cannot tell them apart.

        ``eligible`` is BOUNDED, at ``CANDIDATE_PAGE_SIZE``. This route returns a
        bare ``Response``, so it does not pass through
        ``DEFAULT_PAGINATION_CLASS`` -- and the project's own settings say that
        class exists because "List endpoints returned every row. A hundred and
        fifty scans came back in one response, and nothing bounded it." A new list
        endpoint reintroducing that is the same defect with a newer date on it.
        The counts stay whole: ``eligible_count`` is how many are eligible, not how
        many were returned, so a truncated page cannot read as the complete set --
        which is the only way bounding a list is honest."""
        deployment = self.get_object()
        candidates = packet_candidates(deployment)
        page = candidates[: self.CANDIDATE_PAGE_SIZE]
        return Response(
            {
                "eligible": [
                    {
                        "uuid": str(finding.uuid),
                        "title": finding.title,
                        "severity": finding.severity,
                        "provider": finding.asset.provider.name,
                        "provider_kind": finding.asset.provider.kind,
                        "component_kind": finding.asset.kind,
                    }
                    for finding in page
                ],
                # Returned vs eligible, stated separately and always. `len(eligible)`
                # is not the count and must not be usable as one.
                "eligible_returned": len(page),
                "eligible_truncated": len(page) < len(candidates),
                "page_size": self.CANDIDATE_PAGE_SIZE,
                "eligible_count": len(candidates),
                "total": deployment.findings.count(),
                "basis": (
                    "A finding is eligible when its asset names a provider. Read off "
                    "that edge, never inferred from the finding's title or type: a "
                    "packet sent to a vendor who is not involved is worse than no "
                    "packet."
                ),
            }
        )

    @action(detail=True, methods=["post", "get"], url_path="chain-birth")
    def chain_birth(self, request, uuid=None):
        """Register, or read, the birth of an engine's tamper-evident chain.

        POST is how an engine reports ``{"chain", "birth_id", "born_at", "seq"}``
        from ``mythos_core.db.verify_scan_chain``. The first report establishes
        the baseline; every one after it is compared. A different birth for a
        chain already on file keeps the ORIGINAL, records the event beside it and
        raises an Unknown.

        This is the only check the engine cannot run on itself. Its chain
        integrity is good and all of it reads the same SQLite file, so deleting
        the rows, the head and the watermark and restarting produces a fresh
        chain with a genuine mac that verifies perfectly. Holding the first birth
        somewhere else is what makes that visible.

        Admin-only on write: it is the system of record for whether an engine's
        history is the one we first saw, and a caller that could overwrite it
        could launder exactly the erasure it exists to catch. GET is a read like
        the other assurance reads.
        """
        deployment = self.get_object()
        if request.method.lower() == "get":
            return Response(registry_posture(deployment))

        _require_admin(request)
        payload = request.data if isinstance(request.data, dict) else {}
        raw_seq = payload.get("seq")
        try:
            seq = int(raw_seq) if raw_seq not in (None, "") else None
        except (TypeError, ValueError):
            # A sequence we cannot read is reported as absent rather than zero.
            # Zero is a real sequence -- a freshly seeded chain -- and coercing
            # an unreadable value to it would forge the one number that says a
            # chain went backwards.
            seq = None
        try:
            result = register_birth(
                deployment,
                chain=str(payload.get("chain") or ""),
                birth_id=str(payload.get("birth_id") or ""),
                born_at=str(payload.get("born_at") or ""),
                seq=seq,
            )
        except ChainBirthRefused as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        birth = result["birth"]
        return Response(
            {
                "status": result["status"],
                "matched": result["matched"],
                "chain": birth.chain,
                "birth_id": birth.birth_id,
                "first_registered_at": birth.first_registered_at.isoformat(),
                "rebirth_count": birth.rebirth_count,
                # Said on every answer, including the matching ones: a match is a
                # statement about identity, never about the chain's contents.
                "note": (
                    "A matching birth means this is the chain we first saw. It "
                    "says nothing about what is in it -- the engine's own walk "
                    "does that -- and a chain absent from this registry has not "
                    "been checked rather than passed."
                ),
            },
            status=(
                status.HTTP_201_CREATED
                if result["status"] == "registered"
                else status.HTTP_200_OK
            ),
        )

    @action(detail=True, methods=["get"], url_path="connectors")
    def connectors(self, request, uuid=None):
        """List the outbound connectors and whether each is configured for THIS
        deployment (commercial spine). A read: an operator can see which
        integrations exist, which are live for this tenant (an operational
        per-deployment binding), and which are inert, without triggering anything.

        A connector counts as ``configured`` when this deployment has an
        operational binding for it (enabled, a decryptable credential on file, and
        every endpoint field present) OR a process-wide settings/env config exists.
        With neither — the default in this repo — it is inert, exactly as before.
        No credential value is ever returned, only whether one is on file."""
        from .connectors import available_connectors, build_connector

        deployment = self.get_object()  # scope/permission check on the deployment
        bindings = {
            b.connector: b
            for b in ConnectorBinding.objects.filter(deployment=deployment)
        }
        rows = []
        for name in available_connectors():
            binding = bindings.get(name)
            settings_configured = build_connector(name).configured
            operational = bool(binding and binding.is_operational())
            rows.append(
                {
                    "name": name,
                    "configured": operational or settings_configured,
                    "bound": binding is not None,
                    "binding_operational": operational,
                    "has_secret": bool(binding and binding.has_secret),
                }
            )
        return Response({"connectors": rows})

    @action(detail=True, methods=["post"], url_path=r"connectors/(?P<connector>[\w-]+)/push")
    def connector_push(self, request, uuid=None, connector=None):
        """Push one of the deployment's findings OUT into an external system as a
        ticket / issue / event (commercial spine). Admin-only: it is an outbound
        action against a customer's live GRC / CI-CD / SIEM.

        Body: ``{"finding": "<finding-uuid>"}``. The finding must belong to this
        deployment. The result is the connector's :class:`ConnectorResult` as a
        dict, always at HTTP 200 — read ``ok``, not the status code (the house
        idiom; cf. ``assurance_check``). With no credentials configured the
        connector is inert: it returns ``{"ok": false, "detail": "<name> not
        configured"}`` and makes no network call. Live wiring — a real transport
        bound to per-tenant credentials — is the deferred follow-up; until then a
        push against an unconfigured connector simply reports not-configured."""
        _require_admin(request)
        from .connectors import RequestsTransport, UnknownConnector, build_connector

        deployment = self.get_object()
        finding_uuid = _valid_uuid(request.data.get("finding"))
        if finding_uuid is None:
            return Response(
                {"detail": "A 'finding' UUID belonging to this deployment is required."},
                status=400,
            )
        try:
            finding = deployment.findings.get(uuid=finding_uuid)
        except Finding.DoesNotExist:
            return Response(
                {"detail": f"No such finding {finding_uuid!r} in this deployment."},
                status=404,
            )
        try:
            # Prefer this deployment's per-tenant binding when it is operational
            # (its endpoint + decrypted credential); otherwise fall back to the
            # process-wide settings/env config, which is inert in this repo.
            binding = ConnectorBinding.objects.filter(
                deployment=deployment, connector=connector
            ).first()
            if binding is not None and binding.is_operational():
                conn = binding.build_connector()
            else:
                conn = build_connector(connector)
        except UnknownConnector as exc:
            return Response({"detail": str(exc)}, status=400)
        # RequestsTransport is only ever *touched* when the connector is
        # configured; an inert connector short-circuits before any post.
        result = conn.push_finding(finding, transport=RequestsTransport())
        return Response(result.as_dict())

    @action(
        detail=True,
        methods=["get", "put", "delete"],
        url_path=r"connectors/(?P<connector>[\w-]+)/config",
    )
    def connector_config(self, request, uuid=None, connector=None):
        """Read or manage this deployment's per-tenant binding for one connector
        (commercial spine, admin-gated writes).

        GET (open read) returns the binding's non-secret state — endpoint config,
        whether a credential is on file (``has_secret``), and whether it is
        operational — or ``bound: false`` when there is none. The credential VALUE
        is never returned.

        PUT (admin) upserts the binding from ``{"enabled"?, "endpoint"?:{...},
        "secret"?}``. ``secret`` is write-only and encrypted at rest; it is refused
        with a clear 400 when no ``ASSURANCE_CREDENTIAL_KEY`` is configured, so a
        binding never persists an unusable/plaintext credential. An empty
        ``secret`` clears the stored one.

        DELETE (admin) removes the binding (the connector reverts to inert)."""
        from .connectors import UnknownConnector, get_connector_class

        deployment = self.get_object()
        try:
            get_connector_class(connector)
        except UnknownConnector as exc:
            return Response({"detail": str(exc)}, status=400)

        binding = ConnectorBinding.objects.filter(
            deployment=deployment, connector=connector
        ).first()

        if request.method == "GET":
            if binding is None:
                return Response({"connector": connector, "bound": False})
            return Response(_credential_binding_state(binding))

        _require_admin(request)

        if request.method == "DELETE":
            if binding is not None:
                binding.delete()
            return Response(status=204)

        # PUT — upsert.
        creating = binding is None
        if creating:
            binding = ConnectorBinding(
                deployment=deployment,
                connector=connector,
                created_by=request.user,
            )
        error = _apply_credential_binding_write(binding, request.data)
        if error:
            return Response({"detail": error}, status=400)
        try:
            binding.full_clean(exclude=["created_by"])
        except DjangoValidationError as exc:
            return Response(getattr(exc, "message_dict", {"detail": exc.messages}), status=400)
        binding.save()
        return Response(_credential_binding_state(binding), status=201 if creating else 200)

    @action(
        detail=True,
        methods=["get", "put", "delete"],
        url_path=r"posture/(?P<domain>[\w-]+)/config",
    )
    def posture_config(self, request, uuid=None, domain=None):
        """Read or manage this deployment's per-tenant binding for one posture
        domain (cloud / secrets / repo), admin-gated writes. Same discipline as
        :meth:`connector_config`: a write-only, encrypted-at-rest ``secret`` refused
        when no key is configured; the credential VALUE is never returned; DELETE
        reverts the domain to inert (``connected: false``, catalog only)."""
        from .posture import UnknownPostureDomain, get_assessment_class

        deployment = self.get_object()
        try:
            get_assessment_class(domain)
        except UnknownPostureDomain as exc:
            return Response({"detail": str(exc)}, status=400)

        binding = PostureBinding.objects.filter(
            deployment=deployment, domain=domain
        ).first()

        if request.method == "GET":
            if binding is None:
                return Response({"domain": domain, "bound": False})
            return Response(_credential_binding_state(binding))

        _require_admin(request)

        if request.method == "DELETE":
            if binding is not None:
                binding.delete()
            return Response(status=204)

        creating = binding is None
        if creating:
            binding = PostureBinding(
                deployment=deployment,
                domain=domain,
                created_by=request.user,
            )
        error = _apply_credential_binding_write(binding, request.data)
        if error:
            return Response({"detail": error}, status=400)
        try:
            binding.full_clean(exclude=["created_by"])
        except DjangoValidationError as exc:
            return Response(getattr(exc, "message_dict", {"detail": exc.messages}), status=400)
        binding.save()
        return Response(_credential_binding_state(binding), status=201 if creating else 200)

    @action(detail=True, methods=["get", "put"], url_path="dispatch-policy")
    def dispatch_policy(self, request, uuid=None):
        """Read or set this deployment's automated-dispatch policy (commercial
        spine).

        GET (open read) returns the policy, or the honest default (``configured:
        false`` — no policy, so auto-dispatch is off). PUT (admin) upserts it from
        ``{"enabled"?, "min_severity"?, "on_blocking_decision"?}``. A policy is OFF
        by default and per deployment: with none, or one left disabled, nothing
        auto-dispatches and the manual push stays the only outbound path."""
        from .models import SEVERITY_CHOICES

        deployment = self.get_object()
        policy = DispatchPolicy.objects.filter(deployment=deployment).first()

        if request.method == "GET":
            return Response(_dispatch_policy_state(policy))

        _require_admin(request)
        if policy is None:
            policy = DispatchPolicy(deployment=deployment, created_by=request.user)

        data = request.data
        if "enabled" in data:
            ok, value = _parse_bool_field(data.get("enabled"))
            if not ok:
                return Response({"detail": "enabled must be a boolean."}, status=400)
            policy.enabled = value
        if "on_blocking_decision" in data:
            ok, value = _parse_bool_field(data.get("on_blocking_decision"))
            if not ok:
                return Response(
                    {"detail": "on_blocking_decision must be a boolean."}, status=400
                )
            policy.on_blocking_decision = value
        if "min_severity" in data:
            sev = str(data.get("min_severity")).strip().lower()
            if sev not in {choice for choice, _ in SEVERITY_CHOICES}:
                return Response(
                    {"detail": "min_severity must be one of info/low/medium/high/critical."},
                    status=400,
                )
            policy.min_severity = sev

        policy.save()
        return Response(_dispatch_policy_state(policy))

    @action(detail=True, methods=["get"], url_path="dispatch-attempts")
    def dispatch_attempts(self, request, uuid=None):
        """The auditable record of every automated dispatch for this deployment —
        what was sent, failed, or skipped (and why), per finding and connector. An
        open read, so an operator can always see what did and did not leave the
        record. No credential value is ever surfaced."""
        deployment = self.get_object()
        attempts = DispatchAttempt.objects.filter(deployment=deployment).select_related(
            "finding"
        )
        return Response({"attempts": [_dispatch_attempt_state(a) for a in attempts]})

    @action(detail=True, methods=["get", "put", "patch"], url_path="data-boundary")
    def data_boundary(self, request, uuid=None):
        """AI Data Boundary Assessment (Phase 1.4): reconcile the approved data
        boundary against the deployment's actual data destinations.

        GET returns the assessment (open read). PUT and PATCH declare/update the
        approved boundary (admin-only — they mutate the record) and return the
        fresh assessment. The assessment itself is always computed, never stored.

        PUT is a **true replace**: a field the body omits is reset to the model's
        declared default (regions cleared, training/sharing denied, notes emptied),
        so an unstated posture is never silently inherited from an earlier
        declaration — silence is not consent. PATCH is the **merge** path: only the
        fields supplied change, the rest stay as declared."""
        deployment = self.get_object()
        if request.method in ("PUT", "PATCH"):
            _require_admin(request)
            partial = request.method == "PATCH"
            serializer = DataBoundarySerializer(data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            fields = dict(serializer.validated_data)
            if not partial:
                # True replace: every field the body left out returns to its model
                # default rather than keeping whatever the previous PUT recorded.
                fields = {
                    name: DataBoundary._meta.get_field(name).get_default()
                    for name in DataBoundarySerializer.Meta.fields
                } | fields
            with transaction.atomic():
                DataBoundary.objects.update_or_create(
                    deployment=deployment,
                    defaults={**fields, "updated_by": request.user},
                )
                # A condition declared on this boundary -- "training stays denied",
                # "no region beyond these" -- that the write made true fires here,
                # in the write's transaction, and the decision is refreshed with it.
                # The boundary otherwise reaches the decision only through claims
                # re-derived from it.
                _fire_conditions(deployments_watching_boundary(deployment.pk), request.user)
        assessed = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=deployment.pk)
        )
        return Response(assess_boundary(assessed))

    @action(detail=True, methods=["get"], url_path="capabilities")
    def capabilities(self, request, uuid=None):
        """AI System Capability Map (Phase 1.3): the ground-truth inventory of
        what the deployment can *do*, derived from its asset graph and the
        declared tool permission map. A read — open to any authenticated
        operator, like the rest of the assurance reads — and computed, never
        stored. The prerequisite for the boundary and access assessments."""
        assessed = Deployment.objects.prefetch_related("assets").get(pk=self.get_object().pk)
        return Response(assess_capabilities(assessed))

    @action(detail=True, methods=["get"], url_path="route-map")
    def route_map(self, request, uuid=None):
        """System / Route Map (Phase 1.6): the layered data-flow graph
        (app → gateway → model → data → tools → logs) reconstructed from the
        asset graph and its declared edges. A read — open to any authenticated
        operator, like the rest of the assurance reads — and computed, never
        stored. It ties the asset, provider and capability views into one map."""
        assessed = Deployment.objects.prefetch_related("assets__provider").get(pk=self.get_object().pk)
        return Response(build_route_map(assessed))

    @action(detail=True, methods=["get"], url_path="effective-access")
    def effective_access(self, request, uuid=None):
        """Identity Assurance & Effective Access (Phase 3.1): the honest inventory
        of the deployment's principals (the identities that can act — service
        accounts, agents, and the app/model itself) and what each can effectively
        reach, by direct and transitive paths through the asset graph. A read —
        open to any authenticated operator, like the rest of the assurance reads —
        and computed, never stored. It is the input the blast-radius / Ripple
        Effect assessment (Phase 2.5) consumes.

        It never claims least privilege is satisfied or an identity is secure: it
        reports powers, transitive reach, and gaps only. A shadow (unmanaged)
        principal reads as shadow with its risk raised; a transitive path is
        reported only where a declared edge evidences every hop, never invented;
        and privileged, over-broad, orphaned and ungoverned-reach access are
        surfaced, not smoothed."""
        assessed = Deployment.objects.prefetch_related("assets__provider").get(
            pk=self.get_object().pk
        )
        return Response(assess_effective_access(assessed))

    @action(detail=True, methods=["get"], url_path="ripple-effect")
    def ripple_effect(self, request, uuid=None):
        """Ripple Effect / blast-radius (Phase 2.5): for each origin worth tracing
        — an active high/critical finding tied to a component, or a privileged /
        high-risk principal — a *few well-supported* downstream consequences a
        compromise of it could have, each tied to the evidenced path that supports
        it. A read — open to any authenticated operator, like the rest of the
        assurance reads — and computed, never stored.

        It reads only the effective-access reach graph (Phase 3.1) and the data
        boundary (Phase 1.4), so it re-derives no reachability and inherits their
        no-invented-reach guarantee. Every consequence is potential and
        evidence-based, never a realized harm, a fabricated cascade, or a monetary
        figure; the list is ranked and bounded to the well-supported core; and an
        origin with no evidenced downstream reach reads honestly as such, never as
        safe or contained."""
        assessed = Deployment.objects.prefetch_related(
            "assets__provider__assertions", "findings__asset"
        ).get(pk=self.get_object().pk)
        return Response(assess_ripple(assessed))

    @action(detail=True, methods=["get"], url_path="personal-context")
    def personal_context(self, request, uuid=None):
        """Personal Context Exposure (Phase 3.5): what personal / customer data the
        deployment holds, in which data-bearing components, and which principals can
        reach it. A read — open to any authenticated operator, like the rest of the
        assurance reads — and computed, never stored.

        It reuses the effective-access reach graph (Phase 3.1) for the
        who-can-reach parts and the data boundary (Phase 1.4) for boundary
        crossings, so it re-derives no reachability. An unclassified data store
        reads as unknown (personal-data exposure cannot be ruled out), never "no
        PII"; personal data reachable by a shadow / over-broad principal or crossing
        the approved boundary is surfaced as a gap; and no data value is emitted."""
        assessed = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=self.get_object().pk)
        )
        return Response(assess_personal_context(assessed))

    @action(detail=True, methods=["get"], url_path="data-lifecycle")
    def data_lifecycle(self, request, uuid=None):
        """Data Lifecycle Review (Phase 3.5): the lifecycle stages evidenced in the
        graph — collected, transmitted, processed, logged, retained, reused, deleted
        — the components that evidence each (at their true evidence strength), and
        the gaps where a stage has no evidenced control. A read — open to any
        authenticated operator, computed, never stored.

        An unevidenced stage reads "not evidenced", never "compliant"; a control
        evidenced only weakly (vendor-asserted) is a weak control, still a gap; and
        the assessment never asserts data is deleted or retained correctly without
        evidence."""
        assessed = Deployment.objects.prefetch_related("assets__provider__assertions").get(
            pk=self.get_object().pk
        )
        return Response(assess_data_lifecycle(assessed))

    @action(detail=True, methods=["get"], url_path="training-reuse")
    def training_reuse(self, request, uuid=None):
        """Training / Reuse Review (Phase 3.5): whether customer / internal data is
        reused for training, sharing or retention — VERIFIED vs merely ASSERTED —
        per provider, each posture carried at its true evidence class. A read — open
        to any authenticated operator, computed, never stored.

        A vendor_asserted "we don't train on your data" reads as vendor-asserted,
        never verified; an unstated reuse policy is a gap (reuse cannot be ruled
        out), never "safe"; and nothing upgrades a vendor claim."""
        assessed = Deployment.objects.prefetch_related("assets__provider__assertions").get(
            pk=self.get_object().pk
        )
        return Response(assess_training_reuse(assessed))

    @action(detail=True, methods=["get"], url_path="metadata-logging")
    def metadata_logging(self, request, uuid=None):
        """Metadata & Logging Risk (Phase 3.5): where prompts / traces / embeddings
        / metadata get logged, what sensitive categories could reach those sinks,
        and the gaps where sensitive data is logged with no evidenced control. A
        read — open to any authenticated operator, computed, never stored.

        It reuses the personal-data reading from Phase 3.5's personal-context
        assessment for the PII category, never re-deriving it. Only logging the
        graph evidences is flagged; NO sensitive value is ever emitted (only the
        presence of a category and its lineage); an unknown reads unknown."""
        assessed = Deployment.objects.prefetch_related("assets__provider__assertions").get(
            pk=self.get_object().pk
        )
        return Response(assess_metadata_logging(assessed))

    @action(detail=True, methods=["get"], url_path="posture")
    def posture(self, request, uuid=None):
        """The credential-gated posture catalog (Phase 3.2–3.4): the three posture
        domains and whether each is configured. A read — open to any authenticated
        operator, like the rest of the assurance reads — that lets an operator see
        which posture assessments exist and which are configured for THIS
        deployment (an operational per-tenant binding) versus inert, without
        triggering anything. Mirrors the ``connectors`` list. No credential value
        is ever returned, only whether one is on file."""
        from .posture import available_domains, build_assessment

        deployment = self.get_object()  # scope/permission check on the deployment
        bindings = {
            b.domain: b for b in PostureBinding.objects.filter(deployment=deployment)
        }
        rows = []
        for name in available_domains():
            binding = bindings.get(name)
            settings_configured = build_assessment(name).configured
            operational = bool(binding and binding.is_operational())
            rows.append(
                {
                    "name": name,
                    "label": build_assessment(name).label,
                    "configured": operational or settings_configured,
                    "bound": binding is not None,
                    "binding_operational": operational,
                    "has_secret": bool(binding and binding.has_secret),
                }
            )
        return Response({"domains": rows})

    @action(detail=True, methods=["get"], url_path="cloud-posture")
    def cloud_posture(self, request, uuid=None):
        """3.2 Cloud Assurance posture (credential-gated): public exposure, IAM
        over-permissioning, storage exposure, network reachability, and drift as
        paths into the deployment. A read — open to any authenticated operator,
        computed, never stored. Inert by default: with no cloud credentials
        configured the domain makes no fetch and returns ``{"connected": false,
        ...}`` with the catalog of checks it would run (the house verdict idiom —
        200, read ``connected``). Live wiring is the deferred follow-up."""
        return Response(self._assess_posture("cloud"))

    @action(detail=True, methods=["get"], url_path="secrets-posture")
    def secrets_posture(self, request, uuid=None):
        """3.3 Secrets / Crypto posture (credential-gated): TLS/cert validity,
        KMS/key rotation, secret-store hygiene, committed-secret indicators, and
        encryption at rest. A read — open to any authenticated operator, computed,
        never stored. Inert by default (``connected: false`` with no credentials).
        No secret VALUE is ever emitted — only presence/hygiene facts. Live wiring
        is the deferred follow-up."""
        return Response(self._assess_posture("secrets"))

    @action(detail=True, methods=["get"], url_path="repo-posture")
    def repo_posture(self, request, uuid=None):
        """3.4 Repository / SDLC posture (credential-gated): branch protection,
        CI/CD runner exposure, dependency risk, IaC misconfig, embedded secrets,
        and pipeline drift. A read — open to any authenticated operator, computed,
        never stored. Inert by default (``connected: false`` with no credentials).
        Live wiring is the deferred follow-up."""
        return Response(self._assess_posture("repo"))

    def _assess_posture(self, domain: str) -> dict:
        """Build the posture domain for this deployment and assess it.

        When the deployment has an operational per-tenant binding for the domain,
        it is assessed against the live resource that binding points at, with a
        real :class:`RequestsFetcher` (built from the binding's endpoint + decrypted
        read-credential). Otherwise it falls back to the process-wide settings/env
        config, which is inert in this repo. Either way the domain's own guard holds
        the honesty invariant: an unconfigured domain short-circuits before the
        fetcher is ever touched, so ``connected: false`` and no fetch is made — a
        result that is never read as a pass."""
        from .posture import RequestsFetcher, build_assessment

        deployment = self.get_object()  # scope/permission check on the deployment
        binding = PostureBinding.objects.filter(
            deployment=deployment, domain=domain
        ).first()
        if binding is not None and binding.is_operational():
            assessment = binding.build_assessment()
            fetcher = self._posture_fetcher_for(binding)
        else:
            assessment = build_assessment(domain)
            fetcher = RequestsFetcher()
        return assessment.assess(fetcher=fetcher)

    def _posture_fetcher_for(self, binding):
        """The read-only fetcher a configured posture binding fetches through. Built
        from the binding's endpoint base URL and decrypted read-credential (a Bearer
        header). Isolated as a seam so a test can inject a fake fetcher for a
        configured binding without any real network call ever being made."""
        from .posture import RequestsFetcher

        endpoint = binding.endpoint or {}
        base_url = endpoint.get("base_url")
        secret = binding.get_secret()
        headers = {"Authorization": f"Bearer {secret}"} if secret else {}
        return RequestsFetcher(base_url=base_url, headers=headers)

    #: How many approved workflows one declaration may carry, and how many the
    #: read returns. Deliberately the SAME number: a set you are allowed to
    #: declare is a set you must be able to read back whole, so `truncated` on
    #: that route can only ever be about rows predating this cap.
    #:
    #: There was no cap at all. `compose` is linear in the approved set and the
    #: route left its size to the caller: a 10 MiB body
    #: (`DATA_UPLOAD_MAX_MEMORY_SIZE`) holds ~300,000 minimal rows, and every
    #: later assurance read on that deployment -- including an unprivileged GET
    #: and the decision route -- pays for them. At 1,000 a composition costs
    #: about a millisecond.
    APPROVED_WORKFLOW_LIMIT = 1000

    #: How many chain outcomes one POST may append. Outcomes append forever, so
    #: the bound is on the request rather than on the total; a campaign with more
    #: than this many results posts twice and loses nothing.
    CHAIN_OUTCOME_BATCH_LIMIT = 1000

    #: How many chain outcomes `chain_outcomes` returns at most, newest first.
    #: Outcomes are append-only, so this list grows without bound over a
    #: deployment's life; a route that returned all of them would be the
    #: unbounded-list defect the project's own pagination default exists to
    #: prevent. The counts beside it stay whole.
    CHAIN_OUTCOME_PAGE_SIZE = 100

    @action(detail=True, methods=["get", "put"], url_path="approved-workflows")
    def approved_workflows(self, request, uuid=None):
        """The deployment's APPROVED BUSINESS WORKFLOWS — the set the compositional
        assurance graph is scoped to (:mod:`assurance.composition`).

        GET returns the set beside the live composition, so a reader sees what the
        declaration *does* in the same response rather than having to go and ask.
        PUT REPLACES the whole set (admin-only — it mutates the shared record).

        Replace, not merge, and for the same reason the declared-architecture route
        replaces: a set you can only add to is a set nobody can correct, and an
        approved workflow that was withdrawn has to be able to leave.

        REPLACING THE SET DOES NOT TOUCH RECORDED OUTCOMES. `WorkflowChainOutcome`
        names its workflow by slug rather than by foreign key, so withdrawing an
        approval cannot cascade-delete the measurements taken under it. The
        outcomes for a withdrawn workflow become `workflows_unapproved` -- visible,
        counted and named -- which is the honest result: exercising a workflow the
        customer has since un-approved is a fact worth keeping, not one to erase by
        editing the roster.
        """
        deployment = self.get_object()
        if request.method == "PUT":
            _require_admin(request)
            payload, _ = _rows_from_body(
                request.data, key="workflows", single_allowed=False
            )
            if isinstance(payload, list) and len(payload) > self.APPROVED_WORKFLOW_LIMIT:
                raise ValidationError(
                    {
                        "workflows": (
                            f"{len(payload)} workflows is more than the "
                            f"{self.APPROVED_WORKFLOW_LIMIT} this route accepts. The "
                            "approved set is read on every assurance answer for this "
                            "deployment, so its size is a cost every later request "
                            "pays, including an unprivileged read."
                        )
                    }
                )
            serializer = ApprovedWorkflowSerializer(data=payload, many=True)
            serializer.is_valid(raise_exception=True)
            rows = serializer.validated_data
            slugs = [row["slug"] for row in rows]
            if len(set(slugs)) != len(slugs):
                raise ValidationError(
                    {
                        "workflows": (
                            "Two entries name the same workflow slug. The slug is the "
                            "identity outcomes are matched on, so a duplicate would "
                            "silently drop one of the two declarations."
                        )
                    }
                )
            with transaction.atomic():
                deployment.approved_workflows.all().delete()
                ApprovedWorkflow.objects.bulk_create(
                    ApprovedWorkflow(
                        deployment=deployment, approved_by=request.user, **row
                    )
                    for row in rows
                )
                _refresh_stored_decision(deployment)
        # `select_related` because `approved_by` is read per row: without it a
        # thousand-row set issues a thousand extra user queries.
        recorded = deployment.approved_workflows.select_related("approved_by")
        total = recorded.count()
        page = list(recorded[: self.APPROVED_WORKFLOW_LIMIT])
        return Response(
            {
                "approved": ApprovedWorkflowSerializer(page, many=True).data,
                # Bounded, and saying so, exactly as the outcome route is. This
                # returned every row while its sibling's comment called an
                # unbounded list "the defect the project's own pagination default
                # exists to prevent" -- a rule written down twenty lines from a
                # route that broke it.
                "returned": len(page),
                "truncated": len(page) < total,
                "page_size": self.APPROVED_WORKFLOW_LIMIT,
                "approved_count": total,
                "composition": _composition_payload(deployment),
            }
        )

    @action(detail=True, methods=["get", "post"], url_path="chain-outcomes")
    def chain_outcomes(self, request, uuid=None):
        """What the deployment's per-workflow assurance chains established.

        GET returns the most recent outcomes beside the live composition. POST
        APPENDS one or more (admin-only — it writes the shared record).

        APPEND, NOT REPLACE, and this is the load-bearing difference from the
        approved set above. An outcome is a REPORT at an instant.
        :mod:`assurance.composition` picks the newest verdict per workflow and
        counts what a re-run superseded; replacing on write would leave exactly one
        outcome per workflow, so supersession would become unreachable and the rule
        would keep its logic while losing its input. It would also let a later
        inconclusive run erase a recorded violation, which the rule refuses by
        design.

        The workflow slug is NOT checked against the approved set. An outcome for a
        workflow nobody approved is precisely what `workflows_unapproved` counts,
        and refusing it here would make that counter unreachable and this route the
        place the platform stopped noticing shadow workflows.
        """
        deployment = self.get_object()
        if request.method == "POST":
            _require_admin(request)
            # One outcome or many. A campaign posts a batch; an operator recording
            # a single run posts an object, and gets its FIELDS back on a 400
            # rather than a list index it never sent -- `many=True` keys its errors
            # by position, which for a single object names something the caller
            # cannot see in its own request.
            payload, single = _rows_from_body(
                request.data, key="outcomes", single_allowed=True
            )
            if isinstance(payload, list) and len(payload) > self.CHAIN_OUTCOME_BATCH_LIMIT:
                raise ValidationError(
                    {
                        "outcomes": (
                            f"{len(payload)} outcomes is more than the "
                            f"{self.CHAIN_OUTCOME_BATCH_LIMIT} one request accepts. Post "
                            "again with the rest; outcomes append, so nothing is lost "
                            "by splitting a batch."
                        )
                    }
                )
            serializer = WorkflowChainOutcomeSerializer(data=payload, many=True)
            if not serializer.is_valid():
                raise ValidationError(
                    serializer.errors[0] if single else serializer.errors
                )
            with transaction.atomic():
                rows = list(serializer.validated_data)
                # Bound like a signed row, so the record says which route each
                # outcome was reported against whoever reported it. A typed-in held
                # floors on its basis either way; the binding is not what gates it.
                routes = routes_for_outcomes(
                    deployment, [row.get("observed_at") for row in rows], now=timezone.now()
                )
                WorkflowChainOutcome.objects.bulk_create(
                    WorkflowChainOutcome(deployment=deployment, route_fingerprint=route, **row)
                    for row, route in zip(rows, routes, strict=True)
                )
                _refresh_stored_decision(deployment)
        recorded = deployment.chain_outcomes.all()
        total = recorded.count()
        page = list(recorded[: self.CHAIN_OUTCOME_PAGE_SIZE])
        return Response(
            {
                "outcomes": WorkflowChainOutcomeSerializer(
                    page, many=True, context={"deployment_uuid": str(deployment.uuid)}
                ).data,
                # Returned vs recorded, stated separately and always: `len(outcomes)`
                # is not the count and must not be usable as one.
                "returned": len(page),
                "truncated": len(page) < total,
                "page_size": self.CHAIN_OUTCOME_PAGE_SIZE,
                "recorded_count": total,
                "composition": _composition_payload(deployment),
            }
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="chain-outcomes/observed",
        # JSON only. A signed outcome is a JSON document, and a form or multipart
        # body is not one: with the default parsers a multipart POST reached a 500,
        # because the audit middleware had already consumed the stream as a form.
        parser_classes=[SafeJSONParser],
    )
    def observed_chain_outcomes(self, request, uuid=None):
        """Record chain outcomes from the envelopes an engine SIGNED.

        "Observed" in the path means reported by an engine at an instant, not that
        an effect was seen: each recorded row is published with its
        ``evidence_kind``, and one Achilles signed is an ``authorization_check``: a
        held there means the gate authorized the action at dispatch, which shows the
        authority chain resolves and not that the effect happened.

        The only route that writes ``basis=demonstrated``. The body is one DSSE
        envelope or ``{"envelopes": [...]}``; each is verified against this
        deployment's outcome keyring and against what a signature does not prove
        (the deployment it names, replay, staleness, clock skew), and the batch is
        recorded whole or not at all -- a 400 names every refusal by position.
        Admin-only, like the operator route: it writes the shared record. What
        makes a row demonstrated is the engine's signature, not who posted it.
        """
        deployment = self.get_object()
        _require_admin(request)
        # The DECLARED length, read before the body is. Reading ``request.body`` to
        # measure it answered a body over Django's own upload cap with Django's
        # generic 400, and raised on a stream the middleware had already consumed;
        # the header answers every size with this route's own 413.
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"body": "Content-Length is not a number"}) from None
        if declared > observed_outcomes.MAX_BODY_BYTES:
            return Response(
                {"error": "the request is larger than a batch of signed outcomes can be"},
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        # Refused by name rather than left to the parser: once the audit middleware
        # has read a form body, DRF hands a non-JSON request back as empty data, and
        # that read as "one malformed envelope" -- a refusal about the wrong thing.
        if (request.content_type or "").split(";")[0].strip().lower() != "application/json":
            return Response(
                {"error": "signed outcomes are posted as application/json"},
                status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        data = request.data
        if isinstance(data, dict) and "envelopes" in data:
            envelopes = data["envelopes"]
        else:
            envelopes = [data]
        if not isinstance(envelopes, list) or not envelopes:
            raise ValidationError({"envelopes": "a non-empty list of signed outcomes"})
        if len(envelopes) > observed_outcomes.BATCH_LIMIT:
            raise ValidationError(
                {"envelopes": f"at most {observed_outcomes.BATCH_LIMIT} outcomes per request"}
            )
        try:
            # The rows and the decision they move commit together, as on the
            # operator route. `ingest` commits in its own block, and the refresh
            # used to run after it: a refresh that failed there left a signed
            # violation recorded under a stored READY, and the engine's retry of the
            # same envelope was refused as a replay -- nothing on this route could
            # bring the two back together.
            with transaction.atomic():
                rows, refusals = observed_outcomes.ingest(deployment, envelopes)
                if not refusals:
                    _refresh_stored_decision(deployment)
        except observed_outcomes.KeyringUnavailable as exc:
            return Response({"error": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        if refusals:
            return Response(
                {
                    "recorded": 0,
                    "refused": [{"index": r.index, "reason": r.reason} for r in refusals],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {
                "recorded": len(rows),
                "outcomes": WorkflowChainOutcomeSerializer(
                    rows, many=True, context={"deployment_uuid": str(deployment.uuid)}
                ).data,
                "composition": _composition_payload(deployment),
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="ai-bom")
    def ai_bom(self, request, uuid=None):
        """AI-BOM (Phase 1.7): the AI supply-chain bill of materials — every
        component and the providers behind it, each provider fact evidence-graded,
        with a tamper-evident digest. A read — open to any authenticated operator,
        like the rest of the assurance reads — and computed, never stored. An
        exportable artifact for procurement, audit, M&A and security
        questionnaires."""
        assessed = Deployment.objects.prefetch_related("assets__provider__assertions").get(
            pk=self.get_object().pk
        )
        return Response(build_ai_bom(assessed))

    @action(detail=True, methods=["get", "put"], url_path="declared-architecture")
    def declared_architecture(self, request, uuid=None):
        """The customer's DECLARED AI architecture (SPINE Stage 3): the components
        they assert the system is built from, and the live drift against what is
        observed.

        GET returns the declaration plus the drift assessment (open read). PUT
        REPLACES the whole declared set from a list of components (admin-only — it
        mutates the record) and returns the fresh declaration and drift. Declaring
        an architecture is a separate axis from the running system, so it does not
        move the system fingerprint.

        It does move the DECISION: the declared set is the baseline the coverage
        cap measures against, so a declared component nobody observed holds the
        deployment at AUDIT_INCOMPLETE. The stored decision is refreshed in the
        same transaction as the declaration."""
        deployment = self.get_object()
        if request.method == "PUT":
            _require_admin(request)
            payload = request.data if isinstance(request.data, list) else request.data.get("components", [])
            serializer = DeclaredComponentSerializer(data=payload, many=True)
            serializer.is_valid(raise_exception=True)
            with transaction.atomic():
                deployment.declared_components.all().delete()
                DeclaredComponent.objects.bulk_create(
                    DeclaredComponent(deployment=deployment, declared_by=request.user, **row)
                    for row in serializer.validated_data
                )
                # Without this the receipt went on saying READY while
                # decision-support, computing live, said AUDIT_INCOMPLETE -- and a
                # dispatch retry fenced on the stored decision pushed under it.
                _refresh_stored_decision(deployment)
        components = deployment.declared_components.all()
        assessed = (
            Deployment.objects.prefetch_related("assets__provider", "declared_components").get(
                pk=deployment.pk
            )
        )
        return Response(
            {
                "declared": DeclaredComponentSerializer(components, many=True).data,
                "drift": assess_bom_drift(assessed),
            }
        )

    @action(detail=True, methods=["get"], url_path="bom-drift")
    def bom_drift(self, request, uuid=None):
        """Declared-vs-observed AI-BOM drift (SPINE Stage 3): where the observed
        supply chain diverges from the declared architecture — undeclared (shadow)
        components and providers, and declared components no longer observed. A
        read, open to any authenticated operator; computed, never stored. Without a
        declared baseline there is no drift to compute, and that is surfaced rather
        than read as a clean bill of materials."""
        assessed = Deployment.objects.prefetch_related("assets__provider", "declared_components").get(
            pk=self.get_object().pk
        )
        return Response(assess_bom_drift(assessed))

    @action(detail=True, methods=["post"], url_path="record-bom-drift")
    def record_bom_drift(self, request, uuid=None):
        """Turn the deployment's current BOM drift into managed findings (SPINE
        Stage 3). Admin-only: it mutates the shared record. Idempotent and
        non-destructive — a re-record opens no duplicate finding, auto-closes a
        finding whose drift has cleared, re-opens a machine-closed one whose drift
        returned, and never overrides a human's disposition. An undeclared component
        also contradicts the AI-BOM claim (recompute claims to reflect it). Returns
        ``{created, updated, reopened, resolved, drift_detected}``.

        The drift findings are findings like any other, so opening or closing one
        moves the decision; it is refreshed in the same transaction as they are."""
        _require_admin(request)
        deployment = self.get_object()
        with transaction.atomic():
            counts = record_bom_drift_findings(deployment)
            _refresh_stored_decision(deployment)
        return Response(counts)

    @action(detail=True, methods=["get"], url_path="compliance")
    def compliance(self, request, uuid=None):
        """Compliance mapping (Phase 2.1): where the deployment's findings land
        against the control frameworks (NIST 800-53, OWASP Top 10, OWASP LLM Top
        10, DoD Zero Trust). A read — open to any authenticated operator, like the
        rest of the assurance reads — and computed, never stored. It is evidence of
        *gaps* (a touched control has an open finding against it), never a
        certificate that a control passes."""
        assessed = Deployment.objects.prefetch_related("findings").get(pk=self.get_object().pk)
        return Response(build_compliance_map(assessed))

    @action(detail=True, methods=["get"], url_path="business-impact")
    def business_impact(self, request, uuid=None):
        """Business-impact map (Phase 2.4): which business-impact *dimensions*
        (financial, regulatory, customer-trust, operational, data-confidentiality,
        safety) the deployment's findings implicate, and how heavily. A read — open
        to any authenticated operator, like the rest of the assurance reads — and
        computed, never stored. It is inferred *potential* exposure from finding
        type and severity, never a realized loss, a dollar figure, or a claim the
        business was harmed. It also attributes exposure to the owner accountable
        for each finding ("whose impact"), grounded in the real ``owner`` FK — a
        finding with no owner rolls up to an explicit unassigned bucket, never a
        guess. It does not attribute to a business *process*: the record carries no
        business-process field."""
        assessed = Deployment.objects.prefetch_related("findings__owner").get(pk=self.get_object().pk)
        return Response(build_business_impact(assessed))

    @action(detail=True, methods=["get"], url_path="vendor-assurance")
    def vendor_assurance(self, request, uuid=None):
        """Third-Party Vendor Assurance: the posture of the vendors the deployment
        depends on — what each asserts, at what evidence strength, which components
        depend on it, an honest gap list, and an ordinal posture band. A read — open
        to any authenticated operator, like the rest of the assurance reads — and
        computed, never stored. It never presents a vendor as secure or compliant: a
        ``vendor_asserted`` claim reads as vendor-asserted, and the band is a concern
        signal derived from the weakest evidence, not a grade."""
        assessed = Deployment.objects.prefetch_related("assets__provider__assertions").get(
            pk=self.get_object().pk
        )
        return Response(assess_vendors(assessed))

    @action(detail=True, methods=["get"], url_path="executive-summary")
    def executive_summary(self, request, uuid=None):
        """Executive summary: the assurance graph rolled up for a leadership reader —
        asset coverage, evidence-strength distribution, finding posture by severity,
        remediation velocity, the standing six-state decision, an ordinal posture and
        assurance-maturity band, and a headline from each sibling assessment. A read —
        open to any authenticated operator, like the rest of the assurance reads — and
        computed, never stored. Every value is a real count, a true ratio of real
        counts, or an ordinal band: there is no dollar figure, ROI amount, or
        realized-loss number anywhere, and nothing claims the system is secure."""
        deployment = self.get_object()
        assessed = (
            Deployment.objects.annotate(**logged_head())
            .prefetch_related(
                "findings__evidence",
                "findings__remediation_events",
                "findings__owner",
                "assets__provider__assertions",
            )
            .select_related("data_boundary")
            .get(pk=deployment.pk)
        )
        # The summary publishes the standing decision: reconciled with its log and
        # the keyring in force first, as the receipt is, so the two cannot
        # disagree. The instance published is the one reconciled: where a row
        # behind its log cannot be written, only that instance holds the decision
        # the log records.
        current_decision(assessed)
        return Response(build_executive_summary(assessed))

    @action(detail=True, methods=["get"], url_path="operational-assurance")
    def operational_assurance(self, request, uuid=None):
        """Operational / continuous-assurance roll-up: the continuous-assurance
        signals tied into one operational-readiness view — evidence freshness vs.
        staleness, the change/drift backlog needing reassessment, remediation
        velocity, the standing six-state decision, and an ordinal readiness band. A
        read — open to any authenticated operator, like the rest of the assurance
        reads — and computed, never stored. It is a REUSE-ONLY roll-up: it reads the
        existing change-intelligence and evidence-expiration signals rather than
        re-deriving them. Every value is a real count, a true ratio of real counts
        (None when there is no basis, never a fake 0%), or an ordinal band: there is
        no dollar figure anywhere, and nothing reads "healthy"/"current"/"secure" as
        an unearned fact — an unassessed or stale deployment reads honestly."""
        deployment = self.get_object()
        assessed = (
            Deployment.objects.annotate(**logged_head())
            .prefetch_related("findings__evidence", "findings__remediation_events")
            .get(pk=deployment.pk)
        )
        current_decision(assessed)  # as the executive summary: see there
        return Response(assess_operational(assessed))

    @action(detail=True, methods=["get"], url_path="operational-risk")
    def operational_risk(self, request, uuid=None):
        """Operational-risk register (Phase 3.9): an honest read of four narrow
        operational-risk classes — unbounded-loop/retry-storm, denial-of-wallet/
        cost-runaway, token-storm, and provider-outage/no-fallback — each tied to a
        safety / cost / deployment-trust concern (the roadmap's narrow scope: not a
        generic metrics dashboard). A read — open to any authenticated operator, like
        the rest of the assurance reads — and computed, never stored. It is a
        REUSE-ONLY assessment: it reads the stored asset/provider graph and the
        deployment's ingested findings, deriving no runtime telemetry.

        It is an honest register, not a green dashboard. Provider-outage and
        retry-storm derive an ordinal risk band from a real structural signal (the
        model-provider dependency graph; the autonomous ``agent`` assets), and every
        class escalates on a direct finding the engine ingested. Where the graph has
        no basis — notably the budget/rate-limit/token-cap controls behind
        denial-of-wallet and token-storm, which live in the engine's execution layer
        — the class reads ``unmapped`` (``risk`` None, never a fabricated ``0``/
        ``0%``), never "no risk"/"safe"/"secure". The overall roll-up is
        weakest-honest: it reflects the worst observed risk and surfaces the unmapped
        classes as open gaps, never as a clean pass."""
        assessed = Deployment.objects.prefetch_related("assets__provider", "findings").get(
            pk=self.get_object().pk
        )
        return Response(assess_operational_risk(assessed))

    @action(detail=True, methods=["get"], url_path="assurance-packs")
    def assurance_packs(self, request, uuid=None):
        """Vertical Assurance Packs (catalog): the code-only catalog of industry
        packs — each naming the control frameworks it emphasizes (the identifiers the
        compliance map already defines), the regulatory regimes it targets, and the
        evidence a buyer in that vertical expects. A read — open to any authenticated
        operator — and static; it does not read the deployment. Apply one to this
        deployment via ``assurance-packs/<pack>``."""
        return Response(list_packs())

    @action(detail=True, methods=["get"], url_path="assurance-packs/(?P<pack>[\\w-]+)")
    def assurance_pack(self, request, uuid=None, pack=None):
        """Apply one vertical assurance pack to this deployment: its compliance
        coverage read through the lens of that pack, by reusing the compliance map and
        filtering to the pack's emphasized frameworks. A read — open to any
        authenticated operator — and computed, never stored. Coverage is honest — a
        touched control is an open gap, never "passed" or "compliant" — and the pack's
        regulatory regimes are carried as context, not computed coverage. An unknown
        pack key is a clean 400, never a guessed pack."""
        assessed = Deployment.objects.prefetch_related("findings").get(pk=self.get_object().pk)
        try:
            return Response(apply_pack(assessed, pack))
        except UnknownPack as exc:
            return Response({"detail": str(exc)}, status=400)

    @action(detail=True, methods=["get"], url_path="assurance-claims")
    def assurance_claims(self, request, uuid=None):
        """The deployment's CURRENT assurance claims (SPINE Phase 1): the
        version-bound, falsifiable statements derived from the assessments, each at
        its honest status and weakest-evidence strength. A read — open to any
        authenticated operator, like the rest of the assurance reads. Only the
        current version of each claim (``valid_to`` null) is returned; superseded
        history is reached through a claim's lifecycle events.

        Query-light: the claims are read in one scoped query with their subject
        asset and human owner joined, so the list is a fixed number of queries."""
        deployment = self.get_object()
        claims = (
            AssuranceClaim.objects.filter(deployment=deployment)
            .current()
            .select_related("deployment", "asset", "human_owner", "superseded_by")
            .order_by("claim_type", "-updated_at")
        )
        return Response(AssuranceClaimSerializer(claims, many=True).data)

    @action(detail=True, methods=["post"], url_path="recompute-claims")
    def recompute_claims(self, request, uuid=None):
        """Re-derive the deployment's assurance claims from its current state
        (SPINE Phase 1). Admin-only: it mutates the shared record. Idempotent and
        transactional — it creates missing claims, refreshes machine fields in
        place when the system state is unchanged, supersedes a version when the
        system fingerprint has changed, and marks expired claims stale, never
        overwriting a human REVOKED claim. Returns the reconciliation counts
        ``{created, updated, superseded, stale}``."""
        _require_admin(request)
        deployment = self.get_object()
        # The decision is capped by the claims, so a re-derivation that moves one
        # moves the decision -- and the stored one is what the receipt, the bundle
        # and decision-support's revision publish. One transaction: the claims
        # committed first and the refresh ran after, so a reader in between saw
        # the new claims beside the old decision under one revision.
        with transaction.atomic():
            counts = derive_claims(deployment)
            _refresh_stored_decision(deployment)
        return Response(counts)

    @action(detail=True, methods=["get"], url_path="retest-requirements")
    def retest_requirements(self, request, uuid=None):
        """The deployment's retest requirements (SPINE Phase 2): the durable,
        attributed obligations to re-test a claim whose bound system state has
        changed. A read — open to any authenticated operator, like the rest of the
        assurance reads. Only OPEN obligations by default; ``?all=true`` includes
        the resolved history.

        Query-light: read in one scoped query with the invalidated claim, the
        resolving claim and the actor joined, so the list is a fixed number of
        queries."""
        deployment = self.get_object()
        qs = (
            RetestRequirement.objects.filter(deployment=deployment)
            .select_related("deployment", "claim", "resolving_claim", "actor")
            .order_by("-opened_at")
        )
        if request.query_params.get("all") not in ("true", "1", "yes", "on"):
            qs = qs.filter(resolved_at__isnull=True)
        return Response(RetestRequirementSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"], url_path="decision-support")
    def decision_support(self, request, uuid=None):
        """The deployment's six-state decision WITH why (SPINE Stage 1C): the final
        decision, the finding-based signal and the claim cap that combined into it,
        and exactly which current claims support or undermine it. This is how a READY
        decision is shown to stand only while its supporting claims stay current — a
        contradicted claim holds it at 'needs remediation', a stale/unknown claim or
        an open retest obligation at 'needs more evidence'. A read, open to any
        authenticated operator like the rest of the assurance reads; it computes,
        it does not persist."""
        deployment = self.get_object()
        # Reconciled first: it publishes the stored revision beside a decision it
        # computes live, and after a key rotation those were two different
        # decisions under one revision number -- a fence that fenced nothing.
        current_decision(deployment)
        # No `paused` argument: `decision_support` reads the pause from the row it
        # reads the revision from. Read here, from this instance, it came from
        # before that transaction, and an operator's pause landing in between was
        # published as a live READY under the revision that recorded the pause.
        return Response(decision_support(deployment))

    @action(detail=True, methods=["get"], url_path="coverage-manifest")
    def coverage_manifest_view(self, request, uuid=None):
        """What was assessed, and what was not (Phase 2 item 1).

        Three tallies -- Expected (declared) / Observed (discovered) / Assessed
        (actually tested) -- with the specific entities behind each gap named. The
        question a finding count cannot answer: every fact gathered can be genuine
        and the assessment still be short, and a decision computed only from what
        was inspected reads READY because everything inspected looked good.

        Three verdicts, not two: COMPLETE, INCOMPLETE, and UNDECLARED for a
        deployment with no declared baseline -- there is nothing to be short of, and
        calling that complete would turn a missing declaration into a clean bill.

        A read, like the other assurance reads; it computes and persists nothing."""
        return Response(coverage_manifest(self.get_object()))

    @action(detail=True, methods=["get"], url_path="revalidation-plan")
    def revalidation_plan(self, request, uuid=None):
        """The minimal revalidation plan (SPINE Stage 1D): for each current claim
        that a change invalidated (an open retest obligation), that expired (STALE),
        or that the state contradicts, the exact Athena reassessment and Achilles
        capability areas to re-run — and everything that stays current and need not
        be re-run. This is 'what must re-run because of this change', not 'run the
        whole assessment again'. A read, open to any authenticated operator; pure
        and deterministic."""
        deployment = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=self.get_object().pk)
        )
        return Response(plan_revalidation(deployment))

    @action(detail=True, methods=["post"], url_path="check-invalidations")
    def check_invalidations(self, request, uuid=None):
        """Run the invalidation engine over the deployment (SPINE Phase 2).
        Admin-only: it mutates the shared record (opens/resolves obligations, marks
        drifted claims stale). Idempotent and transactional — a re-run opens no
        duplicate obligation.

        For each current claim whose bound system state has drifted it opens a
        retest obligation (attributed) and moves the claim away from a pass to
        stale, and it resolves any obligation a prior rebinding re-derivation has
        already satisfied — never inventing an "invalid but passing" state. Returns
        the counts ``{invalidated, retests_opened, retests_resolved}``.

        A stale claim and an open obligation each cap the decision, so the stored
        decision is refreshed in the same transaction as the check."""
        _require_admin(request)
        deployment = self.get_object()
        with transaction.atomic():
            counts = run_invalidation_check(deployment, actor=request.user)
            # And every declared latent condition, attributed to whoever asked: the
            # named preconditions are the other half of "what invalidates a claim".
            counts["conditions_fired"] = fire_due_conditions(deployment, actor=request.user)
            _refresh_stored_decision(deployment)
        return Response(counts)

    @action(detail=True, methods=["get"], url_path="latent-conditions")
    def latent_conditions(self, request, uuid=None):
        """What is watched for on this deployment (Phase 2 item 9): every declared
        latent condition, and three counts never blended -- watching, fired, and
        coverage lost -- plus the conditions on a claim nothing evaluates any more.
        A read; pending is not an all-clear, and the payload says so."""
        return Response(latent_posture(self.get_object()))


class ClaimViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Read access to the assurance claims system of record, scoped like findings:
    a privileged operator sees every claim; another authenticated user sees only
    claims on a deployment they own. Claims are never hand-created or hand-edited
    here — they are machine-derived and moved only through the attributed,
    evidence-gated transition action below, so an illegal or dishonest state can
    never slip in via a raw write."""

    serializer_class = AssuranceClaimSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "post", "head", "options"]

    def _scoped_claims(self):
        qs = AssuranceClaim.objects.all()
        user = self.request.user
        if not _is_privileged(user):
            qs = qs.filter(deployment__owner=user)
        return qs

    def get_object(self):
        """Look a claim up by uuid within the caller's scope, across ALL versions —
        a detail read or a lifecycle event of a superseded version is still
        reachable, unlike the list which defaults to current versions only."""
        qs = self._scoped_claims().select_related(
            "deployment", "asset", "human_owner", "superseded_by"
        )
        obj = get_object_or_404(qs, uuid=self.kwargs["uuid"])
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        # The serializer reads deployment.uuid, asset.uuid/name, owner.username and
        # superseded_by.uuid; select_related them so the list is a fixed number of
        # queries, not O(n).
        qs = self._scoped_claims().select_related(
            "deployment", "asset", "human_owner", "superseded_by"
        )
        deployment = self.request.query_params.get("deployment")
        if deployment:
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        claim_type = self.request.query_params.get("claim_type")
        if claim_type:
            qs = qs.filter(claim_type=claim_type)
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        # Default to the current version of each claim; ?all=true includes history.
        # Current means believed now AND effective now, so a retroactive claim is
        # history here even though Mythos still believes it -- it is about a window
        # that has closed, and a caller asking for "the current claims" is asking
        # about now.
        if self.request.query_params.get("all") not in ("true", "1", "yes", "on"):
            qs = qs.current()
        return qs

    @action(detail=True, methods=["get"], url_path="events")
    def events(self, request, uuid=None):
        """The claim's attributed lifecycle history (SPINE): every status change,
        who made it, from where to where, and why. A read — open to any operator
        who can see the claim."""
        claim = self.get_object()
        events = claim.events.select_related("actor").all()
        return Response(ClaimEventSerializer(events, many=True).data)

    @action(detail=True, methods=["post"], url_path="transition")
    def transition(self, request, uuid=None):
        """Move the claim along its lifecycle. Admin-only — it mutates the shared
        record — and every move is attributed to the caller.

        Body: ``{"to_status": <status>, "note": <optional>}``. An unknown status, an
        illegal jump, a machine-only target (stale/superseded), or an attempt to
        verify a claim whose evidence is not configuration/technically verified (or
        that rests on vendor assertions) is rejected with a clean 400, never
        silently coerced. The move writes a ``ClaimEvent`` and changes only
        ``status`` (and ``verified_at`` on a move to verified)."""
        _require_admin(request)
        claim = self.get_object()
        to_status = request.data.get("to_status")
        if to_status not in AssuranceClaim.ClaimStatus.values:
            return Response({"detail": f"Unknown claim status: {to_status!r}."}, status=400)
        try:
            # A claim an operator contradicts caps the decision. Without the
            # refresh, decision-support computed the capped decision live under the
            # SAME revision the receipt was still publishing READY under: one
            # revision, two decisions. And in the same transaction as the move, or
            # a reader between the two commits saw exactly that.
            with transaction.atomic():
                event = apply_claim_transition(
                    claim, to_status, actor=request.user, note=request.data.get("note", "")
                )
                _refresh_stored_decision(claim.deployment)
        except IllegalClaimTransition as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(
            {
                "status": claim.status,
                "status_label": claim.get_status_display(),
                "event": ClaimEventSerializer(event).data,
            }
        )

    @action(detail=True, methods=["post"], url_path="latent-conditions")
    def declare_latent_condition(self, request, uuid=None):
        """Declare the exact future change that would falsify this claim (Phase 2
        item 9). Admin-only, attributed to the caller.

        Body: ``{"kind", "subject", "description", "expected"?}`` -- ``kind`` one of
        the closed vocabulary of :class:`LatentCondition.Kind`. Refused with a 400
        naming why (:func:`assurance.latent.declare_condition`): a condition that
        already holds is a present fact, not a latent one, and one nothing can read
        today cannot be called latent. Declared only on the claim's current,
        unrevoked version: nothing evaluates a condition on any other.

        From then on it is evaluated whenever the deployment's decision is brought
        current -- every write to what the decision reads, scan ingest, the admin,
        the invalidation check -- and on every write to the data boundary or a
        provider profile it names. The instant it holds, the claim goes STALE and a
        retest opens whose reason names it."""
        _require_admin(request)
        claim = self.get_object()
        if claim.valid_to is not None or claim.status == AssuranceClaim.ClaimStatus.REVOKED:
            return Response(
                {"detail": "Declare a latent condition on the claim's current, unrevoked version; "
                           "nothing evaluates a condition declared on any other."},
                status=400,
            )
        body = request.data if isinstance(request.data, dict) else {}
        try:
            condition = declare_condition(
                claim,
                kind=str(body.get("kind") or ""),
                subject=str(body.get("subject") or ""),
                description=str(body.get("description") or ""),
                expected=str(body.get("expected") or ""),
                declared_by=request.user,
            )
        except LatentConditionRefused as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(condition_view(condition), status=201)

    @action(
        detail=True,
        methods=["post"],
        url_path=r"latent-conditions/(?P<condition_uuid>[^/.]+)/withdraw",
    )
    def withdraw_latent_condition(self, request, uuid=None, condition_uuid=None):
        """Stop watching a declared condition, visibly: kept as WITHDRAWN with the
        caller's note, never deleted. Admin-only. Only a condition still watched
        (pending, or unobservable) can be withdrawn -- a fired one is the record of a
        precondition that came true, and withdrawing it would overwrite what was
        observed when it did."""
        _require_admin(request)
        claim = self.get_object()
        valid = _valid_uuid(condition_uuid)
        condition = (
            LatentCondition.objects.filter(claim=claim, uuid=valid).first()
            if valid
            else None
        )
        if condition is None:
            return Response({"detail": "No such latent condition on this claim."}, status=404)
        watched = (LatentCondition.State.PENDING, LatentCondition.State.UNOBSERVABLE)
        if condition.state not in watched:
            return Response(
                {"detail": f"This condition is {condition.state}, not watched; only a pending or "
                           "unobservable condition can be withdrawn."},
                status=409,
            )
        body = request.data if isinstance(request.data, dict) else {}
        withdraw_condition(condition, note=str(body.get("note") or ""))
        return Response(condition_view(condition))


class RetestRequirementViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """Read access to the retest-obligation system of record (SPINE Phase 2),
    scoped like claims: a privileged operator sees every obligation; another
    authenticated user sees only obligations on a deployment they own.

    Obligations are never hand-created or hand-edited here — they are opened by the
    invalidation engine and resolved by a rebinding re-derivation, so a dishonest
    or unattributed state can never slip in via a raw write. Reads default to the
    OPEN obligations; ``?all=true`` includes resolved history, and ``?status=`` can
    ask for ``open`` / ``resolved`` explicitly."""

    serializer_class = RetestRequirementSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        # The serializer reads deployment.uuid, claim.uuid/claim_type,
        # resolving_claim.uuid and actor.username; select_related them so the list
        # is a fixed number of queries, not O(n).
        qs = RetestRequirement.objects.select_related(
            "deployment", "claim", "resolving_claim", "actor"
        ).all()
        user = self.request.user
        if not _is_privileged(user):
            qs = qs.filter(deployment__owner=user)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        claim = self.request.query_params.get("claim")
        if claim:
            valid = _valid_uuid(claim)
            qs = qs.filter(claim__uuid=valid) if valid else qs.none()
        status_q = self.request.query_params.get("status")
        if status_q == "open":
            qs = qs.filter(resolved_at__isnull=True)
        elif status_q == "resolved":
            qs = qs.filter(resolved_at__isnull=False)
        # Default to the OPEN obligations; ?all=true includes resolved history.
        elif self.request.query_params.get("all") not in ("true", "1", "yes", "on"):
            qs = qs.filter(resolved_at__isnull=True)
        return qs


class FindingViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,  # PATCH: status / owner / business_impact only
    viewsets.GenericViewSet,
):
    serializer_class = FindingSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    # POST is enabled only for the remediation @actions below; without a
    # CreateModelMixin there is no create route, so the collection still 405s.
    http_method_names = ["get", "post", "patch", "head", "options"]

    def update(self, request, *args, **kwargs):
        # PATCH (status/owner/business_impact) mutates the record → admin-only.
        # The remediation workflow (remediation_state / assignee) is NOT patchable
        # here: it moves only through the attributed, state-machine-checked actions
        # below, so an illegal jump or an unattributed change can never slip in via
        # a raw field write.
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        # `status` is a decision input: re-opening a critical finding makes the
        # deployment NOT_RECOMMENDED, closing the last one lifts it. The PATCH
        # used to write the status and leave the stored decision alone, so the
        # receipt could read READY with a critical finding open while
        # decision-support, computing live, said otherwise. The finding and the
        # decision it moves commit together.
        with transaction.atomic():
            finding = serializer.save()
            _refresh_stored_decision(finding.deployment)

    @action(detail=True, methods=["get"], url_path="remediation")
    def remediation(self, request, uuid=None):
        """The finding's remediation workflow (Phase 2.3): its current process
        state, who the work is assigned to, and the full attributed history of
        moves. A read — open to any operator who can see the finding, like the
        rest of the assurance reads.

        The workflow is the *human process* of getting the finding fixed; it is
        NOT the security disposition (``status``), which alone says whether the
        risk is still live. ``remediation_state=resolved`` here means a human
        called the work done, never that the finding is securely closed."""
        finding = self.get_object()
        events = finding.remediation_events.select_related("actor").all()
        return Response(
            {
                "remediation_state": finding.remediation_state,
                "remediation_state_label": finding.get_remediation_state_display(),
                "assignee": finding.assignee.username if finding.assignee_id else None,
                "events": RemediationEventSerializer(events, many=True).data,
            }
        )

    @action(detail=True, methods=["get"], url_path="incident-pack")
    def incident_pack(self, request, uuid=None):
        """The finding's **AI Incident Evidence Pack** (Phase 3.7): a portable,
        verifiable pack that reconstructs the incident's identity, context, surface
        (tools/assets/route), evidence, receipt, ripple/blast-radius, and decision
        from the stored assurance graph, plus the reference to the engine's evidence
        pack Achilles replays against (see
        :func:`assurance.incident.assemble_incident_pack` and its
        ``INCIDENT_PACK_SCHEMA``). A finding IS the incident in this data model.

        A read — open to any operator who can see the finding, like the rest of the
        assurance reads — and computed, never stored. The dict is the canonical
        signable payload; this backend produces it, the engine signs it.

        It attests integrity and provenance — that this is the incident evidence
        that was recorded, unaltered — never that the incident conclusion is true or
        the system is secure or fixed. ``vendor_asserted`` evidence stays
        ``vendor_asserted``, and the runtime transcript (which lives in the engine's
        pack, not this graph) is stated as an explicit gap, never fabricated."""
        finding = (
            Finding.objects.select_related(
                "deployment", "deployment__owner", "asset__provider", "scan"
            )
            .prefetch_related("evidence")
            .get(pk=self.get_object().pk)
        )
        return Response(assemble_incident_pack(finding))

    @action(detail=True, methods=["get"], url_path="vendor-packet")
    def vendor_packet(self, request, uuid=None):
        """The finding's **vendor-coordination packet** (Phase 2 item 10): the
        narrow, mechanical artifact you hand the third party this finding
        implicates, built for a reader with no deployment context (see
        :func:`assurance.vendor_packet.build_vendor_packet`).

        It was a complete, tested module that no view, URL, admin action or export
        referenced, so the product could not hand it to anyone. A capability with
        no route is a decorative one.

        A read, like the receipt and the incident pack: computed, never stored,
        open to any operator who can see the finding.

        **Refused when the finding implicates no third party.** The module's own
        rule is that a packet sent to a vendor who is not involved is worse than no
        packet, and a packet naming NO vendor is the degenerate case of that: an
        artifact whose whole purpose is coordination with a specific party,
        addressed to nobody. ``implicated_component`` would be null and every
        section would still render, which reads as a finished packet.
        :func:`assurance.vendor_packet.packet_candidates`, exposed on the
        deployment, is how a caller finds the findings this can be asked for
        rather than guessing.

        The packet asks; it does not conclude. No PASS/FAIL on the vendor's code,
        no severity judgment of their product, and the customer's identifying
        material is redacted before it leaves — all of which the module enforces
        and its own tests pin. This route adds a door, not a claim."""
        finding = (
            Finding.objects.select_related(
                "deployment", "deployment__owner", "asset__provider", "scan"
            )
            .prefetch_related("evidence")
            .get(pk=self.get_object().pk)
        )
        if finding.asset is None or finding.asset.provider is None:
            return Response(
                {
                    "detail": (
                        "This finding implicates no third-party component, so there "
                        "is nobody to coordinate with. Membership is read off the "
                        "asset -> provider edge and is never inferred from a title "
                        "or a finding type. See the deployment's "
                        "vendor-packet-candidates route for the findings a packet "
                        "can be built for."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )
        return Response(build_vendor_packet(finding))

    @action(detail=True, methods=["post"], url_path="remediation/transition")
    def remediation_transition(self, request, uuid=None):
        """Move the finding along its remediation workflow. Admin-only — it
        mutates the shared record — and every move is attributed to the caller.

        Body: ``{"to_state": <state>, "note": <optional>}``. An unknown state or
        an illegal jump is rejected with a clean 400, never silently coerced. The
        move writes a ``RemediationEvent`` and changes only ``remediation_state``;
        it never touches the security ``status`` or the deployment decision — a
        finding is closed in the security sense only through ``status``."""
        _require_admin(request)
        finding = self.get_object()
        to_state = request.data.get("to_state")
        if to_state not in Finding.RemediationState.values:
            return Response(
                {"detail": f"Unknown remediation state: {to_state!r}."}, status=400
            )
        try:
            event = apply_transition(
                finding, to_state, actor=request.user, note=request.data.get("note", "")
            )
        except IllegalTransition as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(
            {
                "remediation_state": finding.remediation_state,
                "remediation_state_label": finding.get_remediation_state_display(),
                "event": RemediationEventSerializer(event).data,
            }
        )

    @action(detail=True, methods=["post"], url_path="remediation/assign")
    def remediation_assign(self, request, uuid=None):
        """Assign (or unassign, with ``assignee=null``) the remediation work on a
        finding. Admin-only and attributed.

        Body: ``{"assignee": <username|null>, "note": <optional>}``. ``assignee``
        is who does the remediation *work* — distinct from ``owner``, who is
        accountable for the security disposition. Writes an attributed
        ``RemediationEvent``; it does not move the workflow state or the security
        ``status``.

        The assignable set is **active users only** (``is_active=True``). An
        unknown username and an inactive-or-otherwise-not-assignable one get the
        SAME uniform 400 — the response never distinguishes the two, so it leaks
        nothing about which usernames exist. The username is stripped of
        surrounding whitespace before lookup; it is NOT lowercased, because
        Django usernames are case-sensitive. Re-assigning the current assignee
        (or clearing an already-unassigned finding) is idempotent: it writes no
        duplicate event (see :func:`assurance.remediation.assign`)."""
        _require_admin(request)
        finding = self.get_object()
        username = request.data.get("assignee")
        if isinstance(username, str):
            username = username.strip()
        assignee = None
        if username not in (None, ""):
            assignee = User.objects.filter(username=username, is_active=True).first()
            if assignee is None:
                return Response(
                    {"detail": "assignee is not an assignable user"}, status=400
                )
        event = assign(
            finding, assignee, actor=request.user, note=request.data.get("note", "")
        )
        return Response(
            {
                "assignee": assignee.username if assignee else None,
                "event": (
                    RemediationEventSerializer(event).data if event is not None else None
                ),
            }
        )

    @action(detail=True, methods=["get"], url_path="assignable")
    def assignable(self, request, uuid=None):
        """The users a remediation assignment may target, for a picker UI instead
        of free-text entry. Admin-only — same guard as the assign action, since
        it enumerates operator accounts.

        Returns ``{"assignable": [{"username", "display"}], "current": <username|
        null>}``: every **active** user (``is_active=True``), ordered by username,
        with ``display`` the full name when set and the username otherwise, plus
        the finding's current assignee. This is the honest boundary — the app has
        no org/tenant model — and matches exactly the set the assign action will
        accept, so a picked user can never be rejected. A fixed number of queries
        (``get_object`` plus one user query); ``get_full_name`` touches no DB."""
        _require_admin(request)
        finding = self.get_object()
        users = User.objects.filter(is_active=True).order_by("username")
        assignable = [
            {"username": u.username, "display": u.get_full_name() or u.username}
            for u in users
        ]
        return Response(
            {
                "assignable": assignable,
                "current": finding.assignee.username if finding.assignee_id else None,
            }
        )

    def _scoped_findings(self):
        """Every finding the caller may see, BEFORE the severity/status/deployment
        query filters — this is *row visibility* only. The change-intelligence
        boundary (a deployment's latest scan) is NOT computed from this set: it is a
        fact about the deployment, independent of who is asking, so it is computed
        privilege-independently in ``get_serializer_context`` (see L2)."""
        qs = Finding.objects.all()
        user = self.request.user
        if _is_privileged(user):
            return qs
        return (qs.filter(scan__user=user) | qs.filter(deployment__owner=user)).distinct()

    def get_serializer_context(self):
        """Supply the change-intelligence inputs once per request: the latest-scan
        boundary per deployment (one aggregate query) and a single ``now``, so the
        serializer never issues a query per finding.

        The boundary is computed over **all** findings, not the caller's visible
        subset: a deployment's "latest scan" is a fact about the deployment, and
        computing it over only-visible findings would let a non-privileged user who
        sees a subset trail the true latest and mislabel ``change_status`` (audit
        L2). Row visibility stays scoped by ``_scoped_findings``/``get_queryset``;
        the serializer only ever reads the boundary for a deployment whose findings
        the caller can already see, so this leaks nothing."""
        from django.utils import timezone

        from .change import latest_seen_by_deployment

        ctx = super().get_serializer_context()
        ctx["latest_seen"] = latest_seen_by_deployment(Finding.objects.all())
        ctx["now"] = timezone.now()
        return ctx

    def get_queryset(self):
        # The serializer reads deployment.uuid, asset.uuid/name, and owner.username;
        # select_related them so the list is a fixed number of queries, not O(n).
        qs = (
            self._scoped_findings()
            .select_related("deployment", "asset", "owner", "assignee")
            .prefetch_related("evidence")
        )
        severity = self.request.query_params.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs


class AssetViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        qs = (
            Asset.objects.select_related("deployment", "provider")
            .annotate(finding_count=Count("findings"))
            .order_by("deployment_id", "kind", "name")
        )
        user = self.request.user
        if not _is_privileged(user):
            qs = qs.filter(deployment__owner=user).distinct()
        kind = self.request.query_params.get("kind")
        if kind:
            qs = qs.filter(kind=kind)
        classification = self.request.query_params.get("classification")
        if classification:
            qs = qs.filter(classification=classification)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs


class ProviderViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Providers are a global registry (an Asset points at one), so reads are
    open to any authenticated operator. An admin may declare a provider and edit
    its assurance profile; a non-admin may not (open reads, admin-only writes)."""

    serializer_class = ProviderSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "post", "patch", "head", "options"]
    queryset = Provider.objects.all().prefetch_related("assertions")

    def create(self, request, *args, **kwargs):
        _require_admin(request)
        with transaction.atomic():
            return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        with transaction.atomic():
            return super().update(request, *args, **kwargs)

    # A posture condition reads a provider's assertions, never its own fields, so a
    # write here fires none. It can leave one unable to read -- a rename away from
    # the name it watches, or a second provider by that name -- and the conditions
    # naming either name are evaluated now, so the posture says so at once.
    def perform_create(self, serializer):
        serializer.save()
        _fire_conditions(deployments_watching_provider(serializer.instance.name), self.request.user)

    def perform_update(self, serializer):
        before = serializer.instance.name
        serializer.save()
        _fire_conditions(
            deployments_watching_provider(before, serializer.instance.name), self.request.user
        )


class ProviderAssertionViewSet(viewsets.ModelViewSet):
    """The graded facts of a provider's assurance profile (Phase 1.5). Reads are
    open; creating/editing/deleting an assertion is admin-only and records who
    made the change."""

    serializer_class = ProviderAssertionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def get_queryset(self):
        qs = ProviderAssertion.objects.select_related("provider", "updated_by").all()
        provider = self.request.query_params.get("provider")
        if provider:
            valid = _valid_uuid(provider)
            qs = qs.filter(provider__uuid=valid) if valid else qs.none()
        field = self.request.query_params.get("field")
        if field:
            qs = qs.filter(field=field)
        return qs

    def create(self, request, *args, **kwargs):
        _require_admin(request)
        with transaction.atomic():
            return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        with transaction.atomic():
            return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        _require_admin(request)
        with transaction.atomic():
            return super().destroy(request, *args, **kwargs)

    # A provider-posture condition names a provider and a field; a write to one of
    # its assertions is the change it watches for, so the conditions naming that
    # provider -- before the write and after, if the assertion moved -- fire here.
    def perform_create(self, serializer):
        serializer.save(updated_by=self.request.user)
        _fire_conditions(deployments_watching_provider(serializer.instance.provider.name), self.request.user)

    def perform_update(self, serializer):
        before = serializer.instance.provider.name
        serializer.save(updated_by=self.request.user)
        _fire_conditions(
            deployments_watching_provider(before, serializer.instance.provider.name), self.request.user
        )

    def perform_destroy(self, instance):
        name = instance.provider.name
        instance.delete()
        _fire_conditions(deployments_watching_provider(name), self.request.user)


class UnknownViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,  # PATCH: disposition fields only (status/owner/notes/review_by/impact)
    viewsets.GenericViewSet,
):
    serializer_class = UnknownSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "patch", "head", "options"]

    def update(self, request, *args, **kwargs):
        # PATCH (disposition fields) mutates the record → admin-only.
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def get_queryset(self):
        # `owner` is read per row (owner.username), so select_related it too.
        qs = Unknown.objects.all().select_related("deployment", "finding", "owner")
        user = self.request.user
        if not _is_privileged(user):
            # Unknowns on a deployment the user owns, or derived from a finding on
            # a scan they launched. Mirrors the finding scoping.
            qs = qs.filter(deployment__owner=user) | qs.filter(finding__scan__user=user)
            qs = qs.distinct()
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        impact = self.request.query_params.get("impact")
        if impact:
            qs = qs.filter(deployment_impact=impact)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs
