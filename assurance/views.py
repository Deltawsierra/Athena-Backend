"""Read-focused API over the assurance system of record.

Findings, deployments, assets, and providers are exposed for the dashboard to
query. Findings are read-only except for the human workflow fields (status,
owner, business_impact) — the engine owns the rest and ingestion keeps it
current. Access follows the project's existing per-user ownership model: a caller
sees the deployments and findings tied to scans they can see (admins see all),
matching how ``pentest`` already scopes visibility.
"""

from __future__ import annotations

import uuid as uuidlib

from django.contrib.auth import get_user_model
from django.db.models import Count
from rest_framework import mixins, permissions, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from .access import assess_effective_access
from .bom import build_ai_bom
from .boundary import assess_boundary
from .business_impact import build_business_impact
from .capability import assess_capabilities
from .compliance import build_compliance_map
from .data_lifecycle import assess_data_lifecycle
from .decision import recompute_decision
from .metadata_logging import assess_metadata_logging
from .personal_context import assess_personal_context
from .training_reuse import assess_training_reuse
from .packs import UnknownPack, apply_pack, list_packs
from .roi import build_executive_summary
from .route import build_route_map
from .models import Asset, DataBoundary, Deployment, Finding, Provider, ProviderAssertion, Unknown
from .receipt import build_assurance_receipt, deployment_receipt
from .ripple import assess_ripple
from .remediation import IllegalTransition, apply_transition, assign
from .vendor import assess_vendors
from .serializers import (
    AssetSerializer,
    DataBoundarySerializer,
    DeploymentSerializer,
    FindingSerializer,
    ProviderAssertionSerializer,
    ProviderSerializer,
    RemediationEventSerializer,
    UnknownSerializer,
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


def _valid_uuid(value: str) -> str | None:
    """A well-formed UUID string, or None. A malformed ``?deployment=`` filter
    must not reach the ORM as a raw string — that raises a Django ValidationError
    DRF does not catch, surfacing as a 500 instead of an empty result set."""
    try:
        return str(uuidlib.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


class DeploymentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = DeploymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        qs = Deployment.objects.all().annotate(finding_count=Count("findings"))
        user = self.request.user
        if _is_privileged(user):
            return qs
        # Own deployments, or deployments whose findings came from the user's scans.
        return qs.filter(owner=user).distinct()

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
        currently_paused = deployment.decision == Deployment.Decision.PAUSED
        paused = bool(request.data.get("paused", currently_paused))
        decision = recompute_decision(deployment, paused=paused)
        return Response({"decision": decision, "decision_label": deployment.get_decision_display()})

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

    @action(detail=True, methods=["get"], url_path="connectors")
    def connectors(self, request, uuid=None):
        """List the outbound connectors and whether each is configured (commercial
        spine). A read: an operator can see which integrations exist and which are
        inert for lack of credentials, without triggering anything."""
        from .connectors import available_connectors, build_connector

        self.get_object()  # scope/permission check on the deployment
        return Response(
            {
                "connectors": [
                    {"name": name, "configured": build_connector(name).configured}
                    for name in available_connectors()
                ]
            }
        )

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
            conn = build_connector(connector)
        except UnknownConnector as exc:
            return Response({"detail": str(exc)}, status=400)
        # RequestsTransport is only ever *touched* when the connector is
        # configured; an inert connector short-circuits before any post.
        result = conn.push_finding(finding, transport=RequestsTransport())
        return Response(result.as_dict())

    @action(detail=True, methods=["get", "put"], url_path="data-boundary")
    def data_boundary(self, request, uuid=None):
        """AI Data Boundary Assessment (Phase 1.4): reconcile the approved data
        boundary against the deployment's actual data destinations.

        GET returns the assessment (open read). PUT declares/updates the approved
        boundary (admin-only — it mutates the record) and returns the fresh
        assessment. The assessment itself is always computed, never stored."""
        deployment = self.get_object()
        if request.method == "PUT":
            _require_admin(request)
            serializer = DataBoundarySerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            DataBoundary.objects.update_or_create(
                deployment=deployment,
                defaults={**serializer.validated_data, "updated_by": request.user},
            )
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
        which posture assessments exist and which are inert for lack of
        credentials, without triggering anything. Mirrors the ``connectors`` list."""
        from .posture import available_domains, build_assessment

        self.get_object()  # scope/permission check on the deployment
        return Response(
            {
                "domains": [
                    {
                        "name": name,
                        "label": build_assessment(name).label,
                        "configured": build_assessment(name).configured,
                    }
                    for name in available_domains()
                ]
            }
        )

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
        """Build the posture domain from settings/env and assess it. A real
        :class:`RequestsFetcher` is passed exactly as the connector push passes a
        real transport — but an unconfigured domain short-circuits before the
        fetcher is ever touched, so nothing is read. In this repo no domain is
        configured (live wiring deferred), so every posture read is inert."""
        from .posture import RequestsFetcher, build_assessment

        self.get_object()  # scope/permission check on the deployment
        assessment = build_assessment(domain)
        return assessment.assess(fetcher=RequestsFetcher())

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
        business was harmed; it maps to dimensions only, since the record carries no
        business-process or owner-of-process attribution."""
        assessed = Deployment.objects.prefetch_related("findings").get(pk=self.get_object().pk)
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
        assessed = (
            Deployment.objects.prefetch_related(
                "findings__evidence", "findings__remediation_events", "assets__provider__assertions"
            )
            .select_related("data_boundary")
            .get(pk=self.get_object().pk)
        )
        return Response(build_executive_summary(assessed))

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
        ``status``."""
        _require_admin(request)
        finding = self.get_object()
        username = request.data.get("assignee")
        assignee = None
        if username not in (None, ""):
            assignee = User.objects.filter(username=username).first()
            if assignee is None:
                return Response({"detail": f"No such user: {username!r}."}, status=400)
        event = assign(
            finding, assignee, actor=request.user, note=request.data.get("note", "")
        )
        return Response(
            {
                "assignee": assignee.username if assignee else None,
                "event": RemediationEventSerializer(event).data,
            }
        )

    def _scoped_findings(self):
        """Every finding the caller may see, BEFORE the severity/status/deployment
        query filters. The change-intelligence boundary (a deployment's latest
        scan) is a fact about the deployment, so it must be computed over the
        unfiltered set — a ``?status=open`` view must not redefine "latest scan"."""
        qs = Finding.objects.all()
        user = self.request.user
        if _is_privileged(user):
            return qs
        return (qs.filter(scan__user=user) | qs.filter(deployment__owner=user)).distinct()

    def get_serializer_context(self):
        """Supply the change-intelligence inputs once per request: the latest-scan
        boundary per deployment (one aggregate query) and a single ``now``, so the
        serializer never issues a query per finding."""
        from django.utils import timezone

        from .change import latest_seen_by_deployment

        ctx = super().get_serializer_context()
        ctx["latest_seen"] = latest_seen_by_deployment(self._scoped_findings())
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
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        return super().update(request, *args, **kwargs)


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
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        _require_admin(request)
        return super().destroy(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)


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
