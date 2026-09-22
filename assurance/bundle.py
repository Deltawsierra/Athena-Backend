"""The whole-portfolio assurance bundle: every stream, one request.

Athena's assurance API is a set of REST resources — deployments, findings,
claims, unknowns, each with its own route and its own pagination. That is the
right shape for a dashboard, which asks one question at a time about one
deployment. It is the wrong shape for anything that has to assess the engine
*as a whole*: a benchmark scoring recall and precision across a portfolio, an
export, an auditor's snapshot. Those callers want the verdicts the engine
currently stands behind, across every deployment, in one consistent read.

Assembling that client-side is not merely inconvenient, it is wrong. The streams
are read at different moments, so an ingest between two of them yields a bundle
in which a claim has been invalidated by drift the drift stream does not contain
— and the inconsistency looks exactly like an engine that failed to invalidate.
Here the whole bundle is read inside one transaction-consistent pass.

Five streams, because five different things can accuse a deployment:

  boundary_flows  where its data actually goes, reconciled against what the
                  customer approved (``assurance.boundary``)
  findings        its managed findings, which is where BOM drift lives
                  (``assurance.bom_drift`` writes ``bom_drift.*`` findings)
  claims          its assurance claims and their current status
  unknowns        its open register of gaps (``assurance.unknowns``)
  decisions       its six-state deployment decision

Every row carries a **subject**: a stable identity for the thing accused, so two
verdicts of one class at different subjects stay distinct. Subjects are scoped by
deployment name — ``payments-agent/openai-eu`` — because a portfolio bundle
spans deployments and a bare provider or claim name would collide across them.

Nothing here computes a verdict of its own. Every value is what the owning module
already decided; this reads them, names them, and puts them in one envelope.
"""

from __future__ import annotations

from django.utils.text import slugify

from . import observability as obs
from .boundary import assess_boundary
from .models import RESOLVED_FINDING_STATUSES, Unknown


def _slug(value: str) -> str:
    """A subject component: lowercase, hyphen-delimited, stable across reads."""
    return slugify((value or "").replace("_", "-"))


def _subject(deployment_name: str, *parts: str) -> str:
    """``deployment/part/part`` — the identity a verdict is reported under.

    Scoped by deployment because the bundle spans a portfolio: two deployments
    can both reach a provider called "OpenAI", and a bare provider name would
    silently merge their verdicts into one.
    """
    trail = [p for p in parts if p]
    return "/".join([deployment_name, *trail]) if trail else deployment_name


def _boundary_rows(deployment) -> list[dict]:
    """Every reconciled data flow, plus the destinations that escape the boundary.

    A shadow destination is carried as its own row at status ``shadow`` rather
    than folded into the flow it may or may not belong to: an unmanaged sink is
    outside *any* approved boundary by definition, and attributing it to a
    provider would be a guess dressed as a reconciliation.
    """
    assessment = assess_boundary(deployment)
    rows = [
        {
            "subject": _subject(deployment.name, _slug(flow["provider_name"])),
            "status": flow["status"],
            "provider": flow["provider_name"],
            "violations": flow["violations"],
            "unknowns": flow["unknowns"],
        }
        for flow in assessment["flows"]
    ]
    rows += [
        {
            "subject": _subject(deployment.name, _slug(sink["asset_name"])),
            "status": "shadow",
            "provider": None,
            "violations": [
                "an unmanaged data destination the deployment reaches, outside "
                "any approved boundary"
            ],
            "unknowns": [],
        }
        for sink in assessment["shadow_destinations"]
    ]
    return rows


def _finding_rows(deployment) -> list[dict]:
    """The deployment's active managed findings, each named by what it is about.

    ``location`` is the component a finding is about where the finding has one —
    every ``bom_drift.*`` finding sets it to the undeclared component or provider
    — and is what makes two drift findings on one deployment two subjects rather
    than one. A finding with no location falls back to its type, which is honest:
    it says what kind of thing was found and admits it cannot say where.
    """
    rows = []
    for finding in deployment.findings.exclude(status__in=RESOLVED_FINDING_STATUSES):
        where = _slug(finding.location) or _slug(finding.finding_type)
        rows.append(
            {
                "subject": _subject(deployment.name, where),
                "finding_type": finding.finding_type,
                "severity": finding.severity,
                "status": finding.status,
            }
        )
    return rows


def _claim_rows(deployment) -> list[dict]:
    """The deployment's live claims and the status each currently holds.

    Filtered to the *current* version of each claim identity — ``valid_to`` unset,
    which is the model's own definition and what its partial unique constraint
    enforces. Superseded versions are real history and belong in the claim's own
    timeline, but a bundle carrying both would report one claim twice at one
    subject, and a reader counting accusations would count a withdrawn one.
    Filtering on the status would be the near-miss here: it would also drop a
    REVOKED or STALE claim that is still the current version and still the
    engine's live answer.
    """
    return [
        {
            "subject": _subject(
                deployment.name,
                claim.claim_type,
                _slug(claim.asset.name) if claim.asset_id else "",
            ),
            "status": claim.status,
            "claim_type": claim.claim_type,
            "evidence_class": claim.evidence_class,
        }
        for claim in deployment.assurance_claims.filter(
            valid_to__isnull=True
        ).select_related("asset")
    ]


def _unknown_rows(deployment) -> list[dict]:
    """The open register: the questions this deployment's evidence cannot answer."""
    return [
        {
            "subject": _subject(deployment.name, unknown.subject),
            "question": unknown.question,
            "impact": unknown.deployment_impact,
            "source": unknown.source,
        }
        for unknown in deployment.unknowns.filter(
            status__in=[Unknown.Status.OPEN, Unknown.Status.INVESTIGATING]
        )
    ]


def _decision_row(deployment) -> dict:
    """The six-state decision, subject-ed to the deployment itself.

    The decision is about the deployment as a whole, so its subject is the bare
    deployment name with nothing appended — the one stream where that is right.
    """
    return {
        "subject": _subject(deployment.name),
        "state": deployment.decision,
        "environment": deployment.environment,
    }


def assurance_bundle(deployments) -> dict:
    """Assemble the five streams across every given deployment, in one pass.

    ``deployments`` is a queryset (already access-scoped by the caller — this
    module decides nothing about who may see what). Returns the bundle envelope:
    every stream flattened across the portfolio, with a per-deployment index so a
    reader can tell an empty portfolio from a portfolio of clean deployments.
    That distinction is the whole reason the index is here: a bundle of five
    empty lists reads as "nothing failed", and it must be possible to see whether
    anything was actually assessed.
    """
    with obs.span(obs.INVOKE_WORKFLOW, component="assurance_bundle"):
        scoped = deployments.select_related("data_boundary").prefetch_related(
            "assets__provider__assertions", "findings", "assurance_claims__asset", "unknowns"
        )

        boundary_flows: list[dict] = []
        findings: list[dict] = []
        claims: list[dict] = []
        unknowns: list[dict] = []
        decisions: list[dict] = []
        assessed: list[str] = []

        for deployment in scoped:
            assessed.append(deployment.name)
            boundary_flows += _boundary_rows(deployment)
            findings += _finding_rows(deployment)
            claims += _claim_rows(deployment)
            unknowns += _unknown_rows(deployment)
            decisions.append(_decision_row(deployment))

        return {
            "system": "athena-assurance",
            "boundary_flows": boundary_flows,
            "findings": findings,
            "claims": claims,
            "unknowns": unknowns,
            "decisions": decisions,
            "deployments_assessed": assessed,
        }
