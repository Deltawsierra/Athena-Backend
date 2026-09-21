"""Derive the Unknowns Register from what a deployment cannot answer.

Roadmap Phase 0.4. A gap is a specific question the evidence does not answer. It
is neither a clean result nor a proven vulnerability, and this module turns each
one into a managed :class:`~assurance.models.Unknown` so it is owned, dated, and
shown, instead of silently rounding down to "fine" or up to "broken".

Two sources feed it, and the second exists because the first is not enough:

* **Unverified findings.** A finding the scan flagged but could not confirm, or
  one nothing documented. The evidence class says so; the gap is the question of
  whether it is real.

* **Undeclared provider postures.** The data-boundary assessment
  (:mod:`assurance.boundary`) reconciles where a deployment's data actually goes
  against what the customer approved, and reports, per flow, the postures it
  could not assess because nobody declared them — does this provider train on
  customer data, does it reach third-party subprocessors, where does it process.
  Those are the highest-consequence questions the platform asks, and they arise
  precisely where there is **no finding at all**: a provider nobody documented
  produces no scan output, so a findings-only register reports zero gaps for the
  deployment that knows the least about itself. That is the silent-zero failure
  this whole discipline exists to prevent, so the assessment's gaps are promoted
  here into the same managed, owned, dated rows.

It is **idempotent** and **non-destructive**, exactly like ingestion: an Unknown
is keyed within its deployment by a fingerprint derived from the finding, so a
re-derive updates the machine-owned fields and refreshes ``last_seen`` rather
than duplicating the row, and human-set state (status, owner, review date,
notes) is never clobbered. When a finding stops being unverified — it was
resolved, or fresh evidence upgraded its class — its still-open derived Unknown
is auto-resolved, because the question it asked has been answered. Nothing here
reaches the network.
"""

from __future__ import annotations

import hashlib

from django.utils import timezone
from django.utils.text import slugify

from .boundary import (
    BOUNDARY_UNDECLARED,
    REGION_UNDECLARED,
    SHARING_UNDECLARED,
    TRAINING_UNDECLARED,
    assess_boundary,
)
from .models import (
    RESOLVED_FINDING_STATUSES,
    Deployment,
    EvidenceClass,
    Finding,
    Unknown,
    severity_rank,
)

# The evidence classes that mean "we saw something but cannot stand behind it":
# a low-strength observation the scan could not confirm, an unknown, or nothing
# documented. These are the honest gaps — a technically- or configuration-verified
# finding is a known quantity and belongs in the decision, not the register.
# (This is intentionally broader than ``decision._UNVERIFIED``: the decision's
# NEEDS_MORE_EVIDENCE state is a whole-deployment verdict for the narrow "clean
# but unproven" case, whereas a gap is worth tracking per-finding the moment the
# evidence is merely partial.)
UNVERIFIED_CLASSES = frozenset(
    {
        EvidenceClass.PARTIALLY_VERIFIED.value,
        EvidenceClass.UNKNOWN.value,
        EvidenceClass.NOT_DOCUMENTED.value,
    }
)



def _slug(value: str) -> str:
    """A subject slug: lowercase, hyphen-delimited, no surprises in a URL or a key."""
    return slugify((value or "").replace("_", "-"))


def _subject_for(finding: Finding) -> str:
    """What a finding-derived gap is *about*: the kind of thing left unconfirmed.

    The finding's own type, slugified — ``prompt-injection`` for an unconfirmed
    prompt-injection finding. Deliberately not the finding's primary key: the
    subject is a description a person or an external consumer can read and match
    on, and the row's identity is already carried by its fingerprint. Two
    unconfirmed findings of the same type are two rows with the same subject,
    which is correct — they are two instances of one kind of gap.

    Falls back to the row id only when a finding carries no type at all, so a gap
    is never left nameless."""
    return _slug(finding.finding_type) or f"finding-{finding.pk}"


def _fingerprint(finding: Finding) -> str:
    """Tie the Unknown to the finding it derives from, stable across re-derives.

    The raw string is ``finding:<pk>`` and must stay that way: it is the dedup key
    of every row already in the register, so changing it would orphan them —
    every existing gap auto-resolved and silently re-created, losing the owner,
    the review date, and the notes a human put there."""
    raw = f"finding:{finding.pk}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _impact_for(finding: Finding) -> str:
    """How much an unverified finding moves the deployment decision. A gap on a
    high/critical finding is a high-impact unknown (we cannot rule out the worst
    case); a medium is medium; anything lower is low."""
    rank = severity_rank(finding.severity)
    if rank >= severity_rank("high"):
        return Unknown.Impact.HIGH
    if rank >= severity_rank("medium"):
        return Unknown.Impact.MEDIUM
    return Unknown.Impact.LOW


def _question(finding: Finding) -> str:
    return f"Is '{finding.title}' real, and what is its true severity?"


def _why(finding: Finding) -> str:
    return (
        f"A {finding.severity} finding was reported but its evidence is unverified, "
        "so it can neither be counted as a confirmed risk nor cleared."
    )


def _evidence_needed(finding: Finding) -> str:
    return (
        "Reproduce the finding against the live system, or obtain configuration / "
        "vendor evidence that confirms or rules it out."
    )


# The sources this module owns. A row carrying one of these is machine-managed:
# the deriver refreshes its substance and may auto-resolve it. MANUAL is absent
# by design — a gap a human raised is theirs.
_MACHINE_SOURCES = (Unknown.Source.DERIVED, Unknown.Source.POSTURE)


def _upsert(deployment: Deployment, fingerprint: str, machine_fields: dict, now) -> Unknown:
    """Create or refresh one machine-owned Unknown, keyed by its fingerprint.

    Refreshes only the machine-owned fields; status, owner, review date and notes
    are a human's and are never written here. The one exception is a gap the
    *machine* auto-resolved that has since come back — it is re-opened, because
    the question it asks is live again — and a gap a human resolved or accepted
    stays exactly as they left it."""
    unknown, created = Unknown.objects.get_or_create(
        deployment=deployment,
        fingerprint=fingerprint,
        defaults={**machine_fields, "first_seen": now},
    )
    if created:
        return unknown

    for key, value in machine_fields.items():
        setattr(unknown, key, value)
    fields = [*machine_fields.keys(), "updated_at"]
    if unknown.status == Unknown.Status.RESOLVED and unknown.auto_resolved:
        unknown.status = Unknown.Status.OPEN
        unknown.auto_resolved = False
        fields += ["status", "auto_resolved"]
    unknown.save(update_fields=fields)
    return unknown


def _derive_finding_unknowns(deployment: Deployment, now) -> tuple[set[str], list[Unknown]]:
    """Reconcile the register's finding-derived gaps. Returns (live, open)."""
    live: set[str] = set()
    open_unknowns: list[Unknown] = []

    active = deployment.findings.exclude(
        status__in=RESOLVED_FINDING_STATUSES
    ).prefetch_related("evidence")

    for finding in active:
        if finding.evidence_class not in UNVERIFIED_CLASSES:
            continue
        fingerprint = _fingerprint(finding)
        live.add(fingerprint)

        machine_fields = {
            "finding": finding,
            "subject": _subject_for(finding),
            "question": _question(finding),
            "why_it_matters": _why(finding),
            "evidence_needed": _evidence_needed(finding),
            "deployment_impact": _impact_for(finding),
            "source": Unknown.Source.DERIVED,
            "last_seen": now,
        }
        unknown = _upsert(deployment, fingerprint, machine_fields, now)
        if unknown.is_open:
            open_unknowns.append(unknown)

    return live, open_unknowns


# ---------------------------------------------------------------------------
# The second source: postures nobody declared
# ---------------------------------------------------------------------------

# One entry per gap the data-boundary assessment can report, keyed by the code
# ``assurance.boundary`` emits. ``subject`` is the slug the register (and anything
# reading it from outside) names this gap by; the rest is the substance an Unknown
# must carry to be worth tracking.
#
# On the impact grades: a posture gap is scored by what it can be *hiding*, not by
# how loud it is. Training and subprocessor gaps are HIGH because the breach they
# could conceal is irreversible — customer data absorbed into a model's weights,
# or handed to a party nobody approved, cannot be recalled once it has happened,
# and in both cases the customer's own boundary says it is not allowed. A region
# gap is MEDIUM: a jurisdiction breach is a serious compliance exposure but a
# correctable one, and the data is still only where the provider put it. The
# undeclared-boundary gap is HIGH because it is not one unanswered question but
# the absence of the standard all three are measured against — with no approved
# boundary on file, *nothing* about this deployment's data flows has been assessed,
# and a register that graded that as a minor housekeeping item would be lying
# about the state of the deployment that knows the least about itself.
_POSTURE_GAPS: dict[str, dict] = {
    BOUNDARY_UNDECLARED: {
        "subject": "data-boundary",
        "impact": Unknown.Impact.HIGH,
        "question": (
            "What is this deployment approved to do with customer data — which "
            "regions, and may it be trained on or shared with third parties?"
        ),
        "why_it_matters": (
            "No data boundary has been approved for this deployment, so there is "
            "nothing to reconcile its actual data flows against. Every provider it "
            "reaches is unassessed rather than approved, and no flow can be called "
            "a violation or a pass."
        ),
        "evidence_needed": (
            "An approved data boundary for the deployment: the permitted "
            "processing regions, and explicit decisions on training on customer "
            "data and third-party sharing."
        ),
    },
    REGION_UNDECLARED: {
        "subject": "region-posture",
        "impact": Unknown.Impact.MEDIUM,
        "question": "In which regions do this deployment's providers process its data?",
        "why_it_matters": (
            "The approved boundary restricts processing to named regions, but the "
            "provider has not declared where it processes. The flow can be neither "
            "cleared nor called a violation, so a jurisdiction breach would not "
            "show up as one."
        ),
        "evidence_needed": (
            "The provider's declared processing region — from its documentation, "
            "its DPA, or a region-pinned endpoint — recorded as a region assertion."
        ),
    },
    TRAINING_UNDECLARED: {
        "subject": "training-posture",
        "impact": Unknown.Impact.HIGH,
        "question": "Does any provider this deployment relies on train on its customer data?",
        "why_it_matters": (
            "The approved boundary does not permit training on customer data, and "
            "the provider has not declared its posture, so the platform cannot rule "
            "it out. Data absorbed into a model cannot be withdrawn afterwards, "
            "which makes an undeclared training posture the most expensive gap in "
            "the register to leave open."
        ),
        "evidence_needed": (
            "The provider's training-on-customer-data posture in writing — a "
            "zero-retention or no-training commitment in its documentation or DPA — "
            "recorded as a trains_on_data assertion."
        ),
    },
    SHARING_UNDECLARED: {
        "subject": "sharing-posture",
        "impact": Unknown.Impact.HIGH,
        "question": (
            "Which third parties or subprocessors does this deployment's data reach "
            "through its providers?"
        ),
        "why_it_matters": (
            "The approved boundary does not permit third-party sharing, and the "
            "provider has not declared its subprocessors, so the set of parties "
            "holding this deployment's data is unknown. Data already handed to an "
            "unapproved party cannot be taken back."
        ),
        "evidence_needed": (
            "The provider's subprocessor list, or an explicit declaration that it "
            "uses none, recorded as a subprocessors assertion."
        ),
    },
}


def _posture_fingerprint(code: str) -> str:
    """Dedup key for a posture gap. Namespaced so it can never collide with a
    finding-derived fingerprint, whatever a finding's primary key happens to be."""
    return hashlib.sha256(f"posture:{code}".encode("utf-8")).hexdigest()


def _providers_phrase(names: list[str]) -> str:
    """Name the providers a gap is about, so the question is answerable."""
    if not names:
        return ""
    if len(names) == 1:
        return f" Undeclared for: {names[0]}."
    return f" Undeclared for: {', '.join(names[:-1])} and {names[-1]}."


def _posture_gaps(deployment: Deployment) -> dict[str, list[str]]:
    """The deployment's undeclared postures, as ``{code: [provider names]}``.

    Aggregates the boundary assessment's per-flow gaps by what is unanswered
    rather than by which provider left it unanswered: the register tracks
    questions about the *deployment*, and "do any of my providers train on my
    data?" is one question however many vendors are silent about it. The provider
    names go into the gap's text so nothing is lost by grouping.
    """
    # Re-read the deployment with the assessment's own prefetches so this costs a
    # fixed handful of queries no matter how many assets or providers it has.
    prefetched = (
        Deployment.objects.filter(pk=deployment.pk)
        .select_related("data_boundary")
        .prefetch_related("assets__provider__assertions")
        .first()
    )
    assessment = assess_boundary(prefetched or deployment)

    gaps: dict[str, list[str]] = {}
    for flow in assessment["flows"]:
        for code in flow.get("unknown_codes", ()):
            names = gaps.setdefault(code, [])
            # BOUNDARY_UNDECLARED repeats on every flow (it is a property of the
            # deployment, not the provider), so the same name can arrive twice.
            if flow["provider_name"] not in names:
                names.append(flow["provider_name"])
    for names in gaps.values():
        names.sort()
    return gaps


def _derive_posture_unknowns(deployment: Deployment, now) -> tuple[set[str], list[Unknown]]:
    """Reconcile the register's posture gaps. Returns (live fingerprints, open)."""
    live: set[str] = set()
    open_unknowns: list[Unknown] = []

    for code, provider_names in _posture_gaps(deployment).items():
        spec = _POSTURE_GAPS.get(code)
        if spec is None:
            # An assessment code this module has no entry for. Skipping is the
            # honest choice over inventing a question: a gap with no substance
            # would be an empty row that looks worked and asks nothing.
            continue
        fingerprint = _posture_fingerprint(code)
        live.add(fingerprint)

        machine_fields = {
            # A posture gap has no finding behind it — that is the whole point of
            # this source — so the link stays null.
            "finding": None,
            "subject": spec["subject"],
            "question": spec["question"],
            "why_it_matters": spec["why_it_matters"] + _providers_phrase(provider_names),
            "evidence_needed": spec["evidence_needed"],
            "deployment_impact": spec["impact"],
            "source": Unknown.Source.POSTURE,
            "last_seen": now,
        }
        unknown = _upsert(deployment, fingerprint, machine_fields, now)
        if unknown.is_open:
            open_unknowns.append(unknown)

    return live, open_unknowns


# ---------------------------------------------------------------------------
# The entry point
# ---------------------------------------------------------------------------


def derive_unknowns(deployment: Deployment) -> list[Unknown]:
    """Reconcile the deployment's Unknowns register with what it cannot answer.

    Creates or refreshes a machine-owned Unknown for every active finding whose
    evidence is unverified *and* for every provider posture the data-boundary
    assessment could not assess, then auto-resolves the machine-owned Unknowns
    whose gap has closed. Returns the Unknowns that are currently open after
    reconciliation. Manually raised Unknowns are never touched, and human-set
    disposition survives every re-derive. Safe to call repeatedly."""
    now = timezone.now()

    from_findings, open_from_findings = _derive_finding_unknowns(deployment, now)
    from_posture, open_from_posture = _derive_posture_unknowns(deployment, now)

    # One live set across both sources. Keeping them separate would make each
    # pass auto-resolve the other's rows on sight, so the register would flap
    # between two halves of itself on every ingest.
    live_fingerprints = from_findings | from_posture
    open_unknowns = open_from_findings + open_from_posture

    # Auto-resolve machine-owned Unknowns whose gap has closed: the finding was
    # resolved or its evidence upgraded, or the posture has since been declared.
    # Manual Unknowns and already-closed ones are left alone.
    stale = deployment.unknowns.filter(
        source__in=_MACHINE_SOURCES,
        status__in=[Unknown.Status.OPEN, Unknown.Status.INVESTIGATING],
    ).exclude(fingerprint__in=live_fingerprints)
    for unknown in stale:
        unknown.status = Unknown.Status.RESOLVED
        # Mark this a *machine* resolution so a later re-derive can re-open it if
        # the gap comes back, without ever disturbing a human's disposition.
        unknown.auto_resolved = True
        unknown.last_seen = now
        unknown.save(update_fields=["status", "auto_resolved", "last_seen", "updated_at"])

    return open_unknowns
