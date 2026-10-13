"""The review and override gates a signed receipt passes (section 28 hardening, T9a
and T1/T4; ``docs/economics/spec-v1.md``, section 35).

**The review gate (T9a).** The specification asks for "human review before external
delivery". A Financial Exposure Receipt is the delivered figure, so
:func:`review_refusal` refuses one (``scenario_not_reviewed``) unless the LATEST
review of the run's scenario version is ``approved``, by a person who authored no
version of the scenario (matched on the account and the username, as every
separation rule here). The review itself is written through
``POST .../economics/scenarios/<uuid>/reviews/`` (:mod:`.report_api`), whose model
refuses an author, and refuses an approval from someone an author promoted, who
promoted themselves, or who was promoted after the version was recorded (T9b,
``approver_role_not_independent``). The gate is ON by default. It is switched only by
the environment variable :data:`REVIEW_GATE_ENV`, read here in code and in no
settings module: ``off`` (exactly) turns it off; ``required``, unset, or any other
value keeps it on. It applies to every receipt: a receipt of a ``dev`` or
``staging`` deployment carries the same signature and states no environment, so it
is gated the same way.

**The override gate (T1/T4).** :func:`sensitive_changes` lists what moved between the
customer parameter-set version the run's build names and the version before it of
the same set: a variable added or removed, its unit or currency changed, its low,
base or high moved by a factor of :data:`MATERIAL_FACTOR` or more either way (or to
or from zero, or across zero), its stated distribution changed in kind or a
parameter of it moved by that factor, or the set's insurance exclusions changed.
That is how one analyst cut the transactions, the value or the frequency prior of a
version (the audit's probes T1b and T3a). Each change needs an IN-FORCE
:class:`~assurance.economics.models.SensitiveOverride` on the run's scenario version
naming its subject exactly: approved by two people, neither its requester; not
expired (:data:`~assurance.economics.engine.governance.OVERRIDE_EXPIRES_AFTER`); and
not revoked. Otherwise the receipt is refused (``material_change_unapproved``). An
override counts only while it is in force, read at the moment the receipt is asked
for, never stored. A first version has no version before it, and nothing to compare.

Both gates read rows and nothing else: no lock, no transaction, no engine. Nothing
here is on a stop path; nothing Django loads at start imports it.
"""

from __future__ import annotations

import os
from decimal import Decimal, InvalidOperation

from .engine import governance
from .models import (
    CustomerParameterSet,
    FinancialParameter,
    FinancialScenario,
    ReviewVerdict,
    ScenarioBuild,
    ScenarioReview,
    SensitiveOverride,
)

#: The environment variable that switches the review gate, read in code only.
REVIEW_GATE_ENV = "ATHENA_ECONOMICS_RECEIPT_REVIEW"
REVIEW_REQUIRED = "required"
REVIEW_OFF = "off"
#: How far a parameter-set figure moves, either way, before it is a sensitive change.
MATERIAL_FACTOR = Decimal(2)

#: What each code of the gates means.
REFUSALS = {
    "scenario_not_reviewed": (
        "a signed receipt is human-reviewed before it is delivered: the latest review of the run's scenario version "
        "is approved by a person who authored no version of it (POST .../reviews/ with verdict approved)"
    ),
    "material_change_unapproved": (
        "a figure of the run's customer parameter-set version moved materially against the version before it (by a "
        "factor of 2 or more, added, removed, or its distribution changed): each such change needs a sensitive "
        "override naming it that is IN FORCE -- approved by two people other than its requester, not expired and "
        "not revoked -- before a receipt is signed"
    ),
}


def review_gate() -> str:
    """:data:`REVIEW_OFF` only where :data:`REVIEW_GATE_ENV` is exactly ``off``;
    :data:`REVIEW_REQUIRED` otherwise (unset, ``required``, or anything unknown)."""
    return REVIEW_OFF if os.environ.get(REVIEW_GATE_ENV) == REVIEW_OFF else REVIEW_REQUIRED


def latest_review(scenario_id) -> ScenarioReview | None:
    """The scenario version's latest review, the one that stands (as
    :func:`assurance.economics.builder.review_status` orders them)."""
    return ScenarioReview._base_manager.filter(scenario_id=scenario_id).order_by("-reviewed_at", "-id").first()


def review_refusal(scenario_id) -> tuple[str, str] | None:
    """``("scenario_not_reviewed", detail)`` unless the gate is off or the latest
    review of the scenario version ``scenario_id`` is ``approved`` by someone who
    authored no version of it, read from the rows now; ``None`` otherwise."""
    if review_gate() == REVIEW_OFF:
        return None
    latest = latest_review(scenario_id)
    if latest is None:
        return "scenario_not_reviewed", "no review is recorded for this scenario version"
    if latest.verdict != ReviewVerdict.APPROVED:
        who = latest.reviewer_username or "nobody"
        return "scenario_not_reviewed", f"its latest review, by {who}, is {latest.verdict}"
    reviewer = governance.Person(id=latest.reviewer_id, username=latest.reviewer_username)
    refused = governance.review_refusal(FinancialScenario.authors_of(scenario_id), reviewer)
    if refused is not None:
        return "scenario_not_reviewed", f"its approving review is not a second person's ({refused})"
    return None


# ------------------------------------------------------------------ sensitive changes


def _material(before: str, after: str) -> bool:
    """Whether a figure moved materially: by :data:`MATERIAL_FACTOR` or more either
    way, to or from zero, or across zero. Text that is not a decimal moved."""
    try:
        a, b = Decimal(before), Decimal(after)
    except (InvalidOperation, TypeError, ValueError):
        return before != after
    if not (a.is_finite() and b.is_finite()):
        return before != after
    if a == b:
        return False
    if a == 0 or b == 0 or (a < 0) != (b < 0):
        return True
    small, large = sorted((abs(a), abs(b)))
    return large >= small * MATERIAL_FACTOR


def _distribution_change(before, after) -> str | None:
    if before == after:
        return None
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "its stated distribution was added or removed"
    held, now = before.get("params") or {}, after.get("params") or {}
    if (before.get("id"), before.get("version"), sorted(held)) != (after.get("id"), after.get("version"), sorted(now)):
        return f"its stated distribution changed from {before.get('id')} to {after.get('id')}"
    for name in sorted(held):
        if _material(str(held[name]), str(now[name])):
            return f"its stated distribution's {name} moved from {held[name]} to {now[name]}"
    return None


def _change(before: FinancialParameter, after: FinancialParameter) -> str | None:
    if (before.unit, before.currency) != (after.unit, after.currency):
        return f"its unit or currency changed ({before.unit} {before.currency} to {after.unit} {after.currency})"
    for field, held, now in (
        ("low", before.low, after.low), ("base", before.base, after.base), ("high", before.high, after.high)
    ):
        if _material(held, now):
            return f"its {field} moved from {held} to {now}"
    return _distribution_change(before.distribution, after.distribution)


def subject(version: CustomerParameterSet, name: str) -> str:
    """The override subject a change of ``name`` in ``version`` is approved under."""
    return f"parameter-set:{version.set_key}:v{version.version}:{name}"


def sensitive_changes(scenario_id) -> list[dict]:
    """What moved between the parameter-set version the scenario version's build
    names and the version before it of the same set, each as ``{"subject", "change"}``,
    sorted by subject (see the module's rules). Empty for a version with no build,
    or a first version."""
    build = ScenarioBuild._base_manager.filter(scenario_id=scenario_id).first()
    if build is None:
        return []
    version = CustomerParameterSet._base_manager.filter(pk=build.parameter_set_id).first()
    if version is None:
        return []
    previous = (
        CustomerParameterSet._base_manager.filter(
            deployment_id=version.deployment_id, set_key=version.set_key, version__lt=version.version
        )
        .order_by("-version")
        .first()
    )
    if previous is None:
        return []
    before = {row.name: row for row in previous.parameter_rows()}
    after = {row.name: row for row in version.parameter_rows()}
    changes = []
    for name in sorted(set(before) | set(after)):
        if name not in after:
            what = f"removed (v{previous.version} stated it)"
        elif name not in before:
            what = f"added (v{previous.version} did not state it)"
        else:
            what = _change(before[name], after[name])
        if what is not None:
            changes.append({"subject": subject(version, name), "change": what})
    if sorted(previous.insurance_exclusions or []) != sorted(version.insurance_exclusions or []):
        changes.append(
            {
                "subject": subject(version, "insurance_exclusions"),
                "change": f"the insurance exclusions changed from {previous.insurance_exclusions} to "
                f"{version.insurance_exclusions}",
            }
        )
    return sorted(changes, key=lambda change: change["subject"])


def in_force_subjects(scenario_id) -> set[str]:
    """The subjects of the scenario version's overrides that are in force now."""
    return {
        override.subject
        for override in SensitiveOverride._base_manager.filter(scenario_id=scenario_id).order_by("id")
        if SensitiveOverride.standing_refusal(override.pk) is None
    }


def override_refusal(scenario_id) -> tuple[str, str] | None:
    """``("material_change_unapproved", detail)`` naming each sensitive change of the
    scenario version that no override in force names; ``None`` otherwise."""
    changes = sensitive_changes(scenario_id)
    if not changes:
        return None
    approved = in_force_subjects(scenario_id)
    missing = [change["subject"] for change in changes if change["subject"] not in approved]
    if missing:
        return "material_change_unapproved", f"no override in force names {missing}"
    return None


def gate_refusal(scenario_id) -> tuple[str, str] | None:
    """The first refusal of the two gates, the review's first, or ``None``."""
    return review_refusal(scenario_id) or override_refusal(scenario_id)


__all__ = [
    "MATERIAL_FACTOR",
    "REFUSALS",
    "REVIEW_GATE_ENV",
    "REVIEW_OFF",
    "REVIEW_REQUIRED",
    "gate_refusal",
    "in_force_subjects",
    "latest_review",
    "override_refusal",
    "review_gate",
    "review_refusal",
    "sensitive_changes",
    "subject",
]
