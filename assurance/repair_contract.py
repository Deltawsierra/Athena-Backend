"""A repair contract is agreed before any fix is worked on (Roadmap Phase 6).

"Before proposing a fix, force explicit agreement on two things: the prohibited
effect the repair must eliminate, and the legitimate behavior it must preserve.
Generating candidate repairs first and checking them against requirements after is
backwards -- it lets a repair that passes shallow tests through while silently
breaking preserved behavior."

A :class:`~assurance.models.RepairContract` is that agreement, for one finding:

- ``prohibited_effect``    -- the unauthorized effect the repair must eliminate;
- ``preserved_behaviours`` -- the legitimate behaviours that must keep working,
  each named once (a non-empty list of unique, non-empty names).

It is agreed by an operator (``agreed_by``, ``agreed_at``), versioned per finding
(1, 2, ...) and APPEND-ONLY: a row is never edited and never deleted on its own (it
goes only with its finding). A change of mind is a new version, and the latest
version is the CURRENT contract. ``content_digest`` is ``sha256:`` over the canonical
JSON (sorted keys, no spaces, UTF-8 -- :func:`assurance.closure_evidence.canonical_digest`)
of ``{finding_ref, version, prohibited_effect, preserved_behaviours}``, so a replay
can name the exact contract it was held to.

Two gates read it:

1. **No fix before agreement** (:func:`assurance.remediation.enforce_contract`, from
   :meth:`Finding.save` and :meth:`Finding.clean`, so the API, the admin, the
   remediation service and a shell all pass it): a finding's remediation cannot move
   into a working state -- ``in_progress``, ``in_review``, ``resolved`` -- without a
   current contract. A finding already in one of those states when this landed is
   not rewritten: it stays where it is, may still be moved to ``wont_fix``, needs a
   contract for any further move into a working state, and its closure is held to
   the contract like any other's (2).
2. **Closure is held to the contract** (:func:`contract_reasons`, read by
   :mod:`assurance.retest_closure`): a retest-gated closure stands only on a latest
   record whose replay document carries a ``contract`` block naming the finding's
   CURRENT contract's digest and reading ``retained`` for every preserved behaviour
   that contract names, and naming no other.

The routes: ``GET /api/assurance/findings/<uuid>/repair-contracts/`` lists a
finding's versions (any operator who can see the finding), ``POST`` agrees a new
version (admin only, attributed to the caller). Nothing here is a stop, holds one
back, or is read by one.
"""

from __future__ import annotations

import re

from django.db import transaction
from django.utils import timezone

#: The bounds of a contract. A preserved behaviour's name becomes a key of the
#: replay document's ``contract.preserved``, so it obeys that document's text rules
#: (:mod:`assurance.closure_evidence`, Minotaur-Backend's ``remediation_outcomes``).
MAX_EFFECT = 2000
MAX_NAME = 500
MAX_PRESERVED = 32

#: What a replay can say about each preserved behaviour (the replay's own utility
#: vocabulary). Only ``retained`` carries a closure.
RETAINED = "retained"
BROKEN = "broken"
UNKNOWN = "unknown"
PRESERVED_READINGS = frozenset({RETAINED, BROKEN, UNKNOWN})

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EFFECT_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # a newline or a tab is text


class ContractRefused(ValueError):
    """A contract that cannot be agreed. ``errors`` maps each field to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


class ContractIsAppendOnly(ValueError):
    """An edit or a delete of an agreed contract. A change is a new version."""


def _text_error(value, *, limit: int, control) -> str | None:
    if not isinstance(value, str):
        return "must be text"
    if not value.strip():
        return "must not be blank"
    if len(value) > limit:
        return f"must be at most {limit} characters"
    if value != value.strip():
        return "must be sent with no surrounding whitespace"
    if control.search(value):
        return "must hold no control characters"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "must be valid UTF-8 text"
    return None


def validate(prohibited_effect, preserved_behaviours) -> None:
    """Refuse (:class:`ContractRefused`) a contract that does not say both things."""
    errors: dict = {}
    reason = _text_error(prohibited_effect, limit=MAX_EFFECT, control=_EFFECT_CONTROL)
    if reason:
        errors["prohibited_effect"] = reason
    if not isinstance(preserved_behaviours, list):
        errors["preserved_behaviours"] = "must be a list of the behaviours that must keep working"
    elif not preserved_behaviours:
        errors["preserved_behaviours"] = "must name at least one behaviour that must keep working"
    elif len(preserved_behaviours) > MAX_PRESERVED:
        errors["preserved_behaviours"] = f"must name at most {MAX_PRESERVED} behaviours"
    else:
        seen: set = set()
        for i, name in enumerate(preserved_behaviours):
            reason = _text_error(name, limit=MAX_NAME, control=_CONTROL)
            if reason:
                errors[f"preserved_behaviours[{i}]"] = reason
            elif name in seen:
                errors[f"preserved_behaviours[{i}]"] = f"names {name!r} twice"
            else:
                seen.add(name)
    if errors:
        raise ContractRefused(errors)


def content_digest(finding_ref: str, version: int, prohibited_effect: str, preserved_behaviours) -> str:
    """``sha256:`` over the canonical JSON of the contract's four agreed fields."""
    from .closure_evidence import canonical_digest

    return canonical_digest(
        {
            "finding_ref": str(finding_ref),
            "version": int(version),
            "prohibited_effect": prohibited_effect,
            "preserved_behaviours": list(preserved_behaviours),
        }
    )


def contracts_of(finding) -> list:
    """Every agreed version of ``finding``'s contract, oldest first, read from the
    database -- what a gate decides on."""
    from .models import RepairContract

    if finding.pk is None:
        return []
    return list(RepairContract.objects.filter(finding_id=finding.pk).order_by("version"))


def current_contract(finding):
    """The latest version of ``finding``'s contract, or None. Read from the database."""
    from .models import RepairContract

    if finding.pk is None:
        return None
    return RepairContract.objects.filter(finding_id=finding.pk).order_by("-version").first()


def served_contracts(finding) -> list:
    """:func:`contracts_of` for SERVING: from the prefetched ``repair_contracts``
    when a view prefetched them, so a page of findings is one query. Never a gate's."""
    cached = getattr(finding, "_prefetched_objects_cache", {}).get("repair_contracts")
    if cached is None:
        return contracts_of(finding)
    return sorted(cached, key=lambda c: c.version)


@transaction.atomic
def agree(finding, *, prohibited_effect, preserved_behaviours, agreed_by=None, now=None):
    """Agree the next version of ``finding``'s repair contract and return it.

    Validated first (:func:`validate`); the version is the finding's latest plus one,
    allocated under a lock on the finding's row (and the ``(finding, version)``
    uniqueness behind it), so two agreements never take one number."""
    from .models import Finding, RepairContract

    validate(prohibited_effect, preserved_behaviours)
    Finding.objects.select_for_update().filter(pk=finding.pk).values_list("pk", flat=True).first()
    latest = current_contract(finding)
    version = 1 if latest is None else latest.version + 1
    return RepairContract.objects.create(
        finding=finding,
        version=version,
        prohibited_effect=prohibited_effect,
        preserved_behaviours=list(preserved_behaviours),
        agreed_by=agreed_by,
        agreed_at=now or timezone.now(),
    )


def served(contract, *, current_version=None) -> dict:
    """One contract version as a reader is served it."""
    return {
        "uuid": str(contract.uuid),
        "finding": str(contract.finding.uuid),
        "version": contract.version,
        "current": current_version is not None and contract.version == current_version,
        "prohibited_effect": contract.prohibited_effect,
        "preserved_behaviours": list(contract.preserved_behaviours),
        "agreed_by": contract.agreed_by.username if contract.agreed_by_id else None,
        "agreed_at": contract.agreed_at.isoformat(),
        "content_digest": contract.content_digest,
    }


def block_of(document) -> dict | None:
    """The replay document's ``contract`` block as it is served: its digest, and each
    behaviour's reading -- ``"unreadable"`` for anything that is not one of
    :data:`PRESERVED_READINGS`. None when the document carries no block."""
    if not isinstance(document, dict) or "contract" not in document:
        return None
    block = document["contract"]
    if not isinstance(block, dict):
        return {"digest": None, "preserved": {}, "unreadable": True}
    digest = block.get("digest")
    preserved = block.get("preserved")
    return {
        "digest": digest if isinstance(digest, str) else None,
        "preserved": {
            str(name): (reading if isinstance(reading, str) and reading in PRESERVED_READINGS else "unreadable")
            for name, reading in (preserved.items() if isinstance(preserved, dict) else ())
        },
        "unreadable": not isinstance(digest, str) or not isinstance(preserved, dict),
    }


def _names(names) -> str:
    return ", ".join(repr(n) for n in names)


def contract_reasons(document, contracts) -> list[str]:
    """Every reason the replay ``document`` does not hold its repair to the finding's
    current contract; empty when it does. ``contracts`` is every version of the
    finding's contract, oldest first. Never raises: whatever JSON a record holds,
    what cannot be read is a reason."""
    current = contracts[-1] if contracts else None
    if not isinstance(document, dict):
        return [
            "contract: the closure evidence carries no replay document, so it names no repair "
            "contract; a closure needs a replay held to the finding's current contract"
        ]
    if "contract" not in document:
        return [
            "contract: the replay names no repair contract; a closure needs a contract block "
            "naming the finding's current contract and reading every preserved behaviour retained"
        ]
    if current is None:
        return [
            "contract: no repair contract has been agreed for this finding; a closure needs one, "
            "and a replay held to it"
        ]
    block = document["contract"]
    digest = block.get("digest") if isinstance(block, dict) else None
    preserved = block.get("preserved") if isinstance(block, dict) else None
    if not isinstance(digest, str) or not isinstance(preserved, dict):
        return ["contract: unreadable"]
    reasons = []
    if digest != current.content_digest:
        named = next((c for c in contracts if c.content_digest == digest), None)
        if named is not None:
            reasons.append(
                f"contract: names version {named.version}, superseded by version {current.version}: "
                "evidence held to a superseded contract cannot close"
            )
        else:
            reasons.append(
                f"contract: names a digest that is no version of this finding's contract; the "
                f"current one is version {current.version}"
            )
    behaviours = list(current.preserved_behaviours) if isinstance(current.preserved_behaviours, list) else []
    missing = [n for n in behaviours if n not in preserved]
    if missing:
        reasons.append(f"contract: the replay does not report preserved behaviour(s) {_names(missing)}")
    for name in behaviours:
        if name not in preserved:
            continue
        reading = preserved[name]
        if not isinstance(reading, str) or reading not in PRESERVED_READINGS:
            reasons.append(f"contract: preserved behaviour {name!r}: unreadable reading")
        elif reading == BROKEN:
            reasons.append(f"contract: preserved behaviour {name!r} is broken: the repair broke what it must keep")
        elif reading == UNKNOWN:
            reasons.append(f"contract: could not tell whether preserved behaviour {name!r} survives")
    extra = sorted(str(n) for n in preserved if n not in behaviours)
    if extra:
        reasons.append(f"contract: names behaviour(s) the contract does not: {_names(extra)}")
    return reasons
