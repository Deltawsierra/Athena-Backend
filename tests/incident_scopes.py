"""An incident's declared scope, for the recovery-record tests (SPINE SP-3).

A recovered state (``restored_with_restrictions``, ``recovery_accepted``) is reached only
under a declared scope revision (``assurance/incident_scope.py``). The suites that drive a
recovery that far declare one with these, so what each of them tests -- the witnesses, the
coverage, the owner's acceptance -- is judged exactly as it was.
"""

from __future__ import annotations


def asset(deployment, name="primary-route", kind="gateway"):
    """The asset of ``deployment`` of that name (made here when it is not there yet):
    something a scope can hold."""
    from assurance.models import Asset

    return Asset.objects.get_or_create(deployment=deployment, kind=kind, identifier=name, defaults={"name": name})[0]


def item(record) -> dict:
    """``record`` (an asset or an approved workflow) as a scope revision names it."""
    from assurance.models import ApprovedWorkflow

    if isinstance(record, ApprovedWorkflow):
        return {"kind": "workflow", "ref": record.slug}
    return {"kind": "asset", "ref": str(record.uuid)}


def evidence_of(finding):
    """One piece of ``finding``'s evidence, for a revision to rest on."""
    from assurance.models import Evidence

    return Evidence.objects.create(finding=finding, classification="technically_verified")


def body(finding, *records, reason="what the incident is known to have reached", evidence=None) -> dict:
    """What a revision holding ``records`` posts, resting on one piece of the finding's
    evidence (made here unless given)."""
    return {
        "items": [item(record) for record in records],
        "reason": reason,
        "evidence": [str((evidence or evidence_of(finding)).uuid)],
    }


def declare(finding, *records, by=None, **kw):
    """Declare the next revision of ``finding``'s scope, holding ``records`` (one asset of
    its deployment, made here, when none is given)."""
    from assurance import incident_scope

    records = records or (asset(finding.deployment),)
    return incident_scope.declare(finding, by=by, body=body(finding, *records, **kw))
