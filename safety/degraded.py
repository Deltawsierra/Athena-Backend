"""How every operation degrades when something it depends on fails (G14).

The owner's decision 13 (1 Nov 2026) names four operation classes and one
degraded behaviour for each, for whenever a dependency of this backend is down,
slow or answering garbage -- the database, an engine, Mythos-Core, the evidence
store, a connector, a signer:

* :data:`STOP` -- stand-down, pause, terminate, revoke, a scan's Stop, the
  dispatch kill switch. Always works. Nothing here gates one, and nothing here
  changes what one answers: the stop set is :mod:`safety.stops`' alone.
* :data:`EVIDENCE_READ` -- history, findings, chains, contracts, status views.
  Degrades to an honest ``unknown``, with the reason: never a stale value shown
  as current, never a 5xx with no reason, never an empty list shown as "none".
* :data:`EFFECT` -- dispatch, approvals, declarations, a preflight-gated launch,
  every other write. Fails closed: ``HOLD``, never proceed.
* :data:`ASSESSMENT` -- readiness, a receipt's decision, compliance, posture,
  a verdict rolled up from evidence. Comes out ``AUDIT_INCOMPLETE``, never PASS.

Every route declares its class here, by URL name and method, except the stops:
a method :mod:`safety.stops` lists in ``EXEMPT_ROUTES`` is :data:`STOP` and is
declared nowhere else, so the stop set keeps one definition.
``tests/test_every_operation_says_how_it_degrades.py`` walks the URLconf and
fails on a route or method with no class, on a stop declared here, and on a stop
that this policy touches.

Where it acts. A view that knows its dependency failed answers for itself, in
its own response shape (the preflight's 409, an engine's 502, a posture
check's ``unknown``). A failure no view caught -- the database refusing the
authentication read, a row that does not decode, a library raising -- used to
reach Django as an uncaught exception and answer a bare HTML "Server Error
(500)" that named nothing. :func:`server_error` is the root URLconf's
``handler500``: for every route but a stop it answers the same 500, now in DRF's
error shape (``detail``), with the class's status word, the dependency that
failed and why. The status code is kept: every client and every chaos table that
reads a fault as a 500 still does, and only the reason is new.
It runs only after a view has already raised, so it delays nothing and refuses
nothing; for a stop, and for any request it cannot place, it returns Django's
own 500 unchanged.

The status words are Mythos-Core's, never a third vocabulary:
``mythos_core.status.UNKNOWN``, ``mythos_core.action_assurance.decision.HOLD``
and ``mythos_core.status.AUDIT_INCOMPLETE``.
"""

from __future__ import annotations

import logging
import sys

from django.db import DatabaseError
from django.http import JsonResponse
from django.views import defaults

from . import stops

# Mythos-Core's words, spelled here rather than imported: this module is the root
# URLconf's handler500, which ``manage.py check`` and ``deliver_owed_stops`` import
# before they run, so an import that can fail here (a Mythos-Core module that will
# not load) would take a stop's delivery down with it. The test module asserts each
# equals Mythos-Core's own constant, so they cannot drift.
#: ``mythos_core.status.UNKNOWN``
UNKNOWN = "unknown"
#: ``mythos_core.action_assurance.decision.HOLD``
HOLD = "HOLD"
#: ``mythos_core.status.AUDIT_INCOMPLETE``
AUDIT_INCOMPLETE = "AUDIT_INCOMPLETE"

logger = logging.getLogger(__name__)

STOP = "stop"
EVIDENCE_READ = "evidence_read"
EFFECT = "effect"
ASSESSMENT = "assessment"

#: Each operation class and its degraded behaviour: the policy, as data.
POLICY = {
    STOP: {
        "status": None,
        "behaviour": "always works: never gated, never held on a failed dependency beyond its own bounds",
    },
    EVIDENCE_READ: {
        "status": UNKNOWN,
        "behaviour": "an honest unknown with its reason: never a stale value as current, never a bare 5xx, "
        "never an empty list as none",
    },
    EFFECT: {
        "status": HOLD,
        "behaviour": "fails closed: held, never proceeds",
    },
    ASSESSMENT: {
        "status": AUDIT_INCOMPLETE,
        "behaviour": "audit incomplete, never pass",
    },
}

_R, _E, _A = EVIDENCE_READ, EFFECT, ASSESSMENT

#: URL name -> {method: class}, for every method that is not a stop. "ANY" is a
#: plain Django view, which serves every method.
ROUTES = {
    "health": {"GET": _R},
    # Each dependency's state with its reason: a not-ready answer is itself this
    # class's degraded answer (503, unknown, the dependency named).
    "readiness": {"GET": _R},
    "token_obtain_pair": {"POST": _E},
    "api-root": {"GET": _R},
    "accounts:api-root": {"GET": _R},
    "accounts:user-list": {"GET": _R, "POST": _E},
    "accounts:user-me": {"GET": _R},
    "accounts:user-detail": {"GET": _R, "PUT": _E, "PATCH": _E},
    "audit_log_list": {"GET": _R},
    "export_pdf": {"GET": _R},
    "asset-detail": {"GET": _R},
    "asset-list": {"GET": _R},
    "claim-list": {"GET": _R},
    "claim-detail": {"GET": _R},
    "claim-events": {"GET": _R},
    "claim-evidence": {"GET": _R},
    "claim-declare-latent-condition": {"POST": _E},
    "claim-withdraw-latent-condition": {"POST": _E},
    "deployment-list": {"GET": _R},
    "deployment-detail": {"GET": _R},
    # Every assurance stream in one read, the decision among them.
    "deployment-check": {"POST": _A},
    "deployment-latency": {"GET": _R},
    "deployment-receipt": {"GET": _A},
    "deployment-assurance-receipt": {"GET": _A},
    "deployment-signed-assurance-receipt": {"GET": _A},
    "deployment-vendor-packet-candidates": {"GET": _R},
    "deployment-chain-birth": {"GET": _R, "POST": _E},
    "deployment-connectors": {"GET": _R},
    "deployment-connector-push": {"POST": _E},
    "deployment-connector-config": {"GET": _R, "PUT": _E, "DELETE": _E},
    "deployment-posture-config": {"GET": _R, "PUT": _E, "DELETE": _E},
    "deployment-dispatch-attempts": {"GET": _R},
    "deployment-dispatch-policy": {"GET": _R},
    "deployment-data-boundary": {"GET": _R, "PUT": _E, "PATCH": _E},
    "deployment-capabilities": {"GET": _R},
    "deployment-route-map": {"GET": _R},
    "deployment-effective-access": {"GET": _R},
    "deployment-ripple-effect": {"GET": _R},
    "deployment-personal-context": {"GET": _R},
    "deployment-data-lifecycle": {"GET": _R},
    "deployment-training-reuse": {"GET": _R},
    "deployment-metadata-logging": {"GET": _R},
    # Posture: a verdict per check, rolled up from what a connector read.
    "deployment-posture": {"GET": _A},
    "deployment-cloud-posture": {"GET": _A},
    "deployment-secrets-posture": {"GET": _A},
    "deployment-repo-posture": {"GET": _A},
    "deployment-approved-workflows": {"GET": _R, "PUT": _E},
    "deployment-chain-outcomes": {"GET": _R, "POST": _E},
    "deployment-observed-chain-outcomes": {"POST": _E},
    "deployment-authority-chains": {"GET": _R, "POST": _E},
    "deployment-observed-effects": {"POST": _E},
    "deployment-effect-reconciliations": {"POST": _E},
    "deployment-achilles-scan-results": {"GET": _R, "POST": _E},
    "deployment-approval-in-force": {"GET": _R},
    "deployment-authentications": {"POST": _E},
    "deployment-delegations": {"POST": _E},
    "deployment-economics-parameter-set": {"GET": _R},
    "deployment-economics-parameter-set-versions": {"GET": _R, "POST": _E},
    "deployment-economics-scenario-build": {"POST": _E},
    "deployment-economics-scenario-events": {"GET": _R},
    "economics-packs": {"GET": _R},
    "economics-source-trust-raises": {"GET": _R, "POST": _E},
    "economics-trust-raise-approve": {"POST": _E},
    "economics-trust-raise-withdraw": {"POST": _E},
    "deployment-economics-scenario": {"GET": _R},
    "deployment-economics-scenario-simulate": {"POST": _E},
    "deployment-economics-scenario-results": {"GET": _R},
    "deployment-economics-scenarios": {"GET": _R},
    "deployment-economics-receipt": {"GET": _R},
    "deployment-economics-scenario-freshness": {"GET": _R},
    "deployment-economics-assurance": {"GET": _R, "POST": _E},
    "deployment-economics-scenario-refresh": {"POST": _E},
    "deployment-economics-scenario-reviews": {"GET": _R, "POST": _E},
    "deployment-economics-scenario-overrides": {"GET": _R, "POST": _E},
    "deployment-economics-override-approve": {"POST": _E},
    "deployment-economics-scenario-mitigations": {"POST": _E},
    "deployment-economics-mitigation-simulate": {"POST": _E},
    "deployment-economics-scenario-roi": {"GET": _A},
    "deployment-economics-data-health": {"GET": _R},
    "deployment-economics-suggestions": {"GET": _R},
    "deployment-economics-scenario-precedents": {"GET": _R},
    "deployment-economics-normalization": {"GET": _R},
    "deployment-economics-portfolio": {"GET": _R},
    "deployment-economics-portfolio-simulate": {"POST": _E},
    "deployment-economics-portfolio-groups": {"GET": _R, "POST": _E},
    "deployment-legal-obligations": {"GET": _R, "POST": _E},
    "deployment-legal-obligation": {"GET": _R},
    "deployment-legal-obligation-supersede": {"POST": _E},
    "deployment-ai-bom": {"GET": _R},
    "deployment-declared-architecture": {"GET": _R, "PUT": _E},
    "deployment-bom-drift": {"GET": _R},
    "deployment-record-bom-drift": {"POST": _E},
    "deployment-compliance": {"GET": _A},
    "deployment-business-impact": {"GET": _A},
    "deployment-vendor-assurance": {"GET": _A},
    "deployment-executive-summary": {"GET": _A},
    "deployment-operational-assurance": {"GET": _A},
    "deployment-operational-risk": {"GET": _A},
    "deployment-assurance-packs": {"GET": _A},
    "deployment-assurance-pack": {"GET": _A},
    "deployment-assurance-claims": {"GET": _A},
    # Re-derives the claims and the decision from what is stored.
    "deployment-recompute-claims": {"POST": _A},
    "deployment-retest-requirements": {"GET": _R},
    "deployment-decision-support": {"GET": _A},
    "deployment-approval-history": {"GET": _R},
    "deployment-tool-contracts": {"GET": _R},
    "deployment-tool-contract-bindings": {"GET": _R},
    "deployment-decision-history": {"GET": _R},
    "deployment-recovery-records": {"GET": _R},
    "deployment-coverage-manifest-view": {"GET": _A},
    "deployment-revalidation-plan": {"GET": _A},
    "deployment-check-invalidations": {"POST": _A},
    "deployment-latent-conditions": {"GET": _R},
    "retest-requirement-list": {"GET": _R},
    "retest-requirement-detail": {"GET": _R},
    "finding-list": {"GET": _R},
    "finding-detail": {"GET": _R, "PUT": _E, "PATCH": _E},
    "finding-remediation": {"GET": _R},
    "finding-incident-pack": {"GET": _R},
    "finding-vendor-packet": {"GET": _R},
    "finding-remediation-transition": {"POST": _E},
    "finding-remediation-assign": {"POST": _E},
    "finding-closure-evidence": {"POST": _E},
    "finding-retest-checks": {"GET": _R},
    "finding-retest-checks-collect": {"POST": _E},
    "finding-assignable": {"GET": _R},
    "finding-repair-contracts": {"GET": _R, "POST": _E},
    "finding-recovery-record": {"GET": _R, "POST": _E},
    "provider-list": {"GET": _R, "POST": _E},
    "provider-detail": {"GET": _R, "PUT": _E, "PATCH": _E},
    "provider-assertion-list": {"GET": _R, "POST": _E},
    "provider-assertion-detail": {"GET": _R, "PUT": _E, "PATCH": _E, "DELETE": _E},
    "unknown-list": {"GET": _R},
    "unknown-detail": {"GET": _R, "PUT": _E, "PATCH": _E},
    # The defender's and the classifier's verdicts on what an analyst submitted.
    "detection:defender-text-scan": {"POST": _A},
    "detection:defender-file-scan": {"POST": _A},
    "detection:defender-list": {"GET": _R},
    "detection:defender-detail": {"GET": _R},
    "detection:cve-classify": {"POST": _A},
    "detection:cve-list": {"GET": _R},
    "detection:cve-detail": {"GET": _R},
    "detection:cve-pdf": {"GET": _R},
    "detection:cve-email": {"POST": _E},
    "failsafe:audit": {"GET": _R},
    "pentest:run_pentest_scan": {"POST": _E},
    "pentest:run_llm_pentest_scan": {"POST": _E},
    "pentest:list_pentest_scans": {"GET": _R},
    "pentest:detail_pentest_scan": {"GET": _R},
    "pentest:reconcile_pentest_scan": {"POST": _E},
    "pentest:collect_pentest_scan": {"POST": _E},
    "pentest:download_scan_pdf": {"GET": _R},
    "pentest:resend_scan_email": {"POST": _E},
    "pentest:pentest_scan_status": {"GET": _R},
    "pentest:allowed_pentest_checks": {"GET": _R},
    "pentest:engagements": {"GET": _R, "POST": _E},
    "pentest:engagement_detail": {"GET": _R, "DELETE": _E},
    "pentest:engagement_plan": {"POST": _E},
}

#: The admin site serves every method on every page, writes included, so each of
#: its routes is an effect: a failure holds it, and nothing there is a stop
#: (safety.stops names the routes that are).
ADMIN_CLASS = EFFECT


def class_of(name, method):
    """The operation class of ``method`` on the route named ``name``, or None
    when nothing declares one. A stop is a stop whatever else is declared."""
    method = "GET" if method == "HEAD" else method
    stop_methods = stops.EXEMPT_ROUTES.get(name, {})
    if method in stop_methods or "ANY" in stop_methods:
        return STOP
    if name and name.startswith("admin:"):
        return ADMIN_CLASS
    declared = ROUTES.get(name, {})
    return declared.get(method) or declared.get("ANY")


def dependency_of(exc):
    """(dependency, what it raised) for an exception: the first link in its chain
    of causes that names a dependency, else an internal fault. Only the type is
    named, never the message, which can carry a query or a credential."""
    from ai_engine.services.cyberengine_client import EngineError

    seen = []
    link = exc
    while link is not None and len(seen) < 8 and not any(link is s for s in seen):
        seen.append(link)
        module = type(link).__module__ or ""
        if isinstance(link, DatabaseError):
            return "the database", type(link).__name__
        if isinstance(link, EngineError):
            return "the engine", type(link).__name__
        if module.startswith("mythos_core"):
            return "Mythos-Core", type(link).__name__
        if module.startswith("cryptography"):
            return "a signer", type(link).__name__
        if module.startswith(("requests", "urllib3")):
            return "an outbound service", type(link).__name__
        link = link.__cause__ or link.__context__
    return "an internal fault", type(exc).__name__ if exc is not None else "unknown"


_SAYS = {
    EVIDENCE_READ: "This could not be read, so it is unknown -- not empty, and not as it last was",
    EFFECT: "Held, not done: this did not run to completion and is not to be taken as done",
    ASSESSMENT: "This could not be assessed, so it is audit incomplete -- never a pass",
}


def degraded_body(klass, exc):
    """The answer for a request of ``klass`` that failed with ``exc``."""
    dependency, raised = dependency_of(exc)
    return {
        "detail": f"{_SAYS[klass]}: {dependency} failed ({raised}).",
        "status": POLICY[klass]["status"],
        "operation_class": klass,
        "dependency": dependency,
    }


def server_error(request, *args, **kwargs):
    """The root URLconf's handler500. Called by Django only after a view raised,
    inside that ``except``. A stop, a request it cannot place, and any fault of
    its own get Django's own 500 unchanged."""
    try:
        exc = sys.exc_info()[1]
        match = getattr(request, "resolver_match", None)
        klass = class_of(match.view_name, (request.method or "").upper()) if match is not None else None
        if klass is None or klass == STOP:
            return defaults.server_error(request, *args, **kwargs)
        return JsonResponse(degraded_body(klass, exc), status=500)
    except Exception:  # noqa: BLE001 - the degraded answer must never be what fails a request
        logger.exception("the degraded answer could not be built; answering Django's own 500")
        return defaults.server_error(request, *args, **kwargs)
