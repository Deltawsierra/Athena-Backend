"""
Ask the engine's own gates before pointing it at a customer.

Six subsystems were built into the engine and none of them was on this
code path. A grep of this repository for "assurance", "/api/extensions",
"/api/authority" and "/api/evidence" returned nothing: the change gate was
consulted only by its own HTTP route and its own tests, so a deployment
whose model, tools, routes, policies, hooks and permissions had all changed
since approval ran every scan with nothing objecting.

Three questions are asked here, in the order they matter:

  Is the engine still the deployment that was approved? Both the declared
  half, from deployment/approved_deployment.yaml, and the measured half,
  which the engine takes from its own process and which nothing here can
  state.

  Is every loaded extension the one that was approved? A revoked scanner
  still running is a blocking answer in every mode.

  Did anything reach the network with no authority in force? Not blocking --
  it is a fact about the past, not about this scan -- but it belongs in the
  record next to the scan it preceded.

The result is cached briefly. Not for speed: the engine's own boot review
is measured once per process and a six-hour-old answer was one of the
audit's findings, so the cache is short enough that an operator revoking a
scanner sees it take effect within a minute rather than at the next restart.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from django.conf import settings

from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

log = logging.getLogger(__name__)

DECLARATION = Path(settings.BASE_DIR) / "deployment" / "approved_deployment.yaml"

# Short on purpose. See the module docstring.
CACHE_SECONDS = 60

_cache: dict[str, Any] = {}
_lock = threading.Lock()


class DeploymentNotApproved(Exception):
    """The engine is not the deployment that was approved."""

    def __init__(self, message: str, report: dict[str, Any] | None = None):
        super().__init__(message)
        self.report = report or {}


def declaration() -> dict[str, Any]:
    """The approved deployment, as declared in the repository.

    yaml is imported here rather than at module scope. This module is
    imported by pentest.views, which is imported by pentest.urls, which is
    imported by the root URL conf -- so a missing dependency in a governance
    check took down every route in the application rather than the check. A
    gate that cannot answer should refuse scans, not the login page.

    Read from disk each time rather than cached at import: a deployment that
    edits this file and restarts one worker should not have two workers
    disagreeing about what was approved.
    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - a packaging error, not a path
        raise DeploymentNotApproved(
            f"PyYAML is not installed, so {DECLARATION.name} cannot be read and "
            f"nothing can say what this deployment is approved to be: {exc}"
        ) from exc

    if not DECLARATION.exists():
        raise DeploymentNotApproved(
            f"{DECLARATION} does not exist, so there is nothing that says what "
            f"this deployment is approved to be"
        )
    loaded = yaml.safe_load(DECLARATION.read_text()) or {}
    if not loaded.get("deployment_id") or not loaded.get("components"):
        raise DeploymentNotApproved(
            f"{DECLARATION} does not name a deployment_id and its components"
        )
    return loaded


def mode() -> str:
    """enforce or observe.

    Defaults to observe, matching the engine's own extension gate: a gate
    that blocks on the day it is switched on, in a deployment nobody has
    approved yet, is one somebody turns off. Turning it to enforce is the
    deliberate act -- and until then a blocked verdict is still logged, so
    the record shows what would have been refused.
    """
    value = str(getattr(settings, "CYBERENGINE_ASSURANCE_MODE", "observe")).strip().lower()
    return "enforce" if value in {"1", "true", "yes", "on", "enforce", "enforced",
                                  "require", "required", "strict", "block"} else "observe"


def deployment_for_routes():
    """The Deployment whose serving routes the gate measures, or None.

    Resolved by the declared ``deployment_id``. None when there is no such row:
    a gate that measured the wrong deployment's routes would be worse than one
    that measured none, and `_attestation_for` turns None into an explicit
    "nothing was measured" rather than an empty pass.
    """
    from assurance.models import Deployment

    try:
        declared_id = declaration()["deployment_id"]
    except DeploymentNotApproved:
        return None
    return (
        Deployment.objects.prefetch_related("assets")
        .filter(name=declared_id)
        .first()
    )


def _attestation_for(deployment, client, tenant_id) -> dict[str, Any]:
    """The attestation half of the report, or an honest absence.

    A deployment this backend does not hold cannot have its routes measured, and
    that is reported as ``unobservable`` rather than as a clean sheet: the whole
    point of this gate is that an unmeasured route never reads like a measured
    one.
    """
    if deployment is None:
        return {
            "verdict": ATTEST_UNOBSERVABLE,
            "detail": (
                "no deployment record matches the declared deployment_id, so no "
                "serving route could be measured"
            ),
            "routes": [],
            "unmeasurable": [],
            # None, not 0. We do not hold the inventory, so we do not know how
            # many routes went unmeasured -- and "0 not measured" is precisely
            # the silent zero this gate exists to stop: an absence of knowledge
            # reading as an absence of gaps.
            "not_measured_count": None,
            "truncated": [],
        }
    return _attest_routes(client, deployment, tenant_id=tenant_id)


def check(client: CyberEngineClient | None = None,
          tenant_id: str | None = None,
          force: bool = False) -> dict[str, Any]:
    """Ask the gates. Returns a report; raises only under enforce."""
    key = f"{tenant_id or 'default'}"
    now = time.monotonic()

    if not force:
        with _lock:
            cached = _cache.get(key)
            if cached and now - cached["at"] < CACHE_SECONDS:
                report = cached["report"]
                _raise_if_enforcing(report)
                return report

    client = client or CyberEngineClient.from_settings()
    declared = declaration()

    report: dict[str, Any] = {
        "deployment_id": declared["deployment_id"],
        "mode": mode(),
        "checked_at": time.time(),
    }

    try:
        report["assurance"] = client.assurance_check(
            declared["deployment_id"], declared["components"], tenant_id=tenant_id
        )
        report["extensions"] = client.extension_review()
        report["unattributed"] = client.unattributed_effects(limit=25)
        report["attestation"] = _attestation_for(deployment_for_routes(), client, tenant_id)
    except EngineError as exc:
        # An engine that cannot answer is not an engine that answered yes.
        # Under observe this is logged and the scan proceeds, because the
        # gate is not yet the thing standing between a customer and their
        # test; under enforce it is a refusal.
        report["error"] = str(exc)
        report["verdict"] = "unknown"
        report["detail"] = f"the engine could not be asked: {exc}"
        _store(key, report, now)
        _raise_if_enforcing(report)
        return report

    report["verdict"], report["detail"] = _decide(report)
    # "attestation" included: it carries the engine's raw route measurements,
    # which are external data and get stored on the scan row. Left out, a reply
    # holding anything non-JSON would fail to persist the verdict that governed
    # the scan.
    for section in ("assurance", "extensions", "unattributed", "attestation"):
        report[section] = _jsonable(report.get(section))
    _store(key, report, now)
    _raise_if_enforcing(report)
    return report


def _jsonable(value: Any, depth: int = 0) -> Any:
    """A value that can be stored and read back.

    The engine's replies are external data and this report is persisted on
    the scan row, so what goes in has to be JSON, not whatever the client
    handed back. Anything that is not is kept as its repr rather than
    dropped: a field that could not be stored is still a fact about the
    answer, and silently omitting it would make a malformed reply look like
    a well-formed one.
    """
    if depth > 6:
        return "..."
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, depth + 1) for v in list(value)[:100]]
    return repr(value)[:500]


# The attestation verdicts the engine returns, named here so this module reads
# the engine's vocabulary rather than inventing a parallel one.
ATTEST_UNCHANGED = "unchanged"
ATTEST_REVIEW = "review"
ATTEST_BLOCKED = "blocked"
ATTEST_UNOBSERVABLE = "unobservable"

ATTEST_VERDICTS = (ATTEST_UNCHANGED, ATTEST_REVIEW, ATTEST_BLOCKED, ATTEST_UNOBSERVABLE)

# athena-engine #71 marks every launch answer with `answer`, and an attestation
# answers 2xx only as `answer: "verdict"`. Engine main sends no `answer`. A route
# answer carrying any other value is not a verdict, whatever else it holds.
_ANSWER_FIELD = "answer"
_ANSWER_VERDICT = "verdict"

# How many routes one preflight will measure. Each is a live round trip to a
# customer endpoint, and a gate that hangs is a gate somebody switches off. The
# cap is reported when it bites (see `_attest_routes`) rather than silently
# shortening the answer.
MAX_ATTESTED_ROUTES = 8


def _serving_routes(deployment) -> tuple[list, list]:
    """The routes this deployment serves inference on, as (measurable, unmeasurable).

    The url comes from ``Asset.identifier``, which the model documents as "an
    endpoint URL, ARN, tool name, etc." -- so for a serving asset it is the
    endpoint, and for others it is not a url at all. Nothing else in the record
    carries one: ``ROUTE_FIELDS`` fingerprints *what* serves (provider, model,
    engine, template) and the approved-deployment declaration's ``routes`` are
    inbound path patterns like ``/api/scan``, which nothing can probe.

    An asset that serves inference but whose identifier is not a url is returned
    in the second list, NOT dropped. A route we cannot measure is a hole in the
    gate's coverage, and a gate that silently measured six of eight routes would
    report the same "ok" as one that measured all eight.
    """
    from assurance.served_route import serves_inference

    measurable, unmeasurable = [], []
    for asset in deployment.assets.all():
        if not serves_inference(asset):
            continue
        identifier = (asset.identifier or "").strip()
        if identifier.startswith(("http://", "https://")):
            measurable.append((asset.name, identifier))
        else:
            unmeasurable.append(
                {
                    "name": asset.name,
                    "why": (
                        "this asset serves inference but its identifier is not a "
                        "url, so there is no endpoint to measure"
                    ),
                }
            )
    return measurable, unmeasurable


def _attest_routes(client, deployment, tenant_id=None) -> dict[str, Any]:
    """Measure each serving route against its baseline.

    Returns a report whose ``verdict`` follows the engine's own vocabulary, and
    which never reads better than the worst route in it.

    The behavioural half is NOT re-decided here. ``engine/attestation/store.py``
    already folds it so it can raise a verdict to review and never to blocked --
    "a changed fingerprint has four explanations and only one of them is a
    substituted model" -- and a second opinion from this side would either
    duplicate that rule or quietly contradict it.
    """
    measurable, unmeasurable = _serving_routes(deployment)
    truncated = []
    if len(measurable) > MAX_ATTESTED_ROUTES:
        truncated = [name for name, _ in measurable[MAX_ATTESTED_ROUTES:]]
        measurable = measurable[:MAX_ATTESTED_ROUTES]

    routes = []
    # The name each answer was asked under: the gate's own record of which route
    # it is, rather than whatever the answer says its name is.
    asked = [name for name, _ in measurable]
    for name, url in measurable:
        try:
            answer = client.attestation_check(name, url, tenant_id=tenant_id)
            if not isinstance(answer, dict):
                # Kept, as what it was, under the route it answered for: an answer
                # that is not an object is not a verdict, and it must not crash
                # the gate or vanish from the record either.
                answer = {
                    "name": name,
                    "url": url,
                    "verdict": None,
                    "detail": "the engine's answer for this route was not an object",
                    "engine_answer": answer,
                }
            routes.append(answer)
        except EngineError as exc:
            # A route the engine could not be asked about is unobserved, not
            # unchanged. The egress allowlist refusing a host lands here too, and
            # "we were not allowed to look" must never read as "we looked and it
            # was fine".
            routes.append(
                {
                    "name": name,
                    "url": url,
                    "verdict": ATTEST_UNOBSERVABLE,
                    "detail": f"the engine could not measure this route: {exc}",
                    "blocking": [],
                    "advisory": [],
                }
            )

    return {
        "verdict": _attest_verdict(routes, unmeasurable, truncated),
        "detail": _attest_detail(routes, unmeasurable, truncated, asked),
        "routes": routes,
        # The routes the engine answered for without a verdict this gate can read.
        # Named apart from `routes` so the reason can say THAT is why the gate
        # reads review -- not a moved route, and not a coverage gap.
        "verdict_missing": _verdict_missing(routes, asked),
        # Carried separately and counted, because these are the routes the gate
        # did NOT check. Folding them into `routes` would let a coverage hole be
        # read as a measurement.
        "unmeasurable": unmeasurable,
        "not_measured_count": len(unmeasurable) + len(truncated),
        "truncated": truncated,
    }


def _route_verdict(route: Any) -> tuple[str | None, str | None]:
    """A route answer's verdict, or (None, why there is none this gate can read).

    #334: this read ``str(route.get("verdict") or "")`` and then treated "" as
    no objection, so an answer with no verdict, or a null one, made a route read
    UNCHANGED -- "1 serving route(s) match their baseline" -- when nothing had
    said so. An absent verdict is not a verdict of unchanged. Nor is a word this
    gate does not know, a verdict that is not a word, an answer that is not an
    object, or an answer whose ``answer`` field says it is not a verdict.
    """
    if not isinstance(route, dict):
        return None, "was not an object"
    if _ANSWER_FIELD in route and route[_ANSWER_FIELD] != _ANSWER_VERDICT:
        return None, f"was answer {route[_ANSWER_FIELD]!r}, not a verdict"
    if "verdict" not in route:
        return None, "carried no verdict"
    verdict = route["verdict"]
    if verdict is None:
        return None, "carried a null verdict"
    if not isinstance(verdict, str):
        return None, f"carried a verdict that is not a word ({type(verdict).__name__})"
    if verdict not in ATTEST_VERDICTS:
        return None, f"carried a verdict this gate does not know ({verdict[:40]!r})"
    return verdict, None


def _asked_name(route: Any, asked: list | None, index: int):
    if asked is not None and index < len(asked):
        return asked[index]
    return route.get("name") if isinstance(route, dict) else None


def _verdict_missing(routes, asked: list | None = None) -> list[dict[str, Any]]:
    missing = []
    for index, route in enumerate(routes):
        verdict, why = _route_verdict(route)
        if verdict is None:
            missing.append({"name": _asked_name(route, asked, index), "why": why})
    return missing


def _attest_verdict(routes, unmeasurable, truncated) -> str:
    """The worst thing seen, and an unmeasured route is not a good thing seen.

    Order matters: blocked beats unobservable beats review beats unchanged. A
    deployment with nothing serving inference reads ``unchanged`` -- there was
    nothing to measure and that is a true answer -- while one whose routes could
    not be read reads ``unobservable``, which is not.

    A route whose answer carries no verdict this gate can read is review: the
    engine was asked and said nothing usable, so it establishes nothing either
    way. It is never unchanged.
    """
    verdicts = [_route_verdict(r)[0] for r in routes]
    if ATTEST_BLOCKED in verdicts or any(isinstance(r, dict) and r.get("blocking") for r in routes):
        return ATTEST_BLOCKED
    if ATTEST_UNOBSERVABLE in verdicts or unmeasurable or truncated:
        return ATTEST_UNOBSERVABLE
    if None in verdicts or ATTEST_REVIEW in verdicts:
        return ATTEST_REVIEW
    return ATTEST_UNCHANGED


def _attest_detail(routes, unmeasurable, truncated, asked: list | None = None) -> str:
    parts = []
    for index, route in enumerate(routes):
        verdict, why = _route_verdict(route)
        name = _asked_name(route, asked, index)
        if verdict is None:
            parts.append(
                f"{name}: the engine's answer {why}, so nothing was established "
                f"about whether this route moved"
            )
        elif verdict != ATTEST_UNCHANGED:
            parts.append(f"{route.get('name')}: {route.get('detail') or verdict}")
    if unmeasurable:
        parts.append(
            f"{len(unmeasurable)} serving route(s) carry no measurable endpoint"
        )
    if truncated:
        parts.append(
            f"{len(truncated)} further route(s) were not measured "
            f"(cap of {MAX_ATTESTED_ROUTES} per preflight): {', '.join(truncated)}"
        )
    if not parts:
        measured = len(routes)
        return (
            f"{measured} serving route(s) match their baseline"
            if measured
            else "this deployment serves no inference route with an endpoint to measure"
        )
    return "; ".join(parts)


def _verdict(answer: Any, nested: str | None = None) -> str | None:
    """The verdict in an answer, or None if the answer is not one.

    The engine's replies are external data. An answer that is not the shape
    this expects is not an answer that said yes: it reads as no verdict,
    which _decide turns into "unknown" rather than into a pass. A malformed
    reply must not crash the scan path either -- the caller would see a 500
    where the honest report is "the engine could not be understood".
    """
    if not isinstance(answer, dict):
        return None
    if nested and isinstance(answer.get(nested), dict):
        answer = answer[nested]
    verdict = answer.get("verdict")
    return verdict if isinstance(verdict, str) else None


def _detail(answer: Any, nested: str | None = None) -> str:
    if not isinstance(answer, dict):
        return "the engine's answer was not a report"
    if nested and isinstance(answer.get(nested), dict):
        answer = answer[nested]
    detail = answer.get("detail")
    return detail if isinstance(detail, str) else "no detail given"


def _attest_reason(attestation: Any, verdict: str | None,
                   gate_mode: str = "observe") -> str | None:
    """Why the attestation half is holding this scan at review, or None.

    Four states that are not the same fact, and each says which it is. An
    earlier version of this had three branches that all appended the engine's
    generic detail, so two of them were decoration: deleting either changed
    nothing, which a mutation proved. Worse than dead code -- an operator
    reading "route attestation: ..." could not tell a coverage gap from a moved
    baseline from a reply nobody could parse, and those call for different work.

    The fourth (#334): a route the engine answered for without a verdict this
    gate can read. That is neither a moved route ("drift") nor a route nobody
    could measure ("coverage"), and it used to read as neither -- it read as
    unchanged. It is named as what it is, and under observe the reason says the
    gate refuses nothing in that mode rather than implying it held anything.
    """
    if verdict is None:
        # An answer we cannot read is not an answer that said yes, and it is a
        # bug in the engine or the contract rather than a fact about the routes.
        return (
            "route attestation: the engine's answer was not a report, so nothing "
            "was established about the routes this scan will touch"
        )

    raw_missing = attestation.get("verdict_missing") if isinstance(attestation, dict) else None
    missing = [m for m in raw_missing if isinstance(m, dict)] if isinstance(raw_missing, list) else []
    parts = []
    if missing or verdict not in ATTEST_VERDICTS:
        if missing:
            which = "; ".join(f"{m.get('name')}: {m.get('why')}" for m in missing[:MAX_ATTESTED_ROUTES])
            said = f"{len(missing)} route(s) answered without a verdict this gate can read ({which})"
        else:
            said = f"the attestation carried a verdict this gate does not know ({str(verdict)[:40]!r})"
        consequence = (
            "observe mode: this is reported, and nothing is refused in this mode"
            if gate_mode != "enforce"
            else "so the gate reads review, never ok"
        )
        parts.append(
            f"route attestation (missing verdict): {said}, so nothing was "
            f"established about whether they moved -- {consequence}"
        )
        if verdict not in ATTEST_VERDICTS:
            return parts[0]

    if verdict == ATTEST_UNOBSERVABLE:
        # Routes we could not measure. Review rather than block: not being able
        # to look is a coverage gap, not evidence of drift, and blocking on it
        # would make the first deployment with an un-probeable route unable to
        # scan at all -- which is how a gate gets switched off.
        missing_count = (
            attestation.get("not_measured_count")
            if isinstance(attestation, dict)
            else None
        )
        measured = (
            len(attestation.get("routes") or [])
            if isinstance(attestation, dict)
            else 0
        )
        # A count we do not have is not a count of zero. Anything that is not a
        # plain integer -- None from `_attestation_for`, or a malformed number
        # from the engine's reply -- is reported as unknown rather than coerced
        # into a reassuring zero.
        counted = (
            f"{missing_count} not measured"
            if isinstance(missing_count, int) and not isinstance(missing_count, bool)
            else "an unknown number not measured"
        )
        parts.append(
            f"route attestation (coverage): {measured} route(s) measured, "
            f"{counted} -- {_detail(attestation)}"
        )
    elif verdict == ATTEST_REVIEW:
        # Drift only when something the engine measured asked for review: a
        # review that is only the missing verdicts above is not a moved route.
        routes = attestation.get("routes") if isinstance(attestation, dict) else None
        drifted = (
            any(_route_verdict(r)[0] == ATTEST_REVIEW for r in routes)
            if isinstance(routes, list) and routes
            else not missing
        )
        if drifted:
            parts.append(f"route attestation (drift): {_detail(attestation)}")
    return "; ".join(parts) or None


def _decide(report: dict[str, Any]):
    assurance_verdict = _verdict(report.get("assurance"))
    extension_verdict = _verdict(report.get("extensions"), nested="review")

    raw_unattributed = report.get("unattributed")
    if isinstance(raw_unattributed, dict) and isinstance(raw_unattributed.get("effects"), list):
        unattributed = raw_unattributed["effects"]
    else:
        unattributed = []

    if assurance_verdict is None or extension_verdict is None:
        return "unknown", (
            "the engine did not answer in a shape this understands, so nothing "
            "was established about whether it is the approved deployment"
        )

    if assurance_verdict == "blocked":
        return "blocked", f"assurance gate: {_detail(report.get('assurance'))}"
    if extension_verdict == "blocked":
        return "blocked", (
            f"extension gate: {_detail(report.get('extensions'), nested='review')}"
        )
    if assurance_verdict == "unapproved":
        return "blocked", (
            "this engine has no approval on record, so there is nothing for the "
            "gate to measure against: run `manage.py approve_deployment`"
        )

    attestation = report.get("attestation")
    attest_verdict = _verdict(attestation)
    if attest_verdict == ATTEST_BLOCKED:
        # The certificate half, and only that. A route whose issuer or names
        # changed under a scan is a different endpoint from the one the baseline
        # describes, and a scan of a different endpoint is not the scan that was
        # asked for.
        return "blocked", f"route attestation: {_detail(attestation)}"

    reasons = []
    if assurance_verdict != "unchanged":
        reasons.append(f"assurance gate: {_detail(report.get('assurance'))}")
    if extension_verdict != "ok":
        reasons.append(
            f"extension gate: {_detail(report.get('extensions'), nested='review')}"
        )
    attest_reason = _attest_reason(attestation, attest_verdict,
                                   report.get("mode") or mode())
    if attest_reason:
        reasons.append(attest_reason)
    if unattributed:
        # Not blocking: it is a fact about the past, not about this scan.
        reasons.append(
            f"{len(unattributed)} effect(s) reached the network with no authority "
            f"in force"
        )

    if reasons:
        return "review", "; ".join(reasons)
    return "ok", "the engine is the deployment that was approved"


def _store(key: str, report: dict[str, Any], at: float) -> None:
    with _lock:
        _cache[key] = {"at": at, "report": report}


def _raise_if_enforcing(report: dict[str, Any]) -> None:
    verdict = report.get("verdict")
    if verdict in ("blocked", "unknown") and report.get("mode") == "enforce":
        raise DeploymentNotApproved(report.get("detail") or verdict, report)
    if verdict in ("blocked", "unknown"):
        log.warning(
            "[ASSURANCE] %s: %s (mode=observe, so the scan proceeds; set "
            "CYBERENGINE_ASSURANCE_MODE=enforce to refuse)",
            verdict, report.get("detail"),
        )
    elif verdict == "review":
        log.info("[ASSURANCE] review: %s", report.get("detail"))


def clear_cache() -> None:
    """For tests, and for a worker that has just been told to re-check."""
    with _lock:
        _cache.clear()
