"""Retest checks: a retest run's verdict, PULLED from the engine and recorded against the
finding it was retested for (owner decision 8, as resolved on 2026-10-22).

The engine's retest (athena-engine ``POST /api/remediation/retest``) answers ``closed``,
``still_open`` or ``inconclusive`` -- "an absence on a retest that looked, not proof of a
fix", in the engine's own words. That is a CHECK, not closure evidence. It carries none
of what the closure gate reads (no fixture classes, no replay variants, no remediation
kind, no contract), so it is never written into ``RetestClosureEvidence``, never
forwarded to Minotaur's remediation-outcomes dataset (``assurance.closure_forward``), and
it never changes a finding's ``status``, ``last_seen``, retest flag, remediation state or
closure standing -- a ``still_open`` check is a sighting on a retest scan this record
never ingested, so the check row carries its date and the finding's ``last_seen`` stays.
``finding-closure-evidence`` stays the engine service's route for Minotaur's replay
documents. A check is the record of what the engine actually produced, attributed to the
person who collected it, naming what its identity stood on.

PULL, not push: this backend reads the run with its own operator key
(``CyberEngineClient.retest_status`` -> ``read_retest_run``), so "the backend read it from
the engine" is true of every row; an operator cannot type a verdict in, and the engine
needs no credential for this backend and no change.

The order of :func:`collect`, which ``POST /api/assurance/findings/<uuid>/retest-checks/
collect/`` runs (``FindingViewSet.retest_checks_collect``):

1. a run already recorded is answered with its row, and the engine is not read;
2. ONE bounded engine read of the run, BEFORE and OUTSIDE any transaction -- no engine
   answer is ever awaited while a row is locked. The engine's own 404 is a 404 here: a
   tenant-bound key cannot read another tenant's run, which the engine answers as no
   such run (owner decision 7). Anything else unreadable is a 503. Nothing is written;
3. a run that is still going is a 202; one that stopped before a verdict, failed, was
   refused, or ended without a verdict is a 200 with its honest phase -- NOTHING is
   written for any of them, as the dashboard's own watch files nothing for them. A
   verdict the engine recorded before the run was aborted IS recorded, marked
   ``stopped_after_recording``;
4. identity, every check of which must pass or nothing is written: the scan run the
   twin was listed under (``twin_run_id``) is a ``PentestScan`` of this record (else 404
   "not in this record": a scan started outside this record), its deployment exists
   already (never created here) and is this finding's, the verdict's type is this
   finding's and exactly one finding of it is in the deployment, the verdict's target
   host is the scan's, and one more bounded engine read (``GET /api/decisions?run_id=``)
   lists the twin under that scan run with that type;
5. one short transaction inserting one :class:`~assurance.models.RetestCheck`, UNIQUE on
   the engine's run id: a second collect of the same run is one row.

Nothing here is on a stop path (``safety.stops``: the route is not a stop), nothing here
launches (no ``POST /api/scan``, no ``POST /api/remediation/retest``), and what is stored
and served is said as the scan says it: the login its target carries is withheld
(``PentestScan.said``) from ``detail`` and from the engine's result kept in ``raw``, as
``pentest.views._without_target_login`` withholds it from a scan's own answer.
"""

from __future__ import annotations

import re

from django.db import IntegrityError, transaction
from django.utils.dateparse import parse_datetime

from ai_engine.services.cyberengine_client import (
    ANSWER_VERDICT,
    ENGINE_REFUSED,
    RETEST_ENDED,
    RETEST_FAILED,
    RETEST_REFUSED,
    RETEST_RUNNING,
    RETEST_STOPPED,
    RUN_ABORTED,
    EngineError,
)

from .ingest import _host, existing_deployment_for_scan
from .models import Finding, RetestCheck

#: The verdicts the engine's retest files (athena-engine ``engine/replay/runner.py``).
#: Any other word is kept as the engine sent it and served ``verdict_known: false``.
KNOWN_VERDICTS = ("closed", "still_open", "inconclusive")
#: How much of the engine's ``detail`` is kept, after the target's login is withheld.
MAX_DETAIL_CHARS = 1000
#: The shape of an engine run id (a registry id): the only thing sent to the engine's
#: ``/api/scans/{run_id}`` -- never a path, a query or another route.
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

#: What the route says for a run that ended without a verdict this record keeps. The
#: engine's own ``reason`` and ``error`` are not quoted: they may quote the target back.
_PHASE_DETAIL = {
    RETEST_STOPPED: "the run was stopped on the engine before its check was filed: no verdict, and nothing "
    "was recorded",
    RETEST_FAILED: "the run failed on the engine: its inconclusive result is not a verdict on the finding, "
    "and nothing was recorded",
    RETEST_REFUSED: "the engine refused the run before any of its work started: nothing was recorded",
    RETEST_ENDED: "the run ended without a verdict: nothing was recorded",
}


class NotRecorded(Exception):
    """The collect wrote nothing. The route answers ``status`` with ``body``: a run still
    going (202), a run that ended without a verdict (200, its phase), a run or scan this
    record does not have (404), an identity that does not hold (409, 422), or an engine
    that could not be read (503)."""

    def __init__(self, status: int, body: dict):
        super().__init__(body.get("detail") or f"HTTP {status}")
        self.status = status
        self.body = body


def is_run_id(value) -> bool:
    """Whether ``value`` is a run id this backend will name to the engine."""
    return isinstance(value, str) and RUN_ID.fullmatch(value) is not None


def collect(finding, run_id: str, twin_run_id: str, *, client, user):
    """Record the verdict of retest run ``run_id`` against ``finding`` as one
    :class:`~assurance.models.RetestCheck`, PULLED from ``client`` (the engine, read with
    this backend's operator key): the steps in the module's order. Returns ``(check,
    created)``; raises :class:`NotRecorded` when nothing was written.

    ``twin_run_id`` is the scan run the retested twin was listed under -- the run a
    ``PentestScan`` of this record names as ``engine_run_id`` -- which is how the finding
    is told: its deployment is that scan's, and the verdict's type is this finding's.
    ``user`` is who collected it (``collected_by``); ``None`` for nobody."""
    existing = RetestCheck.objects.filter(engine_run_id=run_id).first()
    if existing is not None:
        return _already(existing, finding), False

    # 2. The engine, read once, before and outside any transaction: a run's record, as
    # athena-engine answers GET /api/scans/{run_id}, read by read_retest_run.
    read = _read_run(client, run_id)
    if read.get("answer") != ANSWER_VERDICT:
        _not_a_verdict(read, run_id)  # 3. raises: nothing is recorded for it
    result = read.get("body") if isinstance(read.get("body"), dict) else {}

    # 4. Identity. Every check passes, or nothing is written.
    scan, deployment = _scan_of(finding, twin_run_id)
    finding_type = _same_finding(finding, deployment, result)
    _same_target(scan, result)
    twin_id = _twin_listed(client, twin_run_id, finding_type, result)

    # 5. One short transaction, one insert, this table only.
    row = _row(finding, scan, read, result, run_id=run_id, twin_run_id=twin_run_id, twin_id=twin_id, user=user)
    try:
        with transaction.atomic():
            row.save(force_insert=True)
    except IntegrityError:
        # Two collects raced past the lookup above: the run is one row, the first's.
        existing = RetestCheck.objects.filter(engine_run_id=run_id).first()
        if existing is None:
            raise
        return _already(existing, finding), False
    return row, True


def _already(existing, finding):
    """The row a run already has: this finding's, answered as it stands; another
    finding's is refused -- a run's twin maps to one finding, so the second collect named
    the wrong one."""
    if existing.finding_id != finding.pk:
        raise NotRecorded(
            409,
            {
                "detail": f"run {existing.engine_run_id} is already recorded as a retest check of another "
                "finding; nothing was written",
                "run_id": existing.engine_run_id,
                "recorded": False,
            },
        )
    return existing


def _read_run(client, run_id):
    try:
        return client.retest_status(run_id)
    except EngineError as exc:
        # The failure is described by its kind, never by the engine's words: an
        # EngineError's message carries the engine's host and port, and a reader of this
        # answer has no business with either (cyberengine_client, ENGINE_UNREACHABLE).
        if exc.kind == ENGINE_REFUSED and exc.status == 404:
            raise NotRecorded(
                404,
                {
                    "detail": f"the engine has no run {run_id} this backend can read",
                    "run_id": run_id,
                    "recorded": False,
                },
            ) from exc
        raise NotRecorded(
            503,
            {
                "detail": f"Not recorded: the engine could not be read about retest run {run_id} ({exc.kind}). "
                "Nothing was written; collect it again once the engine can be read.",
                "run_id": run_id,
                "recorded": False,
                "engine": exc.kind,
            },
        ) from exc


def _not_a_verdict(read, run_id):
    phase = read.get("phase")
    if phase == RETEST_RUNNING:
        raise NotRecorded(
            202,
            {
                "phase": phase,
                "state": read.get("state"),
                "run_id": run_id,
                "recorded": False,
                "detail": "the run is still going on the engine: nothing was recorded; collect it once it has ended",
            },
        )
    raise NotRecorded(
        200,
        {
            "phase": phase,
            "state": read.get("state"),
            "run_id": run_id,
            "recorded": False,
            "detail": _PHASE_DETAIL.get(phase, "the run produced no verdict this backend reads: nothing was recorded"),
        },
    )


def _scan_of(finding, twin_run_id):
    """The scan of this record that ran under ``twin_run_id``, and its deployment -- the
    one ``ingest.deployment_for_scan`` keyed when the scan was ingested, found and never
    created here."""
    from pentest.models import PentestScan

    scan = PentestScan.objects.filter(engine_run_id=twin_run_id).order_by("pk").first()
    if scan is None:
        raise NotRecorded(
            404,
            {
                "detail": "that scan is not in this record: no scan of this backend ran under that engine run, "
                "so its retest cannot be recorded here",
                "twin_run_id": twin_run_id,
                "recorded": False,
            },
        )
    deployment = existing_deployment_for_scan(scan)
    if deployment is None:
        raise NotRecorded(
            422,
            {
                "detail": "that scan's deployment is not in this record: its run was never ingested here, so "
                "no finding of it can have been retested",
                "twin_run_id": twin_run_id,
                "recorded": False,
            },
        )
    if deployment.pk != finding.deployment_id:
        raise NotRecorded(
            422,
            {
                "detail": "the twin's scan belongs to another deployment than this finding's; nothing was written",
                "twin_run_id": twin_run_id,
                "recorded": False,
            },
        )
    return scan, deployment


def _same_finding(finding, deployment, result) -> str:
    """The verdict's finding type, once it is this finding's and this finding is the
    one finding of that type in the deployment (ingest keys a Finding by (deployment,
    fingerprint), and the fingerprint is a function of the type on the pinned engine)."""
    finding_type = result.get("finding_type")
    if not isinstance(finding_type, str) or not finding_type:
        raise NotRecorded(
            422,
            {"detail": "the engine's verdict names no finding type; nothing was written", "recorded": False},
        )
    if finding_type != finding.finding_type:
        raise NotRecorded(
            422,
            {
                "detail": f"the verdict is of type {finding_type!r}; this finding is of type "
                f"{finding.finding_type!r}; nothing was written",
                "finding_type": finding_type,
                "recorded": False,
            },
        )
    candidates = [
        str(uuid)
        for uuid in Finding.objects.filter(deployment=deployment, finding_type=finding_type)
        .order_by("pk")
        .values_list("uuid", flat=True)
    ]
    if len(candidates) > 1:
        raise NotRecorded(
            409,
            {
                "detail": f"{len(candidates)} findings of type {finding_type!r} are in that deployment, so the "
                "run's twin cannot be told to one of them; nothing was written",
                "finding_type": finding_type,
                "candidates": candidates,
                "recorded": False,
            },
        )
    if candidates != [str(finding.uuid)]:
        raise NotRecorded(
            409,
            {"detail": "the run's twin is a finding other than this one; nothing was written", "recorded": False},
        )
    return finding_type


def _same_target(scan, result):
    target = result.get("target")
    verdict_host = _host(target) if isinstance(target, str) else ""
    scan_host = _host(scan.target_url)
    if not verdict_host or verdict_host != scan_host:
        raise NotRecorded(
            422,
            {
                "detail": f"the verdict's target host {verdict_host or '(none)'!r} is not the scan's "
                f"({scan_host!r}); nothing was written",
                "recorded": False,
            },
        )


def _twin_listed(client, twin_run_id, finding_type, result) -> int:
    """The twin the verdict names, once the engine lists it under the scan run with the
    verdict's type: the strong check, one more bounded read."""
    twin_id = result.get("twin_id")
    if isinstance(twin_id, bool) or not isinstance(twin_id, int):
        raise NotRecorded(
            422, {"detail": "the engine's verdict names no twin; nothing was written", "recorded": False}
        )
    try:
        twins = client.decision_twins(twin_run_id, finding_type=finding_type)
    except EngineError as exc:
        raise NotRecorded(
            503,
            {
                "detail": f"Not recorded: the engine could not be read about the twins of scan run "
                f"{twin_run_id} ({exc.kind}). Nothing was written; collect it again once the engine can be read.",
                "twin_run_id": twin_run_id,
                "recorded": False,
                "engine": exc.kind,
            },
        ) from exc
    listed = any(
        isinstance(twin, dict) and twin.get("id") == twin_id and twin.get("finding_type") == finding_type
        for twin in twins
    )
    if not listed:
        raise NotRecorded(
            422,
            {
                "detail": f"the engine lists no twin {twin_id} of type {finding_type!r} under scan run "
                f"{twin_run_id}; nothing was written",
                "twin_run_id": twin_run_id,
                "recorded": False,
            },
        )
    return twin_id


def _row(finding, scan, read, result, *, run_id, twin_run_id, twin_id, user):
    """The check, as it is recorded: the engine's words with the target's login withheld
    (``PentestScan.said``), and the identity it stood on."""
    verdict = result.get("verdict")
    verdict = verdict if isinstance(verdict, str) else ""
    detail = result.get("detail")
    detail = scan.said(detail) if isinstance(detail, str) else ""
    digest = result.get("inventory_digest")
    check = read.get("check") if isinstance(read.get("check"), dict) else {}
    checked_at = check.get("checked_at")
    try:
        engine_checked_at = parse_datetime(checked_at) if isinstance(checked_at, str) else None
    except ValueError:
        engine_checked_at = None
    scan_record_id = read.get("scan_record_id")
    aborted = read.get("state") == RUN_ABORTED
    return RetestCheck(
        finding=finding,
        engine_run_id=run_id,
        scan_record_id=str(scan_record_id)[:64] if scan_record_id is not None else None,
        twin_id=twin_id,
        twin_run_id=twin_run_id,
        verdict=verdict[:32],
        verdict_known=verdict in KNOWN_VERDICTS,
        detail=detail[:MAX_DETAIL_CHARS],
        inventory_digest=(digest if isinstance(digest, str) else "")[:128],
        engine_checked_at=engine_checked_at,
        state=RetestCheck.State.ABORTED if aborted else RetestCheck.State.COMPLETED,
        stopped_after_recording=aborted,
        collected_by=user if getattr(user, "is_authenticated", False) else None,
        raw=_withheld(scan, result),
    )


def _withheld(scan, value):
    """``value`` with the login the scan's target carries withheld from every string in
    it, its shape unchanged (as ``pentest.views._without_target_login`` keeps a scan's
    engine answer)."""
    if isinstance(value, str):
        return scan.said(value)
    if isinstance(value, dict):
        return {key: _withheld(scan, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_withheld(scan, item) for item in value]
    return value
