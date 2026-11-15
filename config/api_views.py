from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


@api_view(["GET"])
@permission_classes([AllowAny])
# A liveness probe runs far more often than 30 times a minute. The default
# anonymous throttle answered 429 to a load balancer polling every second,
# which reads as an outage.
@throttle_classes([])
def health(request):
    """
    Simple health check endpoint for the Athena desktop client.

    Returns:
    {
        "status": "ok" | "degraded" | "unknown" | "error",
        "message": "<short text>",
        "degraded": {"<count>": <n>, ...},              (only when "degraded")
        "counts": {"<count>": 0, ...}                    (only when "ok": every count, each 0)
        "workers": {"<worker id>": {"state": ..., "<count>": <n>, ...}, ...}
                                                         (when "degraded": the workers with a count;
                                                          when "ok": empty, no worker has one)
        "unknown": {"<worker id>": "<why>", ...}          (when a worker's report reads unknown)
    }

    "degraded": a worker lost or refused something an operator must act on
    (:func:`assurance.dispatch.degraded_counts`: a line meant for stderr, a log
    record, a dispatch its stop could not record refused past the hard bound; and a
    report it could not publish), with each non-zero count summed over EVERY worker:
    this one's read live, every other's from the report it publishes
    (:mod:`assurance.worker_reports`) -- an exited worker's until an operator
    acknowledges it (``manage.py acknowledge_worker_reports``). "unknown": a count
    could not be read -- this worker's, or another worker's report, unreadable or not
    rewritten within its bound. Never "ok" unless every count was read and is zero;
    "ok" names every count it read under "counts", each 0, so a reader can tell an
    "ok" with its counts from one that reports none (a backend from before #217).
    Always 200: it is the liveness probe, and the process is alive. The counts are
    plain reads and the reports small files; no lock a stop takes is taken here.
    Worker ids are random: the host and the pid behind each are in the command's list.
    """
    try:
        from assurance import worker_reports
        from assurance.dispatch import degraded_counts

        local = worker_reports.local_counts(degraded_counts)
    except Exception as exc:  # noqa: BLE001 - an honest unknown, never ok
        return Response({"status": "unknown", "message": f"the degraded counts could not be read: {type(exc).__name__}"})
    try:
        summary = worker_reports.summarize(local)
    except Exception as exc:  # noqa: BLE001 - an honest unknown, never ok
        return Response(
            {"status": "unknown", "message": f"the other workers' reports could not be read: {type(exc).__name__}"}
        )
    degraded = {name: count for name, count in summary["counts"].items() if count}
    unknown = summary["unknown"]
    unread = (
        f"{len(unknown)} worker report(s) read unknown: "
        + "; ".join(f"{worker} {why}" for worker, why in sorted(unknown.items()))
        if unknown
        else ""
    )
    if degraded:
        body = {
            "status": "degraded",
            "message": "Django backend is alive, and lost or refused what an operator must act on: "
            + ", ".join(f"{name}={count}" for name, count in degraded.items())
            + (f"; and {unread}" if unread else ""),
            "degraded": degraded,
            "workers": {
                worker: {"state": seen["state"], **{name: n for name, n in seen["counts"].items() if n}}
                for worker, seen in summary["workers"].items()
                if any(seen["counts"].values())
            },
        }
        if unknown:
            body["unknown"] = unknown
        return Response(body)
    if unknown:
        return Response({"status": "unknown", "message": f"Django backend is alive, and {unread}", "unknown": unknown})
    # Every count, as read, each 0 here (no count is non-zero, or it read degraded above).
    return Response(
        {"status": "ok", "message": "Django backend is alive.", "counts": dict(summary["counts"]), "workers": {}}
    )
