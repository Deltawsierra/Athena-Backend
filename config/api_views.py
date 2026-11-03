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
        "degraded": {"<count>": <n>, ...}   (only when "degraded")
    }

    "degraded": this process lost or refused something an operator must act on
    (:func:`assurance.dispatch.degraded_counts`: a line meant for stderr, a log
    record, a dispatch its stop could not record refused past the hard bound),
    with each non-zero count. "unknown": the counts could not be read. Never "ok"
    unless every count was read and is zero. Always 200: it is the liveness
    probe, and the process is alive. The counts are plain reads; no lock a stop
    takes is taken here.
    """
    try:
        from assurance.dispatch import degraded_counts

        counts = degraded_counts()
    except Exception as exc:  # noqa: BLE001 - an honest unknown, never ok
        return Response({"status": "unknown", "message": f"the degraded counts could not be read: {type(exc).__name__}"})
    degraded = {name: count for name, count in counts.items() if count}
    if degraded:
        return Response(
            {
                "status": "degraded",
                "message": "Django backend is alive, and lost or refused what an operator must act on: "
                + ", ".join(f"{name}={count}" for name, count in degraded.items()),
                "degraded": degraded,
            }
        )
    return Response({"status": "ok", "message": "Django backend is alive."})
