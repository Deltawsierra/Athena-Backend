"""The legal-obligations routes (the owner's freeze exception 22, 14 Oct): the
obligations a deployment is bound by, read, recorded and superseded over the API.

:class:`~assurance.models.LegalObligation` and :mod:`assurance.legal` (Phase 2 item 6)
held the second invalidation axis with no route to it: a rule moving reached the claims
only from code. These routes are that route, and they add no rule of their own about
the legal axis. Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in
a guard of its own: a fault here leaves these three routes unserved and nothing else --
not the URLconf, not a stop (``tests/test_legal_obligation_routes.py``,
``test_a_legal_obligations_fault_never_takes_down_a_stop``).

- ``GET deployments/<uuid>/legal-obligations/``: the obligations the deployment is
  bound by, newest rule first (at most :data:`LIST_LIMIT`, saying when there are
  more), each with who recorded it and whether a later version supersedes it.
- ``POST deployments/<uuid>/legal-obligations/``: record an obligation binding the
  deployment, attributed to the signed-in admin (201). A version already recorded is
  409 (``obligation_version_taken``), and so is a second instrument of the same
  jurisdiction and source while the deployment is bound by a current version of it
  (``obligation_recorded_here``): a change to an obligation is a new version that
  supersedes it, never a second record beside it.
- ``GET deployments/<uuid>/legal-obligations/<obligation uuid>/``: one obligation the
  deployment is bound by, its versions linked by supersession (oldest first), and the
  materiality decisions people recorded against it on this deployment's claims.
- ``POST deployments/<uuid>/legal-obligations/<obligation uuid>/supersede/``: record
  the next version of that obligation, attributed to the signed-in admin, which
  supersedes it (201). The previous version is never edited: only its link to the
  version that replaced it is written (:func:`assurance.legal.link_supersession`).
  The same request again returns the version it recorded (200); another version of
  one already superseded is 409 (``obligation_superseded``, naming its successor).

What a change does to claims, and what it never does. Recording an obligation calls
:func:`assurance.legal.flag_for_materiality_review` on it, in the record's own
transaction, with the one deployment it binds. A supersession binds every deployment
the previous version bound, and nothing it does inside its own transaction grows with
how many (the SAFETY RULE; the lead's decision of 19 Oct): it records the new version,
links it and carries the bindings (:func:`assurance.legal.link_supersession`), and
owes each bound deployment its review flag in one statement
(:func:`assurance.legal.owe_reviews`). Once it commits, the flags are written one
deployment per short transaction (:func:`assurance.legal.settle_reviews_owed`), each
with that deployment's decision refreshed in it -- the same flag, narrowed to one
deployment, writing the same events the carry in :mod:`assurance.legal` replays. A
stop waits at most for one deployment's flag and refresh, never for the whole fan-out
(``tests/test_a_supersede_never_holds_back_a_stop.py`` times them). What a process that
died midway left owed, ``manage.py settle_legal_reviews`` settles. Neither route ever
moves a claim to legally current or legally stale: only a person's materiality
decision with a written rationale does (the gate in :mod:`assurance.legal`), and no
body field here reaches the legal axis -- a field the route does not read is refused.
This module names no claim and no legal status at all
(``tests/test_legal_obligation_routes.py``).

Access is the assurance API's: a signed-in account; a deployment the caller cannot
see is 404 whether or not it exists (admins and analysts see every deployment, anyone
else their own), and so is an obligation the deployment is not bound by; every role
reads; only an admin records or supersedes (403 for an analyst or a viewer, even the
owner). A body is strict JSON of at most :data:`MAX_BODY_BYTES` (413 on the declared
length; the parser never reads past it; a duplicated key, ``NaN`` or ``Infinity`` is
400; a form is 415). ``authority_tier`` -- the source type -- is one of ``statute``,
``regulation``, ``binding_guidance``, ``case_law`` or ``advisory``. Every answer,
refusals included, carries ``Cache-Control: no-store``.

The claims a change flags are a decision input, so wherever a deployment's claims are
flagged, its stored decision is brought current in that same transaction
(:func:`assurance.views._refresh_stored_decision`, as every write of a decision input
does): the claims and the decision commit together or neither does, so no committed
state pairs flagged claims with a decision computed before them. A review merely
pending caps nothing, but the carry can read a flagged version stale again where the
only ruling on record says so -- a later ruling's obligation since deleted -- and that
moves the decision (``tests/test_every_write_route_keeps_the_decision_current.py``:
recording is in MOVES, a supersession in MOVES_AFTER_COMMIT, which writes no decision
input until it commits).

None of these routes is a stop, and none sits on a stop's path: each is classified in
``safety.stops.NOT_STOPS``. The account that recorded a version is kept as a name
beside a nullable link, so removing an operator (a stop) is never held back by one.
This module does nothing at import but define its views.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date

from django.db import IntegrityError, transaction
from django.http import QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path, reverse
from rest_framework import permissions, status
from rest_framework.exceptions import APIException, ParseError, PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from config.parsers import SafeJSONParser

from . import legal
from .models import Deployment, LegalObligation, LegalReviewOwed, MaterialityDecision
from .views import _is_admin, _is_privileged, _refresh_stored_decision

logger = logging.getLogger(__name__)

#: The largest body an obligation is posted in. A version with its thresholds and
#: exemptions is a few KiB; a body over this is refused (413) on its declared
#: Content-Length before anything reads it, and the parser reads no more than this.
MAX_BODY_BYTES = 64 * 1024

#: The most rows a list returns: a custom view is not paginated by the project's
#: default pagination, so each list here carries its own bound and says when it hit it.
LIST_LIMIT = 200
HISTORY_LIMIT = 100

#: What every answer here carries: an obligation's record and the decisions on it are
#: not for a shared cache.
NO_STORE = "no-store"

#: The source types an obligation may be: the model's authority tiers, strongest first.
AUTHORITY_TIERS = tuple(LegalObligation.AuthorityTier.values)

#: The longest free-text note a change may carry onto the claims it flags.
NOTE_LIMIT = 2000

CREATE_FIELDS = frozenset(
    {"jurisdiction", "authority_tier", "source", "source_version", "operative_date", "thresholds", "exemptions",
     "note"}
)
SUPERSEDE_FIELDS = frozenset(
    {"source_version", "operative_date", "authority_tier", "thresholds", "exemptions", "note"}
)

_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class BodyTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = f"A legal obligation is posted in at most {MAX_BODY_BYTES} bytes."
    default_code = "body_too_large"


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ParseError(f"JSON parse error - the key {key!r} appears twice in one object")
        seen[key] = value
    return seen


def _no_constant(name):
    raise ParseError(f"JSON parse error - {name} is not a value")


class StrictJSONParser(SafeJSONParser):
    """JSON only, and strictly: a duplicate key in any object, and a bare NaN or
    Infinity, are refused, where ``json`` would keep the last key and read NaN. Reads
    at most :data:`MAX_BODY_BYTES` whatever Content-Length said."""

    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        encoding = parser_context.get("encoding", "utf-8")
        raw = stream.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise BodyTooLarge()
        try:
            return json.loads(raw.decode(encoding), object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
        except RecursionError:
            raise ParseError("JSON parse error - the body is nested too deeply") from None
        except (UnicodeDecodeError, ValueError) as exc:
            raise ParseError(f"JSON parse error - {exc}") from None


class _NoStoreView(APIView):
    """Every answer, a refusal included, carries ``Cache-Control: no-store``."""

    permission_classes = [permissions.IsAuthenticated]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = NO_STORE
        return response


def visible_deployments(user):
    """The deployments ``user`` may read, as the deployment list scopes them
    (:class:`assurance.views.DeploymentViewSet`): every one for an admin or an
    analyst, their own for anyone else."""
    deployments = Deployment.objects.all()
    if _is_privileged(user):
        return deployments
    return deployments.filter(owner=user)


def _deployment(request, deployment_uuid) -> Deployment:
    return get_object_or_404(visible_deployments(request.user), uuid=deployment_uuid)


def _bound(deployment, obligation_uuid) -> LegalObligation:
    """An obligation ``deployment`` is bound by, or 404: one it is not bound by is not
    this deployment's to read or change, whether or not it exists."""
    return get_object_or_404(deployment.legal_obligations.select_related("superseded_by"), uuid=obligation_uuid)


def _require_admin(request) -> None:
    """An obligation is the assurance record's, and only an admin writes that record
    (:func:`assurance.views._is_admin`): an analyst or a viewer reads it."""
    if not _is_admin(request.user):
        raise PermissionDenied("Recording or superseding a legal obligation requires an admin role.")


def _refused(code: str, detail: str, field: str | None = None) -> ValidationError:
    body = {"code": code, "detail": detail}
    if field is not None:
        body["field"] = field
    return ValidationError(body)


def _conflict(code: str, detail: str, **named) -> Response:
    return Response({"code": code, "detail": detail, "recorded": False, **named}, status=status.HTTP_409_CONFLICT)


def _body(request) -> dict:
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise _refused("content_length_malformed", "Content-Length is not a number") from None
    if declared > MAX_BODY_BYTES:
        raise BodyTooLarge()
    body = request.data
    if isinstance(body, QueryDict):
        raise UnsupportedMediaType(request.content_type)
    if not isinstance(body, dict):
        raise _refused("body_malformed", "the body is one JSON object")
    return body


def _only(body: dict, allowed: frozenset, what: str) -> None:
    unknown = sorted(str(name) for name in body if name not in allowed)
    if unknown:
        raise _refused(
            "field_unrecognised",
            f"{what} takes only {', '.join(sorted(allowed))}; not {', '.join(unknown)}",
            unknown[0],
        )


def _text(body: dict, field: str, limit: int) -> str:
    if field not in body:
        raise _refused("field_missing", f"{field} is required", field)
    value = body[field]
    if not isinstance(value, str) or not value.strip():
        raise _refused("field_malformed", f"{field} is a non-empty string", field)
    value = value.strip()
    if len(value) > limit:
        raise _refused("field_malformed", f"{field} is at most {limit} characters", field)
    return value


def _tier(body: dict, default: str | None) -> str:
    if "authority_tier" not in body:
        if default is None:
            raise _refused("field_missing", "authority_tier is required", "authority_tier")
        return default
    value = body["authority_tier"]
    if not isinstance(value, str) or value not in AUTHORITY_TIERS:
        raise _refused(
            "authority_tier_unknown",
            f"authority_tier, the source type, is one of {', '.join(AUTHORITY_TIERS)}",
            "authority_tier",
        )
    return value


def _operative(body: dict) -> date:
    if "operative_date" not in body:
        raise _refused("field_missing", "operative_date is required: the date the rule bites", "operative_date")
    value = body["operative_date"]
    if isinstance(value, str) and _DATE.fullmatch(value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise _refused(
        "field_malformed", "operative_date is a calendar date, YYYY-MM-DD: the date the rule bites", "operative_date"
    )


def _structure(body: dict, field: str, kind: type, default):
    if field not in body:
        return default
    value = body[field]
    if not isinstance(value, kind):
        named = "an object" if kind is dict else "a list"
        raise _refused("field_malformed", f"{field} is {named}", field)
    return value


def _note(body: dict) -> str:
    value = body.get("note", "")
    if not isinstance(value, str) or len(value) > NOTE_LIMIT:
        raise _refused("field_malformed", f"note is a string of at most {NOTE_LIMIT} characters", "note")
    return value.strip()


def _attribution(user, note: str) -> str:
    said = f"Recorded by {user.get_username()} through the legal-obligations route."
    return f"{said} {note}" if note else said


def _served(obligation: LegalObligation, deployment) -> dict:
    successor = obligation.superseded_by if obligation.superseded_by_id is not None else None
    return {
        "uuid": str(obligation.uuid),
        "jurisdiction": obligation.jurisdiction,
        "authority_tier": obligation.authority_tier,
        "source": obligation.source,
        "source_version": obligation.source_version,
        "operative_date": obligation.operative_date.isoformat(),
        "thresholds": obligation.thresholds,
        "exemptions": obligation.exemptions,
        "legal_review_status": obligation.legal_review_status,
        "current": successor is None,
        "superseded_by": None if successor is None else str(successor.uuid),
        # Nobody named is said as nobody: a version recorded before this route, or by
        # code, reads "not recorded", never as a person.
        "recorded_by": obligation.recorded_by_username or None,
        "recorded_at": obligation.created_at.isoformat(),
        "detail": reverse(
            "deployment-legal-obligation", kwargs={"uuid": deployment.uuid, "obligation": obligation.uuid}
        ),
    }


def _states(obligation: LegalObligation, wanted: dict) -> bool:
    """Whether ``obligation`` is the version ``wanted`` describes, stated the same way."""
    return (
        obligation.source_version == wanted["source_version"]
        and obligation.operative_date == wanted["operative_date"]
        and obligation.authority_tier == wanted["authority_tier"]
        and obligation.thresholds == wanted["thresholds"]
        and obligation.exemptions == wanted["exemptions"]
    )


def _review(flagged: dict) -> dict:
    """What a change sent for review, as :mod:`assurance.legal` reports it: a queue,
    never a verdict."""
    return {
        "flagged": flagged["flagged"],
        "flagged_count": flagged["flagged_count"],
        "judged": flagged["judged"],
        "bindings_carried_forward": flagged.get("bindings_carried_forward", []),
    }


def _history(obligation: LegalObligation, deployment) -> dict:
    """The versions linked to ``obligation`` by supersession, oldest first: back
    through what each superseded, forward through what superseded each."""
    chain = [obligation]
    seen = {obligation.pk}
    earliest = obligation
    while len(chain) < HISTORY_LIMIT:
        before = (
            LegalObligation.objects.filter(superseded_by=earliest)
            .exclude(pk__in=seen)
            .select_related("superseded_by")
            .order_by("created_at", "pk")
            .first()
        )
        if before is None:
            break
        chain.insert(0, before)
        seen.add(before.pk)
        earliest = before
    latest = obligation
    while latest.superseded_by_id is not None and latest.superseded_by_id not in seen and len(chain) < HISTORY_LIMIT:
        latest = LegalObligation.objects.select_related("superseded_by").get(pk=latest.superseded_by_id)
        chain.append(latest)
        seen.add(latest.pk)
    bound_here = set(deployment.legal_obligations.filter(pk__in=seen).values_list("pk", flat=True))
    return {
        "truncated": len(chain) >= HISTORY_LIMIT,
        "versions": [
            {
                "uuid": str(version.uuid),
                "source_version": version.source_version,
                "operative_date": version.operative_date.isoformat(),
                "authority_tier": version.authority_tier,
                "superseded_by": None if version.superseded_by_id is None else str(version.superseded_by.uuid),
                "recorded_by": version.recorded_by_username or None,
                "recorded_at": version.created_at.isoformat(),
                "binds_this_deployment": version.pk in bound_here,
            }
            for version in chain
        ],
    }


def _decisions(obligation: LegalObligation, deployment) -> dict:
    """The materiality decisions people recorded against ``obligation`` on this
    deployment's claims, newest first: the only thing that judges the legal axis."""
    rows = (
        MaterialityDecision.objects.filter(obligation=obligation, claim__deployment=deployment)
        .select_related("claim", "decided_by")
        .order_by("-decided_at", "-pk")
    )
    total = rows.count()
    shown = list(rows[:LIST_LIMIT])
    return {
        "count": total,
        "truncated": total > len(shown),
        "decisions": [
            {
                "claim": str(decision.claim.uuid),
                "material": decision.material,
                "rationale": decision.rationale,
                "decided_by": decision.decided_by.get_username(),
                "decided_at": decision.decided_at.isoformat(),
            }
            for decision in shown
        ],
    }


class LegalObligationsView(_NoStoreView):
    """The obligations a deployment is bound by (GET), or a new one recorded binding
    it (POST, an admin)."""

    parser_classes = [StrictJSONParser]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        rows = deployment.legal_obligations.select_related("superseded_by").order_by(
            "-operative_date", "source", "-pk"
        )
        total = rows.count()
        shown = list(rows[:LIST_LIMIT])
        return Response(
            {
                "deployment": str(deployment.uuid),
                "count": total,
                "truncated": total > len(shown),
                "obligations": [_served(obligation, deployment) for obligation in shown],
            }
        )

    def post(self, request, uuid):
        deployment = _deployment(request, uuid)
        _require_admin(request)
        body = _body(request)
        _only(body, CREATE_FIELDS, "Recording an obligation")
        jurisdiction = _text(body, "jurisdiction", 64)
        source = _text(body, "source", 255)
        wanted = {
            "source_version": _text(body, "source_version", 64),
            "operative_date": _operative(body),
            "authority_tier": _tier(body, None),
            "thresholds": _structure(body, "thresholds", dict, {}),
            "exemptions": _structure(body, "exemptions", list, []),
        }
        note = _note(body)
        with transaction.atomic():
            taken = LegalObligation.objects.filter(
                jurisdiction=jurisdiction, source=source, source_version=wanted["source_version"]
            ).first()
            if taken is not None:
                here = taken.deployments.filter(pk=deployment.pk).exists()
                return _conflict(
                    "obligation_version_taken",
                    f"{taken} is already recorded: a version is recorded once"
                    + (
                        ", and a change to it is a new version that supersedes it"
                        if here
                        else "; this deployment is not bound by it, and this route does not bind a recorded "
                        "version to another deployment"
                    ),
                    obligation=str(taken.uuid),
                )
            held = (
                deployment.legal_obligations.filter(
                    jurisdiction=jurisdiction, source=source, superseded_by__isnull=True
                )
                .order_by("-operative_date", "-pk")
                .first()
            )
            if held is not None:
                return _conflict(
                    "obligation_recorded_here",
                    f"the deployment is bound by {held}: a new version of it supersedes it "
                    "(POST its supersede route), never a second record beside it",
                    obligation=str(held.uuid),
                    supersede=reverse(
                        "deployment-legal-obligation-supersede",
                        kwargs={"uuid": deployment.uuid, "obligation": held.uuid},
                    ),
                )
            try:
                with transaction.atomic():
                    obligation = LegalObligation.objects.create(
                        jurisdiction=jurisdiction,
                        source=source,
                        recorded_by=request.user,
                        recorded_by_username=request.user.get_username(),
                        **wanted,
                    )
            except IntegrityError:
                return _conflict(
                    "obligation_version_taken",
                    "the version was recorded by another request meanwhile; read it and supersede it",
                )
            obligation.deployments.add(deployment)
            # The one path a rule moving takes to the claims: each current claim of the
            # deployment goes to review pending. Nothing here judges one.
            flagged = legal.flag_for_materiality_review(obligation, note=_attribution(request.user, note))
            # The claims are a decision input: the stored decision is brought current in
            # this transaction, so the two commit together or neither does.
            _refresh_stored_decision(deployment)
        return Response(
            {
                "deployment": str(deployment.uuid),
                "created": True,
                "obligation": _served(obligation, deployment),
                "review": _review(flagged),
            },
            status=status.HTTP_201_CREATED,
        )


class LegalObligationView(_NoStoreView):
    """One obligation the deployment is bound by, its versions and the decisions on it."""

    def get(self, request, uuid, obligation):
        deployment = _deployment(request, uuid)
        found = _bound(deployment, obligation)
        return Response(
            {
                "deployment": str(deployment.uuid),
                "obligation": _served(found, deployment),
                "history": _history(found, deployment),
                "materiality_decisions": _decisions(found, deployment),
            }
        )


class LegalObligationSupersedeView(_NoStoreView):
    """Record the next version of an obligation, which supersedes it (an admin)."""

    parser_classes = [StrictJSONParser]

    def post(self, request, uuid, obligation):
        deployment = _deployment(request, uuid)
        _require_admin(request)
        previous = _bound(deployment, obligation)
        body = _body(request)
        _only(body, SUPERSEDE_FIELDS, "Superseding an obligation (a new version keeps its jurisdiction and source)")
        wanted = {
            "source_version": _text(body, "source_version", 64),
            "operative_date": _operative(body),
            "authority_tier": _tier(body, previous.authority_tier),
            "thresholds": _structure(body, "thresholds", dict, previous.thresholds),
            "exemptions": _structure(body, "exemptions", list, previous.exemptions),
        }
        note = _note(body)
        with transaction.atomic():
            # One successor per version: the row is read under a lock where the
            # database takes one, so two supersessions of one version cannot both land.
            locked = LegalObligation.objects.select_for_update().get(pk=previous.pk)
            if locked.superseded_by_id is not None:
                successor = LegalObligation.objects.select_related("superseded_by").get(pk=locked.superseded_by_id)
                if _states(successor, wanted):
                    # The same request again: the version it recorded, recorded nothing
                    # new. A review its first answer left owed -- a process that died
                    # before settling it -- is settled once this commits.
                    settle = _SettleAfterCommit(successor.pk)
                    transaction.on_commit(settle)
                    locked.superseded_by = successor
                    answer = {
                        "deployment": str(deployment.uuid),
                        "created": False,
                        "previous": _served(locked, deployment),
                        "obligation": _served(successor, deployment),
                    }
                    carried, created = [], False
                else:
                    return _conflict(
                        "obligation_superseded",
                        f"{locked} is already superseded by v{successor.source_version}: a version has one "
                        "successor, so a change now supersedes the current version",
                        current=str(successor.uuid),
                    )
            else:
                answer, carried, settle = self._record(request, deployment, locked, wanted, note)
                if not isinstance(answer, dict):
                    return answer  # refused: nothing recorded
                created = True
        # Committed. The reviews this owed were settled by the commit hook as it
        # committed, one deployment per short transaction; what it could not settle
        # stays owed, and says so.
        answer["review"] = _owed_review(settle, carried)
        return Response(answer, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    @staticmethod
    def _record(request, deployment, locked, wanted, note):
        """In the supersession's own transaction: the new version, its link and the
        bindings it carries, and the review each bound deployment is owed -- a fixed
        number of statements, however many deployments the rule binds. The flags are
        written once it commits (:class:`_SettleAfterCommit`). Returns ``(answer,
        carried, settle)``, or a refusal in place of the answer."""
        if LegalObligation.objects.filter(
            jurisdiction=locked.jurisdiction, source=locked.source, source_version=wanted["source_version"]
        ).exists():
            return _conflict(
                "obligation_version_taken",
                f"{locked.jurisdiction} {locked.source} v{wanted['source_version']} is already recorded: a new "
                "version names a source_version not recorded before",
            ), [], None
        try:
            with transaction.atomic():
                replacement = LegalObligation.objects.create(
                    jurisdiction=locked.jurisdiction,
                    source=locked.source,
                    recorded_by=request.user,
                    recorded_by_username=request.user.get_username(),
                    **wanted,
                )
        except IntegrityError:
            return _conflict(
                "obligation_version_taken",
                "the version was recorded by another request meanwhile; read it and supersede the current one",
            ), [], None
        # What a rule moving is: the versions linked, the bindings carried forward,
        # and every bound deployment owed its review flag -- written once this
        # commits, one deployment per transaction, judging none of them.
        carried = legal.link_supersession(locked, replacement)
        legal.owe_reviews(
            replacement,
            note=f"Supersedes {locked} (v{locked.source_version}). {_attribution(request.user, note)}",
        )
        settle = _SettleAfterCommit(replacement.pk)
        transaction.on_commit(settle)
        answer = {
            "deployment": str(deployment.uuid),
            "created": True,
            "previous": _served(locked, deployment),
            "obligation": _served(replacement, deployment),
        }
        return answer, carried, settle


class _SettleAfterCommit:
    """The reviews a supersession owes, flagged once it commits: one deployment per
    short transaction, each with its decision refreshed in it
    (:func:`assurance.legal.settle_reviews_owed`). A class so a test can find it among
    the commit hooks.

    It runs after the commit, so it never raises: the supersession stands, and an
    answer of 500 would have its client send it again. What it could not settle stays
    owed -- the answer says how many -- and ``manage.py settle_legal_reviews`` settles
    it."""

    __slots__ = ("obligation_pk", "result")

    def __init__(self, obligation_pk):
        self.obligation_pk = obligation_pk
        self.result = None

    def __call__(self):
        try:
            self.result = legal.settle_reviews_owed(_refresh_stored_decision, obligation=self.obligation_pk)
        except Exception:  # the supersession has committed; its reviews stay owed and are settled later
            logger.exception(
                "legal obligation %s: the review flags its supersession owes were not all written; "
                "what is left stays owed for manage.py settle_legal_reviews",
                self.obligation_pk,
            )


def _owed_review(settle: _SettleAfterCommit, carried) -> dict:
    """What a supersession sent for review, as it stands when it answers: the claims
    its settled reviews flagged, and the deployments still owed one -- none, once its
    commit hook has run, unless that failed."""
    done = settle.result
    return {
        "flagged": [] if done is None else done["flagged"],
        "flagged_count": 0 if done is None else done["flagged_count"],
        "judged": False,
        "bindings_carried_forward": [str(d.uuid) for d in carried],
        "owed": LegalReviewOwed.objects.filter(obligation_id=settle.obligation_pk).count(),
    }


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/legal-obligations/",
        LegalObligationsView.as_view(),
        name="deployment-legal-obligations",
    ),
    path(
        "deployments/<uuid:uuid>/legal-obligations/<uuid:obligation>/",
        LegalObligationView.as_view(),
        name="deployment-legal-obligation",
    ),
    path(
        "deployments/<uuid:uuid>/legal-obligations/<uuid:obligation>/supersede/",
        LegalObligationSupersedeView.as_view(),
        name="deployment-legal-obligation-supersede",
    ),
]
