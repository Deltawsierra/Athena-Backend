"""Chain outcomes an engine observed, taken in only as signed evidence.

Every chain status in :mod:`assurance.composition` claims an EXERCISE, and until
now every one of them was written by an operator POST -- including the ones that
said ``basis: demonstrated``, the value that means "a run produced this". A person
could type that word, so the one field built to tell a run from an assertion
could be set by an assertion.

This module is the only writer of a demonstrated outcome. It takes DSSE envelopes
an engine signed (:mod:`mythos_core.outcome`: Achilles per dispatch, Athena per
scan), verifies each against a keyring this deployment trusts, and records what
survives with ``basis=demonstrated`` and the evidence that makes it so: the key
that signed it, the engine it is bound to, the run, and the digest of what the run
saw. A plain POST can no longer claim ``demonstrated``
(:class:`~assurance.serializers.WorkflowChainOutcomeSerializer` refuses it).

WHAT A SIGNATURE DOES NOT PROVE, and so what is checked here as well. A valid
signature says an engine this deployment trusts produced these bytes. It does not
say they were produced for THIS deployment, or only once, or recently. So beyond
authenticity (R6/R7) an envelope is refused when:

  R1  it names a different deployment than the one it is posted to;
  R2  its workflow is not a slug this record can hold;
  R3  its outcome id was already recorded -- a replay, anywhere, of any outcome;
  R4  it is older than the newest outcome the same engine already reported for
      the same workflow here -- a replay of a stale verdict, reordered;
  R5  its instant is in the future beyond clock skew, or older than the window a
      measurement is accepted in;
  R8  the request is larger than a batch of envelopes can honestly be.

and it is recorded with its key id (R7) and evidence digest (R9). Output is JSON
through DRF, which escapes it (R10); nothing here renders text into markup.

ALL OR NOTHING. A batch is refused whole if any envelope in it is refused, and the
answer names each refusal by position. A half-written batch would leave the record
depending on the order a campaign happened to send it in.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.db import transaction
from mythos_core import outcome as oc

from . import composition
from .models import WorkflowChainOutcome

#: Where the keyring lives: a JSON file listing the engines this deployment
#: trusts, ``[{"engine": "achilles", "public_key": "<base64 raw Ed25519>"}, ...]``.
#: A file rather than rows in the database because a trust anchor an admin POST
#: could add would let the same admin who can no longer type ``demonstrated``
#: sign it instead.
KEYRING_ENV = "ASSURANCE_OUTCOME_KEYRING"

#: How far in the future an outcome's instant may be. Clocks drift; a minute or
#: two is drift, an hour is a claim about a run that has not happened.
MAX_CLOCK_SKEW = timedelta(minutes=5)
#: How old an outcome may be when it arrives. A measurement a month old is a
#: backfill, and a backfill of a signed verdict is exactly what a replay looks
#: like; an engine reports what it saw when it saw it.
MAX_AGE = timedelta(days=30)
#: How many envelopes one request may carry, and so how large it may be (R8):
#: each envelope's payload is capped by mythos_core, so the body is bounded by
#: the batch. Kept under Django's own upload ceiling, so an oversized body is
#: refused here with a reason rather than earlier with a generic error.
BATCH_LIMIT = 20
MAX_BODY_BYTES = BATCH_LIMIT * (oc.MAX_PAYLOAD_B64 + 2048)

_SLUG = re.compile(r"^[-a-zA-Z0-9_]{1,200}$")


class KeyringUnavailable(Exception):
    """The keyring is not configured or cannot be read. Nothing can be verified,
    and the caller is told so rather than having its evidence refused as forged."""


@dataclass(frozen=True)
class Refusal:
    index: int
    reason: str


def load_keyring(path: str | None = None) -> dict[str, oc.TrustedKey]:
    """The trusted keys, by key id. Every key passes through
    :class:`mythos_core.outcome.TrustedKey`, which refuses a key that
    authenticates nothing (a small-order point, a non-canonical encoding)."""
    location = path or os.environ.get(KEYRING_ENV)
    if not location:
        raise KeyringUnavailable(
            f"no outcome keyring is configured ({KEYRING_ENV}), so no signed outcome "
            "can be verified here"
        )
    try:
        with open(location, encoding="utf-8") as handle:
            entries = json.load(handle)
    except (OSError, ValueError, RecursionError) as exc:
        # RecursionError: a file of nested brackets exhausts the parser's stack,
        # which is a keyring nobody can use -- not a server error.
        raise KeyringUnavailable(f"the outcome keyring could not be read: {exc}") from exc
    if not isinstance(entries, list) or not entries:
        raise KeyringUnavailable("the outcome keyring is not a non-empty list of keys")
    keyring: dict[str, oc.TrustedKey] = {}
    for position, entry in enumerate(entries):
        try:
            engine = entry["engine"]
            raw = base64.b64decode(entry["public_key"], validate=True)
            key = oc.TrustedKey(raw, engine)
        except (KeyError, TypeError, ValueError, oc.OutcomeError) as exc:
            raise KeyringUnavailable(f"keyring entry {position} is not a usable key: {exc}") from exc
        key_id = oc.key_id_for(raw)
        if key_id in keyring and keyring[key_id].engine != engine:
            raise KeyringUnavailable(
                f"keyring entry {position} binds a key already bound to "
                f"{keyring[key_id].engine!r} to {engine!r}; one key has one engine"
            )
        keyring[key_id] = key
    return keyring


#: The last keyring read for verification at READ time, keyed by the file's
#: identity so an edited or replaced keyring is re-read rather than trusted stale.
_READ_KEYRING: dict[str, tuple[tuple, dict[str, oc.TrustedKey] | None]] = {}


def trusted_keyring() -> dict[str, oc.TrustedKey] | None:
    """The configured keyring for verifying RECORDED outcomes, or ``None``.

    ``None`` rather than an exception, because a reader must still answer: with no
    usable keyring, no recorded outcome can be shown to rest on a signature, so
    every one reads as the assertion it then is. That is the direction this
    module fails in on purpose -- ingest refuses with a 503 for the same reason.
    """
    location = os.environ.get(KEYRING_ENV)
    if not location:
        return None
    try:
        stat = os.stat(location)
    except OSError:
        return None
    identity = (location, stat.st_ino, stat.st_mtime_ns, stat.st_size)
    cached = _READ_KEYRING.get("keyring")
    if cached is not None and cached[0] == identity:
        return cached[1]
    try:
        keyring: dict[str, oc.TrustedKey] | None = load_keyring(location)
    except KeyringUnavailable:
        keyring = None
    _READ_KEYRING["keyring"] = (identity, keyring)
    return keyring


def recorded_outcome_is_authentic(row, keyring, *, deployment_uuid: str | None = None) -> bool:
    """Does ``row`` rest on an envelope a trusted engine signed, saying what the row says?

    Checked at READ time, every time, rather than trusted from ingest. The row's
    columns are writable by anything with the ORM -- a fixture, a shell, a future
    route -- and a check of their mere presence let ``envelope={}`` with any
    ``outcome_id`` read as a run, and let a genuine envelope signed for ANOTHER
    deployment, copied onto this one's row, read as a run here. So the envelope is
    verified against the keyring as it stands now (a key since withdrawn no longer
    vouches for anything), and every column the rule reads must be the one the
    signature covers. The ingest-time windows (skew, age, replay order) are NOT
    re-applied: they judge when an outcome may be recorded, not whether a recorded
    one is authentic.
    """
    if not keyring or not row.outcome_id or not isinstance(row.envelope, dict):
        return False
    verdict = oc.verify_outcome(row.envelope, keyring)
    if verdict.verdict != oc.AUTHENTIC or verdict.outcome is None:
        return False
    outcome = verdict.outcome
    try:
        observed = _instant(outcome["observed_at"])
    except (KeyError, TypeError, ValueError):
        return False
    deployment = deployment_uuid if deployment_uuid is not None else str(row.deployment.uuid)
    return (
        outcome["outcome_id"] == row.outcome_id
        and outcome["deployment"] == deployment
        and outcome["workflow"] == row.workflow
        and outcome["status"] == row.status
        and observed == row.observed_at
        and outcome["observer"]["engine"] == row.observer_engine
        and verdict.key_id == row.observer_key_id
        and outcome["evidence_digest"] == row.evidence_digest
    )


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt_timezone.utc)


def _examine(envelope: Any, deployment, keyring, now: datetime) -> tuple[dict | None, str | None, str]:
    """``(outcome, key_id, "")`` for an envelope that may be recorded, else
    ``(None, None, why)``."""
    verdict = oc.verify_outcome(envelope, keyring)
    if verdict.verdict != oc.AUTHENTIC:
        return None, None, f"{verdict.verdict}: {verdict.reason}"
    outcome = verdict.outcome
    if outcome["deployment"] != str(deployment.uuid):
        return None, None, (
            f"the outcome is for deployment {outcome['deployment']!r}, not this one "
            f"({deployment.uuid}); a signature proves who observed it, not where"
        )
    if not _SLUG.match(outcome["workflow"]):
        return None, None, f"workflow {outcome['workflow']!r} is not a slug this record can hold"
    observed = _instant(outcome["observed_at"])
    if observed > now + MAX_CLOCK_SKEW:
        return None, None, f"observed_at {outcome['observed_at']} is in the future"
    if observed < now - MAX_AGE:
        return None, None, (
            f"observed_at {outcome['observed_at']} is older than the {MAX_AGE.days}-day "
            "window an observation is accepted in"
        )
    return outcome, verdict.key_id, ""


def ingest(deployment, envelopes: list, *, keyring=None, now: datetime | None = None):
    """Verify and record ``envelopes`` for ``deployment``, all or none.

    Returns ``(recorded_rows, refusals)``; when ``refusals`` is non-empty nothing
    was recorded. Raises :class:`KeyringUnavailable` when nothing can be verified.
    """
    keyring = keyring if keyring is not None else load_keyring()
    now = now or datetime.now(dt_timezone.utc)
    refusals: list[Refusal] = []
    accepted: list[tuple[int, dict, str, Any]] = []
    seen_ids: set[str] = set()
    for index, envelope in enumerate(envelopes):
        outcome, key_id, why = _examine(envelope, deployment, keyring, now)
        if outcome is None:
            refusals.append(Refusal(index, why))
            continue
        if outcome["outcome_id"] in seen_ids:
            refusals.append(Refusal(index, "the same outcome appears twice in this batch"))
            continue
        seen_ids.add(outcome["outcome_id"])
        accepted.append((index, outcome, key_id, envelope))
    if refusals:
        return [], refusals

    # The newest outcome each (workflow, engine) reports within this batch. A
    # verdict older than one the same engine reports alongside it is the same
    # replay as one posted after it: whether the two arrive together or apart
    # must not decide whether the stale one is recorded.
    batch_newest: dict[tuple[str, str], datetime] = {}
    for _, outcome, _, _ in accepted:
        key = (outcome["workflow"], outcome["observer"]["engine"])
        instant = _instant(outcome["observed_at"])
        if key not in batch_newest or instant > batch_newest[key]:
            batch_newest[key] = instant

    with transaction.atomic():
        # Checked inside the transaction and against the database, so two
        # concurrent posts of one envelope cannot both pass; the unique column
        # backs this if they race anyway.
        existing = set(
            WorkflowChainOutcome.objects.filter(
                outcome_id__in=[o["outcome_id"] for _, o, _, _ in accepted]
            ).values_list("outcome_id", flat=True)
        )
        # ``index`` is the envelope's place in the batch the caller sent, never its
        # place in ``accepted`` -- a refusal must name the envelope it refuses.
        for index, outcome, _, _ in accepted:
            if outcome["outcome_id"] in existing:
                refusals.append(Refusal(index, f"outcome {outcome['outcome_id']} was already recorded"))
                continue
            newest = (
                WorkflowChainOutcome.objects.filter(
                    deployment=deployment,
                    workflow=outcome["workflow"],
                    observer_engine=outcome["observer"]["engine"],
                    basis=composition.BASIS_DEMONSTRATED,
                )
                .exclude(observed_at__isnull=True)
                .order_by("-observed_at")
                .values_list("observed_at", flat=True)
                .first()
            )
            observed = _instant(outcome["observed_at"])
            if newest is not None and observed < newest:
                refusals.append(
                    Refusal(
                        index,
                        f"observed_at {outcome['observed_at']} is older than the newest "
                        f"outcome {outcome['observer']['engine']} already reported for "
                        f"{outcome['workflow']!r} here ({newest.isoformat()})",
                    )
                )
                continue
            in_batch = batch_newest[(outcome["workflow"], outcome["observer"]["engine"])]
            if observed < in_batch:
                refusals.append(
                    Refusal(
                        index,
                        f"observed_at {outcome['observed_at']} is older than the newest "
                        f"outcome {outcome['observer']['engine']} reports for "
                        f"{outcome['workflow']!r} in this same batch ({in_batch.isoformat()})",
                    )
                )
        if refusals:
            return [], refusals
        rows = [
            WorkflowChainOutcome(
                deployment=deployment,
                workflow=outcome["workflow"],
                status=outcome["status"],
                basis=composition.BASIS_DEMONSTRATED,
                observed_at=_instant(outcome["observed_at"]),
                source=(
                    f"{outcome['observer']['engine']} {outcome['observer']['version']} "
                    f"run {outcome['observer']['run_id']}"
                )[:255],
                note=outcome["reason"],
                outcome_id=outcome["outcome_id"],
                observer_engine=outcome["observer"]["engine"],
                observer_key_id=key_id,
                evidence_digest=outcome["evidence_digest"],
                envelope=envelope,
            )
            for _, outcome, key_id, envelope in accepted
        ]
        WorkflowChainOutcome.objects.bulk_create(rows)
    return rows, []


__all__ = [
    "BATCH_LIMIT",
    "KEYRING_ENV",
    "MAX_AGE",
    "MAX_BODY_BYTES",
    "MAX_CLOCK_SKEW",
    "KeyringUnavailable",
    "Refusal",
    "ingest",
    "load_keyring",
]
