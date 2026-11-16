"""Reconciliation receipts: what a provider's readback said became of an unknown effect (F1).

Achilles carries a permitted action out through the provider the operator registered
for its tool, and signs an ``observed_effect`` (:mod:`assurance.observed_effects`) when
the provider answers success. When the answer is lost -- a read timeout, a connection
dropped once the request was on its way, an ambiguous 5xx -- the effect is ``unknown``,
and Achilles signs nothing for it (G3, ``achilles/observed_effect.py``). It keeps the
dispatch in its reconciliation book and asks the provider's READBACK what became of the
dispatch's idempotency key. Each answer is signed as a ``mythos.effect-reconciliation``
receipt (version 1 or 2): ``applied`` concludes ``committed``, ``not_applied`` ``failed`` (and only then
may the dispatch be retried, under the same key, re-gated), ``cannot_say`` ``unknown``.
This module is the receiving half.

THE ENVELOPE AND THE DOCUMENT are defined ONCE, in Mythos-Core
(``mythos_core.observed_effect``: ``verify_reconciliation``, ``validate_reconciliation``),
for the engine that signs a receipt and for this backend alike. This module keeps none
of the rules: until the core defined them, a copy was kept here by hand. Versions 1 and
2 are read. Version 2 carries keyed references (``action_ref``,
``readback.response_ref``) in place of the plain digests, and ``keyed_under``, the id of
the engine's chain key; a receipt is signed in the version its dispatch was first signed
in, so the two are compared like with like (:func:`assurance.authority_chain.readback`).

The envelope is DSSE, exactly one signature, under the payload type
:data:`PAYLOAD_TYPE` -- a type of its own, which the pre-authentication encoding binds
into the signed bytes: no receipt verifies as a chain outcome, and no chain outcome (an
observed effect included) verifies as a receipt. Its signer is the observed-effect key,
the key the keyring (``ASSURANCE_OUTCOME_KEYRING``) files under ``achilles-effect``; the
verdict is the core's (:func:`verify_envelope`), and this module adds only the sentence
that says where the envelope belongs or whose key signed it. Its evidence kind is
:data:`assurance.composition.EVIDENCE_EFFECT_RECONCILIATION`, which follows from the
payload type: :data:`assurance.composition.SIGNER_EVIDENCE` maps a signer's OUTCOMES and
is not widened, so the effect key proves nothing new under the outcome payload type.
The conformance vectors are the core's own files, carried byte for byte
(``tests/vectors/effect-reconciliation-v1.json`` and ``-v2.json``). The core is read at
its first use, never with this module (:func:`_core`).

WHAT IS REFUSED at the route (:func:`ingest`), with nothing recorded and a 4xx that
names it: an envelope that is not a receipt -- an observed effect or a gate decision
among them (both are chain outcomes) -- or that does not verify under the
``achilles-effect`` key; a document that is not a receipt; a receipt for another
deployment; one read in the future beyond the clock skew, or older than the window a
signed outcome is accepted in; a receipt id already recorded with other bytes (409).
The same envelope posted again is answered 200 and recorded once. A receipt is never
refused because its gate decision is not on record yet: it is stored, and proves
nothing until it binds (:func:`assurance.authority_chain.readback`).

WHAT IT PROVES is read at read time, never at intake: the ``produces`` hop of a chain
that cites the receipt's gate decision (:func:`assurance.authority_chain.readback`) --
``committed`` proves it (``readback``), ``failed`` breaks it (``effect_not_produced``),
``unknown`` leaves it unproven (``effect_unknown``), and conflicting or mismatched
evidence proves nothing. Every read re-verifies the envelope under the keyring in force
(:func:`in_force`): a column edited after the fact, or a key since withdrawn, proves
nothing.

WHO MAY POST: the observed-effect service, on its own credential
(:class:`assurance.observed_effects.ObservedEffectServiceAuthentication`,
``X-Observed-Effect-Token``). The same service and the same signer as the observed
effects; the credential only lets it post, and what a receipt proves is the signature's.

DEGRADED (the owner's G14 policy). An unset or unreadable keyring, or one that files no
key under ``achilles-effect``, refuses intake with a 503 that names it -- never accepts
unverified -- and a read under it finds no receipt in force, so nothing a receipt would
prove reads proven. NOTHING HERE IS ON A STOP'S PATH: the route records evidence, is
classified in :mod:`safety.stops` as not a stop, and nothing a stop reads or writes
reads this module or its table.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.db import IntegrityError, transaction
from django.db.models import Q
from mythos_core import outcome as oc

from . import authority_chain as rule
from . import composition, observed_outcomes

logger = logging.getLogger(__name__)


def _core():
    """``mythos_core.observed_effect``: the one definition of the receipt. Read at first
    use, never with this module, as :mod:`assurance.observed_effects` reads it: nothing
    of a receipt's rules is loaded before a receipt is read."""
    from mythos_core import observed_effect

    return observed_effect


#: This module's own names for what the core defines, each read from the core at its
#: first use (:func:`__getattr__`) and none spelled here.
_FROM_THE_CORE = {
    # ``SCHEMA`` has named version 1 since there was one version, and still does: what
    # reads it (the tests' own v1 receipts among them) reads what it did.
    "SCHEMA": lambda core: core.RECONCILIATION_SCHEMA_V1,
    "SCHEMA_V1": lambda core: core.RECONCILIATION_SCHEMA_V1,
    "SCHEMA_V2": lambda core: core.RECONCILIATION_SCHEMA_V2,
    "SCHEMAS": lambda core: core.RECONCILIATION_SCHEMAS,
    "PAYLOAD_TYPE": lambda core: core.RECONCILIATION_PAYLOAD_TYPE,
    # The engine the keyring files the observed-effect key under: the one key a receipt
    # is verified by, and the observer name the document must carry.
    "SIGNER": lambda core: core.ENGINE,
    "TOOL_KINDS": lambda core: core.TOOL_KINDS,
    # The readback's answers, in its own words, and the conclusion each gives.
    "APPLIED": lambda core: core.READBACK_APPLIED,
    "NOT_APPLIED": lambda core: core.READBACK_NOT_APPLIED,
    "CANNOT_SAY": lambda core: core.READBACK_CANNOT_SAY,
    "ANSWERS": lambda core: core.READBACK_ANSWERS,
    "CONCLUSIONS": lambda core: core.READBACK_CONCLUSIONS,
    # A receipt's basis: the readback was read.
    "BASIS_OBSERVED": lambda core: core.status.OBSERVED,
    "ReceiptRefused": lambda core: core.EvidenceRefused,
}


def __getattr__(name: str):
    read = _FROM_THE_CORE.get(name)
    if read is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return read(_core())


EVIDENCE_KIND = composition.EVIDENCE_EFFECT_RECONCILIATION
BODY_FIELDS = frozenset({"envelope"})

#: The longest payload decoded (the core's bound on any signed payload), and so the
#: body. A version 2 receipt is no longer than a version 1 one by more than its key id,
#: so this route's bound is what it was.
MAX_PAYLOAD_B64 = oc.MAX_PAYLOAD_B64
MAX_BODY_BYTES = MAX_PAYLOAD_B64 + 4 * 1024


# ------------------------------------------------------------------ the document


def instant(value: str) -> datetime:
    """A receipt's instant (``YYYY-MM-DDTHH:MM:SS.ffffffZ``) as an aware datetime."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt_timezone.utc)


def validate_receipt(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.effect-reconciliation`` receipt, version 1 or 2,
    else the core's :class:`ReceiptRefused` with the code of the first rule it breaks.
    The core's ``validate_reconciliation``: nothing is checked here."""
    return _core().validate_reconciliation(document)


# ------------------------------------------------------------------ the envelope


def has_effect_key(keyring) -> bool:
    """Whether ``keyring`` files a key under ``achilles-effect``: without one, no
    receipt can be verified here at all."""
    signer = _core().ENGINE
    return any(key.engine == signer for key in (keyring or {}).values())


def _said(verdict, envelope: Any, keyring) -> str:
    """Why a receipt the core did not find authentic is refused: the core's code and
    its reason, and -- where this backend knows more than the core can -- one sentence
    of its own: which route a chain outcome belongs on, that the key is none this
    deployment trusts, or whose key the keyring says signed it. The verdict is the
    core's; nothing here decides."""
    reason = f"{verdict.code}: {verdict.reason}"
    if verdict.verdict == oc.WRONG_TYPE and isinstance(envelope, dict):
        if envelope.get("payloadType") == oc.OUTCOME_PAYLOAD_TYPE:
            return (
                f"{reason}. An observed effect is recorded with its evidence document on the observed-effects "
                "route, a gate decision on chain-outcomes/observed/; posted here it would prove nothing"
            )
        return f"{reason} ({_core().RECONCILIATION_PAYLOAD_TYPE})"
    if verdict.verdict == oc.UNKNOWN_KEY:
        return f"{reason}: the receipt is signed by a key this deployment does not trust"
    if verdict.verdict == oc.WRONG_OBSERVER:
        held = keyring.get(verdict.key_id) if hasattr(keyring, "get") else None
        engine = getattr(held, "engine", None)
        if isinstance(engine, str):
            return f"{reason}; the receipt is signed by {engine!r}'s key"
    return reason


def verify_envelope(envelope: Any, keyring) -> tuple[dict | None, str | None, str]:
    """``(receipt, key id, "")`` when ``envelope`` is a reconciliation receipt, version
    1 or 2, that the observed-effect key in ``keyring`` signed; else ``(None, key id or
    None, why)``. Never raises on bad input. The core's ``verify_reconciliation`` decides
    every part of it: the envelope's shape, its payload type (a chain outcome -- an
    observed effect's or a gate decision's -- is refused before anything is decoded), the
    key, the signature, the receipt's rules for its version, its canonical bytes, and
    that the key's engine is the observer the receipt names."""
    verdict = _core().verify_reconciliation(envelope, keyring or {})
    if verdict.authentic:
        return verdict.document, verdict.key_id, ""
    return None, verdict.key_id, _said(verdict, envelope, keyring or {})


def envelope_digest(envelope: dict) -> str:
    """``sha256:`` over the envelope's canonical JSON: what "the same envelope" means
    when one is posted again."""
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()


# ------------------------------------------------------------------- the intake


class BodyRefused(ValueError):
    """A body this route cannot read. ``errors`` maps each field to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


def read_body(data: Any) -> Any:
    """The envelope from ``{"envelope": {...}}``: one receipt per request, exactly that
    field -- the ``reconciliation`` Achilles' reconcile answer carries."""
    if not isinstance(data, dict):
        raise BodyRefused({"body": "an object with an envelope"})
    unknown = sorted(str(k) for k in set(data) - BODY_FIELDS)
    missing = sorted(BODY_FIELDS - set(data))
    if unknown or missing:
        raise BodyRefused({**{k: "unknown field" for k in unknown}, **{k: "required" for k in missing}})
    return data["envelope"]


@dataclass(frozen=True)
class Refusal:
    """Why a posted receipt is not recorded, and the 4xx that says so."""

    status: int
    reason: str


def keyring_for_intake(keyring=None):
    """The keyring a receipt is verified against at intake, or
    :class:`assurance.observed_outcomes.KeyringUnavailable` -- unset, unreadable, or
    filing no key under ``achilles-effect`` -- so the route refuses clearly and never
    takes a receipt in unverified."""
    keyring = keyring if keyring is not None else observed_outcomes.load_keyring()
    if not has_effect_key(keyring):
        raise observed_outcomes.KeyringUnavailable(
            f"the outcome keyring files no key under {_core().ENGINE!r}, so no reconciliation receipt can be verified here"
        )
    return keyring


def ingest(deployment, envelope: Any, *, keyring=None, now: datetime | None = None):
    """Verify and record one receipt for ``deployment``.

    Returns ``(row, True)`` for a receipt recorded now, ``(row, False)`` for the same
    envelope already recorded (posted again: nothing changes), or a :class:`Refusal`.
    Raises :class:`assurance.observed_outcomes.KeyringUnavailable` when nothing can be
    verified. Never refuses a receipt because its gate decision is not on record."""
    from .models import EffectReconciliationReceipt

    keyring = keyring_for_intake(keyring)
    now = now or datetime.now(dt_timezone.utc)
    document, key_id, why = verify_envelope(envelope, keyring)
    if document is None:
        return Refusal(400, why)
    if document["deployment"] != str(deployment.uuid):
        return Refusal(
            400,
            f"the receipt is for deployment {document['deployment']!r}, not this one ({deployment.uuid}); a "
            "signature proves who read it back, not where",
        )
    read_at = instant(document["readback"]["read_at"])
    if read_at > now + observed_outcomes.MAX_CLOCK_SKEW:
        return Refusal(400, f"readback.read_at {document['readback']['read_at']} is in the future")
    if read_at < now - observed_outcomes.MAX_AGE:
        return Refusal(
            400,
            f"readback.read_at {document['readback']['read_at']} is older than the "
            f"{observed_outcomes.MAX_AGE.days}-day window a signed record is accepted in",
        )
    digest = envelope_digest(envelope)
    receipt_id = document["receipt_id"]

    def again(row):
        if row.envelope_digest == digest and row.deployment_id == deployment.pk:
            return row, False
        return Refusal(
            409,
            f"receipt {receipt_id} is already recorded, with other bytes: one receipt id is one receipt, and the "
            "one on record stands",
        )

    with transaction.atomic():
        existing = EffectReconciliationReceipt.objects.filter(receipt_id=receipt_id).first()
        if existing is not None:
            return again(existing)
        try:
            # A savepoint of its own: the unique receipt id is the backstop for two
            # posts racing past the read above, and a race lost there is answered as
            # the post that won it would be -- never a 500.
            with transaction.atomic():
                row = EffectReconciliationReceipt.objects.create(
                    deployment=deployment,
                    receipt_id=receipt_id,
                    dispatch_id=document["dispatch_id"],
                    attempt=document["attempt"],
                    gate_outcome_id=document["gate_outcome_id"],
                    workflow=document["workflow"],
                    answer=document["readback"]["answer"],
                    conclusion=document["conclusion"]["state"],
                    provider=document["readback"]["provider"],
                    read_at=read_at,
                    observer_key_id=key_id,
                    envelope_digest=digest,
                    envelope=envelope,
                    recorded_at=now,
                )
        except IntegrityError:
            existing = EffectReconciliationReceipt.objects.filter(receipt_id=receipt_id).first()
            if existing is None:
                return Refusal(409, f"receipt {receipt_id} could not be recorded: another write conflicted with it")
            return again(existing)
    return row, True


# ------------------------------------------------------------------ the read

#: Verdicts already computed, by the envelope's exact JSON and the keyring's (key id,
#: engine) pairs: the Ed25519 work is done once per pair; the columns are compared
#: with what it signs on every read, because the columns are what can be edited.
_VERDICTS: dict[tuple, tuple] = {}
_VERDICT_LIMIT = 50_000


def _verified(envelope: dict, keyring) -> tuple[dict | None, str | None, str]:
    try:
        memo_key = (
            json.dumps(envelope, sort_keys=True, separators=(",", ":")),
            tuple(sorted((kid, key.engine) for kid, key in keyring.items())),
        )
    except (TypeError, ValueError):
        return verify_envelope(envelope, keyring)
    verdict = _VERDICTS.get(memo_key)
    if verdict is None:
        verdict = verify_envelope(envelope, keyring)
        if len(_VERDICTS) >= _VERDICT_LIMIT:
            _VERDICTS.clear()
        _VERDICTS[memo_key] = verdict
    return verdict


def in_force(row, keyring) -> dict | None:
    """``row``'s receipt, if its envelope verifies NOW under the observed-effect key in
    ``keyring`` and every column the read relies on is what it signs; else None. With no
    keyring nothing is in force: no receipt is shown to rest on a signature, so none
    proves anything (the owner's G14 policy: a read degrades to unknown)."""
    if not keyring or not isinstance(row.envelope, dict):
        return None
    document, key_id, _ = _verified(row.envelope, keyring)
    if document is None:
        return None
    if (
        document["receipt_id"] != row.receipt_id
        or document["dispatch_id"] != row.dispatch_id
        or document["gate_outcome_id"] != row.gate_outcome_id
        or document["attempt"] != row.attempt
        or document["workflow"] != row.workflow
        or document["readback"]["answer"] != row.answer
        or document["conclusion"]["state"] != row.conclusion
        or key_id != row.observer_key_id
    ):
        return None
    return document


def as_reconciliation(document: dict) -> rule.Reconciliation:
    """A receipt in force, as :mod:`assurance.authority_chain` reads it. A version 1
    receipt refers to its action by a plain digest; a version 2 one by a keyed reference
    and the id of the key it is keyed under, and holds no plain digest at all."""
    keyed = document.get("keyed_under")
    return rule.Reconciliation(
        receipt_id=document["receipt_id"],
        deployment=document["deployment"],
        workflow=document["workflow"],
        tool_kind=document["tool"]["kind"],
        tool_identifier=document["tool"]["identifier"],
        action=document["action"],
        action_digest=document.get("action_digest", ""),
        action_ref=document.get("action_ref", ""),
        keyed_under=(keyed["chain"], keyed["chain_key"]) if isinstance(keyed, dict) else None,
        dispatch_id=document["dispatch_id"],
        attempt=document["attempt"],
        permit_digest=document["permit_digest"],
        gate_outcome_id=document["gate_outcome_id"],
        dispatched_at=instant(document["dispatched_at"]),
        answer=document["readback"]["answer"],
        conclusion=document["conclusion"]["state"],
        provider=document["readback"]["provider"],
        read_at=instant(document["readback"]["read_at"]),
    )


def rows_for(deployment, gate_ids, dispatch_ids) -> list:
    """Every receipt recorded on ``deployment`` that names one of ``gate_ids`` as its
    gate decision or one of ``dispatch_ids`` as its dispatch -- and every other receipt
    of each dispatch those name, whatever attempt it is of. Oldest first. One query, and
    a second only when a receipt names a dispatch the first did not ask for; none when
    nothing is asked."""
    from .models import EffectReconciliationReceipt

    gates = sorted({g for g in gate_ids if g})
    dispatches = sorted({d for d in dispatch_ids if d})
    if not gates and not dispatches:
        return []
    found = {
        row.pk: row
        for row in EffectReconciliationReceipt.objects.filter(deployment=deployment).filter(
            Q(gate_outcome_id__in=gates) | Q(dispatch_id__in=dispatches)
        )
    }
    more = sorted({row.dispatch_id for row in found.values()} - set(dispatches))
    if more:
        found.update(
            (row.pk, row)
            for row in EffectReconciliationReceipt.objects.filter(deployment=deployment, dispatch_id__in=more)
        )
    return [found[pk] for pk in sorted(found)]


def _stamp(value: datetime) -> str:
    return value.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def served(chain: rule.Chain, found: rule.Readback | None, rows) -> list[dict]:
    """The receipts the chain read serves beside a chain's ``produces`` evidence: every
    receipt recorded about the dispatch its gate decision let through, each with its
    id, dispatch, attempt, gate decision, answer, conclusion, when and from which
    provider it was read, whether it verifies now and whether it binds (and why not).
    A receipt that does not verify under the keyring in force is served from its row
    with ``verified`` false: it binds nothing. Oldest attempt first."""
    bindings = {b.receipt.receipt_id: b for b in (found.bindings if found else ())}
    dispatches = {found.dispatch_id} if found and found.dispatch_id else set()
    gate = chain.gate_outcome_id
    dispatches |= {row.dispatch_id for row in rows if gate and row.gate_outcome_id == gate}
    entries = []
    for row in rows:
        binding = bindings.get(row.receipt_id)
        if binding is None and not ((gate and row.gate_outcome_id == gate) or row.dispatch_id in dispatches):
            continue
        if binding is not None:
            r = binding.receipt
            entries.append(
                {
                    "receipt_id": r.receipt_id,
                    "dispatch_id": r.dispatch_id,
                    "attempt": r.attempt,
                    "gate_outcome_id": r.gate_outcome_id,
                    "answer": r.answer,
                    "conclusion": r.conclusion,
                    "read_at": _stamp(r.read_at),
                    "provider": r.provider,
                    "verified": True,
                    "binds": binding.binds,
                    "why": binding.why or None,
                }
            )
        else:
            entries.append(
                {
                    "receipt_id": row.receipt_id,
                    "dispatch_id": row.dispatch_id,
                    "attempt": row.attempt,
                    "gate_outcome_id": row.gate_outcome_id,
                    "answer": row.answer,
                    "conclusion": row.conclusion,
                    "read_at": _stamp(row.read_at),
                    "provider": row.provider,
                    "verified": False,
                    "binds": False,
                    "why": (
                        "it does not verify under the observed-effect key in the keyring in force, or its row is not "
                        "what it signs: it binds nothing"
                    ),
                }
            )
    return sorted(entries, key=lambda e: (e["attempt"], e["read_at"], e["receipt_id"]))


# The names read from the core at first use (``_FROM_THE_CORE``) are this module's too,
# and are not listed here: see :mod:`assurance.observed_effects`.
__all__ = [
    "MAX_BODY_BYTES",
    "BodyRefused",
    "Refusal",
    "as_reconciliation",
    "envelope_digest",
    "in_force",
    "ingest",
    "read_body",
    "rows_for",
    "served",
    "validate_receipt",
    "verify_envelope",
]
