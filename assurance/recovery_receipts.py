"""SPINE SP-4, part 2b: the backend issues signed recovery receipts.

An owner, an auditor or an insurer reads a recovery's standing as a signed receipt, not
as a page of this backend. ``mythos_core.recovery_receipt`` defines the receipt
(``mythos.recovery-receipt/v2``, Mythos-Core#86); :mod:`assurance.recovery_record` keeps
the record a receipt is taken of. This module issues one, stores it and reads it back.

**What a receipt says** (:func:`issue`) is the incident's recovery record as its read
serves it at one instant, the server's clock at the issue, which is the receipt's
``as_of``: the last step (:func:`assurance.recovery_record.served_steps`), its state,
what it is held back from, its restrictions that are names, who vouches for each
witness (``support``), every gap with what would close it (``gaps_named``), and the
owner's acceptance as the step recorded it. Nothing is typed in and nothing is
defaulted: the core's ``build_receipt`` builds it, and computes its release.

- **v2 only.** ``build_receipt`` builds v2 and nothing here builds v1; a document that
  is not v2 is never sent, and an envelope that is not v2 is never stored.
- **An engine's support names its key.** A step's support entry that names an engine
  and no key id vouches for nothing in v2: it is not issued as signed, it is the gap
  ``support:<condition>:<kind>:<ref>``, with what would close it (that record, signed
  by an engine that names its key). The record's own read still serves such an entry
  as it always has (v1's rule); the receipt is the stricter of the two.
- **The scope** is the incident's current revision, read as the record reads it: its
  number and reference, each item with the revision it has been in scope since, and
  each item a revision removed, with who removed it (that revision's declarer, by
  reference) and why. A step derived before any scope was declared reads
  ``scope:not_declared`` against every revision since, so its receipt is taken under no
  declared scope, as the step was, and stands ``scope_moved`` from the first instant,
  as the step itself does. An unreadable scope is said as the core spells it.

**The key is the engine's** (:func:`engine_signer`): the backend holds none. The
receipt is signed by Athena-Engine's ``POST /api/assurance/recovery-receipt/sign`` in
the ``recovery-receipt`` role (:meth:`CyberEngineClient.sign_recovery_receipt`,
athena-engine #146), the Financial Exposure Receipt's path and shape, presented with the
recovery-receipt-signer key alone (``ce_rr_``,
:meth:`CyberEngineClient.for_recovery_receipt_signing`): never the operator key, and
never the exposure signer's. With none configured nothing is sent.

**Verified before it is stored.** The envelope must verify under the engine's published
keyring (:func:`engine_keyring`) in the ``recovery-receipt`` role, every other role it
publishes filed as another role so that a key of one is refused ``wrong_role``; and the
receipt it carries must be the document sent, byte for byte as the core canonicalises
it. Anything else is never stored, and the answer says why. The keyring is read before
anything is sent to be signed: no signature nobody can check is asked for.

**Append-only** (:class:`~assurance.models.RecoveryReceipt`): a receipt is never edited.
Each after the first supersedes the latest, naming it, with the pointer to why
(``reason``): ``recovery-step:<uuid>`` (a later step), ``scope-revision:<uuid>`` (the
scope moved), ``acceptance-ended:<uuid>`` (the step's acceptance has ended), or
``recovery-record:<uuid>`` (the same step reads otherwise now); the core's
``check_supersedes`` is asked before anything is signed. A receipt whose record has not
moved -- it would say exactly what the latest says, at a later instant -- is not issued
again: the latest is returned, and nothing is signed or stored. A latest receipt that no
longer verifies is never superseded here (``latest_receipt_unverified``): unreadable
means caution.

**Engine unreachable or refusing: nothing is stored.** One request, never retried on the
request thread. An engine that could not be reached (or a gateway's 502 or 504 in its
place) is ``engine_unreachable``, and an engine that answered 503 (``signer_not_configured``
among them) is ``engine_unavailable``: each 503 with ``Retry-After``. A 400 is the
engine's core refusing the document, ``receipt_refused_by_signer``, with the engine's code
carried. Any other refusal (a 403 for a key it does not take, a 404 for an engine
without the route) is ``signer_refused``, with its status and code where it named one.

**The reads** (:func:`receipts_of`, :func:`head_of`) serve every receipt oldest first,
each verified again now against the keyring read now, its columns held to the signed
payload, and its standing the core's (``receipt_standing``) against the head:
``{current_scope_revision, latest_receipt_ref}``. One that does not verify, whose
columns are not what it signed, or that cannot be checked at all (no keyring) reads
``unknown``, never ``current``.

Nothing here is on a stop path. The URL conf loads this module with the views; it loads
neither ``mythos_core.recovery_receipt`` nor the engine client, which are read at first
use (:func:`_core`, :func:`engine_signer`, :func:`engine_keyring`). No transaction is
open while the engine is asked; the one write is one row of this record's own table.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.utils import timezone
from mythos_core import scope as core_scope

from . import incident_scope
from . import recovery_record as rr

#: Every receipt's name: this prefix and a fresh uuid4. A name, never a digest.
REF_PREFIX = "recovery-receipt:"
_REF = re.compile(r"recovery-receipt:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_PERSON = re.compile(r"user:[0-9]{1,20}")
#: The role the engine's own ``keys`` (the artifact key: evidence packs and assurance
#: receipts) are filed under in a recovery receipt's keyring: athena-engine #146's name.
ARTIFACT_ROLE = "engine-artifact"
#: Published keys of these statuses verify; a revoked key verifies nothing.
VERIFYING_STATUSES = frozenset({"active", "retired"})
#: Seconds an answer that could not reach the engine tells its caller to wait.
RETRY_AFTER_SECONDS = 30
#: The statuses a gateway answers in the engine's place when it could not be reached.
_UNREACHED_STATUSES = frozenset({502, 504})
#: The codes answered 503 with ``Retry-After``: ask again later.
RETRY_LATER = frozenset({"engine_unreachable", "engine_unavailable"})
#: What a receipt says besides when it was issued and what it supersedes: two receipts
#: equal in these say the same thing, and the later is not issued.
_IDENTITY = frozenset({"receipt_ref", "as_of", "supersedes", "reason"})

#: What each code of this module means, and the status it is answered with.
REFUSALS = {
    "no_recovery_record": (409, "the incident has no recovery record: there is nothing for a receipt to say"),
    "receipt_not_built": (
        409, "the core refuses a receipt of the record as it reads now; core_code names its rule, and nothing "
        "was sent to be signed",
    ),
    "keyring_unavailable": (
        502, "no keyring of the engine's published recovery-receipt keys could be read: nothing is signed or "
        "stored without one to check the signature with",
    ),
    "latest_receipt_unverified": (
        409, "the incident's latest receipt does not verify now: it is never superseded by a receipt that names "
        "it, and nothing was signed or stored",
    ),
    "supersession_refused": (
        409, "the core refuses the new receipt as one superseding the latest (core_code names its rule): nothing "
        "was signed or stored",
    ),
    "engine_unreachable": (
        503, "the engine could not be reached, or did not answer in time: nothing was signed or stored; ask again "
        "after Retry-After",
    ),
    "engine_unavailable": (
        503, "the engine answered that it cannot sign now (503; signer_code is its code where it named one, "
        "signer_not_configured among them): nothing was signed or stored; ask again after Retry-After",
    ),
    "signer_unavailable": (
        503, "nothing here can ask the engine to sign: no recovery-receipt-signer key (ce_rr_...) or engine "
        "address is configured; nothing was sent or stored, and no other key is sent instead",
    ),
    "signer_refused": (
        502, "the engine refused to sign; signer_code is its code where it named one, signer_status its status; "
        "nothing was stored",
    ),
    "receipt_refused_by_signer": (
        502, "the engine's core read the receipt and refused it (400), by the rule signer_code names: the engine's "
        "code, carried as it sent it; nothing was stored",
    ),
    "envelope_unverified": (
        502, "what the engine returned does not verify under its published recovery-receipt keys (verdict and "
        "verdict_code say why): it is never stored",
    ),
    "envelope_not_over_receipt": (
        502, "what the engine returned verifies, but its receipt is not the document sent, byte for byte as the "
        "core canonicalises it, or not a v2 receipt: it is never stored",
    ),
    "receipt_raced": (
        409, "another receipt of this incident was stored while this one was issued; nothing of this one was "
        "stored: ask again",
    ),
}


class ReceiptRowRefused(ValueError):
    """A receipt row whose columns are not what its signed payload says, refused at
    save (``receipt_row_mismatch``)."""

    code = "receipt_row_mismatch"


@dataclass(frozen=True)
class Issued:
    """What :func:`issue` gives: the receipt (``row``) and whether this call stored it,
    or the code it was refused with, and what goes with that code."""

    row: object | None
    created: bool
    code: str | None = None
    detail: str = ""
    core_code: str | None = None
    signer_code: str | None = None
    signer_status: int | None = None
    verdict: str | None = None
    verdict_code: str | None = None
    keyring: object | None = None

    @property
    def status(self) -> int:
        if self.code is None:
            return 201 if self.created else 200
        return REFUSALS[self.code][0]


def _core():
    """``mythos_core.recovery_receipt``: read at first use, never with the URL conf."""
    from mythos_core import recovery_receipt

    return recovery_receipt


def _is_keyring(keyring) -> bool:
    """Whether ``keyring`` is a keyring the core verifies a recovery receipt against: the
    exposure receipt's ``ReceiptKeyring``, which ``recovery_receipt_keyring`` builds."""
    from mythos_core import exposure_receipt

    return type(keyring) is exposure_receipt.ReceiptKeyring


def _canonical(document) -> bytes:
    from mythos_core.outcome import canonical_bytes

    return canonical_bytes(document)


# ------------------------------------------------------------------- the engine


def engine_signer(document: dict) -> dict:
    """The engine signs ``document`` in the ``recovery-receipt`` role, asked with the
    recovery-receipt-signer key alone (never the operator key, never the exposure
    signer's). Raises what the client raises."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient.for_recovery_receipt_signing().sign_recovery_receipt(document)


def engine_keyring():
    """The ``ReceiptKeyring`` of the engine's published recovery-receipt keys
    (:func:`keyring_from_published` over ``GET /api/assurance/keyring``, which needs no
    key), read with the recovery-receipt signing client, so no other key is sent. A
    keyring read from the engine that signs establishes that the engine signed in the
    role, not more: an auditor verifies against one read out of band, as the engine's own
    caveat says."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return keyring_from_published(CyberEngineClient.for_recovery_receipt_signing().assurance_keyring())


def _published_keys(document) -> list[bytes]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), dict):
        raise ValueError("a published keyring is an object with a keys object")
    keys = []
    for key_id, entry in sorted(document["keys"].items()):
        if not isinstance(entry, dict) or entry.get("status") not in VERIFYING_STATUSES | {"revoked"}:
            raise ValueError(f"key {key_id!r} has no status the keyring publishes")
        if entry["status"] in VERIFYING_STATUSES:
            public = entry.get("public_key")
            if not isinstance(public, str):
                raise ValueError(f"key {key_id!r} has no base64 public_key text")
            try:
                keys.append(base64.b64decode(public, validate=True))
            except (binascii.Error, ValueError):
                raise ValueError(f"key {key_id!r}'s public_key is not base64") from None
    return keys


def keyring_from_published(published):
    """The keyring a recovery receipt is verified with, from the document the engine
    publishes: ``roles["recovery-receipt"]``'s active and retired keys are the receipt
    keys, and the artifact keys (``keys``) and every other role's are filed under their
    roles, so a receipt one of them signed is refused ``wrong_role``. A revoked key is
    left out. Raises ``ValueError`` (the core's ``RecoveryReceiptError`` among them) for
    a document without the role, or one it cannot read."""
    core = _core()
    if not isinstance(published, dict) or not isinstance(published.get("roles"), dict):
        raise ValueError("the published keyring has no roles")
    roles = published["roles"]
    if core.RECOVERY_RECEIPT_ROLE not in roles:
        raise ValueError(f"the published keyring has no {core.RECOVERY_RECEIPT_ROLE} role")
    others = {ARTIFACT_ROLE: _published_keys(published)}
    for role, document in sorted(roles.items()):
        if role != core.RECOVERY_RECEIPT_ROLE:
            others[role] = _published_keys(document)
    return core.recovery_receipt_keyring(_published_keys(roles[core.RECOVERY_RECEIPT_ROLE]), other_roles=others)


def _engine_failure(error) -> Issued | None:
    """What an engine call's failure answers, or None when ``error`` is not one."""
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError, RecoveryReceiptRefused

    if isinstance(error, EngineError):
        named = isinstance(error, RecoveryReceiptRefused)
        code = error.code if named else None
        if error.kind == ENGINE_UNREACHABLE or (error.status in _UNREACHED_STATUSES and not named):
            return Issued(None, False, "engine_unreachable", REFUSALS["engine_unreachable"][1],
                          signer_status=error.status)
        said = f"{error.code}: {error.reason}" if named else (
            f"the engine answered {error.kind}" + ("" if error.status is None else f" (status {error.status})")
        )
        if error.status == 503:
            return Issued(None, False, "engine_unavailable", said, signer_code=code, signer_status=503)
        if error.status == 400 and named:
            if error.code not in _core().REFUSALS:
                said = f"{said} (a code that is not one of the core's)"
            return Issued(None, False, "receipt_refused_by_signer", said, signer_code=code, signer_status=400)
        return Issued(None, False, "signer_refused", said, signer_code=code, signer_status=error.status)
    if isinstance(error, RuntimeError):
        # The client's own "not configured" (no receipt-signer key, no engine address):
        # nothing was sent. Never the operator key instead.
        return Issued(None, False, "signer_unavailable", REFUSALS["signer_unavailable"][1])
    return None


def _keyring():
    """``(keyring, None)``, or ``(None, Issued)`` saying why there is none."""
    try:
        keyring = engine_keyring()
    except ValueError as error:
        return None, Issued(None, False, "keyring_unavailable", f"{type(error).__name__}: {error}")
    except Exception as error:  # noqa: BLE001 - an engine failure is answered by its kind below; any other re-raised
        failed = _engine_failure(error)
        if failed is None:
            raise
        if failed.code == "signer_refused":
            failed = Issued(None, False, "keyring_unavailable", failed.detail, signer_status=failed.signer_status)
        return None, failed
    if not _is_keyring(keyring):
        return None, Issued(None, False, "keyring_unavailable", f"a {type(keyring).__name__}, not a ReceiptKeyring")
    return keyring, None


# ---------------------------------------------------------- what a receipt says


def _scope_of(step: dict, revisions: list) -> dict:
    """The scope a receipt of ``step`` is taken under, in ``build_receipt``'s words."""
    if not revisions or core_scope.NOT_DECLARED in step["scope_gaps"]:
        return {"scope_revision": None, "scope_ref": None, "scope_items": None, "scope_removed": None}
    current = revisions[-1]
    standing = incident_scope.since(revisions)
    gone = incident_scope.removed(revisions)
    by = {
        row.revision: incident_scope.served(row, current=current.revision)["declared_by_ref"] for row in revisions
    }
    readable = standing is not None and gone is not None
    return {
        "scope_revision": current.revision,
        "scope_ref": str(current.uuid),
        "scope_items": [
            {"kind": kind, "ref": ref, "since": since} for (kind, ref), since in standing.items()
        ] if readable else None,
        "scope_removed": [{**item, "removed_by": by[item["removed"]]} for item in gone] if readable else None,
    }


def _support_and_gaps(step: dict) -> tuple[list, list]:
    """The step's support entries a v2 receipt takes, and every gap with what would close
    it: the step's own (``gaps_named``), and one for each entry that names an engine and
    no key id, which vouches for nothing in v2 and is never issued as signed."""
    core = _core()
    support, gaps = [], {}
    for named in step["gaps_named"]:
        gaps[named["gap"]] = [{"kind": c["kind"], "voucher": c["voucher"]} for c in named["would_close"]]
    for entry in step["support"] or ():
        if core.ENGINE in entry and entry.get("key_id") is None:
            gap = f"{rr.SUPPORT}:{entry['condition']}:{entry['kind']}:{entry['ref']}"
            gaps.setdefault(gap, [{"kind": c["kind"], "voucher": c["voucher"]} for c in rr.would_close(gap)])
        else:
            support.append(dict(entry))
    return support, [{"gap": gap, "would_close": closers} for gap, closers in gaps.items()]


def _inputs(finding, row, step: dict, revisions: list, at) -> dict:
    """Every argument of the core's ``build_receipt`` but the receipt's own name and what
    it supersedes: what the record says at ``at``, from ``step`` (the last step as its
    read serves it) and ``row`` (that step as recorded)."""
    support, gaps = _support_and_gaps(step)
    acceptance = None
    if row.accepted_until is not None:
        acceptance = {
            "owner": step["accepted_by_ref"], "decided_at": rr.instant(row.recorded_at),
            "expires_at": rr.instant(row.accepted_until), "scope_revision": row.scope_revision,
        }
    deployment = str(finding.deployment.uuid)
    return {
        # The deployment is the tenant, as for the Financial Exposure Receipt.
        "tenant_id": deployment,
        "deployment": deployment,
        "incident": str(finding.uuid),
        "as_of": rr.instant(at),
        "record": step["ref"],
        "state": step["state"],
        "reopens": step["reopens"] or "",
        "restrictions": [one for one in step["restrictions"] if rr.is_name(one)],
        "held_back_from": step["held_back_from"],
        "support": support,
        "gaps": gaps,
        "acceptance": acceptance,
        **_scope_of(step, revisions),
    }


def _said(document: dict) -> dict:
    """What ``document`` says besides its name, instant and what it supersedes."""
    return {key: value for key, value in document.items() if key not in _IDENTITY}


def _why(latest: dict, candidate: dict, at) -> str:
    """The pointer to why ``candidate`` supersedes ``latest``: a later step, the scope's
    move, the latest's acceptance ended, or the same step read otherwise now."""
    if latest["record"] != candidate["record"]:
        return f"recovery-step:{candidate['record']}"
    if latest["scope"]["ref"] != candidate["scope"]["ref"] and candidate["scope"]["ref"] is not None:
        return f"scope-revision:{candidate['scope']['ref']}"
    acceptance = latest["acceptance"]
    if acceptance is not None and acceptance["expires_at"] is not None and acceptance["expires_at"] <= rr.instant(at):
        return f"acceptance-ended:{candidate['record']}"
    return f"recovery-record:{candidate['record']}"


# ----------------------------------------------------------------- the check


def _payload(envelope):
    """The document an envelope's payload decodes to, or None."""
    try:
        document = json.loads(base64.b64decode(envelope["payload"], validate=True).decode("utf-8"))
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, binascii.Error):
        return None
    return document if isinstance(document, dict) else None


def row_problem(row, document, finding) -> str | None:
    """Why ``row``'s columns are not what ``document`` (its signed receipt) says, for
    ``finding``, or None. Pure but for the core, read at first use."""
    core = _core()
    envelope = row.envelope
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        return "the envelope is not one of exactly payloadType, payload and signatures"
    if envelope["payloadType"] != core.RECEIPT_PAYLOAD_TYPE_V2:
        return "the envelope is not a v2 recovery receipt's"
    signatures = envelope["signatures"]
    if (
        not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], dict)
        or signatures[0].get("keyid") != row.key_id
    ):
        return "the key id is not the one signature's"
    if not isinstance(document, dict):
        return "the payload is not a receipt"
    try:
        core.validate_receipt(document)
    except core.RecoveryReceiptError as exc:
        return f"the payload is refused by the core ({exc.code})"
    if document["schema"] != core.RECEIPT_SCHEMA_V2:
        return "the payload is not a v2 receipt"
    deployment = str(finding.deployment.uuid)
    expected = {
        "receipt_ref": row.receipt_ref, "incident": str(finding.uuid), "deployment": deployment,
        "tenant_id": deployment, "record": row.record, "as_of": rr.instant(row.as_of),
        "supersedes": row.supersedes, "reason": row.reason,
    }
    wrong = sorted(field for field, value in expected.items() if document[field] != value)
    if wrong:
        return f"the row's {', '.join(wrong)} is not what the receipt says"
    if not _REF.fullmatch(str(row.receipt_ref)):
        return "the receipt's name is not recovery-receipt:<uuid4>"
    if not _PERSON.fullmatch(str(row.issued_by_ref)):
        return "issued_by_ref is not a person's reference"
    if not isinstance(row.sequence, int) or row.sequence < 1 or (row.sequence == 1) != (row.supersedes is None):
        return "the first receipt supersedes nothing and every later one supersedes the one before"
    return None


def check_row(row) -> None:
    """Refuse a row (at save) whose columns are not what its signed payload says
    (:class:`ReceiptRowRefused`). The signature itself is verified by :func:`issue`
    before the row is built; this holds the columns to it."""
    problem = row_problem(row, _payload(row.envelope), row.finding)
    if problem is not None:
        raise ReceiptRowRefused(f"receipt_row_mismatch: {problem}")


def envelope_problem(document: dict, envelope, keyring) -> Issued | None:
    """Why ``envelope`` is not to be stored as the receipt of ``document``, or None: it
    must verify under ``keyring`` in the ``recovery-receipt`` role, be v2, and carry
    exactly ``document``, byte for byte as the core canonicalises it."""
    core = _core()
    verdict = core.verify_receipt(envelope, keyring)
    if not verdict.authentic:
        return Issued(None, False, "envelope_unverified", verdict.reason, verdict=verdict.verdict,
                      verdict_code=verdict.code)
    if (
        envelope["payloadType"] != core.RECEIPT_PAYLOAD_TYPE_V2
        or verdict.receipt["schema"] != core.RECEIPT_SCHEMA_V2
        or _canonical(verdict.receipt) != _canonical(document)
    ):
        return Issued(None, False, "envelope_not_over_receipt", REFUSALS["envelope_not_over_receipt"][1],
                      verdict=verdict.verdict, verdict_code=verdict.code)
    return None


def _verified(row, keyring, finding):
    """``(verdict, problem)``: the core's verdict on ``row``'s envelope now, and why the
    row is not to be read as that receipt (None when it is). Never raises."""
    core = _core()
    if not _is_keyring(keyring):
        return None, "no keyring of the engine's published recovery-receipt keys to verify it with"
    verdict = core.verify_receipt(row.envelope, keyring)
    if not verdict.authentic:
        return verdict, f"{verdict.verdict} ({verdict.code})"
    return verdict, row_problem(row, verdict.receipt, finding)


# ------------------------------------------------------------------- the issue


def _latest(finding):
    from .models import RecoveryReceipt

    return RecoveryReceipt.objects.filter(finding=finding).order_by("-sequence").first()


def issue(finding, *, by, keyring=None, signer=None) -> Issued:
    """Issue ``finding``'s recovery receipt now, as its record reads now: built by the
    core, signed by the engine (``signer`` when given, as the tests give one), verified
    under ``keyring`` (the engine's published keys unless given), checked against the
    latest, and only then stored. The same latest when nothing moved. ``by`` is the
    signed-in person who asked. Raises only what a database read or write raises."""
    from .models import RecoveryReceipt, RecoveryRecord

    core = _core()
    at = timezone.now()
    steps = list(
        RecoveryRecord.objects.filter(finding=finding).select_related("finding", "accepted_by", "recorded_by")
        .order_by("version")
    )
    if not steps:
        return Issued(None, False, "no_recovery_record", REFUSALS["no_recovery_record"][1])
    revisions = incident_scope.revisions_of([finding.pk]).get(finding.pk, [])
    step = rr.served_steps(steps, revisions, at)[-1]
    latest = _latest(finding)
    inputs = _inputs(finding, steps[-1], step, revisions, at)
    ref = f"{REF_PREFIX}{uuid.uuid4()}"
    try:
        candidate = core.build_receipt(receipt_ref=ref, **inputs)
    except core.RecoveryReceiptError as exc:
        return Issued(None, False, "receipt_not_built", str(exc), core_code=exc.code)
    if candidate.get("schema") != core.RECEIPT_SCHEMA_V2:
        return Issued(None, False, "receipt_not_built", "the backend issues v2 alone", core_code=core.WRONG_SCHEMA)

    if keyring is None:
        keyring, failed = _keyring()
        if failed is not None:
            return failed
    elif not _is_keyring(keyring):
        return Issued(None, False, "keyring_unavailable", f"a {type(keyring).__name__}, not a ReceiptKeyring")

    if latest is not None:
        verdict, problem = _verified(latest, keyring, finding)
        if problem is not None:
            return Issued(None, False, "latest_receipt_unverified", f"{latest.receipt_ref}: {problem}",
                          keyring=keyring)
        if _said(verdict.receipt) == _said(candidate):
            # Nothing moved: the latest says exactly this. Nothing is signed or stored.
            return Issued(latest, False, keyring=keyring)
        reason = _why(verdict.receipt, candidate, at)
        try:
            candidate = core.build_receipt(receipt_ref=ref, supersedes=latest.receipt_ref, reason=reason, **inputs)
            core.check_supersedes(verdict.receipt, candidate)
        except core.RecoveryReceiptError as exc:
            return Issued(None, False, "supersession_refused", str(exc), core_code=exc.code, keyring=keyring)

    try:
        envelope = (signer or engine_signer)(candidate)
    except Exception as error:  # noqa: BLE001 - an engine failure is answered by its kind; any other re-raised
        failed = _engine_failure(error)
        if failed is None:
            raise
        return failed
    failed = envelope_problem(candidate, envelope, keyring)
    if failed is not None:
        return failed

    row = RecoveryReceipt(
        finding=finding,
        sequence=1 if latest is None else latest.sequence + 1,
        receipt_ref=candidate["receipt_ref"],
        record=candidate["record"],
        as_of=at,
        supersedes=candidate["supersedes"],
        reason=candidate["reason"],
        envelope=envelope,
        key_id=envelope["signatures"][0]["keyid"],
        issued_by_ref=rr.person_ref(by.pk),
    )
    try:
        with transaction.atomic():
            row.save()
    except IntegrityError:
        return Issued(None, False, "receipt_raced", REFUSALS["receipt_raced"][1], keyring=keyring)
    return Issued(row, True, keyring=keyring)


def refusal(outcome: Issued) -> dict:
    """The answer to a refused issue: its code, what the code means, and what goes with it."""
    body = {"code": outcome.code, "detail": outcome.detail or REFUSALS[outcome.code][1]}
    for name in ("core_code", "signer_code", "signer_status", "verdict", "verdict_code"):
        if getattr(outcome, name) is not None:
            body[name] = getattr(outcome, name)
    return body


# ------------------------------------------------------------------- the reads


def head_of(finding) -> dict:
    """What a reader asks a receipt's standing with: the incident's current scope
    revision (None when none is declared) and the latest receipt's name (None when none
    is issued). Two queries; no engine."""
    from .models import RecoveryReceipt

    revisions = incident_scope.revisions_of([finding.pk]).get(finding.pk, [])
    latest = RecoveryReceipt.objects.filter(finding=finding).order_by("-sequence").values_list(
        "receipt_ref", flat=True
    ).first()
    return {"current_scope_revision": incident_scope.current_of(revisions), "latest_receipt_ref": latest}


def served(row, finding, keyring, head: dict, at) -> dict:
    """One receipt as its reads serve it, verified now: ``standing`` is the core's word
    against ``head`` at the reader's instant ``at``, and ``unknown`` for one that does
    not verify, whose columns are not what it signed, or that cannot be checked."""
    core = _core()
    verdict, problem = _verified(row, keyring, finding)
    ok = problem is None
    return {
        "receipt_ref": row.receipt_ref,
        "sequence": row.sequence,
        "record": row.record,
        "as_of": rr.instant(row.as_of),
        "supersedes": row.supersedes,
        "reason": row.reason,
        "key_id": row.key_id,
        "issued_by_ref": row.issued_by_ref,
        "recorded_at": row.recorded_at.isoformat(),
        "verified": ok,
        "verification": {
            "verdict": verdict.verdict if verdict is not None else core.UNKNOWN,
            "code": verdict.code if verdict is not None else "keyring_unavailable",
            "problem": problem,
        },
        "standing": core.receipt_standing(
            verdict if ok else None, current_scope_revision=head["current_scope_revision"],
            latest_receipt_ref=head["latest_receipt_ref"], at=rr.instant(at),
        ),
        # The core's finding about what the receipt rests on (none in v2), or its
        # unknown finding for a receipt that cannot be read.
        "unvouched_support": [list(found) for found in core.unvouched_support(verdict if ok else None)],
        "receipt": verdict.receipt if ok else None,
        "envelope": row.envelope,
    }


def receipts_of(finding, *, keyring=None) -> dict:
    """Every receipt of ``finding``, oldest first, each verified again now against the
    engine's published keyring read now (``keyring`` when given), with the head and the
    reader's instant. With no receipt the engine is not asked. A keyring that cannot be
    read is said (``keyring``), and every receipt then reads ``unknown``."""
    from .models import RecoveryReceipt

    rows = list(RecoveryReceipt.objects.filter(finding=finding).order_by("sequence"))
    head = head_of(finding)
    at = timezone.now()
    held = None
    if rows and keyring is None:
        keyring, failed = _keyring()
        if failed is not None:
            held = {"available": False, "code": failed.code, "detail": failed.detail}
    if rows and held is None:
        held = {"available": True, "code": None, "detail": ""}
    return {
        "deployment": str(finding.deployment.uuid),
        "finding": str(finding.uuid),
        "as_of": rr.instant(at),
        "head": head,
        "keyring": held,
        "receipts": [served(row, finding, keyring, head, at) for row in rows],
    }


def issued(finding, outcome: Issued) -> dict:
    """The answer to an issue that gave a receipt: it, served as the reads serve it, and
    the head."""
    head = head_of(finding)
    return {
        "finding": str(finding.uuid),
        "issued": outcome.created,
        "head": head,
        "receipt": served(outcome.row, finding, outcome.keyring, head, timezone.now()),
    }
