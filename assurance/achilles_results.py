"""Achilles scan results, taken in as this backend's findings.

Owner freeze exception 22 (14 Oct 2026), second half: "Achilles results feeding
backend findings and the release decision", under the terms of item 6.

An Achilles scan reports, per scenario, a verdict -- ``pass``, ``fail`` or
``inconclusive`` -- with a severity. Until now none of it reached this backend: the
only Achilles evidence recorded here was a chain outcome (a permit check) and an
observed effect. This module turns a scan's results into :class:`Finding` rows, so
they count in the deployment's decision exactly as Athena's do: the same severity
rule, the same blocking rule, the same SPINE claims, unknowns and evidence, because
every one of those reads ``Finding`` and ``Evidence`` rows and this module writes
nothing else they read.

THE SIGNATURE. A result is taken only as ``{"envelope": ..., "result": ...}``: a
``mythos_core.outcome`` DSSE envelope (``mythos.chain-outcome/v1``, the platform's one
signature format) signed with Achilles' SCAN-RESULT key, a key that signs nothing
else, under the observer name :data:`SIGNER` -- as the observed-effect key is
``achilles-effect``. The keyring (``ASSURANCE_OUTCOME_KEYRING``) files that key under
:data:`SIGNER` and refuses one key filed under two engines, so neither Achilles'
outcome key nor its observed-effect key can sign a scan result, and this key cannot
sign either of theirs. The envelope names, as its evidence digest, the
:data:`DOCUMENT_SCHEMA` document posted beside it (:func:`validate_document`):

- ``deployment``: this backend's deployment uuid -- the tenant boundary here, the
  deployment IS the tenant -- the outcome's own, repeated;
- ``scan_id``, ``release``: the Achilles scan (job) id and release, the outcome's
  ``observer.run_id`` and ``observer.version``;
- ``observed_at``: the outcome's own instant;
- ``status``: ``completed`` (the outcome is signed ``held``), or ``aborted`` /
  ``failed`` (signed ``incomplete``, with its reason);
- ``evidence_pack``: ``{"pack_head", "anchored"}``, the head of Achilles' hash-chained
  evidence pack over every scenario's verdict (``achilles/evidence.py``);
- ``results``: per scenario, exactly ``scenario_id``, ``capability`` (the catalogue
  slug), ``verdict``, ``severity``, ``evidence_tier``, ``confidence``, ``title``,
  ``implication`` and ``recommendation``. Not the transcript and not Achilles'
  ``observed`` text or violation quotes, which carry excerpts of the target's replies:
  nothing here needs them (FREEZE.md: no collecting raw prompts or customer documents
  without a specific purpose).

The envelope's ``workflow`` is :data:`WORKFLOW`. Achilles does not sign this today;
until its signer ships, no key is filed under :data:`SIGNER` and every post is
refused, and recorded.

WHAT IS REFUSED, every refusal recorded with why (:class:`AchillesScanRefusal`),
outside the write it refused: ``unsigned`` (no envelope, no signature, a key this
deployment does not trust); ``tampered`` (a signature that does not verify, a document
that is not the one the signature names); ``wrong_signer`` (signed by any key but the
scan-result key); ``wrong_tenant`` (signed for another deployment, or a document that
names another); ``replayed`` (an outcome or a scan already recorded, a result older
than the newest one recorded here, or older than the window a signed outcome is
accepted in); ``malformed``; ``keyring_unavailable``. The chain-outcome route refuses a
scan-result envelope in turn (:mod:`assurance.observed_outcomes`).

WHAT A RESULT BECOMES. Only a result whose capability Achilles has been SCREENED for
grades anything (the terms of item 6, carried by items 11 to 22: a Minotaur answer
key, a benign look-alike that must read PASS, a Validity Card and the benchmark screen
before its score grades anything). :data:`SCREENED` is the reviewed record of that, and
it is EMPTY: no Validity Card exists for any Achilles capability yet. A result of an
unscreened capability -- no entry, a screen not passed, a release the screen did not
measure -- is recorded on the result row as INFORMATIONAL, with why, and makes no
finding: an informational finding row would still grade (any finding lifts a
deployment nothing has assessed to READY). A screened result:

- ``fail`` -> a finding at the result's severity, its evidence ``partially_verified``,
  as Athena's ingest grades a non-info hit: the engine saw a violation, nothing
  confirmed an exploit;
- ``inconclusive`` -> an info finding whose evidence is ``unknown``, which the decision
  reads as needs-more-evidence: a boundary nobody could test is a gap, never a pass;
- ``pass`` -> no finding, as a clean check makes none for Athena. A pass closes nothing:
  closure is effect-backed only.

A failure and an inconclusive run of one scenario are two findings, so a later run
that could not test the boundary never lowers a failure it found before. Each finding
carries its provenance (engine, release, scan id, outcome id, evidence digest, the
evidence pack's head and the signing key) on ``Finding.raw`` and on its
``Evidence(source="achilles_scan")`` row. The severity, the retest flag and the
re-ingest refresh (engine-owned fields refreshed, a person's status and owner never
touched) are Athena's ingest's.

An Achilles result only ever holds a decision back. Nothing here records a scan as
an assessment that lifts a deployment (``last_complete_scan_at``): a benign result
leaves the decision where it was.

SAFETY. This is evidence, and it stops nothing (``safety.stops.NOT_STOPS``). Nothing
on a stop, pause, stand-down or revoke path imports it. The signature, the document
and the screen are checked before any transaction opens (:func:`examine`, which
reads and writes no row); the transaction holds only the replay reads, the rows and
the decision's refresh, as on the signed-outcome route.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone as dt_timezone
from types import MappingProxyType
from typing import Any

from django.db import DatabaseError, IntegrityError, transaction
from mythos_core import outcome as oc

from . import observed_outcomes
from .ingest import _fingerprint
from .models import (
    SEVERITY_INFO,
    SEVERITY_ORDER,
    AchillesScanRefusal,
    AchillesScanResult,
    Evidence,
    EvidenceClass,
    Finding,
    severity_rank,
)

logger = logging.getLogger(__name__)

#: The observer name Achilles' scan-result key is filed under in the keyring.
SIGNER = "achilles-scan"
#: The ``workflow`` a scan-result outcome carries: a scan is no workflow's chain.
WORKFLOW = "achilles-scan"
#: The engine a finding names as its source.
ENGINE = "achilles"
#: The ``Evidence.source`` of a finding's Achilles evidence row.
EVIDENCE_SOURCE = "achilles_scan"
DOCUMENT_SCHEMA = "mythos.achilles-scan-result/v1"

BODY_FIELDS = frozenset({"envelope", "result"})
DOCUMENT_FIELDS = frozenset(
    {"schema", "deployment", "scan_id", "release", "observed_at", "status", "evidence_pack", "results"}
)
PACK_FIELDS = frozenset({"pack_head", "anchored"})
RESULT_FIELDS = frozenset(
    {
        "scenario_id",
        "capability",
        "verdict",
        "severity",
        "evidence_tier",
        "confidence",
        "title",
        "implication",
        "recommendation",
    }
)

PASS = "pass"
FAIL = "fail"
INCONCLUSIVE = "inconclusive"
VERDICTS = (PASS, FAIL, INCONCLUSIVE)
#: The tiers Achilles can establish (``achilles/assurance.py::ESTABLISHABLE_TIERS``).
#: ``verified_unauthorized_effect`` is not one: Achilles refuses to assign it.
TIERS = frozenset({"judgment_compromise", "authority_violation"})
#: The scan statuses each signed status stands for.
SCAN_STATUSES = {oc.HELD: frozenset({"completed"}), oc.INCOMPLETE: frozenset({"aborted", "failed"})}

#: The most results one document may carry. Achilles' catalogue is a few dozen
#: scenarios; the bound keeps the write the transaction holds small.
MAX_RESULTS = 100
MAX_TITLE = 200
MAX_TEXT = 1000
#: One envelope (bounded by mythos_core) and its document.
MAX_BODY_BYTES = 512 * 1024

#: A result's disposition, as the result row records it.
DISPOSITION_FINDING = "finding"
DISPOSITION_NO_FINDING = "no_finding"
DISPOSITION_INFORMATIONAL = "informational"

_TOKEN = re.compile(r"^[-a-zA-Z0-9_.:+]{1,200}$")
_SLUG = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

Code = AchillesScanRefusal.Code


# ------------------------------------------------------------------ the screen


@dataclass(frozen=True)
class Screen:
    """What lets one Achilles capability's results grade: the terms of item 6.

    ``validity_card`` and ``answer_key`` are ``sha256:`` digests of the capability's
    Validity Card and its Minotaur answer key; ``passed`` is the benchmark screen's
    verdict, its benign look-alikes reading PASS included; ``releases`` are the
    Achilles releases the screen measured. A detector change moves verdicts (Achilles
    #102 moved 384 scenario rows), so a screen holds for the releases it measured and
    no other."""

    validity_card: str
    answer_key: str
    passed: bool
    releases: frozenset[str]


#: The capabilities Achilles has been screened for, by catalogue slug
#: (``achilles.scenarios.CAPABILITY_SUITES``). Reviewed code, not configuration: no
#: request, row or environment variable can make an unscreened capability grade.
#: EMPTY: no Validity Card exists for any Achilles capability yet (owner freeze
#: exception 22; the cards and answer keys for this path are a follow-up).
SCREENED: Mapping[str, Screen] = MappingProxyType({})


def screen_problem(capability: str, release: str) -> str:
    """Why ``capability``'s results from ``release`` may not grade, or ``""``.
    Read from :data:`SCREENED` at every call."""
    entry = SCREENED.get(capability)
    if entry is None:
        return (
            f"capability {capability!r} has no Validity Card on record: Achilles has not been "
            "screened for it, so its results are informational and grade nothing"
        )
    if (
        not isinstance(entry, Screen)
        or not isinstance(entry.validity_card, str)
        or not _DIGEST.match(entry.validity_card)
        or not isinstance(entry.answer_key, str)
        or not _DIGEST.match(entry.answer_key)
        or not isinstance(entry.releases, frozenset)
    ):
        return (
            f"capability {capability!r}'s screen record does not name a Validity Card and an answer "
            "key by digest and the releases it measured, so it screens nothing"
        )
    if entry.passed is not True:
        return f"capability {capability!r} is below the benchmark screen, so its results grade nothing"
    if release not in entry.releases:
        return (
            f"capability {capability!r} was screened on releases {sorted(entry.releases)}, not on "
            f"{release!r}, so this release's results grade nothing"
        )
    return ""


# ---------------------------------------------------------------- the document


class DocumentRefused(ValueError):
    """A document that is not a :data:`DOCUMENT_SCHEMA` scan-result document."""


def _token(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _TOKEN.match(value):
        raise DocumentRefused(f"{name} is a token of letters, digits and -_.:+")
    return value


def _text(value: Any, name: str, *, limit: int, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise DocumentRefused(f"{name} is text, not {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not value or value != value.strip():
        raise DocumentRefused(f"{name} is non-empty text with no surrounding whitespace")
    if len(value) > limit:
        raise DocumentRefused(f"{name} is at most {limit} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise DocumentRefused(f"{name} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DocumentRefused(f"{name} is not encodable as UTF-8") from exc
    return value


def _validate_result(result: Any, where: str) -> None:
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        raise DocumentRefused(f"{where} has exactly the fields {sorted(RESULT_FIELDS)}")
    _token(result["scenario_id"], f"{where}.scenario_id")
    if not isinstance(result["capability"], str) or not _SLUG.match(result["capability"]):
        raise DocumentRefused(f"{where}.capability is a catalogue slug (lowercase letters, digits, _)")
    verdict = result["verdict"]
    if verdict not in VERDICTS:
        raise DocumentRefused(f"{where}.verdict is one of {list(VERDICTS)}")
    severity = result["severity"]
    if severity not in SEVERITY_ORDER:
        raise DocumentRefused(f"{where}.severity is one of {list(SEVERITY_ORDER)}")
    if verdict == FAIL and severity == SEVERITY_INFO:
        raise DocumentRefused(f"{where} is a failure with no severity: a fail is low, medium, high or critical")
    if verdict != FAIL and severity != SEVERITY_INFO:
        raise DocumentRefused(f"{where} is a {verdict} with a severity: only a fail carries one")
    tier = result["evidence_tier"]
    if tier is not None and tier not in TIERS:
        raise DocumentRefused(f"{where}.evidence_tier is null or one of {sorted(TIERS)}")
    if tier is not None and verdict != FAIL:
        raise DocumentRefused(f"{where} is a {verdict} with an evidence tier: only a fail establishes one")
    confidence = result["confidence"]
    if confidence is not None and (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
        or not 0 <= confidence <= 1
    ):
        raise DocumentRefused(f"{where}.confidence is null or a number from 0 to 1")
    _text(result["title"], f"{where}.title", limit=MAX_TITLE, allow_empty=False)
    _text(result["implication"], f"{where}.implication", limit=MAX_TEXT, allow_empty=True)
    _text(result["recommendation"], f"{where}.recommendation", limit=MAX_TEXT, allow_empty=True)


def validate_document(document: Any) -> dict[str, Any]:
    """``document`` if it is a :data:`DOCUMENT_SCHEMA` document, else
    :class:`DocumentRefused` naming the first thing wrong. Exactly the fields, no
    more, at every level."""
    if not isinstance(document, dict):
        raise DocumentRefused("the result is an object")
    if set(document) != DOCUMENT_FIELDS:
        raise DocumentRefused(
            f"a {DOCUMENT_SCHEMA} document has exactly the fields {sorted(DOCUMENT_FIELDS)}; missing "
            f"{sorted(DOCUMENT_FIELDS - set(document))}, unexpected "
            f"{sorted(str(k) for k in set(document) - DOCUMENT_FIELDS)}"
        )
    if document["schema"] != DOCUMENT_SCHEMA:
        raise DocumentRefused(f"schema is {DOCUMENT_SCHEMA!r}")
    _token(document["deployment"], "deployment")
    _token(document["scan_id"], "scan_id")
    _token(document["release"], "release")
    if not isinstance(document["observed_at"], str) or not _INSTANT.match(document["observed_at"]):
        raise DocumentRefused("observed_at is YYYY-MM-DDTHH:MM:SS.ffffffZ")
    if document["status"] not in {"completed", "aborted", "failed"}:
        raise DocumentRefused("status is completed, aborted or failed")
    pack = document["evidence_pack"]
    if not isinstance(pack, dict) or set(pack) != PACK_FIELDS:
        raise DocumentRefused(f"evidence_pack has exactly the fields {sorted(PACK_FIELDS)}")
    _token(pack["pack_head"], "evidence_pack.pack_head")
    if not isinstance(pack["anchored"], bool):
        raise DocumentRefused("evidence_pack.anchored is true or false")
    results = document["results"]
    if not isinstance(results, list) or len(results) > MAX_RESULTS:
        raise DocumentRefused(f"results is a list of at most {MAX_RESULTS}")
    seen: set[str] = set()
    for index, result in enumerate(results):
        _validate_result(result, f"results[{index}]")
        if result["scenario_id"] in seen:
            raise DocumentRefused(f"results[{index}] repeats scenario {result['scenario_id']!r}")
        seen.add(result["scenario_id"])
    return document


# ------------------------------------------------------------------ examining


@dataclass(frozen=True)
class Refusal:
    """Why a result was refused, with what may be kept of it: its outcome and scan
    ids only when its signature verified."""

    code: str
    reason: str
    key_id: str = ""
    outcome_id: str = ""
    scan_id: str = ""


@dataclass(frozen=True)
class Examined:
    """A result whose signature, binding and document all hold, graded per result."""

    outcome: dict
    key_id: str
    envelope: dict
    document: dict
    grading: tuple


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt_timezone.utc)


def _claimed_key_id(envelope: Any) -> str:
    """The key id an envelope names, as claimed, for the refusal record."""
    try:
        key_id = envelope["signatures"][0]["keyid"]
    except (KeyError, IndexError, TypeError):
        return ""
    return key_id[:80] if isinstance(key_id, str) else ""


def grade(result: dict, release: str) -> dict:
    """What one screened-or-not result becomes: its disposition, and why."""
    row = {
        "scenario_id": result["scenario_id"],
        "capability": result["capability"],
        "verdict": result["verdict"],
        "severity": result["severity"],
        "disposition": DISPOSITION_FINDING,
        "finding": None,
        "why": "",
    }
    unscreened = screen_problem(result["capability"], release)
    if unscreened:
        row.update(disposition=DISPOSITION_INFORMATIONAL, why=unscreened)
    elif result["verdict"] == PASS:
        row.update(
            disposition=DISPOSITION_NO_FINDING,
            why="a pass records no finding, as a clean check makes none, and closes none",
        )
    elif result["verdict"] == FAIL:
        row["why"] = f"a {result['severity']} failure: a finding at that severity"
    else:
        row["why"] = "inconclusive: the boundary was not tested, a finding whose evidence is unknown"
    return row


def examine(deployment, body: Any, *, keyring, now: datetime) -> Examined | Refusal:
    """Check everything about ``body`` that needs no row: the envelope's signature
    and signer, the deployment it names, its instant, and the document its digest
    names. Reads and writes nothing in the database."""
    if not isinstance(body, dict):
        return Refusal(Code.MALFORMED, "the body is an object with envelope and result")
    envelope = body.get("envelope")
    if envelope is None or envelope == {} or envelope == "":
        return Refusal(Code.UNSIGNED, "the result arrives with no envelope: nothing signed it")
    unknown = sorted(str(k) for k in set(body) - BODY_FIELDS)
    if unknown or "result" not in body:
        return Refusal(
            Code.MALFORMED,
            f"the body has exactly the fields {sorted(BODY_FIELDS)}"
            + (f"; unexpected {unknown}" if unknown else "; result is missing"),
        )
    claimed = _claimed_key_id(envelope)
    if isinstance(envelope, dict) and not envelope.get("signatures"):
        return Refusal(Code.UNSIGNED, "the envelope carries no signature", key_id=claimed)

    verdict = oc.verify_outcome(envelope, keyring)
    key_id = (verdict.key_id or claimed)[:80]
    if verdict.verdict in (oc.UNKNOWN_KEY, oc.WRONG_TYPE):
        return Refusal(Code.UNSIGNED, f"{verdict.verdict}: {verdict.reason}", key_id=key_id)
    if verdict.verdict == oc.FORGED:
        return Refusal(Code.TAMPERED, f"{verdict.verdict}: {verdict.reason}", key_id=key_id)
    if verdict.verdict == oc.WRONG_OBSERVER:
        return Refusal(Code.WRONG_SIGNER, f"{verdict.verdict}: {verdict.reason}", key_id=key_id)
    if verdict.verdict != oc.AUTHENTIC or verdict.outcome is None:
        return Refusal(Code.MALFORMED, f"{verdict.verdict}: {verdict.reason}", key_id=key_id)

    outcome = verdict.outcome
    ids = {"key_id": key_id, "outcome_id": outcome["outcome_id"], "scan_id": outcome["observer"]["run_id"][:200]}
    engine = outcome["observer"]["engine"]
    if engine != SIGNER:
        return Refusal(
            Code.WRONG_SIGNER,
            f"the result is signed by {engine!r}'s key; only Achilles' scan-result key ({SIGNER!r}), a key "
            "that signs nothing else, signs a scan result",
            **ids,
        )
    if outcome["deployment"] != str(deployment.uuid):
        return Refusal(
            Code.WRONG_TENANT,
            f"the result is signed for deployment {outcome['deployment']!r}, not this one ({deployment.uuid}); "
            "a signature proves who observed it, not where",
            **ids,
        )
    if outcome["workflow"] != WORKFLOW:
        return Refusal(Code.MALFORMED, f"a scan result's outcome names workflow {WORKFLOW!r}", **ids)
    if outcome["status"] not in SCAN_STATUSES:
        return Refusal(
            Code.MALFORMED,
            f"a scan result is signed {oc.HELD!r} (it completed) or {oc.INCOMPLETE!r} (it stopped); "
            f"this one is {outcome['status']!r}",
            **ids,
        )
    observed = _instant(outcome["observed_at"])
    if observed > now + observed_outcomes.MAX_CLOCK_SKEW:
        return Refusal(Code.MALFORMED, f"observed_at {outcome['observed_at']} is in the future", **ids)
    if observed < now - observed_outcomes.MAX_AGE:
        return Refusal(
            Code.REPLAYED,
            f"observed_at {outcome['observed_at']} is older than the {observed_outcomes.MAX_AGE.days}-day window "
            "a signed result is accepted in; a backfill of a signed result is what a replay looks like",
            **ids,
        )

    document = body["result"]
    if not isinstance(document, dict):
        return Refusal(Code.MALFORMED, "the result is an object", **ids)
    try:
        digest = oc.evidence_digest_of(document)
    except (TypeError, ValueError, RecursionError):
        return Refusal(Code.MALFORMED, "the result cannot be serialised to the bytes a digest is taken over", **ids)
    if digest != outcome["evidence_digest"]:
        return Refusal(
            Code.TAMPERED,
            f"the result is not the document the signature names: its digest is {digest}, the outcome signs "
            f"{outcome['evidence_digest']}",
            **ids,
        )
    try:
        validate_document(document)
    except DocumentRefused as exc:
        return Refusal(Code.MALFORMED, f"the result is not a {DOCUMENT_SCHEMA} document: {exc}", **ids)
    if document["deployment"] != outcome["deployment"]:
        return Refusal(
            Code.WRONG_TENANT,
            f"the result names deployment {document['deployment']!r}; the outcome signs {outcome['deployment']!r}",
            **ids,
        )
    for name, signed in (
        ("scan_id", outcome["observer"]["run_id"]),
        ("release", outcome["observer"]["version"]),
        ("observed_at", outcome["observed_at"]),
    ):
        if document[name] != signed:
            return Refusal(Code.MALFORMED, f"the result's {name} is {document[name]!r}; the outcome signs {signed!r}", **ids)
    if document["status"] not in SCAN_STATUSES[outcome["status"]]:
        return Refusal(
            Code.MALFORMED,
            f"the result's status is {document['status']!r}; the outcome is signed {outcome['status']!r}",
            **ids,
        )
    grading = tuple(grade(result, document["release"]) for result in document["results"])
    return Examined(outcome=outcome, key_id=key_id, envelope=envelope, document=document, grading=grading)


# ------------------------------------------------------------------ recording


class RecordRaced(Exception):
    """Another post recorded this outcome or scan between the replay check and the
    write. Raised so the whole write rolls back; carries the refusal to record."""

    def __init__(self, refusal: Refusal):
        self.refusal = refusal
        super().__init__(refusal.reason)


def _provenance(examined: Examined) -> dict:
    outcome = examined.outcome
    return {
        "engine": ENGINE,
        "release": outcome["observer"]["version"],
        "scan_id": outcome["observer"]["run_id"],
        "outcome_id": outcome["outcome_id"],
        "evidence_digest": outcome["evidence_digest"],
        "pack_head": examined.document["evidence_pack"]["pack_head"],
        "signer": SIGNER,
        "signer_key_id": examined.key_id,
        "observed_at": outcome["observed_at"],
    }


def _content_hash(result: dict) -> str:
    return hashlib.sha256(oc.canonical_bytes(result)).hexdigest()


def _record_finding(deployment, result: dict, provenance: dict, now) -> Finding:
    """The finding one screened failure or inconclusive result makes or refreshes,
    and its evidence row: Athena's ingest's rules (assurance.ingest)."""
    failed = result["verdict"] == FAIL
    group = FAIL if failed else INCONCLUSIVE
    fingerprint = _fingerprint(deployment, f"achilles:{group}:{result['scenario_id'].lower()}")
    severity = result["severity"] if failed else SEVERITY_INFO
    engine_fields = {
        "finding_type": f"achilles.{result['capability']}"[:128],
        "title": result["title"][:512],
        "severity": severity,
        "confidence": None if result["confidence"] is None else float(result["confidence"]),
        "cvss_score": None,
        "cvss_vector": "",
        "impact": result["implication"],
        "recommendation": result["recommendation"],
        "control_mapping": {},
        "location": f"achilles:{result['scenario_id']}"[:1024],
        "retest_required": severity_rank(severity) >= severity_rank("medium"),
        "raw": {
            **provenance,
            "scenario_id": result["scenario_id"],
            "capability": result["capability"],
            "verdict": result["verdict"],
            "severity": result["severity"],
            "evidence_tier": result["evidence_tier"],
        },
        "last_seen": now,
    }
    finding, created = Finding.objects.get_or_create(
        deployment=deployment,
        fingerprint=fingerprint,
        defaults={**engine_fields, "first_seen": now},
    )
    if not created:
        # The engine's current truth; never a person's status or owner.
        for key, value in engine_fields.items():
            setattr(finding, key, value)
        finding.save(update_fields=[*engine_fields.keys()])
    Evidence.objects.update_or_create(
        finding=finding,
        source=EVIDENCE_SOURCE,
        defaults={
            "classification": EvidenceClass.PARTIALLY_VERIFIED if failed else EvidenceClass.UNKNOWN,
            "summary": (
                f"Observed by Achilles scan {provenance['scan_id']} (release {provenance['release']}), "
                f"signed result {provenance['evidence_digest']}."
            ),
            "content_hash": _content_hash(result),
            "raw": provenance,
        },
    )
    return finding


def record(deployment, examined: Examined, *, now) -> tuple[AchillesScanResult, list[Finding]] | Refusal:
    """Record ``examined`` for ``deployment``: its findings, the Unknowns Register
    brought current, and the result row. Call INSIDE the transaction that refreshes
    the decision. A replay is returned as a :class:`Refusal` before anything is
    written; a replay that races past the check raises :class:`RecordRaced`."""
    outcome = examined.outcome
    ids = {
        "key_id": examined.key_id,
        "outcome_id": outcome["outcome_id"],
        "scan_id": outcome["observer"]["run_id"][:200],
    }
    if AchillesScanResult.objects.filter(outcome_id=outcome["outcome_id"]).exists():
        return Refusal(Code.REPLAYED, f"outcome {outcome['outcome_id']} was already recorded", **ids)
    scan_id = outcome["observer"]["run_id"]
    if AchillesScanResult.objects.filter(deployment=deployment, scan_id=scan_id).exists():
        return Refusal(Code.REPLAYED, f"scan {scan_id!r} was already recorded for this deployment", **ids)
    observed = _instant(outcome["observed_at"])
    newest = (
        AchillesScanResult.objects.filter(deployment=deployment)
        .order_by("-observed_at")
        .values_list("observed_at", flat=True)
        .first()
    )
    if newest is not None and observed < newest:
        return Refusal(
            Code.REPLAYED,
            f"observed_at {outcome['observed_at']} is older than the newest Achilles result already recorded "
            f"here ({newest.isoformat()}): a stale result would put back what a newer scan reported",
            **ids,
        )

    provenance = _provenance(examined)
    grading: list[dict] = []
    findings: list[Finding] = []
    for result, graded in zip(examined.document["results"], examined.grading, strict=True):
        row = dict(graded)
        if graded["disposition"] == DISPOSITION_FINDING:
            finding = _record_finding(deployment, result, provenance, now)
            row["finding"] = str(finding.uuid)
            findings.append(finding)
        grading.append(row)
    if findings:
        # The register of what this deployment cannot answer, brought current with the
        # findings, as Athena's ingest brings it.
        from .unknowns import derive_unknowns

        derive_unknowns(deployment)
    try:
        # A savepoint of its own: the unique columns are the backstop for two posts
        # racing past the checks above, and the race lost is a refusal like any replay.
        with transaction.atomic():
            saved = AchillesScanResult.objects.create(
                deployment=deployment,
                outcome_id=outcome["outcome_id"],
                scan_id=scan_id,
                release=outcome["observer"]["version"],
                observer_engine=outcome["observer"]["engine"],
                observer_key_id=examined.key_id,
                evidence_digest=outcome["evidence_digest"],
                scan_status=examined.document["status"],
                observed_at=observed,
                envelope=examined.envelope,
                document=examined.document,
                grading=grading,
            )
    except IntegrityError:
        raise RecordRaced(
            Refusal(
                Code.REPLAYED,
                "the record already holds this outcome or this scan: another post recorded it first",
                **ids,
            )
        ) from None
    return saved, findings


def _envelope_digest(body: Any) -> str:
    envelope = body.get("envelope") if isinstance(body, dict) else None
    if envelope is None:
        return ""
    try:
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        return ""
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def record_refusal(deployment, body: Any, refusal: Refusal) -> bool:
    """Record ``refusal`` for ``deployment``, in its own short write. True if it was
    recorded. A failed write of the record never turns the refusal into anything else."""
    try:
        with transaction.atomic():
            AchillesScanRefusal.objects.create(
                deployment=deployment,
                code=refusal.code,
                reason=refusal.reason[:2000],
                envelope_digest=_envelope_digest(body),
                key_id=refusal.key_id[:80],
                outcome_id=refusal.outcome_id[:32],
                scan_id=refusal.scan_id[:200],
            )
    except DatabaseError:
        logger.exception("the refusal of an Achilles scan result for deployment %s was not recorded", deployment.pk)
        return False
    return True


def listing(deployment, *, page_size: int) -> dict:
    """What this deployment took in and refused, newest first, a page of each."""
    recorded = deployment.achilles_scan_results.all()
    refused = deployment.achilles_scan_refusals.all()
    recorded_count = recorded.count()
    refused_count = refused.count()
    results = list(recorded[:page_size])
    refusals = list(refused[:page_size])
    return {
        "results": [
            {
                "outcome_id": row.outcome_id,
                "scan_id": row.scan_id,
                "release": row.release,
                "scan_status": row.scan_status,
                "observed_at": row.observed_at.isoformat(),
                "recorded_at": row.recorded_at.isoformat(),
                "evidence_digest": row.evidence_digest,
                "signer_key_id": row.observer_key_id,
                "grading": row.grading,
            }
            for row in results
        ],
        "recorded_count": recorded_count,
        "refusals": [
            {
                "received_at": row.received_at.isoformat(),
                "code": row.code,
                "reason": row.reason,
                "key_id": row.key_id,
                "outcome_id": row.outcome_id,
                "scan_id": row.scan_id,
                "envelope_digest": row.envelope_digest,
            }
            for row in refusals
        ],
        "refused_count": refused_count,
        "returned": {"results": len(results), "refusals": len(refusals)},
        "truncated": len(results) < recorded_count or len(refusals) < refused_count,
        "page_size": page_size,
        "screened": sorted(SCREENED),
    }


__all__ = [
    "DOCUMENT_SCHEMA",
    "MAX_BODY_BYTES",
    "SCREENED",
    "SIGNER",
    "WORKFLOW",
    "DocumentRefused",
    "Examined",
    "RecordRaced",
    "Refusal",
    "Screen",
    "examine",
    "grade",
    "listing",
    "record",
    "record_refusal",
    "screen_problem",
    "validate_document",
]
