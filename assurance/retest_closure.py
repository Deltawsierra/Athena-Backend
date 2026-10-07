"""A retest-gated closure is recorded only against an incomplete repair that still fails.

FREEZE.md: "No closing remediation because a ticket status changed -- closure is
effect-backed only." A finding that carries ``retest_required`` ("a failure must
be proven fixed") could be moved to ``status=closed`` or
``remediation_state=resolved`` by a PATCH, the admin or the remediation workflow
with nothing behind it but the click. This module is the one gate every such move
goes through (:meth:`assurance.models.Finding.save` calls :func:`enforce`), and it
reads the effect, not the ticket: the latest :class:`RetestClosureEvidence`.

A retest is a check, and a check is believed only once it has been seen to tell
the cases apart. So a record names FOUR fixture classes:

- ``vulnerable``  -- the original defect. The check must FAIL on it (or it cannot
  see the defect at all, and a pass elsewhere means nothing).
- ``repaired``    -- the fix. The check must PASS.
- ``benign``      -- a case that never had the defect. The check must PASS.
- ``incomplete_repair`` -- a fixture engineered to LOOK repaired while leaving the
  forbidden effect reachable. The check must still FAIL on every one of the six
  named patterns, each its own fixture:

  ``restored_reachability``     the path reopens some other way;
  ``changed_defaults``          the fix works but flips a default users depend on;
  ``lost_compensating_control`` a workaround the patch removes without replacing;
  ``displaced_effects``         the behaviour moves to an adjacent code path;
  ``restored_persistence``      state that should have been purged survives;
  ``operational_breakage``      the fix is correct but breaks something unrelated.

An incomplete-repair fixture that PASSED is the gate being fooled: the check
accepts a cosmetic error-message change, a disabled logger or a partial endpoint
check as a repair, so its pass on the real fix proves nothing either.

Refused, with every reason named: no record; a record from an origin other than an
independent observer (the only origin that carries weight, as for claim evidence);
a record naming no artifact digest; a record older than the finding's last
observation (the scan saw the defect after the retest ran); and any fixture class
or pattern missing, not run, unreadable, or with the wrong outcome. A refused move
leaves the finding where it was. A move to ACCEPTED, FALSE_POSITIVE or INVALIDATED
is not a closure and never comes here; nor does a finding without
``retest_required``. A later close of an INVALIDATED finding is one, and does: so
an INVALIDATED finding is served what its closure would stand on, while an accepted
or false-positive one is served ``not_a_closure`` (:func:`closure_standing`).

A record may also carry the replay it came from (``document``: Minotaur-Backend's
remediation replay row, recorded by the engine service through
``POST /api/assurance/findings/<uuid>/closure-evidence/``, :mod:`assurance.closure_evidence`).
Such a record is held to its replay as well (:func:`replay_reasons`): a replay that
did not reach the target, could not tell whether the effect is gone on the original
scenario or on every variant it replayed, or whether legitimate use survives, that
replayed no variant at all, or that found the effect still produced or the use
broken, carries no closure -- it is kept, and its result (:func:`classify`) is
``inconclusive``, ``cosmetic``, ``partial`` or ``utility_breaking``. Every condition
above still applies to it unchanged.

THE REPAIR CONTRACT (Roadmap Phase 6: a repair contract before any candidate patch;
:mod:`assurance.repair_contract`). A repair is agreed before it is worked on -- the
prohibited effect it must eliminate and the legitimate behaviours it must preserve
-- and a closure is held to that agreement. On top of every condition above, a
retest-gated closure is refused (:func:`refusal_reasons`) unless the latest record's
replay document carries a ``contract`` block,
``{"digest": "sha256:<hex>", "preserved": {"<behaviour>": "retained"|"broken"|"unknown"}}``,
that

- names the digest of the finding's CURRENT contract (a contract superseded after
  the replay leaves that replay unable to close: it was held to the old terms), and
- reads ``retained`` for every preserved behaviour of that contract, and names no
  behaviour the contract does not.

So a record without a replay (``document`` null), or a replay without the block, is
still recorded and still judged on everything above -- and cannot close; nor can any
record of a finding with no agreed contract. This gate only ever got stricter: no
closure it refused before is allowed now.
"""

from __future__ import annotations

from django.utils import timezone

from .repair_contract import block_of

PASSED = "passed"
FAILED = "failed"
ERRORED = "errored"
OUTCOMES = frozenset({PASSED, FAILED, ERRORED})

VULNERABLE = "vulnerable"
REPAIRED = "repaired"
BENIGN = "benign"
INCOMPLETE_REPAIR = "incomplete_repair"
FIXTURE_CLASSES = (VULNERABLE, REPAIRED, BENIGN, INCOMPLETE_REPAIR)

INCOMPLETE_REPAIR_PATTERNS = (
    "restored_reachability",
    "changed_defaults",
    "lost_compensating_control",
    "displaced_effects",
    "restored_persistence",
    "operational_breakage",
)

# What each single-fixture class must have read for a closure to stand.
_EXPECTED = {VULNERABLE: FAILED, REPAIRED: PASSED, BENIGN: PASSED}

# The replay's vocabulary, verbatim from Minotaur-Backend's remediation-outcomes
# dataset (minotaur_backend/remediation_outcomes.py): one document is read there and
# here. What a replay can say about the effect on one path, and about legitimate use.
GONE = "gone"
PRESENT = "present"
UNKNOWN = "unknown"
EFFECT_READINGS = frozenset({GONE, PRESENT, UNKNOWN})
RETAINED = "retained"
BROKEN = "broken"
UTILITY_READINGS = frozenset({RETAINED, BROKEN, UNKNOWN})

#: What a replay comes to (:func:`classify`), the dataset's outcomes. Only
#: ``verified_closed`` can stand behind a closure, and only through the gate.
RESULT_VERIFIED_CLOSED = "verified_closed"
RESULT_COSMETIC = "cosmetic"
RESULT_PARTIAL = "partial"
RESULT_UTILITY_BREAKING = "utility_breaking"
RESULT_INCONCLUSIVE = "inconclusive"


class ClosureRefused(ValueError):
    """A retest-gated closure the evidence does not carry. ``reasons`` names every
    class or pattern that is missing, not run, unreadable or wrong."""

    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("Retest-gated closure refused: " + "; ".join(self.reasons))


def _run_reason(name, entry, expected):
    if entry is None:
        return f"{name}: not recorded"
    if not isinstance(entry, dict) or not isinstance(entry.get("ran"), bool):
        return f"{name}: unreadable"
    if not entry["ran"]:
        return f"{name}: not run"
    outcome = entry.get("outcome")
    # A string first: an object or a list is unhashable, and the membership test
    # raised on it -- a 500 for every read of a finding carrying such a record
    # (#125 review round 1, F2).
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        return f"{name}: unreadable outcome {_clip_repr(outcome)}"
    if outcome == expected:
        return None
    if expected == FAILED and outcome == PASSED and name.startswith(INCOMPLETE_REPAIR):
        return (
            f"{name}: passed -- the check accepted a planted incomplete repair, so its "
            "pass on the real repair proves nothing; it must still fail"
        )
    return f"{name}: {outcome}, a closure needs it {expected}"


def fixture_reasons(fixtures) -> list[str]:
    """Every reason ``fixtures`` does not carry a closure; empty when it does."""
    if not isinstance(fixtures, dict):
        return ["fixtures: unreadable"]
    reasons = []
    for name, expected in _EXPECTED.items():
        reason = _run_reason(name, fixtures.get(name), expected)
        if reason:
            reasons.append(reason)
    patterns = fixtures.get(INCOMPLETE_REPAIR)
    if patterns is None:
        return [*reasons, f"{INCOMPLETE_REPAIR}: not recorded"]
    if not isinstance(patterns, dict):
        return [*reasons, f"{INCOMPLETE_REPAIR}: unreadable"]
    for pattern in INCOMPLETE_REPAIR_PATTERNS:
        reason = _run_reason(f"{INCOMPLETE_REPAIR}/{pattern}", patterns.get(pattern), FAILED)
        if reason:
            reasons.append(reason)
    return reasons


def _clip_repr(value, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _replay_verdict(document) -> tuple[str | None, list[str]]:
    """``(result, reasons)`` for the replay ``document`` carries, in the dataset's own
    order (Minotaur-Backend ``remediation_outcomes.classify``); ``(None, [])`` when the
    replay shows the effect gone on the original scenario and every variant, at least
    one variant replayed, and legitimate use retained. Never raises: whatever JSON a
    record holds, an unreadable replay is a reason."""
    replay = document.get("replay") if isinstance(document, dict) else None
    if not isinstance(replay, dict):
        return RESULT_INCONCLUSIVE, ["replay: unreadable"]
    reached = replay.get("reached")
    original = replay.get("original_effect")
    variants = replay.get("variants")
    utility = replay.get("utility")
    if (
        not isinstance(reached, bool)
        or not _one_of(original, EFFECT_READINGS)
        or not _one_of(utility, UTILITY_READINGS)
        or not isinstance(variants, dict)
        or not all(_one_of(v, EFFECT_READINGS) for v in variants.values())
    ):
        return RESULT_INCONCLUSIVE, ["replay: unreadable"]
    if not reached:
        return RESULT_INCONCLUSIVE, ["replay: did not reach the target, so nothing was observed"]
    if original == UNKNOWN:
        return RESULT_INCONCLUSIVE, ["replay: could not tell whether the original scenario's effect is gone"]
    if original == PRESENT:
        return RESULT_COSMETIC, ["replay: the original scenario still produces the unauthorized effect"]
    present = sorted(str(name) for name, reading in variants.items() if reading == PRESENT)
    if present:
        return RESULT_PARTIAL, [f"replay: an adjacent path still produces the effect: {', '.join(present)}"]
    unknown = sorted(str(name) for name, reading in variants.items() if reading == UNKNOWN)
    if unknown:
        return RESULT_INCONCLUSIVE, [
            f"replay: could not tell whether these paths still produce the effect: {', '.join(unknown)}"
        ]
    if utility == BROKEN:
        return RESULT_UTILITY_BREAKING, ["replay: the effect is gone, and so is the legitimate use"]
    if utility == UNKNOWN:
        return RESULT_INCONCLUSIVE, ["replay: could not tell whether the legitimate use survives"]
    if not variants:
        return RESULT_INCONCLUSIVE, [
            "replay: no adjacent path was replayed; a closure needs the effect shown gone on at "
            "least one variant beside the original scenario"
        ]
    return None, []


def _one_of(value, vocabulary) -> bool:
    return isinstance(value, str) and value in vocabulary


def _preserved_verdict(document) -> tuple[str | None, list[str]]:
    """What the replay says of the behaviours its repair contract preserves, as the
    dataset reads it (Minotaur-Backend ``remediation_outcomes.classify``): one read
    ``broken`` is ``utility_breaking``, one read ``unknown`` (or unreadable) is
    ``inconclusive``; ``(None, [])`` otherwise, and for a document with no block.
    Whether the block names the finding's CURRENT contract is the gate's to judge
    (:func:`~assurance.repair_contract.contract_reasons`), on the finding."""
    block = document.get("contract") if isinstance(document, dict) else None
    if block is None:
        return None, []
    preserved = block.get("preserved") if isinstance(block, dict) else None
    if not isinstance(preserved, dict):
        return RESULT_INCONCLUSIVE, ["contract: unreadable"]
    broken = sorted(str(n) for n, r in preserved.items() if r == BROKEN)
    if broken:
        return RESULT_UTILITY_BREAKING, [
            f"contract: the effect is gone, and so is a behaviour the repair had to preserve: {', '.join(broken)}"
        ]
    unsure = sorted(str(n) for n, r in preserved.items() if not _one_of(r, UTILITY_READINGS) or r == UNKNOWN)
    if unsure:
        return RESULT_INCONCLUSIVE, [
            f"contract: could not tell whether these preserved behaviours survive: {', '.join(unsure)}"
        ]
    return None, []


def replay_reasons(document) -> list[str]:
    """Every reason the replay ``document`` carries does not carry a closure; empty
    when it does. What the gate adds for a record that carries a replay."""
    return _replay_verdict(document)[1]


def classify(document) -> tuple[str, list[str]]:
    """``(result, reasons)`` of a whole replay document, as Minotaur-Backend's dataset
    computes a row's outcome: the replay first (:func:`_replay_verdict`), then the
    contract's preserved behaviours (:func:`_preserved_verdict`), then the
    fixture document (a check not proven is ``inconclusive``), then the origin (only
    an independent observer's replay verifies). ``verified_closed`` with no reasons,
    or the result and every reason it is not. Says what a replay came to; never
    decides a closure -- the gate does (:func:`enforce`)."""
    result, reasons = _replay_verdict(document)
    if result is not None:
        return result, reasons
    result, reasons = _preserved_verdict(document)
    if result is not None:
        return result, reasons
    fixtures = fixture_reasons(document.get("fixtures"))
    if fixtures:
        return RESULT_INCONCLUSIVE, ["the check was not proven to tell the cases apart", *fixtures]
    from .models import ClaimEvidence

    origin = document.get("origin")
    if origin != ClaimEvidence.Origin.INDEPENDENT:
        return RESULT_INCONCLUSIVE, [
            f"origin: {_clip_repr(origin)}, only an independent observer's replay verifies a closure"
        ]
    return RESULT_VERIFIED_CLOSED, []


def latest_record(finding):
    """The latest :class:`RetestClosureEvidence` of ``finding`` -- the one the gate
    reads -- or None. Always read from the database, now: the gate decides on it at
    the save (:func:`enforce`), and a record committed after the finding was loaded
    -- a fooled retest landing mid-request -- must be the one it reads (#125 review
    round 1, F1)."""
    from .models import RetestClosureEvidence

    if finding.pk is None:
        return None
    return RetestClosureEvidence.objects.filter(finding_id=finding.pk).order_by("-created_at", "-pk").first()


def _served_latest(finding):
    """:func:`latest_record`, for SERVING only (:func:`closure_standing`): read from
    the prefetched records when the view prefetched them (``closure_evidence``), so
    a page of findings is one query, not one per finding. Same order as the query:
    the latest ``created_at``, the highest pk among equals. Never the gate's read."""
    cached = getattr(finding, "_prefetched_objects_cache", {}).get("closure_evidence")
    if cached is None or finding.pk is None:
        return latest_record(finding)
    records = list(cached)
    return max(records, key=lambda r: (r.created_at, r.pk)) if records else None


#: What a reader is told a finding's closure stands on (:func:`closure_standing`).
VERIFIED_CLOSED = "verified_closed"
CLOSABLE = "closable"
NOT_CLOSABLE = "not_closable"
CLOSED_UNVERIFIED = "closed_without_retest"
NOT_GATED = "not_retest_gated"
NOT_A_CLOSURE = "not_a_closure"

def _dispositions() -> frozenset:
    """Dispositions that are not closures (:attr:`Finding.Status`): a human decision
    to carry the risk, or that there was none. No closure is claimed, so none is
    served."""
    from .models import Finding

    return frozenset({Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE})


def closure_standing(finding) -> dict:
    """What a closure of ``finding`` stands on, as a reader is served it: the gate's
    own verdict (:func:`refusal_reasons`) per finding, never a second judgement.

    ``standing``:

    - ``verified_closed``   -- CLOSED, retest-gated, and its latest closure
      evidence carries the closure now (every fixture class and pattern ran with
      the outcome a closure needs, an independent observer's, after the finding
      was last seen). The only standing that says a closure is effect-backed.
      Status CLOSED only: a remediation RESOLVED says someone called the work
      done, not that the finding is closed (#125 review round 1, F3).
    - ``closable``          -- not closed, retest-gated, and its latest evidence
      would carry a closure if one were made now.
    - ``not_closable``      -- retest-gated, and the evidence would not carry a
      closure: ``reasons`` names every reason, as the gate would refuse. A closed
      finding reads this when its evidence no longer carries it (seen again since).
    - ``closed_without_retest`` -- closed without asking for a retest: a
      disposition, never an effect-backed closure, and said so.
    - ``not_retest_gated``  -- not closed, and no retest was asked for.
    - ``not_a_closure``     -- accepted as residual risk, or a false positive: a
      human decision, not a closure, so no closure standing is claimed for it.

    ``evidence`` is the latest record's provenance and, per fixture class and
    pattern, whether it ran and how it came out, and the replay's ``contract``
    block as read (or None) -- or None when there is no record. ``contract`` is the
    finding's current repair contract's version and digest, or None.
    Pure reads; never writes."""
    from .models import Finding

    record = _served_latest(finding)
    closed = finding.status == Finding.Status.CLOSED
    # A closed finding with closure evidence was closed on it -- the gate counts a
    # retest asked of either copy -- and stands on it still, whatever the flag reads
    # now: a re-observation at a lower severity lowers the flag (ingest), and was
    # served "closed without a retest", hiding that the defect was seen again
    # after its retest (#125 review round 2, L2).
    gated = bool(finding.retest_required) or (closed and record is not None)
    from .repair_contract import served_contracts

    contracts = served_contracts(finding)
    reasons = _record_reasons(finding, record, contracts=contracts) if gated else []
    if finding.status in _dispositions():
        standing, reasons = NOT_A_CLOSURE, []
    elif not gated:
        standing = CLOSED_UNVERIFIED if closed else NOT_GATED
    elif reasons:
        standing = NOT_CLOSABLE
    else:
        standing = VERIFIED_CLOSED if closed else CLOSABLE
    # Built with keywords: the retest flag is READ here and served, never written.
    # test_no_code_path_writes_a_findings_disposition_past_save pins that only
    # ingest writes it, by matching the flag as a quoted dict key or an assignment.
    current = contracts[-1] if contracts else None
    return dict(
        standing=standing,
        retest_required=bool(finding.retest_required),
        reasons=reasons,
        evidence=None if record is None else _served_record(record),
        contract=None if current is None else {
            "version": current.version, "content_digest": current.content_digest,
        },
    )


def _run_of(entry) -> dict:
    """One run as it is served: ``outcome`` is one of :data:`OUTCOMES`, ``None``
    when it did not run, or ``"unreadable"`` -- never the record's raw value, which
    is whatever JSON the recorder wrote (#125 review round 1, F4)."""
    if not isinstance(entry, dict) or not isinstance(entry.get("ran"), bool):
        return {"ran": None, "outcome": "unreadable"}
    if not entry["ran"]:
        return {"ran": False, "outcome": None}
    outcome = entry.get("outcome")
    return {"ran": True, "outcome": outcome if isinstance(outcome, str) and outcome in OUTCOMES else "unreadable"}


def _served_record(record) -> dict:
    fixtures = record.fixtures if isinstance(record.fixtures, dict) else {}
    patterns = fixtures.get(INCOMPLETE_REPAIR)
    return {
        "uuid": str(record.uuid),
        "origin": record.origin,
        "content_digest": record.content_digest,
        "recorded_at": record.created_at.isoformat(),
        "fixtures": {
            **{name: _run_of(fixtures.get(name)) for name in (VULNERABLE, REPAIRED, BENIGN)},
            INCOMPLETE_REPAIR: {
                pattern: _run_of(patterns.get(pattern) if isinstance(patterns, dict) else None)
                for pattern in INCOMPLETE_REPAIR_PATTERNS
            },
        },
        "contract": block_of(record.document),
    }


def refusal_reasons(finding, *, last_seen=None) -> list[str]:
    """Why ``finding`` may not be closed on its latest closure evidence; empty when
    it may. ``last_seen`` is the latest observation of the defect (defaults to the
    finding's own)."""
    return _record_reasons(finding, latest_record(finding), last_seen=last_seen)


def _record_reasons(finding, record, *, last_seen=None, contracts=None) -> list[str]:
    """:func:`refusal_reasons` of ``record``, the latest closure evidence as the
    caller read it, against ``contracts`` -- the finding's repair contract versions,
    oldest first; read from the database when not given (the gate's read)."""
    from .models import ClaimEvidence
    from .repair_contract import contract_reasons, contracts_of

    if record is None:
        return [
            "no closure evidence recorded: a retest-gated closure needs the vulnerable, repaired, "
            "benign and incomplete_repair fixtures run"
        ]
    reasons = []
    if record.origin != ClaimEvidence.Origin.INDEPENDENT:
        reasons.append(f"origin: {record.origin}, only an independent observer's retest carries a closure")
    if not (record.content_digest or "").strip():
        reasons.append("content_digest: blank, the record names no retest artifact")
    last_seen = last_seen or finding.last_seen
    if last_seen is not None and record.created_at < last_seen:
        reasons.append("recorded before the finding was last observed: the defect was seen after the retest ran")
    reasons += fixture_reasons(record.fixtures)
    # A record that carries the replay it came from is held to it too; one without
    # (``document`` null) is judged as it always was.
    if record.document is not None:
        reasons += replay_reasons(record.document)
    # And every closure is held to the finding's current repair contract: a record
    # without a replay, or a replay without the block, cannot close.
    reasons += contract_reasons(record.document, contracts_of(finding) if contracts is None else contracts)
    return reasons


def enforce(finding, update_fields=None) -> None:
    """Refuse a save that moves a retest-required ``finding`` to CLOSED or its
    remediation to RESOLVED without complete closure evidence. Called from
    :meth:`Finding.save`, so every writer -- the API, the admin, the remediation
    workflow, a shell -- goes through it. A save that is not that move passes."""
    from .models import Finding

    closing = finding.status == Finding.Status.CLOSED
    resolving = finding.remediation_state == Finding.RemediationState.RESOLVED
    if update_fields is not None:
        fields = set(update_fields)
        closing = closing and "status" in fields
        resolving = resolving and "remediation_state" in fields
    if not (closing or resolving):
        return
    stored = None
    if finding.pk is not None:
        stored = (
            Finding.objects.filter(pk=finding.pk)
            .values("status", "remediation_state", "retest_required", "last_seen")
            .first()
        )
    if stored is not None:
        closing = closing and stored["status"] != Finding.Status.CLOSED
        resolving = resolving and stored["remediation_state"] != Finding.RemediationState.RESOLVED
        if not (closing or resolving):
            return
    # Either copy asking for a retest makes it one: a write that lowers the flag in
    # the same save as it closes is the hand-marked close this gate exists to stop.
    if not (finding.retest_required or (stored and stored["retest_required"])):
        return
    seen = [t for t in (finding.last_seen, stored and stored["last_seen"]) if t is not None]
    reasons = refusal_reasons(finding, last_seen=max(seen) if seen else None)
    if reasons:
        raise ClosureRefused(reasons)


def record_closure_evidence(
    finding, *, fixtures, origin, content_digest="", summary="", recorded_by=None, now=None, document=None
):
    """Record one retest run against ``finding``'s four fixture classes.

    ANYTHING WELL-FORMED IS RECORDED, as for claim evidence: a record whose
    incomplete repair passed is an honest record of a check that was fooled, and
    the gate reads it as such. Refused here only what cannot be a record: an
    unknown origin, fixtures that are not a mapping, or a ``document`` -- the replay
    the run came from -- that is not a mapping or names other fixtures than the
    record's. Its one API route is the engine service's
    (:mod:`assurance.closure_evidence`), which always passes the document."""
    from .models import ClaimEvidence, RetestClosureEvidence

    if origin not in ClaimEvidence.Origin.values:
        raise ValueError(f"origin {origin!r} is not one of {sorted(ClaimEvidence.Origin.values)}")
    if not isinstance(fixtures, dict):
        raise ValueError("fixtures must be a mapping of fixture class to run")
    if document is not None:
        if not isinstance(document, dict):
            raise ValueError("document must be a mapping: the replay the run came from")
        if "fixtures" in document and document["fixtures"] != fixtures:
            raise ValueError("document names other fixtures than the record's")
    return RetestClosureEvidence.objects.create(
        finding=finding,
        fixtures=fixtures,
        origin=origin,
        content_digest=content_digest or "",
        summary=summary or "",
        recorded_by=recorded_by,
        created_at=now or timezone.now(),
        document=document,
    )
