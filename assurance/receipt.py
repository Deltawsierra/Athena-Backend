"""Assurance Receipt — a verifiable digest over evidence that already exists.

Roadmap spine (EXPOSE). Every piece of :class:`~assurance.models.Evidence`
already carries a ``content_hash`` — a SHA-256 over the exact observation behind
a finding (see ``assurance.ingest._content_hash``). This module binds those
hashes into a single **deterministic, recomputable digest**: the assurance
receipt. An auditor who has the finding's evidence (its classification, source
and content hash, all of which the API already returns) can recompute the same
digest and confirm nothing was altered between the scan and the report.

What the receipt attests, and what it does not:

- it attests **integrity and provenance** — *this is the evidence that was
  recorded, unaltered*;
- it does **not** attest that the conclusion is *true*. How strongly a finding
  is actually known is the evidence *class* (``technically_verified`` down to
  ``vendor_asserted``), a separate axis this receipt never inflates. A receipt
  over a ``vendor_asserted`` claim proves the claim was recorded faithfully, not
  that the vendor is right.

The digest is over stable content only (never a timestamp), so the same DB state
always yields the same digest; ``computed_at`` rides alongside as metadata,
outside the hash.

The Assurance Receipt as a standard (commercial spine)
------------------------------------------------------

:func:`build_assurance_receipt` lifts the bare deployment digest into a
**versioned, documented, portable** assurance receipt — the roadmap tuple made
machine-readable: *system X, version Y, validated against policy Z, evidence set
E, time T, environment C, result R*. Time T is the signed form's ``issued_at``
(4.1): when this backend handed the receipt to be signed, inside the signature and
outside the digest (:func:`signable_receipt`). Before 4.1 nothing signed carried a
time at all. It binds, into one deterministic payload:

- the **version** of the receipt standard (:data:`RECEIPT_VERSION`), so a
  consumer knows exactly which schema it is reading;
- the **system** identity (name, uuid, environment);
- the **result** — the deployment's six-state decision and its human label;
- the **policy** the system is assessed against — the declared data boundary, or
  an honest ``declared: false`` when none was ever approved (never an invented
  policy);
- the **evidence** root — the existing :func:`deployment_receipt` Merkle-style
  digest over the finding/evidence hashes — plus the finding count and algorithm;
- a map of per-**assessment** digests (compliance / capabilities / boundary /
  AI-BOM), each a :func:`_digest` over that assessment's deterministic output, so
  a consumer can detect a change in one specific assessment without transporting
  the whole payload;
- the **served route** — what actually ran, as a fingerprint over every route
  field, with each field either observed or the literal ``unknown`` (see
  :mod:`assurance.served_route`), because a verdict that cannot name the route it
  was taken against cannot say whether that route is still the one running;
- the **coverage** manifest's counts and verdict on both of its axes — what was
  expected, observed and assessed, and how many of the checks an engine can run
  actually ran (see :mod:`assurance.coverage`) — because the evidence root
  attests to the findings that exist and can say nothing about the components
  nothing ever tested. A clean test and an absent test leave the same silence,
  and the receipt has to tell them apart;
- the **chains** -- how the deployment's approved workflows composed into its
  decision, reduced to counts (see :mod:`assurance.composition`): how many were
  approved and assessed, and what KIND of evidence the standing outcomes rest on.
  A READY built on three typed-in ``held`` rows, on three gate authorization
  checks, and on three watched effects are three different claims, and without
  this block the receipt signed all three identically;
- the **authority chains** -- for each consequential effect, the chain of authority
  it was produced through, hop by hop, and each hop's verdict (see
  :mod:`assurance.authority_chain`): proven, unproven (a shadow node, a dangling
  edge, an unverified approval) or broken. Named by digest, never by the nodes'
  names;
- the **consequential effects** -- every effect an approved workflow has through a
  tool its approval binds, and which of them need a chain and have none (see
  :mod:`assurance.consequential`): consequential and covered by a chain in force,
  consequential and MISSING one, of an UNKNOWN class, or read-only. A missing chain
  reads unproven, so a receipt over a deployment that recorded no chain no longer
  reads like one whose chains all hold. Named by digest too.

Together those two are what make the receipt answer, on its own, *which
configuration passed and what was not covered*. Neither is retrievable from the
evidence root, and without them a receipt over a deployment where one asset of
nine was tested, on a route whose every field was unknown, is indistinguishable
from one over a fully instrumented, fully assessed system.

The same honesty the rest of this module keeps applies in full: the receipt
attests **integrity and provenance** — *this is the assurance state that was
recorded, unaltered* — and never that the conclusions are true or the system is
secure. A ``needs_more_evidence`` decision, or an assessment resting on
``vendor_asserted`` claims, is carried faithfully at its true strength; the
digest proves nothing was altered between record and report, not that what was
recorded is correct. :data:`RECEIPT_SCHEMA` documents the shape as data, so
"documented + machine-readable" is real and not merely prose.

This receipt is UNSIGNED, and says so in the payload
-----------------------------------------------------

The receipt dict is the **canonical signable payload**: deterministic,
canonicalisable, and built so that a change to any stable field changes
``["digest"]`` and would invalidate any signature over it. The cryptography
(Ed25519 keys, the Merkle construction) lives in the engine, which owns the keys;
this backend deliberately does not sign.

"Designed to be signed elsewhere" is not "signed elsewhere", and this module said
the first in a way that read as the second. **No component in the platform signs
this object today.** The engine's Ed25519 signing covers the evidence-pack
manifest — a different artifact, in a different repository, with no path between
the two. So a receipt carrying a prominent SHA-256 ``digest`` and nothing at all
about signatures reads, to most readers, as cryptographically vouched. A digest is
a checksum an auditor can recompute; it is not a signature and attests nothing
about who produced the receipt.

So the payload carries ``signed`` (always ``False`` here), ``signature`` (always
``None``) and ``unsigned_reason``. This is exactly the discipline the evidence
pack already keeps — it returns ``signed: false`` with a reason, deliberately, so
that an unsigned pack says so rather than looking like a signed one nobody
checked — and the receipt, the artifact the roadmap wants published as a standard,
was the one that did not keep it.

The three fields sit OUTSIDE the digest, like ``computed_at``: the digest is the
value a signature covers, so it cannot depend on whether a signature exists. When
signing lands, ``signed`` becomes true and ``signature`` fills in, and every
digest recorded before that day still verifies.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime

from django.utils import timezone

from ai_engine.services.cyberengine_client import (
    ENGINE_REFUSED,
    ENGINE_RUN_FAILED,
    ENGINE_STILL_RUNNING,
    ENGINE_UNREACHABLE,
    ENGINE_UNREADABLE,
    MAX_JSON_DEPTH,
    _nesting_depth,
)

ALGORITHM = "sha256"

#: Why every receipt this module emits is unsigned, in the payload rather than only
#: in prose. One string, so the answer cannot drift between the schema, the payload
#: and the docstring.
UNSIGNED_REASON = (
    "THIS COPY is unsigned. This backend produces the canonical signable payload "
    "and holds no signing key. A signed copy exists: GET the deployment's "
    "`signed-assurance-receipt`, which asks the engine to wrap the signable "
    "projection of this same receipt (see `signable_receipt`) in a DSSE envelope "
    "and returns the envelope, or an honest reason it could not. The `digest` "
    "above is a checksum an auditor can recompute to confirm the content is "
    "unaltered against a copy they already trust; it is not a signature and "
    "attests nothing about who produced this receipt."
)

#: The fields a receipt carries for its reader that a signature must NOT cover.
#: Kept as data, not a literal in the view, so the route, the tests and any future
#: second signer cannot disagree about what was signed.
NOT_SIGNED_OVER = ("computed_at", "signed", "signature", "unsigned_reason")

#: Why each of those is excluded, in the response rather than only in prose --
#: a reader comparing the signed copy against the unsigned one will find fields
#: missing and is owed the reason without reading this source file.
NOT_SIGNED_OVER_REASON = (
    "`computed_at` is when the unsigned copy was rendered, and nothing signs it. The "
    "signed copy carries its own time instead: `issued_at`, when this backend handed "
    "it to be signed, inside the signature and outside `digest`. So two signings of "
    "the SAME assurance state carry the same `digest` and differ by their `issued_at` "
    "alone: 'has anything changed?' is answered by comparing digests, and 'when was "
    "this issued?' by the signed time. `signed`, `signature` and `unsigned_reason` are "
    "a document's self-report about whether it is signed, which is false the moment "
    "it is signed -- whether an artifact carries a signature is a property of the "
    "envelope around it, not a claim the content can make about itself. None of these "
    "is inside `digest`, so the signed copy and the unsigned one carry the identical "
    "`digest` and are checkably the same assurance state."
)

#: What the signed form carries that the full form does not: the time it was issued
#: (4.1), stamped by :func:`signable_receipt` when this backend hands the receipt to
#: be signed. Inside the signature, OUTSIDE ``digest``: the same state digests the
#: same whenever it is signed. Not in the full form, which nothing signs.
SIGNED_FORM_ONLY = ("issued_at",)

# The version of the Assurance Receipt standard this module emits. A stable
# string a consumer keys on to know which schema (below) it is reading; bump it
# when the receipt's shape changes: MAJOR for hashed content, MINOR for what sits
# outside the digest (3.1, 4.1).
#   1.1 — added the pinned evaluator ``policy_version`` to the hashed content, so
#         the receipt records not just the declared boundary ("policy Z") but the
#         rule set the decision was actually made under.
#   2.0 — added ``served_route`` (what actually ran, every field observed or
#         explicitly ``unknown``) and ``coverage`` (what was and was not
#         assessed). A MAJOR bump, not a minor one: both are new hashed content,
#         so every 1.1 digest differs from the 2.0 digest of the same state. A
#         consumer that silently compared the two would report a change that did
#         not happen, which is why the version is IN the hashed content and a
#         reader is expected to key on it. Then #67, the same day, added the check
#         axis to ``coverage`` WITHOUT a new version string: 2.0 was emitted in two
#         shapes, and the 2.0 schema reads both and names each (_both_2_0_shapes).
#   3.0 — added ``checks_gap_fingerprint`` and ``checks_reported_at`` to
#         ``coverage``: which checks fell short, and when that was measured.
#   3.1 — the three fields that say whether the receipt is signed. A MINOR bump,
#         and deliberately so. Every previous step here was MAJOR because it
# added new HASHED content: a 2.0 digest and a 3.0 digest of the same state differ,
# so a minor bump would have told a consumer the shapes were compatible when the
# digests were not. The three fields 3.1 adds sit OUTSIDE the digest, so a 3.0
# digest and a 3.1 digest of the same state are IDENTICAL. Calling this major would
# be that same error with the sign flipped -- announcing a digest break that did
# not happen, and inviting a consumer to discard receipts that still verify.
#   4.0 — added ``chains``: the workflow-chain composition behind the decision, as
#         counts. MAJOR, for the reason 2.0 was: it is new HASHED content, so a 3.1
#         digest and a 4.0 digest of the same state differ, and a consumer comparing
#         them has to be told the shapes are not the same.
#   4.1 — the signed form carries ``issued_at``, the time this backend handed it to
#         be signed, inside the signature and OUTSIDE the digest
#         (:data:`SIGNED_FORM_ONLY`). MINOR, by the rule 3.1 set: no hashed member
#         was added, removed or retyped. One hashed VALUE does move: the version
#         string is itself hashed, so the 4.1 digest of a state is its 4.0 digest
#         with ``receipt_version`` changed. At 3.1 two moved -- the policy pin then
#         embedded the stamped version, so ``policy_version`` moved too -- and
#         "IDENTICAL" above was true of neither. :data:`HASHED_CONTENT_VERSION` is
#         why it is one now.
#   5.0 — added ``authority_chains``: every authority chain in force, hop by hop,
#         with each hop's verdict (assurance.authority_chain). MAJOR, for the reason
#         2.0 and 4.0 were: it is new HASHED content, so a 4.1 digest and a 5.0
#         digest of the same state differ. HASHED_CONTENT_VERSION moves with it, and
#         so does the policy pin -- which the two caps this version's chains bring
#         to the decision move anyway.
#   6.0 — added ``consequential_effects``: every effect an approved workflow has
#         through a tool its approval binds, its class, and whether a chain in force
#         names it (assurance.consequential). MAJOR, for the reason 5.0 was: it is
#         new HASHED content, so a 5.0 digest and a 6.0 digest of the same state
#         differ. Not a 5.1: a MINOR step changes only what sits outside the digest
#         (3.1, 4.1), and calling new hashed content minor would tell a consumer two
#         digests of one state are comparable when they are not. The policy pin moves
#         with it, and with the two caps (authority_chain_missing,
#         effect_class_unknown) this version's effects bring to the decision.
RECEIPT_VERSION = "mythos.assurance.receipt/6.0"
_VERSION_5_0 = "mythos.assurance.receipt/5.0"
_VERSION_4_1 = "mythos.assurance.receipt/4.1"
_VERSION_4_0 = "mythos.assurance.receipt/4.0"
_VERSION_3_1 = "mythos.assurance.receipt/3.1"
_VERSION_3_0 = "mythos.assurance.receipt/3.0"
_VERSION_2_0 = "mythos.assurance.receipt/2.0"
_VERSION_1_1 = "mythos.assurance.receipt/1.1"
_VERSION_1_0 = "mythos.assurance.receipt/1.0"

#: 2.0 was emitted in two shapes under one version string. #56 (fdf77bf) gave
#: ``coverage`` five members; #67 (87e83e7), the same day and still as 2.0, added the
#: check axis. ``_VERSION_2_0`` names #67's, the shape the 2.0 schema has always
#: described; this key names #56's. It is not a version string -- the receipt carries
#: 2.0's -- and ``receipt_schema`` does not take it: the published 2.0 schema reads
#: both shapes and names each (:func:`_both_2_0_shapes`).
_VERSION_2_0_AS_56 = "mythos.assurance.receipt/2.0 as emitted by #56"

#: Who emitted each shape, and when: the name a reader is given for what they hold.
EMITTED_AS = {
    _VERSION_1_0: "#27 (673a40b), 17 Sep 2026, until #42",
    _VERSION_1_1: "#42 (5ed69be), 18 Sep 2026, until #56",
    _VERSION_2_0_AS_56: "#56 (fdf77bf), 22 Sep 2026, until #67",
    _VERSION_2_0: "#67 (87e83e7), 22 Sep 2026, until #70",
    _VERSION_3_0: "#70 (99bc3d9), 22 Sep 2026, until #87",
    _VERSION_3_1: "#87 (58083c1), 23 Sep 2026, until #105; signed from #96 (51484fb)",
    _VERSION_4_0: "#105 (7985460), 26 Sep 2026, until #118",
    _VERSION_4_1: "#118 (d81e9cb), 29 Sep 2026, until #133",
    _VERSION_5_0: "#133 (1f357fa), 7 Oct 2026, until #PRNUM",
    RECEIPT_VERSION: "#PRNUM (COMMITSHA), 7 Oct 2026, and since",
}

#: The versions no route ever signed. Receipts were first signed under 3.1, by #96
#: (51484fb), which added the signed route; nothing before it asked the engine to sign
#: a receipt. So a signature over a receipt of one of these was not made by
#: athena-backend's signed route, whoever holds the key -- the engine signs any
#: document an operator hands it -- and a reader is told so rather than VERIFIED.
NEVER_SIGNED = (_VERSION_1_0, _VERSION_1_1, _VERSION_2_0, _VERSION_3_0)

# Every receipt version this module can describe. A receipt in the wild carries
# its own ``receipt_version``, and an auditor holding a 1.1 receipt still needs
# the schema that reads it -- "versioned" is worth nothing if the previous
# version's shape is only recoverable from git history. :func:`receipt_schema`
# is the lookup; :data:`RECEIPT_SCHEMA` stays the current one so existing
# callers are unaffected. Every version ever emitted is here: 1.0 was left out
# until the receipts #27 emitted were read back from git (tests/fixtures/receipts).
SUPERSEDED_VERSIONS = (
    _VERSION_1_0, _VERSION_1_1, _VERSION_2_0, _VERSION_3_0, _VERSION_3_1, _VERSION_4_0, _VERSION_4_1, _VERSION_5_0,
)

#: The version that introduced the HASHED content this module emits: 6.0, which added
#: ``consequential_effects`` (5.0 added ``authority_chains``, 4.0 ``chains``). A MINOR step changes only what sits outside the digest, so it leaves
#: this where it is; a MAJOR step moves it. :mod:`assurance.policy` pins THIS as its
#: ``evaluator_standard``, not :data:`RECEIPT_VERSION`. The policy pin is what every
#: claim and stored decision is bound to, and pinning the stamped version made 4.1 --
#: a signed time, no rule touched -- move it: every claim superseded as "Assurance
#: policy changed" and every stored decision recomputed, for a change to no policy.
HASHED_CONTENT_VERSION = RECEIPT_VERSION


def _digest(payload: dict) -> str:
    """SHA-256 over the canonical JSON of ``payload`` — sorted keys, compact
    separators — so the same content always hashes identically regardless of how
    a caller happened to order it."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _checks_gap_fingerprint(checks: dict) -> str | None:
    """A stable digest of WHICH checks fell short, and why.

    The counts alone cannot answer the question this receipt exists to answer. Two
    deployments -- one where the TLS check never ran against a cleartext target,
    one where SQL injection was switched off in config -- produce the same four
    numbers and therefore the same signed artifact, byte for byte apart from
    `computed_at`. "We never tested transport security" and "we turned off
    injection testing" are not the same disclosure.

    The named rows still stay out (unbounded, and retrievable). This is the middle
    term: a digest over the sorted ``(check, state, reason)`` of every row that did
    not perform, so two different shortfalls never collide, and a reader holding
    two receipts can tell that the gap changed without the receipt having to list
    it. ``None`` when nothing was reported, which is distinct from a digest over an
    empty gap -- that one is a positive statement that every check performed.
    """
    if not checks.get("reported"):
        return None
    short = [
        [str(r.get("check", "")), str(r.get("state", "")), str(r.get("reason", ""))]
        for key in ("not_performed", "degraded", "unmeasured", "unrecognised")
        for r in (checks.get(key) or [])
    ]
    return _digest({"short": sorted(short)})


def _evidence_rows(finding) -> list[list[str]]:
    """The finding's evidence as ``[classification, source, content_hash]`` rows,
    **sorted** so the receipt is independent of insertion order. Uses whatever the
    ORM has prefetched — no extra query when ``evidence`` is prefetched."""
    rows = [
        [e.classification or "", e.source or "", e.content_hash or ""]
        for e in finding.evidence.all()
    ]
    rows.sort()
    return rows


def finding_receipt(finding) -> dict:
    """A recomputable receipt for one finding: a digest binding its identity to
    the evidence hashes behind it. Deterministic given the finding's evidence."""
    rows = _evidence_rows(finding)
    digest = _digest(
        {
            "fingerprint": finding.fingerprint,
            "uuid": str(finding.uuid),
            "evidence": rows,
        }
    )
    return {
        "algorithm": ALGORITHM,
        "digest": digest,
        "evidence_count": len(rows),
        "computed_at": timezone.now().isoformat(),
    }


def deployment_receipt(deployment) -> dict:
    """A single assurance receipt for a whole deployment: a digest over the
    (sorted) digests of its findings' receipts — a Merkle-style root an auditor
    verifies once. Recomputing every finding's receipt and this root reproduces
    the value exactly when nothing has been altered.

    Uses ``prefetch_related('evidence')`` on the caller side to avoid a query per
    finding; the receipt itself issues none beyond reading the prefetched rows."""
    findings = list(deployment.findings.all())
    finding_digests = sorted(finding_receipt(f)["digest"] for f in findings)
    root = _digest({"deployment": str(deployment.uuid), "findings": finding_digests})
    return {
        "algorithm": ALGORITHM,
        "digest": root,
        "finding_count": len(finding_digests),
        "computed_at": timezone.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# The Assurance Receipt as a versioned, documented standard
# ---------------------------------------------------------------------------

# A machine-readable description of the receipt shape — the "documented" half of
# "documented + machine-readable". Deliberately JSON-Schema-flavoured (types +
# descriptions) rather than a full validator: it travels with the receipt so a
# consuming system can introspect the fields without parsing this docstring. It
# describes the CANONICAL, HASHED content plus the two metadata fields that ride
# outside the hash (``digest`` itself and ``computed_at``), and the signed form's
# ``issued_at`` (:data:`SIGNED_FORM_ONLY`), which the full form does not carry.
RECEIPT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": RECEIPT_VERSION,
    "title": "Mythos Assurance Receipt",
    "type": "object",
    "description": (
        "A versioned, portable, reproducible attestation of a deployment's "
        "recorded assurance state. Attests integrity and provenance — that this "
        "is the assurance state that was recorded, unaltered — never that the "
        "conclusions are true or the system is secure."
    ),
    "properties": {
        "receipt_version": {
            "type": "string",
            "const": RECEIPT_VERSION,
            "description": "The version of this receipt standard (see RECEIPT_VERSION).",
        },
        "policy_version": {
            "type": "string",
            "description": (
                "The pinned assurance-policy version the decision was made under — "
                "the rule set (six-state thresholds, required-evidence rules, claim "
                "caps) in force at assessment time (see assurance.policy). Lets a "
                "consumer tell whether the policy behind this receipt still holds."
            ),
        },
        "system": {
            "type": "object",
            "description": "The AI system under assurance — 'system X' in the tuple.",
            "properties": {
                "name": {"type": "string"},
                "uuid": {"type": "string", "format": "uuid"},
                "environment": {
                    "type": "string",
                    "description": "dev / staging / production / other.",
                },
                "environment_label": {"type": "string"},
            },
        },
        "result": {
            "type": "object",
            "description": (
                "The standing six-state deployment decision — 'result R'. Null when "
                "no decision has been computed yet (never silently read as ready)."
            ),
            "properties": {
                "decision": {"type": ["string", "null"]},
                "decision_label": {"type": ["string", "null"]},
            },
        },
        "policy": {
            "type": "object",
            "description": (
                "The declared data boundary the system is assessed against — 'policy "
                "Z'. 'declared' is false when no boundary was ever approved; the "
                "policy is then absent, never invented. Silence is not consent."
            ),
            "properties": {
                "declared": {"type": "boolean"},
                "allowed_regions": {"type": "array", "items": {"type": "string"}},
                "training_allowed": {"type": "boolean"},
                "third_party_sharing_allowed": {"type": "boolean"},
            },
            "required": ["declared"],
        },
        "evidence": {
            "type": "object",
            "description": (
                "The evidence set E, reduced to its Merkle-style root: the "
                "deployment_receipt digest over every finding's evidence hashes, "
                "plus the finding count and the hash algorithm."
            ),
            "properties": {
                "algorithm": {"type": "string", "const": ALGORITHM},
                "root": {
                    "type": "string",
                    "description": "64-hex SHA-256 root over the evidence.",
                },
                "finding_count": {"type": "integer"},
            },
        },
        "assessments": {
            "type": "object",
            "description": (
                "A digest per computed assessment (compliance / capabilities / "
                "boundary / bom), each a SHA-256 over that assessment's deterministic "
                "output. Lets a consumer detect a change in one assessment without "
                "transporting the full payload. A digest attests the assessment was "
                "recorded unaltered, never that it passes."
            ),
            "properties": {
                "compliance": {"type": "string"},
                "capabilities": {"type": "string"},
                "boundary": {"type": "string"},
                "bom": {"type": "string"},
            },
        },
        "served_route": {
            "type": "object",
            "description": (
                "What actually ran — the served-route identity (assurance.served_route). "
                "A model NAME does not say what served the request, and a verdict that "
                "cannot name the route cannot say whether the thing it was taken "
                "against is the thing running now. Every field of every route is "
                "present: one nothing observed is the literal string 'unknown', never "
                "absent and never guessed, so a fully-instrumented route is "
                "distinguishable from one where twelve fields were never looked at."
            ),
            "properties": {
                "route_version": {
                    "type": "string",
                    "description": "The field roster's version.",
                },
                "fingerprint": {
                    "type": "string",
                    "description": (
                        "64-hex SHA-256 over every route, unknowns included. A field "
                        "moving from 'unknown' to a value moves this: the claim was "
                        "bound to a state that included the not-knowing."
                    ),
                },
                "route_count": {"type": "integer"},
                "fully_observed_count": {
                    "type": "integer",
                    "description": "Routes with no unknown field.",
                },
                "complete": {
                    "type": "boolean",
                    "description": (
                        "Every route fully observed. False when there are no routes at "
                        "all: nothing served is not everything observed."
                    ),
                },
                "unknown_fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Every field unobserved on at least one route, named. A count "
                        "alone is a number a reader cannot act on."
                    ),
                },
            },
            "required": ["route_version", "fingerprint", "route_count", "complete"],
        },
        "coverage": {
            "type": "object",
            "description": (
                "What was and was not assessed (assurance.coverage). The half of "
                "'exactly what was and wasn't proven' that the evidence root cannot "
                "answer: a clean test leaves no finding, so 'no finding on this asset' "
                "means either 'tested and clean' or 'never tested', and those are the "
                "two readings that must not be confused."
            ),
            "properties": {
                "expected": {"type": "integer", "description": "Declared components."},
                "observed": {
                    "type": "integer",
                    "description": "Assets discovery found.",
                },
                "assessed": {
                    "type": "integer",
                    "description": "Assets something tested.",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["complete", "incomplete", "undeclared"],
                    "description": (
                        "'undeclared' is its own answer, not a weak 'complete': with no "
                        "declared architecture there is no promise to be short of."
                    ),
                },
                "critical_gap": {
                    "type": "boolean",
                    "description": (
                        "A declared or high-risk component was never assessed, or a "
                        "check the engine can run did not run."
                    ),
                },
                "checks_reported": {
                    "type": "boolean",
                    "description": (
                        "Whether any engine stated which checks it ran. False means "
                        "nobody said -- never that every check ran, which is the "
                        "reading the coverage axes exist to prevent."
                    ),
                },
                "checks_total": {
                    "type": ["integer", "null"],
                    "description": "Checks the engine can run. Null when unreported.",
                },
                "checks_performed": {
                    "type": ["integer", "null"],
                    "description": (
                        "Checks that ran and completed every probe. Null when "
                        "unreported. Lower than the total means questions went unasked."
                    ),
                },
                "checks_complete": {
                    "type": ["boolean", "null"],
                    "description": (
                        "Every check performed. Null when unreported -- distinct in "
                        "both directions from false."
                    ),
                },
                "checks_gap_fingerprint": {
                    "type": ["string", "null"],
                    "description": (
                        "SHA-256 over the sorted (check, state, reason) of every "
                        "check that did not perform, so two different shortfalls "
                        "never produce the same receipt. Null when unreported; a "
                        "digest over an empty gap is the positive statement that "
                        "every check performed."
                    ),
                },
                "checks_reported_at": {
                    "type": ["string", "null"],
                    "description": (
                        "When the stored check coverage was reported. Null when "
                        "unreported. A measurement date, not a render date, which "
                        "is why it is inside the digest."
                    ),
                },
            },
            "required": [
                "expected", "observed", "assessed", "verdict", "critical_gap",
                "checks_reported", "checks_total", "checks_performed",
                "checks_complete", "checks_gap_fingerprint", "checks_reported_at",
            ],
        },
        "chains": {
            "type": "object",
            "description": (
                "How the deployment's approved workflow chains composed into its "
                "decision (assurance.composition), reduced to counts. No workflow is "
                "named: the names are retrievable from the deployment, unbounded, and "
                "the customer's own vocabulary, and this receipt is built to travel. "
                "The censuses are over STANDING outcomes -- one per workflow, the "
                "latest -- and each carries every key its vocabulary defines, zeros "
                "included, because a count that appears only when non-zero reads "
                "exactly like a zero when it is missing."
            ),
            "properties": {
                "approved_set_recorded": {
                    "type": "boolean",
                    "description": (
                        "Whether anyone recorded the approved workflow set. False "
                        "means the counts speak only for the chains that arrived -- "
                        "never that the deployment has no approved workflows."
                    ),
                },
                "workflows_expected": {
                    "type": ["integer", "null"],
                    "description": "Approved workflows. Null when the set was not recorded.",
                },
                "workflows_assessed": {
                    "type": "integer",
                    "description": (
                        "Workflows with a standing outcome, counting an approved one "
                        "nothing reported on as not_demonstrated."
                    ),
                },
                "workflows_unreported": {
                    "type": "integer",
                    "description": "Approved workflows no outcome was recorded for.",
                },
                "workflows_unapproved": {
                    "type": "integer",
                    "description": "Workflows an outcome arrived for that are not approved.",
                },
                "rule_decision": {
                    "type": ["string", "null"],
                    "description": (
                        "What the composition rule alone reaches, before findings, "
                        "claims and coverage are combined with it into `result`. Null "
                        "when no chain was assessed -- never read as ready."
                    ),
                },
                "census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Standing outcomes by status: what each chain SAYS.",
                },
                "basis_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": (
                        "Standing outcomes by basis: whether a key this deployment "
                        "trusts signed it (demonstrated), someone typed it in "
                        "(attested), or nobody said (unknown)."
                    ),
                },
                "workflows_unexercised": {
                    "type": "integer",
                    "description": (
                        "Standing outcomes whose status claims an exercise while their "
                        "basis does not say one happened."
                    ),
                },
                "evidence_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": (
                        "Standing outcomes by what KIND of evidence they are: a gate's "
                        "authorization_check at dispatch, a scan, an observed_effect "
                        "watched by an independent collector, an unclassified signer, "
                        "or an unsigned record at its basis. A held resting on an "
                        "authorization check alone shows the action was authorized, "
                        "not that the effect happened within that authority."
                    ),
                },
                "route_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": (
                        "Standing outcomes by the served route they were taken "
                        "against: the route serving now (current), one that no longer "
                        "serves (moved), or one nothing recorded (unrecorded). A held "
                        "taken against any route but the current one is not evidence "
                        "about the system this receipt describes, and on an approved "
                        "workflow it counts as not_demonstrated."
                    ),
                },
            },
            "required": [
                "approved_set_recorded", "workflows_expected", "workflows_assessed",
                "workflows_unreported", "workflows_unapproved", "rule_decision",
                "census", "basis_census", "workflows_unexercised", "evidence_census",
                "route_census",
            ],
        },
        "authority_chains": {
            "type": "object",
            "description": (
                "Every authority chain in force (assurance.authority_chain): for a "
                "consequential effect, the ordered hops it was produced through -- person, "
                "user, agent, policy, tool, identity, action, effect -- and each hop's "
                "verdict: proven, unproven or broken, with the codes of what proves it or "
                "holds it. A chain with a broken hop holds the decision at "
                "needs_remediation and one with an unproven hop at needs_more_evidence. "
                "No node is named: each chain is identified by its digest, the SHA-256 of "
                "the chain document the deployment's authority-chains route serves."
            ),
            "properties": {
                "recorded": {"type": "integer", "description": "Chains ever recorded, superseded ones included."},
                "standing": {
                    "type": "integer",
                    "description": "Chains in force: the newest per workflow and effect.",
                },
                "superseded": {"type": "integer", "description": "Chains a newer one for the same effect replaced."},
                "verdict_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Chains in force by verdict, every verdict including the zeros.",
                },
                "basis_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": (
                        "Chains in force by what they rest on: an engine's signature over the "
                        "chain that verifies now (demonstrated), or a person's record (attested)."
                    ),
                },
                "chains": {
                    "type": "array",
                    "description": (
                        "The chains in force, ordered by digest, at most 50: each its digest, "
                        "basis, verdict and hops -- relation, from_kind, to_kind, verdict and "
                        "readings (the codes of what proves a proven hop, or of every reason an "
                        "unproven or broken one is not proven)."
                    ),
                    "items": {"type": "object"},
                },
                "not_shown": {
                    "type": "integer",
                    "description": "Chains in force past the 50 listed: counted, never silently dropped.",
                },
            },
            "required": [
                "recorded", "standing", "superseded", "verdict_census", "basis_census", "chains", "not_shown",
            ],
        },
        "consequential_effects": {
            "type": "object",
            "description": (
                "Every effect an approved workflow has through a tool its approval binds "
                "(assurance.consequential), and whether it needs an authority chain: the tool's "
                "declared effect class makes it consequential (write, destructive, or annotated "
                "destructive), read-only (read), or unknown (undeclared, outside the vocabulary, "
                "or the tool no longer registered). A consequential effect no chain in force "
                "names is missing, and holds the decision at needs_more_evidence as an unproven "
                "chain does; so does an unknown one. No workflow or tool is named: each effect is "
                "identified by its digest, the SHA-256 of the effect document the deployment's "
                "authority-chains route serves beside its names."
            ),
            "properties": {
                "status_census": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": (
                        "Effects by status -- covered, missing, unknown, not_required -- every "
                        "status including the zeros."
                    ),
                },
                "effects": {
                    "type": "array",
                    "description": (
                        "The effects, ordered by digest, at most 50: each its digest, tool_kind, "
                        "class (consequential, read_only, unknown), status, readings (the codes "
                        "that decided its class and status) and chains (the digests of the "
                        "authority chains in force that name it)."
                    ),
                    "items": {"type": "object"},
                },
                "not_shown": {
                    "type": "integer",
                    "description": "Effects past the 50 listed: counted, never silently dropped.",
                },
            },
            "required": ["status_census", "effects", "not_shown"],
        },
        "algorithm": {"type": "string", "const": ALGORITHM},
        "digest": {
            "type": "string",
            "description": (
                "The top-level SHA-256 over every field above except algorithm, "
                "digest, computed_at, issued_at and the signature fields -- "
                "reproducible, no timestamp inside. This is the value a signature is "
                "taken over."
            ),
        },
        "computed_at": {
            "type": "string",
            "format": "date-time",
            "description": "When this receipt was rendered — metadata only, OUTSIDE the digest.",
        },
        "issued_at": {
            "type": "string",
            "format": "date-time",
            "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
            "description": (
                "SIGNED FORM ONLY, from 4.1: when this backend handed the receipt to be "
                "signed, by its own clock -- RFC 3339, UTC, whole seconds. Inside the "
                "signature and OUTSIDE the digest, so the same state digests the same "
                "whenever it is signed and two signings of it differ by this alone. The "
                "issuer's clock, not proof of when the state held: a reader applies its "
                "own freshness policy. The full form does not carry it; nothing signs "
                "that copy, and its computed_at is when it was rendered."
            ),
        },
        "signed": {
            "type": "boolean",
            "const": False,
            "description": (
                "Whether this receipt carries a cryptographic signature. Always false: "
                "no component in the platform signs this object today. Present so a "
                "reader cannot mistake the digest — a checksum anyone can recompute — "
                "for a signature. OUTSIDE the digest, like computed_at, because the "
                "digest is the value a signature covers."
            ),
        },
        "signature": {
            "type": "null",
            "description": (
                "The signature block, when there is one. Always null today. Null rather "
                "than absent, because an absent key reads as 'nothing to say here' and "
                "here there is something to say."
            ),
        },
        "unsigned_reason": {
            "type": "string",
            "description": (
                "Why this receipt is unsigned, in words a reader can act on. Never "
                "empty while signed is false."
            ),
        },
    },
    "required": [
        "receipt_version",
        "policy_version",
        "system",
        "result",
        "policy",
        "evidence",
        "assessments",
        "served_route",
        "coverage",
        "chains",
        "authority_chains",
        "consequential_effects",
        "algorithm",
        "digest",
        "computed_at",
        "signed",
        "signature",
        "unsigned_reason",
    ],
}


# Every earlier shape, kept as data rather than in the commit history: "versioned
# and backward-readable" is only true if an auditor holding an older receipt can
# still obtain the schema that reads it.
#
# Each one is the current schema MINUS what every later version added -- all of
# it. Deriving each from the current schema by subtracting only its own successor's
# fields is how 2.0 and 1.1 came to require `signed`, `signature` and
# `unsigned_reason`, which 3.1 added: a genuine 2.0 receipt failed the schema
# published to read it, the failure `UnknownReceiptVersion` exists to prevent,
# arriving through the front door. So what each version added is written down
# once, below, and each older schema subtracts the union of everything after it.
#
# Each schema also SAYS what its receipts lack -- the members every later shape
# added, and what a receipt without them cannot say (``lacks``) -- and whether any
# route ever signed one (``never_signed``). A reader of a 1.0 receipt is told it
# names no policy and carries no signed time; left to infer it, they would infer
# from the current schema, which describes a receipt they do not hold.

#: What each shape added over the one before it, newest first: (the shape before,
#: what was added). ``means`` is what a receipt without those members cannot say.
_ADDED_IN = (
    # 6.0: every effect the approvals cover, and which of them have no chain.
    (_VERSION_5_0, {
        "in": RECEIPT_VERSION, "fields": ("consequential_effects",), "coverage": (),
        "means": "which consequential effects no authority chain names, and which tools' effect class is unknown",
    }),
    # 5.0: every authority chain in force, hop by hop, with each hop's verdict.
    (_VERSION_4_1, {
        "in": _VERSION_5_0, "fields": ("authority_chains",), "coverage": (),
        "means": "which authority chain produced each consequential effect, and which of its hops are proven",
    }),
    # 4.1: the signed form's issue time, outside the digest.
    (_VERSION_4_0, {
        "in": _VERSION_4_1, "fields": SIGNED_FORM_ONLY, "coverage": (),
        "means": "a signed issue time: when the receipt was handed to be signed",
    }),
    # 4.0: the chain composition.
    (_VERSION_3_1, {
        "in": _VERSION_4_0, "fields": ("chains",), "coverage": (),
        "means": "how the approved workflow chains composed into the decision",
    }),
    # 3.1: whether the receipt is signed, outside the digest.
    (_VERSION_3_0, {
        "in": _VERSION_3_1, "fields": ("signed", "signature", "unsigned_reason"), "coverage": (),
        "means": "its own word that it is unsigned",
    }),
    # 3.0: which checks fell short, and when that was measured.
    (_VERSION_2_0, {
        "in": _VERSION_3_0, "fields": (), "coverage": ("checks_gap_fingerprint", "checks_reported_at"),
        "means": "which checks fell short, and when that was reported",
    }),
    # 2.0 as #67 emitted it: the check axis, under the same version string.
    (_VERSION_2_0_AS_56, {
        "in": _VERSION_2_0, "fields": (),
        "coverage": ("checks_reported", "checks_total", "checks_performed", "checks_complete"),
        "means": "whether any engine said which checks it ran, and how many ran",
    }),
    # 2.0 as #56 emitted it: what actually ran, and what was never looked at.
    (_VERSION_1_1, {
        "in": _VERSION_2_0_AS_56, "fields": ("served_route", "coverage"), "coverage": (),
        "means": "what actually ran, and what was and was not assessed",
    }),
    # 1.1: the pinned rules the decision was made under.
    (_VERSION_1_0, {
        "in": _VERSION_1_1, "fields": ("policy_version",), "coverage": (),
        "means": "the pinned rules the decision was made under",
    }),
)


def _schema_before(key: str) -> dict:
    """The schema a receipt of shape ``key`` has: the current one without everything
    a later shape added, with what it therefore lacks and whether any route ever
    signed one said in it (``lacks``, ``never_signed``)."""
    dropped: set[str] = set()
    dropped_coverage: set[str] = set()
    lacks: list[dict] = []
    for older, added in _ADDED_IN:
        dropped.update(added["fields"])
        dropped_coverage.update(added["coverage"])
        lacks.append({
            "members": [*added["fields"], *(f"coverage.{member}" for member in added["coverage"])],
            "added_by": EMITTED_AS[added["in"]].split(" ", 1)[0],
            "means": added["means"],
        })
        if older == key:
            break
    else:
        raise KeyError(key)
    # The version string the receipt carries: #56's 2.0 carries 2.0's.
    version = _VERSION_2_0 if key == _VERSION_2_0_AS_56 else key

    properties = {
        k: v for k, v in RECEIPT_SCHEMA["properties"].items() if k not in dropped
    }
    # Overridden, not inherited. The current schema pins `receipt_version` to the
    # CURRENT version, so copying it would hand an auditor an old schema that
    # requires the new string -- one that rejects the very receipts it exists to
    # read, which is worse than not shipping one.
    properties["receipt_version"] = {
        **RECEIPT_SCHEMA["properties"]["receipt_version"],
        "const": version,
    }
    if "coverage" in properties and dropped_coverage:
        coverage = RECEIPT_SCHEMA["properties"]["coverage"]
        properties["coverage"] = {
            **{k: v for k, v in coverage.items() if k not in ("properties", "required")},
            "properties": {
                k: v for k, v in coverage["properties"].items() if k not in dropped_coverage
            },
            "required": [r for r in coverage["required"] if r not in dropped_coverage],
        }
    return {
        **{k: v for k, v in RECEIPT_SCHEMA.items() if k not in ("$id", "properties", "required")},
        "$id": version,
        "properties": properties,
        "required": [r for r in RECEIPT_SCHEMA["required"] if r not in dropped],
        "lacks": lacks[::-1],
        "never_signed": version in NEVER_SIGNED,
    }


#: What ``coverage.critical_gap`` meant as #56 emitted it (fdf77bf,
#: assurance/receipt.py): before the check axis, a check that did not run could not
#: make a gap critical. #67 widened it under the same version string.
_CRITICAL_GAP_AS_56 = "A declared or high-risk component was never assessed."


def _both_2_0_shapes() -> dict:
    """2.0's published schema, which reads both shapes 2.0 was emitted in and names
    each.

    ``coverage`` describes every member either shape carried, requires the five both
    carried, and must be exactly ONE of the two (``oneOf``, each branch titled with
    who emitted it): a #56 receipt is read as #56's, a #67 receipt as #67's, and a
    mixture neither emitted as neither. The 2.0 schema used to be #67's alone, so it
    refused every receipt #56 emitted, and a reader of one was left to guess why.
    """
    as_67, as_56 = _schema_before(_VERSION_2_0), _schema_before(_VERSION_2_0_AS_56)
    coverage_67 = as_67["properties"]["coverage"]
    coverage_56 = as_56["properties"]["coverage"]
    check_axis = [member for member in coverage_67["required"] if member not in coverage_56["required"]]
    branch_56 = {
        "title": f"{_VERSION_2_0} as emitted by {EMITTED_AS[_VERSION_2_0_AS_56]}",
        "required": list(coverage_56["required"]),
        "not": {"anyOf": [{"required": [member]} for member in check_axis]},
        "properties": {
            "critical_gap": {**coverage_56["properties"]["critical_gap"], "description": _CRITICAL_GAP_AS_56},
        },
        "lacks": [lack for lack in as_56["lacks"] if lack not in as_67["lacks"]],
    }
    branch_67 = {
        "title": f"{_VERSION_2_0} as emitted by {EMITTED_AS[_VERSION_2_0]}",
        "required": list(coverage_67["required"]),
    }
    coverage = {**coverage_67, "required": list(coverage_56["required"]), "oneOf": [branch_56, branch_67]}
    return {**as_67, "properties": {**as_67["properties"], "coverage": coverage}}


_SCHEMA_5_0 = _schema_before(_VERSION_5_0)
_SCHEMA_4_1 = _schema_before(_VERSION_4_1)
_SCHEMA_4_0 = _schema_before(_VERSION_4_0)
_SCHEMA_3_1 = _schema_before(_VERSION_3_1)
_SCHEMA_3_0 = _schema_before(_VERSION_3_0)
_SCHEMA_2_0 = _both_2_0_shapes()
_SCHEMA_1_1 = _schema_before(_VERSION_1_1)
_SCHEMA_1_0 = _schema_before(_VERSION_1_0)

_SCHEMAS = {
    RECEIPT_VERSION: RECEIPT_SCHEMA,
    _VERSION_5_0: _SCHEMA_5_0,
    _VERSION_4_1: _SCHEMA_4_1,
    _VERSION_4_0: _SCHEMA_4_0,
    _VERSION_3_1: _SCHEMA_3_1,
    _VERSION_3_0: _SCHEMA_3_0,
    _VERSION_2_0: _SCHEMA_2_0,
    _VERSION_1_1: _SCHEMA_1_1,
    _VERSION_1_0: _SCHEMA_1_0,
}


class UnknownReceiptVersion(ValueError):
    """A receipt version this module cannot describe.

    Raised rather than falling back to the current schema. Handing back the 2.0
    shape for a version we have never heard of would tell a consumer their receipt
    has fields it does not have, and the fields it would invent -- served route and
    coverage -- are exactly the ones whose absence matters.
    """


def receipt_schema(version: str | None = None) -> dict:
    """The machine-readable schema for ``version``; the current one by default.

    A receipt in the wild carries its own ``receipt_version``, so a consumer reads
    that and asks here. An unknown version raises :class:`UnknownReceiptVersion`
    and names what is available, because a wrong schema is worse than no schema.
    Every version ever emitted is described, 1.0 included, and 2.0's schema reads
    both shapes 2.0 was emitted in and names each (:func:`_both_2_0_shapes`). An
    older schema says what its receipts lack and whether any route ever signed one.
    """
    if version is None:
        return RECEIPT_SCHEMA
    try:
        return _SCHEMAS[version]
    except KeyError:
        known = ", ".join(sorted(_SCHEMAS))
        raise UnknownReceiptVersion(
            f"no schema for receipt version {version!r}; this module describes: {known}"
        ) from None


def _pinned_policy_version(deployment) -> str:
    """The pinned assurance-policy version the receipt is validated under. Imported
    lazily: :mod:`assurance.policy` imports this module for the receipt standard
    version, so a top-level import here would be circular."""
    from .policy import policy_pin

    return policy_pin(deployment)


def _policy_reference(deployment) -> dict:
    """The policy the receipt is validated against — the *declared* data boundary,
    honestly. When no :class:`~assurance.models.DataBoundary` was ever approved,
    this is ``{"declared": False}`` and nothing else: an undeclared boundary is a
    gap, never a policy we invent to make the receipt look complete. When one is
    declared, it carries the approved regions and the training / third-party
    sharing flags exactly as recorded."""
    boundary = getattr(deployment, "data_boundary", None)
    if boundary is None:
        return {"declared": False}
    return {
        "declared": True,
        "allowed_regions": list(boundary.allowed_regions or []),
        "training_allowed": bool(boundary.training_allowed),
        "third_party_sharing_allowed": bool(boundary.third_party_sharing_allowed),
    }


def _assessment_digests(deployment) -> dict:
    """A digest per computed assessment, over its deterministic output.

    Each assessment is a pure function of the stored graph and is timestamp-free
    in the content that matters, so its digest is reproducible for a given DB
    state. The AI-BOM already computes its own tamper-evident digest over its
    stable content (its full payload carries a ``generated_at`` we must not hash),
    so we bind *that* digest rather than re-hash the timestamped envelope.

    A digest here attests that the assessment was recorded unaltered — it never
    means the assessment passes; a touched compliance control or a shadow
    capability is a gap, and its digest proves only that the gap was not edited."""
    # Imported lazily: assurance.bom imports from this module, so a top-level
    # import here would be circular.
    from .bom import build_ai_bom
    from .boundary import assess_boundary
    from .capability import assess_capabilities
    from .compliance import build_compliance_map

    return {
        "compliance": _digest(build_compliance_map(deployment)),
        "capabilities": _digest(assess_capabilities(deployment)),
        "boundary": _digest(assess_boundary(deployment)),
        # The BOM's own deterministic digest over its stable content (never its
        # generated_at) — reused, not recomputed over the timestamped payload.
        "bom": build_ai_bom(deployment)["receipt"]["digest"],
    }


def _served_route_reference(deployment) -> dict:
    """The served-route summary the receipt carries: the fingerprint, how many
    routes there are, how many were fully observed, and which fields were never
    observed anywhere.

    The per-route detail is deliberately NOT in the receipt. It is retrievable
    from the deployment, it would grow the signable payload without bound, and two
    of its fields are digests of the customer's prompt and tool schema -- the
    receipt is built to travel to an external party, and the summary answers
    "which configuration passed" without shipping the configuration.

    ``unknown_fields`` is named rather than counted, because that is the list a
    reader can act on: a field unknown on every route is an instrumentation gap in
    the platform. Imported lazily -- :mod:`assurance.served_route` imports this
    module for the digest helper.
    """
    from .served_route import deployment_served_routes

    routes = deployment_served_routes(deployment)
    return {
        "route_version": routes["route_version"],
        "fingerprint": routes["fingerprint"],
        "route_count": routes["route_count"],
        "fully_observed_count": routes["fully_observed_count"],
        "complete": routes["complete"],
        "unknown_fields": routes["unknown_fields"],
    }


def _coverage_reference(deployment) -> dict:
    """The coverage manifest reduced to its counts and verdict.

    The named entity lists stay out for the same reason the per-route detail does:
    they are retrievable, they are unbounded, and the receipt's job is to let a
    reader tell WHETHER something was left unassessed, then go and look. The
    verdict carries the distinction that matters -- ``undeclared`` is its own
    answer and never a weak ``complete``, because with no declared architecture
    there is no promise to be short of.
    """
    from .coverage import coverage_manifest

    manifest = coverage_manifest(deployment)
    checks = manifest["checks"]
    return {
        "expected": manifest["expected"],
        "observed": manifest["observed"],
        "assessed": manifest["assessed"],
        "verdict": manifest["verdict"],
        "critical_gap": manifest["critical_gap"],
        # The check axis, at the same reduction: counts and the one boolean, with
        # the named rows left out to be retrieved. `checks_reported: false` is the
        # load-bearing value -- a receipt that omitted it would be indistinguishable
        # from one attesting that every check ran, which is the reading this whole
        # module refuses to allow anywhere else.
        "checks_reported": checks["reported"],
        "checks_total": checks["total"],
        "checks_performed": checks["performed"],
        "checks_complete": checks["complete"],
        # Which checks fell short, reduced to a digest so the receipt stays bounded
        # and names nothing. Without it the four counts above let two materially
        # different coverage situations sign identically.
        "checks_gap_fingerprint": _checks_gap_fingerprint(checks),
        # When the stored manifest was reported. The API and the panel can already
        # tell a reader the counts are six months old; the signed artifact could
        # not, and a measurement date belongs inside the digest for the same reason
        # the served route does.
        "checks_reported_at": checks["reported_at"],
    }


def _chains_reference(deployment) -> dict:
    """The workflow-chain composition behind the decision, reduced to counts.

    The result block says READY; before this block, nothing signed said what that
    READY rested on. Three typed-in ``held`` rows, three gate authorization checks
    at dispatch, and three effects an independent collector watched all composed
    to the same decision and produced receipts differing only in the digest of
    nothing a reader could name. The censuses here are what tell those apart, and
    they are inside the digest because they are part of the state being attested.

    Names stay out, as they do for routes and coverage entities: retrievable,
    unbounded, and the customer's own vocabulary on an artifact built to travel.
    Imported lazily -- :mod:`assurance.workflow_chains` reaches this module through
    :mod:`assurance.decision`.
    """
    from .workflow_chains import composition_for

    composition = composition_for(deployment)
    return {
        # `workflows_expected is None` is the recorded-or-not distinction the rule
        # turns on; said as its own boolean so a reader of a receipt with an empty
        # approved set is not left to infer it from a null.
        "approved_set_recorded": composition.workflows_expected is not None,
        "workflows_expected": composition.workflows_expected,
        "workflows_assessed": composition.workflows_assessed,
        "workflows_unreported": composition.workflows_unreported,
        "workflows_unapproved": composition.workflows_unapproved,
        "rule_decision": composition.decision,
        "census": dict(composition.census),
        "basis_census": dict(composition.basis_census),
        "workflows_unexercised": composition.workflows_unexercised,
        "evidence_census": dict(composition.evidence_census),
        "route_census": dict(composition.route_census),
    }


#: How many authority chains the receipt lists. The rest are counted (``not_shown``).
RECEIPT_CHAIN_LIMIT = 50


def _authority_chains_reference(deployment, read=None) -> dict:
    """Every authority chain in force, hop by hop, with each hop's verdict
    (:func:`assurance.authority_chain_records.receipt_reference`).

    The ``chains`` block says what KIND of evidence a workflow's ``held`` rests on;
    this says WHICH authority produced each consequential effect, and which of its
    hops nothing proves -- the shadow node, the dangling edge, the unverified
    approval -- so a READY a receipt attests can be told from one an unproven hop
    could not have reached. Hashed, because it is part of the state attested. Names
    stay out, as for every other block: a chain is named by its digest. Imported
    lazily -- the records module reaches this one through the decision.
    """
    from .authority_chain_records import receipt_reference

    return receipt_reference(deployment, limit=RECEIPT_CHAIN_LIMIT, read=read)


#: How many effects the receipt lists. The rest are counted (``not_shown``).
RECEIPT_EFFECT_LIMIT = 50


def _consequential_effects_reference(deployment, read=None) -> dict:
    """Every effect the approvals cover, its class, and whether a chain in force names
    it (:func:`assurance.authority_chain_records.effects_reference`).

    ``authority_chains`` lists the chains somebody recorded; this lists the effects
    that NEED one, so a deployment that recorded none cannot read like one whose
    chains all hold. Hashed, named by digest, imported lazily, for the reasons
    :func:`_authority_chains_reference` gives."""
    from .authority_chain_records import effects_reference

    return effects_reference(deployment, limit=RECEIPT_EFFECT_LIMIT, read=read)


def consequential_effects_problem(section, chains=None) -> str | None:
    """Why ``section`` is not a ``consequential_effects`` block this module could have
    emitted, or ``None``: the members the schema requires, every status in the census,
    each effect in the vocabulary of :mod:`assurance.consequential` with a status its
    class allows, and the counts counting what is listed. With ``chains`` (the
    receipt's ``authority_chains``), a covered effect must name a chain and every
    chain it names must be in force there whenever that block lists every chain."""
    from . import consequential as rule
    from .authority_chain import TOOL_NODE_KINDS

    required = set(RECEIPT_SCHEMA["properties"]["consequential_effects"]["required"])
    if not isinstance(section, dict) or set(section) != required:
        return "consequential_effects does not have the members the schema requires"
    census = section["status_census"]
    if not isinstance(census, dict) or set(census) != set(rule.STATUSES):
        return "the status census does not count every status"
    effects = section["effects"]
    if not isinstance(effects, list):
        return "effects is not a list"
    allowed = {
        rule.CONSEQUENTIAL: {rule.COVERED, rule.MISSING},
        rule.READ_ONLY: {rule.NOT_REQUIRED},
        rule.UNKNOWN: {rule.UNKNOWN},
    }
    listed = None
    if isinstance(chains, dict) and chains.get("not_shown") == 0 and isinstance(chains.get("chains"), list):
        listed = {c.get("digest") for c in chains["chains"] if isinstance(c, dict)}
    for effect in effects:
        if not isinstance(effect, dict) or set(effect) != {
            "digest", "tool_kind", "class", "status", "readings", "chains",
        }:
            return "an effect does not have the members digest, tool_kind, class, status, readings and chains"
        if effect["tool_kind"] not in TOOL_NODE_KINDS:
            return "an effect names a tool kind outside the vocabulary"
        if effect["class"] not in allowed or effect["status"] not in allowed[effect["class"]]:
            return "an effect names a class, or a status its class does not allow"
        if not isinstance(effect["readings"], list) or not isinstance(effect["chains"], list):
            return "an effect's readings or chains are not lists"
        if (effect["status"] == rule.COVERED) != bool(effect["chains"]) and effect["class"] == rule.CONSEQUENTIAL:
            return "a consequential effect is covered exactly when a chain in force names it"
        if listed is not None and not set(effect["chains"]) <= listed:
            return "an effect names a chain the authority chains do not hold in force"
    if len(effects) + section["not_shown"] != sum(census.values()):
        return "the counts do not count the effects listed"
    return None


def authority_chains_problem(section) -> str | None:
    """Why ``section`` is not an ``authority_chains`` block this module could have
    emitted, or ``None``: the members the schema requires, every verdict and basis in
    the censuses, each chain and hop in the vocabulary of
    :mod:`assurance.authority_chain` -- and each chain exactly as bad as its worst
    hop, which is how :func:`assurance.authority_chain.verify` reads one. The
    backend's own reading of the block, as ``tools/verify_receipt.py`` reads it from
    the specification."""
    from . import authority_chain as rule

    required = set(RECEIPT_SCHEMA["properties"]["authority_chains"]["required"])
    if not isinstance(section, dict) or set(section) != required:
        return "authority_chains does not have the members the schema requires"
    bases = {"demonstrated", "attested"}
    if set(section.get("verdict_census") or {}) != set(rule.HOP_VERDICTS):
        return "the verdict census does not count every verdict"
    if set(section.get("basis_census") or {}) != bases:
        return "the basis census does not count every basis"
    chains = section["chains"]
    if not isinstance(chains, list):
        return "chains is not a list"
    kinds = {k for froms, tos in rule.GRAMMAR.values() for k in (*froms, *tos)}
    for chain in chains:
        if not isinstance(chain, dict) or set(chain) != {"digest", "basis", "verdict", "hops"}:
            return "a chain does not have the members digest, basis, verdict and hops"
        hops = chain["hops"]
        if chain["basis"] not in bases or chain["verdict"] not in rule.HOP_VERDICTS or not isinstance(hops, list):
            return "a chain names a basis or verdict outside the vocabulary"
        for hop in hops:
            if (
                not isinstance(hop, dict)
                or set(hop) != {"relation", "from_kind", "to_kind", "verdict", "readings"}
                or hop["relation"] not in rule.RELATIONS
                or hop["from_kind"] not in kinds
                or hop["to_kind"] not in kinds
                or hop["verdict"] not in rule.HOP_VERDICTS
            ):
                return "a hop is not in the vocabulary"
        if not hops or chain["verdict"] != rule.worst(hop["verdict"] for hop in hops):
            return "a chain does not read as its worst hop"
    standing = section["standing"]
    if len(chains) + section["not_shown"] != standing or sum(section["verdict_census"].values()) != standing:
        return "the counts do not count the chains listed"
    return None


def build_assurance_receipt(deployment) -> dict:
    """The full, versioned assurance receipt for a deployment — the roadmap tuple
    (*system, version, policy, evidence, time, environment, result*) as one
    deterministic, portable, signable payload. See :data:`RECEIPT_SCHEMA` for the
    machine-readable shape and the module docstring for what it does and does not
    attest. The *time* is the signed form's: :func:`signable_receipt` stamps
    ``issued_at`` when the receipt is handed to be signed. This full form carries no
    signed time -- its ``computed_at`` is when it was rendered, and nothing signs it.

    It attests **integrity and provenance** — that this is the assurance state
    that was recorded, unaltered — and never that the conclusions are true or the
    system is secure. Every field is carried at its true strength: a
    ``needs_more_evidence`` result, or an undeclared policy, reads as exactly that.

    Deterministic: the digest is over stable content only (version, system,
    result, policy, evidence root, assessment digests, served route, coverage,
    chains, authority chains, consequential effects). ``computed_at`` rides
    alongside as metadata, outside the hash, so the same DB state always yields
    the same digest. Prefetch ``findings__evidence`` and
    ``assets__provider__assertions`` and select_related ``data_boundary`` on the
    caller side to keep it query-light.

    The returned dict is the **canonical signable payload**: signing (Ed25519) is
    the engine's job, which owns the keys; this backend produces the object to be
    signed, not a signature."""
    # A stored decision computed under another outcome keyring -- a key withdrawn
    # since -- or before the signed-outcome rule is reconciled before it is
    # attested, rather than signed as the state of a record it no longer is.
    from .decision import current_decision

    current_decision(deployment)

    # The evidence set E, reduced to its Merkle-style root. We keep only the
    # stable parts of the deployment receipt — the timestamp inside it is dropped
    # so no clock leaks into our digest.
    evidence_root = deployment_receipt(deployment)
    # The recorded authority chains, read and verified once for the two blocks that
    # carry them: the chains in force, and the effects they name.
    from .authority_chain_records import read_chains

    chains_read = read_chains(deployment)

    stable = {
        "receipt_version": RECEIPT_VERSION,
        # The pinned rule set the decision was made under — "validated against
        # policy Z". Imported lazily to avoid an import cycle (assurance.policy
        # imports this module for the receipt standard version).
        "policy_version": _pinned_policy_version(deployment),
        "system": {
            "name": deployment.name,
            "uuid": str(deployment.uuid),
            "environment": deployment.environment,
            "environment_label": deployment.get_environment_display(),
        },
        "result": {
            "decision": deployment.decision,
            # None-safe: an unassessed deployment has no decision, and an absent
            # decision is never read as "ready".
            "decision_label": deployment.get_decision_display()
            if deployment.decision
            else None,
        },
        "policy": _policy_reference(deployment),
        "evidence": {
            "algorithm": evidence_root["algorithm"],
            "root": evidence_root["digest"],
            "finding_count": evidence_root["finding_count"],
        },
        "assessments": _assessment_digests(deployment),
        # What actually ran, and what was never looked at. Both are hashed: an
        # external party reading this receipt alone has to be able to answer
        # "which configuration passed, and what was not covered", and neither
        # question is answerable from an evidence root -- a clean test and an
        # absent test leave the same silence behind them.
        "served_route": _served_route_reference(deployment),
        "coverage": _coverage_reference(deployment),
        # What the decision's chains rest on: typed in, a gate's authorization
        # check, a scan, or a watched effect. Hashed, because a READY resting on
        # assertion and one resting on observation are different states.
        "chains": _chains_reference(deployment),
        # Which authority produced each consequential effect, hop by hop, and
        # which hops nothing proves. Hashed: a chain through a shadow node and one
        # through a governed tool are different states.
        "authority_chains": _authority_chains_reference(deployment, read=chains_read),
        # Which effects NEED a chain, and which have none. Hashed: a deployment that
        # recorded no chain and one whose chains hold are different states.
        "consequential_effects": _consequential_effects_reference(deployment, read=chains_read),
    }

    return {
        **stable,
        "algorithm": ALGORITHM,
        # Reproducible over the stable content only — the value a signature covers.
        "digest": _digest(stable),
        # Metadata only, OUTSIDE the hash — exactly like the other receipts here.
        "computed_at": timezone.now().isoformat(),
        # Also outside the hash, and for the same reason: the digest is what a
        # signature covers, so it cannot depend on whether a signature exists.
        #
        # Said in the payload rather than left to the docstring, because the reader
        # this receipt is built for is an auditor holding the JSON and nothing else.
        # A prominent SHA-256 `digest` with no mention of signatures reads as
        # cryptographically vouched; a digest is a checksum anyone can recompute and
        # attests nothing about who produced the receipt. The evidence pack has
        # returned `signed: false` with a reason from the start, deliberately, so an
        # unsigned pack says so rather than looking like a signed one nobody checked
        # — and the receipt, the artifact meant to be published as a standard, was
        # the one that did not.
        "signed": False,
        "signature": None,
        "unsigned_reason": UNSIGNED_REASON,
    }


#: The DSSE payload type an assurance-receipt envelope must carry. Mirrors
#: ``engine.evidence.envelope.ASSURANCE_RECEIPT``; kept as a literal rather than
#: imported, because this backend does not depend on the engine and must not start.
ASSURANCE_RECEIPT_TYPE = "application/vnd.mythos.assurance-receipt+json"

#: The envelope version this backend knows how to read.
ENVELOPE_VERSION = 1


class NotAnEnvelope(ValueError):
    """What came back from the signer is not an envelope over the document we sent.

    Raised BEFORE anything is served as signed. Not a verification failure -- this
    backend holds no keys and deliberately does not verify -- but the weaker check
    it can make and was not making: is this an envelope at all, does it carry a
    signature, and does it contain the bytes we asked to have signed.
    """


#: What a reader is told when the engine could not be reached or refused, keyed by
#: the failure kind the client records. Our words, not the engine's.
#:
#: Each one says what happened and where to go, which is what the route's own
#: docstring asks of a reason: "a missing setting and an engine with no key are
#: different things to go and fix". What it does NOT do is quote the engine. An
#: `EngineError` message carries the engine's host and port straight out of
#: `requests`, and for a non-2xx up to `MAX_BODY_EXCERPT` characters of whatever
#: body it answered with -- reproduced against an unresolvable host and a
#: traceback body, that was an internal hostname, a port, a source path, a key
#: path and an upstream address, served to every authenticated reader of an
#: unsigned receipt. The signed route never exposed any of it.
_ENGINE_REASONS = {
    ENGINE_UNREACHABLE: (
        "the signing engine could not be reached, so this receipt is unsigned. That "
        "is an environment fact, not a defect in the receipt: check that the engine "
        "is running and that CYBERENGINE_URL points at it. The engine's own error, "
        "including its address, is in this service's log and deliberately not here."
    ),
    ENGINE_REFUSED: (
        "the signing engine was reached and refused to sign, so this receipt is "
        "unsigned. Its status is named at the end of this sentence; what it said is in "
        "this service's log, because an engine's response body is not this reader's business."
    ),
    ENGINE_UNREADABLE: (
        "the signing engine answered with something this service could not read as "
        "a signing response, so this receipt is unsigned. The body it sent is in "
        "this service's log."
    ),
    ENGINE_RUN_FAILED: (
        "the signing engine reported that the operation failed, so this receipt is "
        "unsigned. What it reported is in this service's log."
    ),
    ENGINE_STILL_RUNNING: (
        "the signing engine had not finished when this service stopped waiting, so "
        "this receipt is unsigned. Ask again; nothing is lost."
    ),
}

#: The reason for an engine failure whose kind this mapping does not know. A NEW kind
#: added to the client must not fall through to the engine's own message, which is
#: the defect this function exists to fix -- so the fallback is ours too, and says
#: plainly that it cannot be more specific.
_UNKNOWN_ENGINE_REASON = (
    "the signing engine did not produce a signature, so this receipt is unsigned. "
    "This service could not classify the failure any further; it is in the log."
)


def unsigned_reason_for(exc: BaseException) -> str:
    """Why a receipt is unsigned, in words this service chose.

    Three kinds of failure reach here and the caller needs to tell them apart:

    * ``RuntimeError`` -- ``CyberEngineClient.from_settings`` refusing, because this
      deployment is not configured with an engine at all. Passed through verbatim:
      the message names OUR setting, which is exactly what the reader must go and
      fix, and there is no engine in it to leak.
    * :class:`NotAnEnvelope` -- the engine answered and the answer is not an envelope
      over the document we sent. Also verbatim, and also ours: these messages say
      things like "a DIFFERENT document" and "not readable JSON", which are this
      service's own findings about the answer, not the answer's text.
    * ``EngineError`` -- the engine could not be reached, refused, or answered
      something unusable. The message is the engine's and does not travel; the KIND
      does, through :data:`_ENGINE_REASONS`.

    An exception of some fourth type is possible only if a caller widens its
    ``except``, and it gets the unknown-kind reason rather than ``str(exc)``: a
    function whose whole purpose is not to publish an exception's text must not have
    a branch that publishes an exception's text.
    """
    kind = getattr(exc, "kind", None)
    if kind is None:
        # Not an EngineError. Ours to publish, and the informative one.
        return str(exc)
    reason = _ENGINE_REASONS.get(kind, _UNKNOWN_ENGINE_REASON)
    status = getattr(exc, "status", None)
    return f"{reason} (engine status {status})" if status is not None else reason


def envelope_over(document: dict, envelope: object) -> dict:
    """``envelope``, if it is an envelope over ``document``. Otherwise raise.

    THE ROUTE SERVED ``signed: true`` FOR ANYTHING THE ENGINE RETURNED. Measured,
    through the real view, against four hostile signers:

        {}                                        -> signed: true, envelope: {}
        {..., "signatures": []}                   -> signed: true
        {"error": "lol", "status": "ok"}          -> signed: true
        an envelope over a DIFFERENT document     -> signed: true, and the
            envelope attested `ready` while the receipt served beside it said
            `needs_more_evidence`

    The route's own docstring said an envelope with an empty signature list "would
    be a receipt that looks signed, which is worse than one that says it is not",
    and that serving a different document beside an envelope "is the mismatch this
    route exists to prevent". It prevented only the BACKEND substituting a
    document; the same mismatch arriving from the engine was served with
    ``signed: true``.

    "Verification is the auditor's job" does not cover it. A merely buggy engine --
    a stale cache, the wrong deployment, a proxy answering 200 with an error body --
    makes ``signed`` true for every reader who trusts the one field the response
    tells them is authoritative. And a compromised engine holding a trusted key
    makes the mismatched envelope verify OFFLINE too, over the forged document; the
    auditor checks the envelope, not the receipt printed beside it.

    What this checks, and what it does not:

    * Shape: ``envelope_version``, the payload type bound into the signed bytes,
      and at least one signature entry carrying a non-empty ``keyid`` and ``sig``.
      A signature list that is empty, or entries missing either field, is a
      document nobody signed.
    * Nesting: the payload is a STRING inside the engine's answer, so the depth
      bound the client puts on the answer (:data:`MAX_JSON_DEPTH`, read before
      anything is parsed) never saw it. It is measured here with the client's own
      linear scan, which stops at the first bracket past the limit, before
      ``json.loads`` runs. A payload of a hundred thousand ``[`` made the parser
      raise RecursionError -- not a ValueError, so out of this function, whose
      contract is that it raises NotAnEnvelope for anything that is not an envelope
      over ``document``. The route did not answer 500, but only because
      RecursionError happens to be a RuntimeError and the route names RuntimeError
      for another reason; the reason it then served was the interpreter's own
      sentence. Now a payload nested past the bound is refused as NotAnEnvelope, in
      words that name the limit and never the payload -- and a parser or a
      comparison that overruns its stack anyway (a stack nearly spent when the route
      is called) is refused the same way.
    * Containment: the base64 payload decodes to JSON EQUAL to ``document``.
      Compared as decoded objects rather than as bytes: the claim worth making is
      "the envelope contains the document we sent", and a signer is entitled to
      re-serialise it. Byte equality would refuse a correct envelope over a
      different key order. After the nesting check the comparison recurses at most
      :data:`MAX_JSON_DEPTH` levels, whatever the signer sent.
    * NOT the signature. That needs the keyring, and checking it here would make
      this route the thing it says it is not -- a checker that trusts the signer's
      own report establishes only that the engine agrees with itself.
    """
    if not isinstance(envelope, dict):
        raise NotAnEnvelope(
            f"the signer returned {type(envelope).__name__}, not an envelope object"
        )
    version = envelope.get("envelope_version")
    if version != ENVELOPE_VERSION:
        raise NotAnEnvelope(
            f"the signer returned envelope_version {version!r}; this backend reads "
            f"version {ENVELOPE_VERSION}"
        )
    payload_type = envelope.get("payloadType")
    if payload_type != ASSURANCE_RECEIPT_TYPE:
        raise NotAnEnvelope(
            f"the signer returned payloadType {payload_type!r}, not "
            f"{ASSURANCE_RECEIPT_TYPE!r} -- an envelope over another document kind "
            "is not a signature on this receipt"
        )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise NotAnEnvelope(
            "the signer returned an envelope with no signatures, which is a receipt "
            "that looks signed and is not"
        )
    for index, entry in enumerate(signatures):
        if not isinstance(entry, dict) or not entry.get("keyid") or not entry.get("sig"):
            raise NotAnEnvelope(
                f"signature {index} names no key or carries no signature bytes"
            )
    raw = envelope.get("payload")
    if not isinstance(raw, str):
        raise NotAnEnvelope("the envelope carries no base64 payload to compare")
    try:
        decoded = base64.b64decode(raw, validate=True)
        # Decoded the way ``json.loads(bytes)`` decodes (a byte-order mark, UTF-16
        # and UTF-32 included), so the nesting scan below reads exactly the text the
        # parser would have read.
        text = decoded.decode(json.detect_encoding(decoded), "surrogatepass")
    except (ValueError, binascii.Error) as unreadable:
        raise NotAnEnvelope(
            f"the envelope's payload is not readable JSON: {unreadable.__class__.__name__}"
        ) from unreadable
    # THE BOUND ON THE ANSWER NEVER SAW THIS. The engine's answer is depth-checked
    # before it is parsed (the client's `_json_of`), but the payload is a string
    # inside it, so nesting arrived here unchecked. Refused in our words, naming the
    # limit and never the payload; and the scan is linear and stops at the first
    # bracket past the limit, so a hostile payload costs what a small one does.
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise NotAnEnvelope(
            f"the envelope's payload nests deeper than {MAX_JSON_DEPTH} levels, so it "
            "is not read; a signature over something this service cannot read does "
            "not attest this receipt"
        )
    try:
        inside = json.loads(text)
        # In the same handler as the parse. Past the scan above the comparison
        # recurses at most MAX_JSON_DEPTH levels, but a stack that is nearly spent
        # when the route is called can still overrun it, and containment that could
        # not be established is unsigned: never signed, and never an exception that
        # is not NotAnEnvelope.
        differs = inside != document
    except RecursionError as too_deep:
        raise NotAnEnvelope(
            "the envelope's payload nests too deeply to be read and compared with the "
            "document sent to be signed"
        ) from too_deep
    except ValueError as unreadable:
        raise NotAnEnvelope(
            f"the envelope's payload is not readable JSON: {unreadable.__class__.__name__}"
        ) from unreadable
    if differs:
        raise NotAnEnvelope(
            "the envelope is over a DIFFERENT document than the one sent to be "
            "signed, so the signature does not attest this receipt"
        )
    return envelope


def _utc_now() -> datetime:
    """This backend's clock, in UTC. A function of its own so a test can hold it."""
    return datetime.now(UTC)


def _issue_time(moment: datetime) -> str:
    """``moment`` as ``issued_at`` is written: RFC 3339, UTC, whole seconds, ``Z``.

    A naive datetime names no instant -- read as local time it would sign a time
    off by the host's offset -- so it is refused rather than guessed."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("an issue time must be an aware datetime; a naive one names no instant")
    return moment.astimezone(UTC).replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def signable_receipt(receipt: dict, *, issued_at: datetime | None = None) -> dict:
    """The form of an Assurance Receipt that a signature covers: the receipt less
    :data:`NOT_SIGNED_OVER`, plus the time it is issued (:data:`SIGNED_FORM_ONLY`).

    ``build_assurance_receipt`` returns a payload built for a human auditor
    holding the JSON and nothing else, so it carries two things a signature must
    not: the wall clock it was rendered at, and its own report of whether it is
    signed. Signing the whole dict would produce an artifact whose signed bytes
    say ``"signed": false`` -- a signature over the assertion that there is no
    signature.

    What it did not carry, until 4.1, was ANY time under the signature: the render
    clock was dropped and nothing replaced it, so one state signed to the same
    bytes on every day, and a retired key goes on verifying what it signed. A
    signed ``ready`` from before a regression verified for ever. So this stamps
    ``issued_at`` -- ``issued_at`` if given, else this backend's clock now, which on
    the signed route is the moment the receipt is handed to the engine -- inside
    the signature. It is the issuer's clock, not proof of when the state held; a
    reader applies its own freshness policy.

    Every excluded member, and ``issued_at``, is OUTSIDE ``digest``, which is
    computed over the stable content alone. So this form carries the same
    ``digest`` as the full payload -- the signed copy and the copy served by
    ``assurance-receipt`` are checkably the same assurance state -- and two
    signings of an unchanged deployment carry one digest and differ by their
    ``issued_at`` alone.
    """
    signable = {k: v for k, v in receipt.items() if k not in NOT_SIGNED_OVER}
    signable["issued_at"] = _issue_time(_utc_now() if issued_at is None else issued_at)
    return signable
