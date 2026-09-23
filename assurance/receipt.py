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
E, time T, environment C, result R*. It binds, into one deterministic payload:

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
  and the receipt has to tell them apart.

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

import hashlib
import json

from django.utils import timezone

ALGORITHM = "sha256"

#: Why every receipt this module emits is unsigned, in the payload rather than only
#: in prose. One string, so the answer cannot drift between the schema, the payload
#: and the docstring.
UNSIGNED_REASON = (
    "No component in the platform signs this object. This backend produces the "
    "canonical signable payload and holds no signing key; the engine's Ed25519 "
    "signing covers the evidence-pack manifest, a different artifact with no path "
    "to this one. The `digest` above is a checksum an auditor can recompute to "
    "confirm the content is unaltered against a copy they already trust; it is not "
    "a signature and attests nothing about who produced this receipt."
)

# The version of the Assurance Receipt standard this module emits. A stable
# string a consumer keys on to know which schema (below) it is reading; bump it
# only when the stable, hashed shape of the receipt changes.
#   1.1 — added the pinned evaluator ``policy_version`` to the hashed content, so
#         the receipt records not just the declared boundary ("policy Z") but the
#         rule set the decision was actually made under.
#   2.0 — added ``served_route`` (what actually ran, every field observed or
#         explicitly ``unknown``) and ``coverage`` (what was and was not
#         assessed). A MAJOR bump, not a minor one: both are new hashed content,
#         so every 1.1 digest differs from the 2.0 digest of the same state. A
#         consumer that silently compared the two would report a change that did
#         not happen, which is why the version is IN the hashed content and a
#         reader is expected to key on it.
# A MINOR bump, and deliberately so. Every previous step here was MAJOR because it
# added new HASHED content: a 2.0 digest and a 3.0 digest of the same state differ,
# so a minor bump would have told a consumer the shapes were compatible when the
# digests were not. The three fields 3.1 adds sit OUTSIDE the digest, so a 3.0
# digest and a 3.1 digest of the same state are IDENTICAL. Calling this major would
# be that same error with the sign flipped -- announcing a digest break that did
# not happen, and inviting a consumer to discard receipts that still verify.
RECEIPT_VERSION = "mythos.assurance.receipt/3.1"
_VERSION_3_0 = "mythos.assurance.receipt/3.0"
_VERSION_2_0 = "mythos.assurance.receipt/2.0"

# Every receipt version this module can describe. A receipt in the wild carries
# its own ``receipt_version``, and an auditor holding a 1.1 receipt still needs
# the schema that reads it -- "versioned" is worth nothing if the previous
# version's shape is only recoverable from git history. :func:`receipt_schema`
# is the lookup; :data:`RECEIPT_SCHEMA` stays the current one so existing
# callers are unaffected.
SUPERSEDED_VERSIONS = ("mythos.assurance.receipt/1.1", _VERSION_2_0, _VERSION_3_0)


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
# outside the hash (``digest`` itself and ``computed_at``).
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
        "algorithm": {"type": "string", "const": ALGORITHM},
        "digest": {
            "type": "string",
            "description": (
                "The top-level SHA-256 over the stable content above (version, system, "
                "result, policy, evidence root, assessment digests, served route, "
                "coverage) — reproducible, no timestamp inside. This is the value a "
                "signature is taken over."
            ),
        },
        "computed_at": {
            "type": "string",
            "format": "date-time",
            "description": "When this receipt was rendered — metadata only, OUTSIDE the digest.",
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
        "algorithm",
        "digest",
        "computed_at",
        "signed",
        "signature",
        "unsigned_reason",
    ],
}


# The shape a 1.1 receipt has: this one, minus the two blocks 2.0 added. Kept as
# data rather than in the commit history, because "the schema is versioned and
# backward-readable" is only true if an auditor holding an older receipt can still
# obtain the schema that reads it.
_VERSION_1_1 = "mythos.assurance.receipt/1.1"

_SCHEMA_1_1 = {
    **{
        k: v
        for k, v in RECEIPT_SCHEMA.items()
        if k not in ("$id", "properties", "required")
    },
    "$id": _VERSION_1_1,
    "properties": {
        **{
            k: v
            for k, v in RECEIPT_SCHEMA["properties"].items()
            if k not in ("served_route", "coverage")
        },
        # Overridden, not inherited. The current schema pins `receipt_version` to
        # the CURRENT version, so copying it would hand an auditor a 1.1 schema
        # that requires the string "2.0" -- a schema that rejects the very
        # receipts it exists to read, which is worse than not shipping one.
        "receipt_version": {
            **RECEIPT_SCHEMA["properties"]["receipt_version"],
            "const": _VERSION_1_1,
        },
    },
    "required": [
        r for r in RECEIPT_SCHEMA["required"] if r not in ("served_route", "coverage")
    ],
}

# The shape a 2.0 receipt has: this one, minus the check-axis fields 2.1 added.
#
# This block exists because the version string did not move when those fields
# became `required`. For a while `receipt_schema("…/2.0")` handed an auditor
# holding a genuine 2.0 receipt a schema that rejected it -- the exact failure
# UnknownReceiptVersion was written to prevent, arriving through the front door.
# Two payload shapes must not share one version string.
_SCHEMA_2_0 = {
    **{
        k: v
        for k, v in RECEIPT_SCHEMA.items()
        if k not in ("$id", "properties")
    },
    "$id": _VERSION_2_0,
    "properties": {
        **{
            k: v
            for k, v in RECEIPT_SCHEMA["properties"].items()
            if k != "coverage"
        },
        "receipt_version": {
            **RECEIPT_SCHEMA["properties"]["receipt_version"],
            "const": _VERSION_2_0,
        },
        "coverage": {
            **{
                k: v
                for k, v in RECEIPT_SCHEMA["properties"]["coverage"].items()
                if k not in ("properties", "required")
            },
            "properties": {
                k: v
                for k, v in RECEIPT_SCHEMA["properties"]["coverage"]["properties"].items()
                if k not in ("checks_gap_fingerprint", "checks_reported_at")
            },
            "required": [
                r
                for r in RECEIPT_SCHEMA["properties"]["coverage"]["required"]
                if r not in ("checks_gap_fingerprint", "checks_reported_at")
            ],
        },
    },
}

# The shape a 3.0 receipt has: this one, minus the three fields 3.1 added to say
# the receipt is unsigned. Kept as data for the same reason 1.1 and 2.0 are: an
# auditor holding a 3.0 receipt needs the schema that reads it, and "versioned and
# backward-readable" is worth nothing if the previous shape lives only in git.
_HONESTY_FIELDS = ("signed", "signature", "unsigned_reason")

_SCHEMA_3_0 = {
    **{k: v for k, v in RECEIPT_SCHEMA.items() if k not in ("$id", "properties", "required")},
    "$id": _VERSION_3_0,
    "properties": {
        **{
            k: v
            for k, v in RECEIPT_SCHEMA["properties"].items()
            if k not in _HONESTY_FIELDS
        },
        "receipt_version": {
            **RECEIPT_SCHEMA["properties"]["receipt_version"],
            "const": _VERSION_3_0,
        },
    },
    "required": [r for r in RECEIPT_SCHEMA["required"] if r not in _HONESTY_FIELDS],
}

_SCHEMAS = {
    RECEIPT_VERSION: RECEIPT_SCHEMA,
    _VERSION_3_0: _SCHEMA_3_0,
    _VERSION_2_0: _SCHEMA_2_0,
    _VERSION_1_1: _SCHEMA_1_1,
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


def build_assurance_receipt(deployment) -> dict:
    """The full, versioned assurance receipt for a deployment — the roadmap tuple
    (*system, version, policy, evidence, time, environment, result*) as one
    deterministic, portable, signable payload. See :data:`RECEIPT_SCHEMA` for the
    machine-readable shape and the module docstring for what it does and does not
    attest.

    It attests **integrity and provenance** — that this is the assurance state
    that was recorded, unaltered — and never that the conclusions are true or the
    system is secure. Every field is carried at its true strength: a
    ``needs_more_evidence`` result, or an undeclared policy, reads as exactly that.

    Deterministic: the digest is over stable content only (version, system,
    result, policy, evidence root, assessment digests). ``computed_at`` rides
    alongside as metadata, outside the hash, so the same DB state always yields
    the same digest. Prefetch ``findings__evidence`` and
    ``assets__provider__assertions`` and select_related ``data_boundary`` on the
    caller side to keep it query-light.

    The returned dict is the **canonical signable payload**: signing (Ed25519) is
    the engine's job, which owns the keys; this backend produces the object to be
    signed, not a signature."""
    # The evidence set E, reduced to its Merkle-style root. We keep only the
    # stable parts of the deployment receipt — the timestamp inside it is dropped
    # so no clock leaks into our digest.
    evidence_root = deployment_receipt(deployment)

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
