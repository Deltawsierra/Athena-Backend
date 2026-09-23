"""AI Incident Evidence Pack — a portable, verifiable pack for one incident.

Roadmap Phase 3.7. In this data model a :class:`~assurance.models.Finding` *is*
the incident: it is the concrete thing that went wrong, the anchor everything else
hangs off. This module assembles, from the stored assurance graph alone, a single
**portable, verifiable incident evidence pack** for one finding — the object the
roadmap describes as *"reconstruct request / identity / context / tools / actions /
logs; Achilles replays the incident against the fixed system."*

This backend's job is to **produce** that pack as a deterministic, documented,
signable object. The engine (Achilles) replays it separately — the replay is not
this module's job and nothing here reaches the engine or the network.

Like :mod:`assurance.receipt`, :mod:`assurance.operational` and
:mod:`assurance.ripple`, this is a **REUSE-ONLY assembler**: a pure function of the
stored graph, with no new model, no migration, and no new stored record. It reads
what already exists and binds it, and it re-uses its siblings rather than
re-deriving their work:

- **evidence** rows and the **finding receipt** come from :mod:`assurance.receipt`
  (:func:`~assurance.receipt._evidence_rows`, :func:`~assurance.receipt.finding_receipt`)
  — the digest discipline is inherited wholesale, not re-implemented;
- the **ripple** / blast-radius comes from :func:`assurance.ripple.assess_ripple`;
- the **decision** is the standing six-state ``Deployment.decision``, None-safe.

What the pack attests, and what it does not
-------------------------------------------

The pack attests **integrity and provenance** — *this is the incident evidence
that was recorded, unaltered.* It never attests that the incident conclusion is
true, that the vulnerability is real, or that the system is now secure or fixed.
Every field is carried at its true strength:

- evidence keeps its recorded class (``technically_verified`` down to
  ``vendor_asserted``); a ``vendor_asserted`` observation is transported faithfully
  and never reads as independently verified;
- a missing field is surfaced as an explicit gap (``false`` / ``None`` /
  ``"unmapped"``), never a fabricated value; a ratio with no basis is ``None``,
  never ``0%``;
- an incident with no decision, no owner or no evidence reads as an honest empty /
  ``None`` — never as "ready", "secure" or "passing".

The runtime transcript gap
--------------------------

The roadmap's *"request / response / tools / actions / logs"* is the turn-by-turn
**runtime transcript**, and that lives in the **engine's** evidence pack (Achilles
``evidence.py``), not in this backend's assurance graph. This module therefore does
**not** fabricate it. What the graph does hold is the *linkage* back to the engine
run — the :class:`~pentest.models.PentestScan` a finding was last observed in, with
its ``uuid`` and the engine's own ``engine_run_id``. The pack carries that
reference so Achilles can fetch and replay, and states the gap honestly
(``runtime_transcript.in_assurance_record = False``) rather than inventing turns
that were never recorded here.

Determinism
-----------

The pack digest is a SHA-256 over the pack's **stable content only** (canonical
JSON, sorted keys, compact separators — exactly :func:`assurance.receipt._digest`).
No timestamp is inside the hash, so the same DB state always yields the same
digest; ``computed_at`` rides alongside as metadata, outside the hash, exactly as
the receipts do. :data:`INCIDENT_PACK_SCHEMA` documents the shape as data (the
"documented + machine-readable" half), and :data:`INCIDENT_PACK_VERSION` versions
it. The returned dict is the **canonical signable payload** — signing (Ed25519)
is the engine's job, which owns the keys; this backend produces the object to be
signed, not a signature. A change to any stable field changes ``digest`` and so
invalidates any signature taken over it.

Prefetch ``evidence`` and ``remediation_events`` on the finding, and
select_related ``deployment``, ``asset__provider`` and ``scan`` on the caller side,
to keep it query-light.
"""

from __future__ import annotations

from django.utils import timezone

from .receipt import ALGORITHM, _digest, _evidence_rows, finding_receipt
from .ripple import assess_ripple

# The version of the AI Incident Evidence Pack standard this module emits. A stable
# string a consumer keys on to know which schema (below) it is reading; bump it only
# when the stable, hashed shape of the pack changes.
INCIDENT_PACK_VERSION = "mythos.assurance.incident-pack/1.0"

# The one thing the pack attests, stated on the wire and not only in the docstring.
# Integrity and provenance — never that the conclusion is true or the system secure.
ATTESTS = (
    "This pack attests integrity and provenance: this is the incident evidence that "
    "was recorded, unaltered. It does NOT attest that the incident conclusion is "
    "true, nor that the system is secure or fixed."
)


def _deployment_identity(deployment) -> dict:
    """The system the incident belongs to — name, uuid, environment, and the
    accountable owner's username, all None-safe. An unowned deployment reads as
    ``owner: None``, never as an invented name."""
    return {
        "name": deployment.name,
        "uuid": str(deployment.uuid),
        "environment": deployment.environment,
        "environment_label": deployment.get_environment_display(),
        # None-safe: a deployment with no owner reads as None, never a placeholder.
        "owner": deployment.owner.username if deployment.owner_id else None,
    }


def _finding_identity(finding) -> dict:
    """The incident's own identity, as stored. ``finding_type`` is the finding's
    category and ``title`` its stored title — carried verbatim, never re-worded into
    a stronger claim."""
    return {
        "uuid": str(finding.uuid),
        "fingerprint": finding.fingerprint,
        "category": finding.finding_type,
        "title": finding.title,
        "severity": finding.severity,
        "severity_label": finding.get_severity_display(),
        "status": finding.status,
        "status_label": finding.get_status_display(),
        # A pack headed "incident evidence" carries its own worst misreading. An
        # INVALIDATED finding in one reads as a confirmed incident unless the pack
        # says otherwise, and CONTAINED reads as handled. Served from the model's
        # one table (Finding.MUST_NOT_IMPLY) so the pack, the API and the console
        # cannot each word the caveat differently. None where the status has no
        # wrong reading worth naming -- absent, not empty.
        #
        # Read off the instance rather than through an import of .models: this
        # function already reaches into the finding for get_status_display(), and
        # MUST_NOT_IMPLY is that same class's table. It keeps this module free of a
        # models import, which is how the rest of it stays callable on any object
        # carrying these attributes.
        "status_must_not_imply": finding.MUST_NOT_IMPLY.get(finding.status),
    }


def _asset_surface(asset) -> dict | None:
    """The concrete component the finding touches — the tool / asset / route on the
    surface — as the graph relates it (``Finding.asset``). None-safe: a finding with
    no asset returns ``None`` (an explicit gap), never a fabricated component. Mirrors
    the node shape :func:`assurance.route._node` uses so a consumer sees one asset
    vocabulary across the assurance API."""
    if asset is None:
        return None
    provider = getattr(asset, "provider", None)
    return {
        "uuid": str(asset.uuid),
        "name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        # A blank identifier is a gap, not an empty-string fact.
        "identifier": asset.identifier or None,
        "provider": None
        if provider is None
        else {
            "name": provider.name,
            "kind": provider.kind,
            "kind_label": provider.get_kind_display(),
        },
    }


def _surface(finding) -> dict:
    """The incident's surface: the asset it touches (None-safe), the stored location
    it was observed at, and its control/framework mapping — read straight from the
    finding. The model relates a finding to a single component via ``Finding.asset``,
    so the surface is that component; no broader route is invented that the graph
    does not tie to this finding."""
    return {
        "asset": _asset_surface(finding.asset if finding.asset_id else None),
        "asset_present": finding.asset_id is not None,
        # A blank location is a gap, surfaced as None rather than "".
        "location": finding.location or None,
        # The stored control mapping (e.g. {"mitre": ["T1190"]}) exactly as recorded.
        "control_mapping": finding.control_mapping if isinstance(finding.control_mapping, dict) else {},
    }


def _evidence(finding) -> dict:
    """The finding's evidence at its **true strength**. The rows reuse
    :func:`assurance.receipt._evidence_rows` — ``[classification, source,
    content_hash]`` sorted, so the pack is independent of insertion order — and each
    class is carried verbatim. ``evidence_class`` is the finding's honest floor (the
    *weakest* class among its rows, via ``Finding.evidence_class``); it is never
    inflated, and a finding with no evidence reads as ``unknown`` with an empty row
    set, never as verified."""
    rows = _evidence_rows(finding)
    return {
        "algorithm": ALGORITHM,
        "rows": rows,
        "count": len(rows),
        # The weakest class behind the finding — a chain is only as strong as its
        # weakest link. UNKNOWN when nothing is attached, never a green default.
        "evidence_class": finding.evidence_class,
    }


def _finding_receipt_stable(finding) -> dict:
    """The finding's receipt (:func:`assurance.receipt.finding_receipt`) with its
    ``computed_at`` dropped, so the reused receipt contributes only its stable,
    timestamp-free content (algorithm + digest + evidence count) to the pack. The
    digest is recomputed by receipt.py, never re-hashed here — provenance stays
    single-sourced."""
    receipt = finding_receipt(finding)
    return {k: v for k, v in receipt.items() if k != "computed_at"}


def _engine_pack_ref(finding) -> dict:
    """The reference back to the **engine's** evidence pack, so Achilles can fetch
    and replay the runtime transcript this backend does not hold. The linkage that
    genuinely exists in the graph is ``Finding.scan`` — the
    :class:`~pentest.models.PentestScan` the finding was last observed in — carrying
    its ``uuid`` and the engine's own ``engine_run_id``. All None-safe: a finding
    with no scan link reads as ``available: False`` with null references, never an
    invented id."""
    if finding.scan_id is None:
        return {"available": False, "scan_uuid": None, "engine_run_id": None}
    scan = finding.scan
    return {
        "available": True,
        "scan_uuid": str(scan.uuid),
        # The engine's own id for the run — the key Achilles replays against. Blank
        # is a gap (older scans predate it), surfaced as None.
        "engine_run_id": scan.engine_run_id or None,
    }


def _runtime_transcript(finding) -> dict:
    """The runtime transcript, stated as the **explicit gap** it is. The turn-by-turn
    *request / response / tools / actions / logs* lives in the engine's evidence pack,
    not in this backend's assurance graph, so the pack never fabricates it: it records
    ``in_assurance_record: False`` and hands over the engine-pack reference so the
    replay can fetch it from where it actually lives."""
    return {
        "in_assurance_record": False,
        "see": "engine evidence pack",
        "reason": (
            "The turn-by-turn runtime transcript (request/response/tools/actions/logs) "
            "is recorded by the engine's evidence pack, not the assurance graph."
        ),
        "engine_pack_ref": _engine_pack_ref(finding),
    }


def _ripple(finding, deployment) -> dict:
    """The incident's ripple / blast radius, reusing
    :func:`assurance.ripple.assess_ripple` wholesale — no reachability is re-derived
    here, so the no-invented-reach guarantee is inherited.

    The deployment-wide assessment is sliced to this incident: the origin(s) this
    finding contributed to (matched by the finding's uuid) and the downstream
    consequences attributed to them. When this finding is not itself a traced origin
    — only an *active* high/critical finding tied to a component is — that reads
    honestly (``is_traced_origin: False`` with a note); the deployment-level ripple
    summary rides along as context, and no reach is attributed to this finding that
    the asset graph does not attest."""
    full = assess_ripple(deployment)
    finding_uuid = str(finding.uuid)

    incident_origins = [
        origin
        for origin in full["origins"]
        if any(fr["uuid"] == finding_uuid for fr in origin["findings"])
    ]
    origin_keys = {origin["key"] for origin in incident_origins}
    incident_consequences = [
        c for c in full["consequences"] if c["origin_key"] in origin_keys
    ]

    note = None
    if not incident_origins:
        note = (
            "This incident is not itself a traced blast-radius origin (only an active "
            "high/critical finding tied to a component is one). No downstream reach is "
            "attributed to it; the deployment-level ripple summary is included as context."
        )

    return {
        "is_traced_origin": bool(incident_origins),
        "origins": incident_origins,
        "consequences": incident_consequences,
        # The wider blast-radius context for the deployment the incident sits in.
        "deployment_summary": full["summary"],
        "note": note,
    }


def _decision(deployment) -> dict:
    """The deployment's standing six-state decision, None-safe. An unassessed
    deployment has no decision, and an absent decision is never read as "ready"."""
    return {
        "decision": deployment.decision,
        "decision_label": deployment.get_decision_display() if deployment.decision else None,
    }


def assemble_incident_pack(finding) -> dict:
    """Assemble the portable AI Incident Evidence Pack for one finding (the incident).

    Binds, into one deterministic, portable, signable payload: the deployment and
    finding **identity/context**; the **surface** (the asset/tool/route the finding
    touches, None-safe); the **evidence** at its true strength (rows + honest class);
    the reused finding **receipt** (integrity/provenance); the **runtime transcript**
    stated as an explicit gap with the engine-pack reference for replay; the
    **ripple** / blast radius (reused from :func:`assurance.ripple.assess_ripple`);
    and the standing six-state **decision**, None-safe.

    See :data:`INCIDENT_PACK_SCHEMA` for the machine-readable shape and the module
    docstring for what it does and does not attest. It attests **integrity and
    provenance** — that this is the incident evidence that was recorded, unaltered —
    never that the conclusion is true or the system secure/fixed. ``vendor_asserted``
    evidence stays ``vendor_asserted``; a missing field is a gap, never a fabricated
    value.

    Deterministic: the ``digest`` is a SHA-256 over the stable content only (no
    timestamp), so a fixed DB state always yields the same digest; ``computed_at``
    rides alongside as metadata, outside the hash. Reuse-only and side-effect-free —
    no new record, no migration. Prefetch ``evidence`` / ``remediation_events`` and
    select_related ``deployment`` / ``asset__provider`` / ``scan`` on the caller side.

    The returned dict is the **canonical signable payload**: signing is the engine's
    job; this backend produces the object to be signed, not a signature."""
    deployment = finding.deployment

    stable = {
        "pack_version": INCIDENT_PACK_VERSION,
        # What the pack attests — on the wire, not only in the docstring.
        "attests": ATTESTS,
        "identity": {
            "deployment": _deployment_identity(deployment),
            "finding": _finding_identity(finding),
        },
        "surface": _surface(finding),
        "evidence": _evidence(finding),
        "receipt": _finding_receipt_stable(finding),
        "runtime_transcript": _runtime_transcript(finding),
        "ripple": _ripple(finding, deployment),
        "decision": _decision(deployment),
    }

    return {
        **stable,
        "algorithm": ALGORITHM,
        # Reproducible over the stable content only — the value a signature covers.
        "digest": _digest(stable),
        # Metadata only, OUTSIDE the hash — exactly like the receipts here.
        "computed_at": timezone.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# The Incident Evidence Pack as a versioned, documented standard
# ---------------------------------------------------------------------------

# A machine-readable description of the pack shape — the "documented" half of
# "documented + machine-readable". Deliberately JSON-Schema-flavoured (types +
# descriptions) rather than a full validator: it travels with the pack so a
# consuming system can introspect the fields without parsing this docstring. It
# describes the CANONICAL, HASHED content plus the two metadata fields that ride
# outside the hash (``digest`` itself and ``computed_at``).
INCIDENT_PACK_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": INCIDENT_PACK_VERSION,
    "title": "Mythos AI Incident Evidence Pack",
    "type": "object",
    "description": (
        "A versioned, portable, reproducible pack for one incident (a Finding), "
        "assembled from the stored assurance graph. Attests integrity and provenance "
        "— that this is the incident evidence that was recorded, unaltered — never "
        "that the incident conclusion is true or the system is secure or fixed."
    ),
    "properties": {
        "pack_version": {
            "type": "string",
            "const": INCIDENT_PACK_VERSION,
            "description": "The version of this pack standard (see INCIDENT_PACK_VERSION).",
        },
        "attests": {
            "type": "string",
            "description": (
                "The one thing the pack attests: integrity and provenance, never the "
                "truth of the conclusion or the security of the system."
            ),
        },
        "identity": {
            "type": "object",
            "description": "The incident's identity/context: the deployment and the finding.",
            "properties": {
                "deployment": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "uuid": {"type": "string", "format": "uuid"},
                        "environment": {"type": "string"},
                        "environment_label": {"type": "string"},
                        "owner": {
                            "type": ["string", "null"],
                            "description": "Owner username, or null when unowned (never invented).",
                        },
                    },
                },
                "finding": {
                    "type": "object",
                    "description": "The finding IS the incident — its stored identity, verbatim.",
                    "properties": {
                        "uuid": {"type": "string", "format": "uuid"},
                        "fingerprint": {"type": "string"},
                        "category": {"type": "string", "description": "The stored finding_type."},
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                        "severity_label": {"type": "string"},
                        "status": {"type": "string"},
                        "status_label": {"type": "string"},
                        "status_must_not_imply": {
                            "type": ["string", "null"],
                            "description": (
                                "What this disposition must NOT be read as, where it "
                                "has a wrong reading worth naming. Null means the "
                                "status has none -- never that the caveat was dropped."
                            ),
                        },
                    },
                },
            },
        },
        "surface": {
            "type": "object",
            "description": (
                "The tools/assets/route the finding touches. The model relates a "
                "finding to one component via Finding.asset; 'asset' is null (an "
                "explicit gap) when none is tied, never a fabricated component."
            ),
            "properties": {
                "asset": {
                    "type": ["object", "null"],
                    "description": "The component the finding touches, or null (a gap).",
                },
                "asset_present": {"type": "boolean"},
                "location": {"type": ["string", "null"], "description": "Where observed, or null."},
                "control_mapping": {
                    "type": "object",
                    "description": "Stored control/framework mapping (e.g. MITRE technique ids).",
                },
            },
        },
        "evidence": {
            "type": "object",
            "description": (
                "The finding's evidence at its true strength. 'rows' are "
                "[classification, source, content_hash] sorted; each class is carried "
                "verbatim and never inflated. 'evidence_class' is the honest weakest "
                "class (UNKNOWN with no evidence, never a green default)."
            ),
            "properties": {
                "algorithm": {"type": "string", "const": ALGORITHM},
                "rows": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "string"}, "minItems": 3, "maxItems": 3},
                },
                "count": {"type": "integer"},
                "evidence_class": {"type": "string"},
            },
        },
        "receipt": {
            "type": "object",
            "description": (
                "The reused finding_receipt (integrity/provenance) minus its "
                "timestamp: the digest binding the finding's identity to its evidence "
                "hashes. Attests the evidence was recorded unaltered, not that it is true."
            ),
            "properties": {
                "algorithm": {"type": "string", "const": ALGORITHM},
                "digest": {"type": "string", "description": "64-hex SHA-256 over the finding's evidence."},
                "evidence_count": {"type": "integer"},
            },
        },
        "runtime_transcript": {
            "type": "object",
            "description": (
                "An EXPLICIT GAP, never fabricated. The turn-by-turn runtime "
                "transcript lives in the engine's evidence pack; this states so and "
                "carries the reference for replay."
            ),
            "properties": {
                "in_assurance_record": {
                    "type": "boolean",
                    "const": False,
                    "description": "Always false: this backend's graph does not hold the transcript.",
                },
                "see": {"type": "string"},
                "reason": {"type": "string"},
                "engine_pack_ref": {
                    "type": "object",
                    "description": "The linkage Achilles fetches/replays against (Finding.scan).",
                    "properties": {
                        "available": {"type": "boolean"},
                        "scan_uuid": {"type": ["string", "null"]},
                        "engine_run_id": {
                            "type": ["string", "null"],
                            "description": "The engine's own id for the run, or null (a gap).",
                        },
                    },
                    "required": ["available"],
                },
            },
            "required": ["in_assurance_record", "engine_pack_ref"],
        },
        "ripple": {
            "type": "object",
            "description": (
                "The incident's blast radius, reused from assurance.ripple. Sliced to "
                "the origin(s) this finding contributed to and their downstream "
                "consequences; 'is_traced_origin' is false (with a note) when this "
                "finding is not itself an origin. No reach is invented."
            ),
            "properties": {
                "is_traced_origin": {"type": "boolean"},
                "origins": {"type": "array", "items": {"type": "object"}},
                "consequences": {"type": "array", "items": {"type": "object"}},
                "deployment_summary": {"type": "object"},
                "note": {"type": ["string", "null"]},
            },
        },
        "decision": {
            "type": "object",
            "description": (
                "The deployment's standing six-state decision. Null when none has been "
                "computed (never silently read as ready)."
            ),
            "properties": {
                "decision": {"type": ["string", "null"]},
                "decision_label": {"type": ["string", "null"]},
            },
        },
        "algorithm": {"type": "string", "const": ALGORITHM},
        "digest": {
            "type": "string",
            "description": (
                "The SHA-256 over the stable content above (everything but algorithm, "
                "digest and computed_at) — reproducible, no timestamp inside. This is "
                "the value a signature is taken over."
            ),
        },
        "computed_at": {
            "type": "string",
            "format": "date-time",
            "description": "When this pack was rendered — metadata only, OUTSIDE the digest.",
        },
    },
    "required": [
        "pack_version",
        "attests",
        "identity",
        "surface",
        "evidence",
        "receipt",
        "runtime_transcript",
        "ripple",
        "decision",
        "algorithm",
        "digest",
        "computed_at",
    ],
}
