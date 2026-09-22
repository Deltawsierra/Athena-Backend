"""The vendor-coordination packet — what you hand a third party, and only that
(Phase 2 item 10).

The Assurance Receipt (:mod:`assurance.receipt`) is built for the customer: it
asserts a conclusion about *their* deployment, signed, with evidence digests
behind it. This is a different artifact for a different reader, and the roadmap
is precise about who that reader is:

    a narrower, more mechanical artifact than the full evidence receipt, built
    for handoff to someone with no deployment context.

Someone with no deployment context is the whole design constraint, and it cuts
two ways.

**They cannot fill in what we leave out.** A vendor engineer cannot infer the
affected version, guess which request to look up, or work out what we were unable
to observe. So the seven sections the roadmap names are REQUIRED, and a section
with nothing behind it is rendered as an explicit "not provided, because ..."
rather than dropped. A packet missing its limitations section silently claims we
saw everything; a packet that says "limitations: not provided" claims nothing.

**They are not entitled to the customer's internals.** The packet leaves the
customer's control, so it carries no deployment name, no tenant, no internal
hostname, no asset identifier, no owner. Request identifiers are the one thing a
vendor genuinely needs to look up on their side, and they travel as a salted
digest plus the raw *format* of the identifier, so the vendor can match their own
logs by asking rather than by receiving the customer's IDs wholesale.
:func:`build_vendor_packet` runs a redaction pass, and a guard enumerates the
rendered payload for anything that looks like a leak rather than trusting the
construction.

Three things the packet must never become
-----------------------------------------
**A verdict on the vendor's code.** Mythos observes a deployment from outside; it
cannot see the vendor's implementation and is in no position to conclude anything
about it. So the packet carries no PASS/FAIL, no severity judgment of the
vendor's product, and no CVE-style claim. It carries what we observed and the
question we cannot answer ourselves. The receipt concludes; the packet asks.

**A fix disguised as a containment step.** ``proposed_containment`` is a way to
limit a path, not a repair, and it says so in the payload. This is the same
distinction the ``Contained`` finding disposition draws: a control on a path is
not a removed defect, and a vendor reading "proposed fix" would reasonably assume
the reporter believes the problem is solved.

**A reproducer nobody ran.** ``reproduced`` is carried explicitly alongside the
steps. An unverified reproducer presented as verified wastes a vendor's time and
burns the reporter's credibility the first time it does not reproduce -- and
credibility is the only currency coordinated disclosure runs on.

Computed on read, like :func:`assurance.receipt.build_assurance_receipt` and
:func:`assurance.vendor.assess_vendors`: a pure function of stored state, no new
record and no migration.
"""

from __future__ import annotations

import hashlib
import re

from django.utils import timezone

from .models import Finding

PACKET_VERSION = "mythos.assurance.vendor_packet/1.0"

# The seven sections the roadmap names. Enumerated rather than spelled out at
# each call site so a section cannot be quietly dropped from the builder: the
# renderer walks this list, and a guard asserts the payload carries every one.
REQUIRED_SECTIONS = (
    "affected_version",
    "minimal_reproducer",
    "request_references",
    "observed_effect",
    "collection_limitations",
    "proposed_containment",
    "open_question",
)

# What a section says when there is nothing behind it. Never an empty string and
# never an absent key: both read as "nothing to say here", and the whole point of
# the limitations section is that silence is the failure mode.
NOT_PROVIDED = "not_provided"

# Identifier shapes we will not send to a third party. Enumerated so the guard
# can walk the rendered payload rather than trusting that each builder branch
# remembered to redact.
_LEAK_PATTERNS = (
    # An internal hostname or URL.
    re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
    re.compile(r"\b[\w-]+\.(?:internal|local|corp|intranet)\b", re.IGNORECASE),
    # A bare IPv4 address.
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # Cloud resource identifiers.
    re.compile(r"\barn:aws:[\w:/-]+", re.IGNORECASE),
    re.compile(r"\bprojects/[\w-]+/", re.IGNORECASE),
    # Anything that announces itself as a secret, INCLUDING its value. An earlier
    # version of this pattern stopped at the delimiter, so
    # "authorization: Bearer sk-live-..." had its LABEL redacted and its
    # credential shipped to the third party -- a redaction that made the payload
    # look sanitised while leaking the one thing that mattered. Found by a test
    # that pasted a real-looking header into an impact note, not by reading it.
    re.compile(
        r"\b(?:api[_-]?key|secret|token|password|authorization)\b\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    # A bare credential with no label in front of it.
    re.compile(r"\b(?:Bearer|Basic)\s+\S+", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{4,}", re.IGNORECASE),
)

_REDACTED = "[redacted]"


def _redact(text: str) -> str:
    """Replace anything matching a leak shape with a marker.

    Deliberately lossy and deliberately visible. A silently dropped identifier
    leaves the vendor reading a sentence with a hole in it and no idea a hole is
    there; ``[redacted]`` tells them something was removed and that they can ask
    for it through the customer.
    """
    out = str(text or "")
    for pattern in _LEAK_PATTERNS:
        out = pattern.sub(_REDACTED, out)
    return out


def _reference_digest(value: str, *, salt: str) -> str:
    """A stable, salted digest of a request identifier.

    Salted per packet so the digest cannot be used to confirm a guessed customer
    identifier by recomputation, and stable within one packet so a vendor can
    tell two references apart and ask about a specific one.
    """
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:16]


def _identifier_shape(value: str) -> str:
    """The FORM of an identifier without its content: a vendor can tell whether it
    is looking for a UUID or a numeric row id and say so, without us handing over
    the value."""
    raw = str(value or "")
    if not raw:
        return "empty"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        raw,
    ):
        return "uuid"
    if raw.isdigit():
        return f"numeric({len(raw)} digits)"
    if re.fullmatch(r"[0-9a-fA-F]+", raw):
        return f"hex({len(raw)} chars)"
    return f"opaque({len(raw)} chars)"


def _section(value, *, reason: str) -> dict:
    """One section, present either way.

    ``provided`` is the field a reader checks, and a missing section carries the
    REASON it is missing. "We did not collect this" and "there was nothing to
    collect" are different facts and a vendor triaging the report needs to be
    able to tell them apart.
    """
    text = str(value or "").strip()
    if not text:
        return {"provided": False, "status": NOT_PROVIDED, "reason": reason}
    return {"provided": True, "status": "provided", "value": _redact(text)}


def _implicated_provider(finding) -> dict | None:
    """The third-party component this finding implicates, if any.

    Read off the finding's asset, never guessed from the title. A packet built
    for a vendor who turns out not to be involved is worse than no packet.
    """
    asset = finding.asset
    if asset is None or asset.provider is None:
        return None
    provider = asset.provider
    return {
        "name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "region": provider.region or "",
        # The component class, NOT the customer's name for their instance of it.
        "component_kind": asset.kind,
        "component_kind_label": asset.get_kind_display(),
    }


def _affected_version(finding) -> str:
    """The version, read from whatever actually recorded one.

    Checked in order and reported as unknown rather than inferred: a version we
    guessed wrong sends a vendor to the wrong branch, which costs them more than
    a blank.
    """
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    for key in ("version", "component_version", "product_version"):
        value = str(raw.get(key) or "").strip()
        if value:
            return value
    asset = finding.asset
    if asset is not None and isinstance(asset.metadata, dict):
        for key in ("version", "revision", "image_digest"):
            value = str(asset.metadata.get(key) or "").strip()
            if value:
                return value
    return ""


def _request_references(finding, *, salt: str) -> dict:
    """Sanitized request identifiers: a digest and a shape, never the value.

    This is the section the roadmap calls "sanitized request IDs", and sanitized
    has to mean something. The vendor gets enough to ask "can you check the
    request whose reference is a1b2c3...?" and nothing they could use to
    enumerate the customer's traffic.
    """
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    candidates: list[str] = []
    for key in ("request_id", "request_ids", "trace_id", "operation_id"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
        elif isinstance(value, list):
            candidates.extend(str(v).strip() for v in value if str(v).strip())

    if not candidates:
        return {
            "provided": False,
            "status": NOT_PROVIDED,
            "reason": (
                "no request identifier was recorded with this finding; the vendor "
                "cannot be pointed at a specific request"
            ),
        }
    return {
        "provided": True,
        "status": "provided",
        "note": (
            "Each reference is a salted digest of an identifier held by the "
            "customer, not the identifier itself. Quote a reference back to the "
            "customer to have them look it up."
        ),
        "references": [
            {
                "reference": _reference_digest(c, salt=salt),
                "shape": _identifier_shape(c),
            }
            for c in sorted(set(candidates))
        ],
    }


def _collection_limitations(finding) -> dict:
    """What we could NOT see.

    Assembled from what the record actually says rather than written by hand, and
    always non-empty: the honest floor is that an external observer cannot see the
    vendor's implementation, which is true of every packet this builds and is
    exactly the limitation a vendor needs stated before they read our conclusions
    as claims about their code.
    """
    limits = [
        (
            "Observed from outside the vendor's system: no visibility into the "
            "vendor's implementation, internal logs, or infrastructure."
        ),
    ]
    if finding.confidence is None:
        limits.append(
            "No detector confidence was recorded for this finding; its strength is "
            "unquantified rather than low."
        )
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    declared = raw.get("collection_limitations")
    if isinstance(declared, list):
        limits.extend(_redact(str(item)) for item in declared if str(item).strip())
    elif isinstance(declared, str) and declared.strip():
        limits.append(_redact(declared.strip()))
    if not finding.evidence.exists():
        limits.append(
            "No evidence rows are attached to this finding; the observed effect "
            "below rests on the finding record alone."
        )
    return {"provided": True, "status": "provided", "limitations": limits}


def build_vendor_packet(finding: Finding, *, salt: str | None = None) -> dict:
    """Package one finding for handoff to the third party it implicates.

    Returns a payload carrying every section in :data:`REQUIRED_SECTIONS`,
    present whether or not there is content behind it, with the customer's
    identifying material redacted.

    ``complete`` says whether every section has content. It is reported, never
    enforced: an incomplete packet is often exactly what you send first, and
    blocking on completeness would push a reporter into filling sections in with
    guesses -- which is the failure this whole artifact exists to avoid.
    """
    salt = salt or str(finding.uuid)
    provider = _implicated_provider(finding)
    raw = finding.raw if isinstance(finding.raw, dict) else {}

    sections = {
        "affected_version": _section(
            _affected_version(finding),
            reason=(
                "no version was recorded for the implicated component; it was not "
                "inferred, because a wrong version sends the vendor to the wrong code"
            ),
        ),
        "minimal_reproducer": {
            **_section(
                raw.get("reproducer"),
                reason=(
                    "no reproducer was recorded; the observed effect below is a "
                    "report of what was seen, not a recipe"
                ),
            ),
            # Carried beside the steps, always, and defaulting to False. A
            # reproducer nobody ran, presented as one, costs the vendor a day and
            # the reporter their credibility.
            "reproduced": bool(raw.get("reproduced", False)),
            "reproduced_note": (
                "True only where the steps were executed and the effect observed "
                "again. False means the steps are a best reconstruction."
            ),
        },
        "request_references": _request_references(finding, salt=salt),
        "observed_effect": _section(
            finding.impact or finding.title,
            reason="nothing was recorded about what was observed",
        ),
        "collection_limitations": _collection_limitations(finding),
        "proposed_containment": {
            **_section(
                raw.get("proposed_containment") or finding.recommendation,
                reason=(
                    "no containment step is proposed; this is a question for the "
                    "vendor rather than a change the customer can make"
                ),
            ),
            # Said in the payload, not just in this docstring: a vendor reading
            # "proposed fix" would reasonably assume we think it is solved.
            "note": (
                "A containment step limits a path. It does not remove the "
                "underlying defect and is not proposed as a fix."
            ),
        },
        "open_question": _section(
            raw.get("open_question"),
            reason=(
                "no specific question was recorded; without one this is a report "
                "rather than a coordination request, and the vendor has nothing "
                "to answer"
            ),
        ),
    }

    return {
        "packet_version": PACKET_VERSION,
        "built_at": timezone.now().isoformat(),
        # The finding's stable identity, so the customer and the vendor can refer
        # to the same thing. Not the deployment's.
        "finding_reference": _reference_digest(str(finding.uuid), salt=salt),
        "finding_type": finding.finding_type,
        "title": _redact(finding.title),
        "implicated_component": provider,
        "sections": sections,
        "complete": all(
            sections[name].get("provided") is True for name in REQUIRED_SECTIONS
        ),
        "missing_sections": [
            name for name in REQUIRED_SECTIONS if not sections[name].get("provided")
        ],
        # Said in every packet, because a vendor receiving a security report from
        # a security vendor will otherwise read it as a verdict.
        "scope_note": (
            "This packet reports what was observed from outside the vendor's "
            "system and asks a question. It is not an assessment of the vendor's "
            "product, carries no pass/fail conclusion, and asserts nothing about "
            "the vendor's implementation, which was not observed."
        ),
    }


def packet_candidates(deployment) -> list[Finding]:
    """The findings on this deployment that implicate a third-party component.

    Membership is read off the asset -> provider edge, never inferred from a
    title or a finding type. A packet sent to a vendor who is not involved is
    worse than no packet: it spends credibility on a false alarm.
    """
    return [
        finding
        for finding in deployment.findings.select_related("asset__provider").all()
        if finding.asset is not None and finding.asset.provider is not None
    ]
