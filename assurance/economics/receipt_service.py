"""The signed Financial Exposure Receipt of a stored simulation result (MVP step 8;
``docs/economics/spec-v1.md``, section 26.5), built with
``mythos_core.exposure_receipt`` (``mythos.financial-exposure-receipt/v1``).

:func:`issue_receipt` takes one completed
:class:`~assurance.economics.models.SimulationResult`, its Validity Card (issued
first where none is recorded), and binds them in one document:

- the scenario and the tenant (the deployment: a Deployment is the tenant);
- the SPINE system fingerprint the card names;
- the model release: its version token and the digest of every version, limit,
  method and threshold the figures, the analysis, the grade and the card rest on;
- the seed, the draws and the run's input digest (every parameter the run read,
  with its figures, source and distribution, and every version: the receipt's
  ``parameter_set_digest``);
- the source snapshots the run read, each with a content hash recomputed from its
  stored rows: the customer parameter-set version, the scenario build, and the
  scenario version's own parameters;
- the SPINE evidence: the assets (nodes) and the SPINE effects of the scenario;
- the headline figures (retained cash under a policy, gross cash otherwise),
  rounded to the currency's minor unit as shown;
- the Validity Card's digest and grade.

It is SIGNED on the path the backend's signed assurance receipts take: the
backend holds no signing key, and asks the engine (``CyberEngineClient``) to
sign. The envelope that comes back must be exactly one signature over exactly the
document, under the receipt's own payload type, and it must VERIFY with core's
verifier against the caller's ``ReceiptKeyring`` of the engine's published
economics-receipt keys (:func:`keyring_from_published`) before it is stored: no
signature nobody has checked is ever recorded, and without a keyring nothing is
recorded or returned. A signer can be handed in (the tests' keys).

The receipt is recorded append-only, one per result: the same result returns
the same row, where it verifies; one that does not is never returned, and never
overwritten. A receipt that cannot be built (no expected annual exposure without
a frequency, no system fingerprint, a seed past 2^53 - 1, a stored snapshot whose
digest no longer reproduces) or signed is returned with its code and never
recorded. **Never raises.**

:func:`verify_stored_receipt` verifies a stored receipt against a
``ReceiptKeyring`` and refuses, with a code, a forged or wrongly keyed envelope
(core's verdicts), a row moved or relabelled, a card that is not the one it names, a
result whose inputs, record or figures changed, a source snapshot, model build or
evidence that no longer reproduces, a stored analysis that is not the one the card
signs, and a card that its stored rows no longer rebuild under the release it was
made under. A change of today's release is the note ``release_changed`` on an
otherwise authentic receipt, never tampering, with ``card_not_rebuilt``: the card
was then not rebuilt, though its analysis was still checked.

Nothing here is on a stop path; nothing Django loads at start imports it, and it
imports ``mythos_core.exposure_receipt`` and the engine only when called.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import date

from django.db import IntegrityError, transaction

from . import validity_service
from .engine.money import Money
from .models import (
    SIMULATION_COMPLETED,
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossEvent,
    ScenarioBuild,
    SimulationResult,
    canonical_digest,
)

#: The receipt's six figures, in core's order.
FIGURES = ("p10", "p50", "p90", "mean", "expected_annual_exposure", "severe_plausible")

#: What each code of this service means. Core's own codes (its verdicts, and the
#: codes of ``exposure_receipt.MALFORMED_CODES``, ``CARD_CODES`` and
#: ``KEYRING_CODES``) are returned as core's.
REFUSALS = {
    "result_not_completed": "a receipt is made for a completed run: a refused run has no figures to sign",
    "residual_not_receipted": (
        "a receipt is made for a scenario's own run: a residual run under a remediation option (section 28) is "
        "the scenario as the option would leave it, never its exposure, and is not receipted"
    ),
    "receipt_figure_unavailable": (
        "every one of the receipt's six figures exists for the run: a run without a frequency has no expected "
        "annual exposure, and one with an infinite mean no mean; none is estimated"
    ),
    "system_fingerprint_unavailable": "the card names no SPINE system fingerprint for the receipt to bind",
    "source_snapshot_mismatch": "a source snapshot's stored rows no longer give the content hash it was recorded with",
    "signer_unavailable": (
        "nothing could sign the receipt: the engine was not reached or timed out, has no key in the role, or "
        "serves no signing route"
    ),
    "receipt_refused_by_signer": (
        "the signer read the receipt and refused it: core's validator, run by the engine before it signs, refused the "
        "document with the code carried beside this one where it is one of core's (exposure_receipt.MALFORMED_CODES); "
        "a code that is not core's is shown in the detail and carried as no code of core's"
    ),
    "envelope_not_over_receipt": (
        "what the signer returned is not one signature over exactly the receipt, under the receipt's payload type"
    ),
    "card_unavailable": "the result has no Validity Card, and none could be issued",
    "keyring_unavailable": (
        "no receipt keyring to check the signature with: a receipt is recorded, or a recorded one returned, only "
        "once its signature verifies against the engine's published economics-receipt keys"
    ),
    "recorded_receipt_unverified": (
        "the receipt recorded for this result does not verify: it is not returned, and never overwritten"
    ),
    "receipt_row_mismatch": (
        "the stored row's deployment, scenario, result, card, receipt id, key id or instant are not the ones its "
        "result, card, document and envelope name"
    ),
    "receipt_failed": "an unexpected fault: nothing was recorded",
    "receipt_mismatch": "the stored document is not the payload the envelope signs, or names another scenario or tenant",
    "result_digest_mismatch": (
        "the stored result's inputs no longer give its input digest, or its record its result digest (the reason "
        "names which was compared)"
    ),
    "result_mismatch": "the receipt's or the card's figures, seed, draws or digests are not the stored result's",
    "model_build_mismatch": "the stored result's versions no longer give the model release the receipt names",
    "evidence_mismatch": "the scenario's stored effects no longer give the SPINE evidence the receipt names",
    "fingerprint_mismatch": "the receipt binds another system fingerprint than its card names",
    "card_not_reproduced": "the stored result, analysis and rows no longer rebuild the stored card",
    "sensitivity_digest_mismatch": (
        "the stored sensitivity analysis is not the one the card signs (its reproduction.sensitivity_digest), "
        "whatever the release"
    ),
    "verification_failed": "an unexpected fault while verifying: nothing is vouched for",
}


class ReceiptRefused(ValueError):
    """A receipt this service will not build. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


@dataclass(frozen=True)
class ReceiptOutcome:
    """What :func:`issue_receipt` gives: the recorded receipt (``None`` when
    nothing was recorded), whether this call recorded it, and the refusal."""

    receipt: FinancialExposureReceipt | None
    created: bool
    code: str | None = None
    detail: str = ""
    #: Where the signer refused the document (``receipt_refused_by_signer``): the
    #: code of the rule it refused it by, core's (``mythos_core.exposure_receipt``).
    signer_code: str | None = None


@dataclass(frozen=True)
class ReceiptCheck:
    """What :func:`verify_stored_receipt` concluded: ``verified`` only when every
    check passed; otherwise the code of the first that failed, and why."""

    verified: bool
    code: str
    reason: str
    #: What is true of an otherwise authentic receipt and is not tampering:
    #: ``release_changed`` where today's release differs from the one it was made
    #: under, and with it ``card_not_rebuilt``: today's code did not rebuild the card
    #: (its stored analysis was still checked against the digest the card signs).
    notes: tuple[str, ...] = ()


def _core():
    from mythos_core import exposure_receipt
    from mythos_core.outcome import canonical_bytes

    return exposure_receipt, canonical_bytes


# ------------------------------------------------------------- the inputs


def source_snapshots(scenario: FinancialScenario) -> list[dict]:
    """The source snapshots the scenario version's run read, each with its content
    hash recomputed from its stored rows (``source_snapshot_mismatch`` where a
    recorded digest no longer reproduces): the customer parameter-set version its
    build names, the build itself, and the scenario version's own parameters."""
    from .builder import build_digest

    snapshots = []
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    if build is not None:
        version = CustomerParameterSet.objects.get(pk=build.parameter_set_id)
        if not version.intact():
            raise ReceiptRefused("source_snapshot_mismatch", f"parameter set {version.set_key} v{version.version}")
        snapshots.append(
            {"snapshot_id": f"parameter-set:{version.set_key}:{version.version}", "content_hash": version.content_digest}
        )
        if build_digest(build.inputs) != build.build_digest:
            raise ReceiptRefused("source_snapshot_mismatch", f"scenario build {build.uuid}")
        snapshots.append({"snapshot_id": f"scenario-build:{scenario.uuid}", "content_hash": build.build_digest})
    rows = FinancialParameter.objects.filter(scenario=scenario).order_by("name", "id")
    parameters = [
        {
            "name": row.name,
            "unit": row.unit,
            "source_type": row.source_type,
            "currency": row.currency,
            "low": row.low,
            "base": row.base,
            "high": row.high,
            "evidence_ref": row.evidence_ref,
            "effective_date": row.effective_date.isoformat(),
            "fresh_until": row.fresh_until.isoformat() if row.fresh_until else None,
            "distribution": row.distribution,
            "derived_from": list(row.derived_from),
        }
        for row in rows
    ]
    snapshots.append(
        {"snapshot_id": f"scenario-parameters:{scenario.uuid}", "content_hash": canonical_digest(parameters)}
    )
    return sorted(snapshots, key=lambda s: s["snapshot_id"])


def spine_evidence(scenario: FinancialScenario) -> dict:
    """The SPINE references the scenario rests on: its effects' assets (nodes) and
    SPINE effects. Claims are not linked to a scenario yet."""
    effects = list(CausalEffect.objects.filter(scenario=scenario))
    events = list(LossEvent.objects.filter(scenario=scenario))
    spine = {e.spine_effect for e in effects if e.spine_effect} | {e.effect for e in events if e.effect}
    if scenario.causal_effect:
        spine.add(scenario.causal_effect)
    return {"nodes": sorted({e.asset for e in effects}), "effects": sorted(spine), "claims": []}


def _figures(result: SimulationResult) -> dict:
    record = result.record
    block = record["scenario"][record["scenario"]["headline"]]
    currency = record["reporting_currency"]
    figures = {}
    for name in FIGURES:
        value = block.get(name)
        if value is None:
            raise ReceiptRefused("receipt_figure_unavailable", f"{name} (basis {record['basis']})")
        figures[name] = format(Money.parse(value, currency).display_amount(), "f")
    return figures


def _valuation_date(result: SimulationResult, scenario: FinancialScenario) -> date:
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    if build is not None:
        return build.as_of
    dates = [c["as_of"] for event in result.inputs["events"] for c in event["components"]]
    return date.fromisoformat(max(dates))


def _fields(result: SimulationResult, card: FinancialValidityCard) -> dict:
    """Every argument of core's ``build_receipt`` that the stored rows decide: the
    same rows give the same values (a receipt's id and instant are its own)."""
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    from assurance.models import Deployment

    deployment = Deployment.objects.get(pk=result.deployment_id)
    fingerprint = card.card["fields"]["system_fingerprint"]["value"]
    if not fingerprint:
        raise ReceiptRefused("system_fingerprint_unavailable", card.card["fields"]["system_fingerprint"]["statement"])
    # The release the card records it was made under, never today's.
    release = card.card["fields"]["model_version"]
    return {
        "scenario_id": str(scenario.uuid),
        "tenant_id": str(deployment.uuid),
        "system_fingerprint": fingerprint,
        "model_version": release["version"],
        "model_build_digest": release["build_digest"],
        "seed": int(result.seed),
        "draws": result.draws,
        "parameter_set_digest": result.input_digest,
        "sources": source_snapshots(scenario),
        "evidence": spine_evidence(scenario),
        "reporting_currency": result.record["reporting_currency"],
        "valuation_date": _valuation_date(result, scenario),
        "figures": _figures(result),
        "validity_card": card.card,
    }


# ------------------------------------------------------------------ signing


#: Published keys of these statuses verify; a revoked key verifies nothing (the
#: engine's artifact keyring, ``engine.evidence.keyring``).
VERIFYING_STATUSES = frozenset({"active", "retired"})


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
            except (binascii.Error, ValueError) as error:
                raise ValueError(f"key {key_id!r}'s public_key is not base64: {error}") from None
    return keys


#: The role of the engine's own ``keys`` in its published keyring: the key that
#: signs evidence packs and assurance receipts, never a Financial Exposure Receipt.
ARTIFACT_ROLE = "artifact"


def keyring_from_published(published):
    """The ``ReceiptKeyring`` a receipt is checked with, from the document the engine
    publishes at ``GET /api/assurance/keyring`` (athena-engine #88): its ``keys``
    are the artifact role's, and ``roles`` holds each other signing role's keyring
    in the same form (``keys`` by key id, each a base64 ``public_key`` and a
    ``status``) -- ``economics-receipt`` among them. The economics-receipt role's
    active and retired keys are the receipt keys; the artifact keys and every other
    role's are filed under their roles, so a receipt one of them signed is refused
    as ``wrong_role``. A revoked key verifies nothing and is left out. Raises
    ``ValueError`` (or core's ``ReceiptError``) for a document without the
    economics-receipt role, or one it cannot read: an entry with no status it
    publishes, or a verifying one with no base64 ``public_key`` text."""
    core, _ = _core()
    if not isinstance(published, dict) or not isinstance(published.get("roles"), dict):
        raise ValueError("the published keyring has no roles")
    roles = published["roles"]
    if core.ECONOMICS_RECEIPT_ROLE not in roles:
        raise ValueError(f"the published keyring has no {core.ECONOMICS_RECEIPT_ROLE} role")
    others = {ARTIFACT_ROLE: _published_keys(published)}
    for role, document in sorted(roles.items()):
        if role != core.ECONOMICS_RECEIPT_ROLE:
            others[role] = _published_keys(document)
    return core.receipt_keyring(_published_keys(roles[core.ECONOMICS_RECEIPT_ROLE]), other_roles=others)


def engine_keyring():
    """:func:`keyring_from_published` over the keyring the engine publishes now
    (``CyberEngineClient.assurance_keyring``). A keyring fetched from the engine that
    signs establishes that the engine signed in the receipt role, not more: an
    auditor verifies against one fetched out of band, as the engine's own caveat
    says."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return keyring_from_published(CyberEngineClient.from_settings().assurance_keyring())


def engine_signer(document: dict) -> dict:
    """Sign ``document`` on the path the backend's signed assurance receipts take:
    the engine holds the key, and this backend asks it
    (:meth:`CyberEngineClient.sign_exposure_receipt`)."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient.from_settings().sign_exposure_receipt(document)


def envelope_problem(document: dict, envelope) -> str | None:
    """Why ``envelope`` is not one signature over exactly ``document`` under the
    receipt's payload type, or ``None``."""
    core, canonical_bytes = _core()
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        return "not an envelope of exactly payloadType, payload and signatures"
    if envelope["payloadType"] != core.RECEIPT_PAYLOAD_TYPE:
        return f"payload type {envelope['payloadType']!r}"
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (TypeError, ValueError, binascii.Error):
        return "a payload that is not base64"
    if payload != canonical_bytes(document):
        return "a payload that is not the receipt's canonical bytes"
    signatures = envelope["signatures"]
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
        or set(signatures[0]) != {"keyid", "sig"}
        or not isinstance(signatures[0]["keyid"], str)
    ):
        return "not exactly one signature with a key id"
    return None


# -------------------------------------------------------------------- issue


def issue_receipt(result: SimulationResult, *, keyring=None, signer=None) -> ReceiptOutcome:
    """The signed receipt of ``result``: the one recorded, where it verifies against
    ``keyring``, or one built, signed by ``signer`` (the engine unless given),
    verified against ``keyring`` and only then recorded. ``keyring`` is the
    ``ReceiptKeyring`` of the engine's published economics-receipt keys
    (:func:`keyring_from_published`); without one nothing is recorded or returned
    (``keyring_unavailable``). Never raises: see the module's rules."""
    try:
        return _issue(result, signer or engine_signer, keyring)
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        return ReceiptOutcome(None, False, "receipt_failed", f"{type(error).__name__}: {error}")


def _issue(result: SimulationResult, signer, keyring) -> ReceiptOutcome:
    if result.remediation_id is not None:
        # Before anything is read, signed or recorded: a residual run is not exposure.
        return ReceiptOutcome(None, False, "residual_not_receipted", f"remediation option {result.remediation_id}")
    try:
        core, _ = _core()
    except Exception as error:  # noqa: BLE001 - an import fault is a returned refusal
        return ReceiptOutcome(None, False, "receipt_failed", f"{type(error).__name__}: {error}")
    if type(keyring) is not core.ReceiptKeyring:
        return ReceiptOutcome(None, False, "keyring_unavailable", f"a {type(keyring).__name__}, not a ReceiptKeyring")
    found = FinancialExposureReceipt.objects.filter(simulation=result).first()
    if found is not None:
        # A recorded receipt is returned only where it verifies: one that does not
        # is said so, never returned as the result's receipt, and never overwritten.
        check = verify_stored_receipt(found, keyring)
        if not check.verified:
            return ReceiptOutcome(None, False, "recorded_receipt_unverified", f"{check.code}: {check.reason}")
        return ReceiptOutcome(found, False)
    if result.status != SIMULATION_COMPLETED:
        return ReceiptOutcome(None, False, "result_not_completed", f"refused: {result.refusal_code}")
    issued = validity_service.issue_card(result)
    if issued.card is None:
        return ReceiptOutcome(None, False, issued.code or "card_unavailable", issued.detail)
    card = issued.card
    try:
        document = core.build_receipt(**_fields(result, card))
    except (ReceiptRefused, EconomicsRefused) as refused:
        return ReceiptOutcome(None, False, refused.code, refused.detail)
    except core.ReceiptError as refused:
        return ReceiptOutcome(None, False, refused.code, str(refused))
    try:
        envelope = signer(document)
    except Exception as error:  # noqa: BLE001 - a signer fault is a returned refusal: which one, below
        refused = _signer_refusal(error)
        if refused is not None:
            # The signer read the document and refused it: not that nothing could
            # sign. Core's rule is carried only where the code is one of core's own;
            # any other code is shown, never passed off as core's.
            code, reason = refused
            if code in core.MALFORMED_CODES:
                return ReceiptOutcome(None, False, "receipt_refused_by_signer", f"{code}: {reason}", signer_code=code)
            return ReceiptOutcome(
                None, False, "receipt_refused_by_signer",
                f"the signer refused the document with {code!r}, which is not one of core's codes: {reason}",
            )
        status = getattr(error, "status", None)
        return ReceiptOutcome(None, False, "signer_unavailable",
                              type(error).__name__ + ("" if status is None else f" (status {status})"))
    problem = envelope_problem(document, envelope)
    if problem is not None:
        return ReceiptOutcome(None, False, "envelope_not_over_receipt", problem)
    # Never record a signature nobody has checked: core's verifier, against the
    # published keys, before the row is written.
    verdict = core.verify_receipt(envelope, keyring, card=card.card)
    if not verdict.authentic:
        return ReceiptOutcome(None, False, verdict.code, verdict.reason)
    row = FinancialExposureReceipt(
        deployment_id=result.deployment_id,
        scenario_id=result.scenario_id,
        simulation=result,
        card=card,
        receipt_id=document["receipt_id"],
        document=document,
        envelope=envelope,
        key_id=envelope["signatures"][0]["keyid"],
        generated_at=_instant(document["generated_at"]),
    )
    try:
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            return ReceiptOutcome(None, False, raced.code, raced.detail)
        found = FinancialExposureReceipt.objects.filter(simulation=result).first()
        if found is None:
            raise
        check = verify_stored_receipt(found, keyring)
        if not check.verified:
            return ReceiptOutcome(None, False, "recorded_receipt_unverified", f"{check.code}: {check.reason}")
        return ReceiptOutcome(found, False)
    return ReceiptOutcome(row, True)


def _signer_refusal(error) -> tuple[str, str] | None:
    """Core's code and reason where the signer refused the document itself (the
    engine client's ``ExposureReceiptRefused``), or None for any other failure."""
    try:
        from ai_engine.services.cyberengine_client import ExposureReceiptRefused
    except ImportError:
        return None
    if isinstance(error, ExposureReceiptRefused):
        return error.code, error.reason
    return None


def _instant(text: str):
    from datetime import datetime

    return datetime.fromisoformat(text[:-1] + "+00:00")


# ------------------------------------------------------------------- verify


def _refused(code: str, reason: str = "") -> ReceiptCheck:
    return ReceiptCheck(False, code, reason or REFUSALS.get(code, code))


def verify_stored_receipt(receipt: FinancialExposureReceipt, keyring) -> ReceiptCheck:
    """Verify a stored receipt against ``keyring`` (a ``ReceiptKeyring``), and
    everything it names against the stored rows. Never raises: see the module's
    rules."""
    try:
        return _verify(receipt, keyring)
    except Exception as error:  # noqa: BLE001 - a verifier gives a verdict, never an exception
        return _refused("verification_failed", f"{type(error).__name__}: {error}")


def _verify(receipt: FinancialExposureReceipt, keyring) -> ReceiptCheck:
    core, _ = _core()
    card = FinancialValidityCard.objects.get(pk=receipt.card_id)
    result = SimulationResult.objects.get(pk=receipt.simulation_id)
    # 1. The signature, the key's role, the schema, and the card it names (core).
    verdict = core.verify_receipt(receipt.envelope, keyring, card=card.card)
    if not verdict.authentic:
        return _refused(verdict.code, verdict.reason)
    document = verdict.receipt
    # 2. The row is the one its result, card, document and envelope name.
    row = (receipt.deployment_id, receipt.scenario_id, receipt.simulation_id, receipt.receipt_id, receipt.key_id,
           receipt.generated_at)
    named = (result.deployment_id, result.scenario_id, card.simulation_id, document["receipt_id"],
             receipt.envelope["signatures"][0]["keyid"], _instant(document["generated_at"]))
    if row != named or (card.deployment_id, card.scenario_id) != (result.deployment_id, result.scenario_id) \
            or verdict.key_id != receipt.key_id:
        return _refused("receipt_row_mismatch")
    if document != receipt.document:
        return _refused("receipt_mismatch", "the stored document is not the signed payload")
    # 3. The result: its inputs and its record still give their digests, and the
    # card and the receipt name its figures, seed, draws and digests.
    if result.status != SIMULATION_COMPLETED:
        return _refused("result_digest_mismatch", f"the stored result is {result.status}, not completed")
    if canonical_digest(result.inputs) != result.input_digest:
        return _refused(
            "result_digest_mismatch",
            "the stored result's inputs no longer give its input digest (compared: the canonical digest of "
            "result.inputs with result.input_digest)",
        )
    if canonical_digest(result.record) != result.result_digest:
        return _refused(
            "result_digest_mismatch",
            "the stored result's record no longer gives its result digest (compared: the canonical digest of "
            "result.record with result.result_digest)",
        )
    reproduction = card.card["fields"]["reproduction"]
    held = (
        reproduction["result_digest"],
        reproduction["input_digest"],
        reproduction["outcomes_sha256"],
        document["simulation"]["seed"],
        document["simulation"]["draws"],
        document["simulation"]["parameter_set_digest"],
    )
    stored = (
        result.result_digest,
        result.input_digest,
        result.record["outcomes_sha256"],
        int(result.seed),
        result.draws,
        result.input_digest,
    )
    if held != stored:
        return _refused("result_mismatch", "a digest, the seed or the draws are not the stored result's")
    try:
        figures = _figures(result)
    except ReceiptRefused:
        return _refused("result_mismatch", "the stored result has no figure the receipt names")
    if {name: document["result"][name]["amount"] for name in FIGURES} != figures:
        return _refused("result_mismatch", "the receipt's figures are not the stored result's")
    # 4. The identity, the model build (the release the card records), the source
    # snapshots and the evidence.
    fields = _fields_or_refusal(result, card)
    if isinstance(fields, ReceiptCheck):
        return fields
    if (document["scenario_id"], document["tenant_id"]) != (fields["scenario_id"], fields["tenant_id"]):
        return _refused("receipt_mismatch", "another scenario or tenant")
    if document["system_fingerprint"] != fields["system_fingerprint"]:
        return _refused("fingerprint_mismatch")
    recorded = card.card["fields"]["model_version"]
    release = recorded.get("release") or {}
    if (
        document["model"] != {"version": recorded["version"], "build_digest": recorded["build_digest"]}
        or canonical_digest(release) != recorded["build_digest"]
        or release.get("engine") != result.versions
    ):
        return _refused("model_build_mismatch")
    if document["sources"] != fields["sources"]:
        return _refused("source_snapshot_mismatch", "a source snapshot's content hash is not the one signed")
    if document["evidence"] != fields["evidence"]:
        return _refused("evidence_mismatch")
    # 5. The card. Its stored analysis is the one it signs, whatever the release
    # (its digest does not depend on the code). Where the code is today's release,
    # its stored rows rebuild the card exactly. Where the release has changed since,
    # today's code cannot rebuild it: that is said beside the verdict -- the card was
    # not rebuilt -- and never read as tampering.
    signed = card.card["fields"]["reproduction"].get("sensitivity_digest")
    if (None if card.sensitivity is None else canonical_digest(card.sensitivity)) != signed:
        return _refused("sensitivity_digest_mismatch")
    if validity_service.release_changed(card):
        return ReceiptCheck(
            True,
            core.AUTHENTIC,
            "verified: the signature, the row, the result, every snapshot and the stored analysis against the digest "
            "the card signs; the card itself was NOT rebuilt: the release has changed since it was made, and today's "
            "code cannot rebuild it",
            ("release_changed", "card_not_rebuilt"),
        )
    if not validity_service.reproduces(card):
        return _refused("card_not_reproduced")
    return ReceiptCheck(
        True, core.AUTHENTIC, "verified: the signature, the row, the card, the result and every snapshot"
    )


def _fields_or_refusal(result, card):
    try:
        return _fields(result, card)
    except (ReceiptRefused, EconomicsRefused) as refused:
        return _refused(refused.code if refused.code in REFUSALS else "receipt_mismatch", refused.detail)


__all__ = [
    "FIGURES",
    "REFUSALS",
    "ReceiptCheck",
    "ReceiptOutcome",
    "ReceiptRefused",
    "engine_signer",
    "envelope_problem",
    "issue_receipt",
    "engine_keyring",
    "keyring_from_published",
    "source_snapshots",
    "spine_evidence",
    "verify_stored_receipt",
]
