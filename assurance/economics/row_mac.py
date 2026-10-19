"""Row MACs: a simulation result and its Validity Card bound by a key the database
never holds (review round 1 of #169, M1; ``docs/economics/spec-v1.md``, section 35.9).

The digests a result and a card carry are plain hashes: someone who can write the
database can rewrite a record AND its digest, and the card's reproduction AND the
card's digest, before any receipt (the reviewer's P1b, P1c), or after one together
with the receipt row (P1d), and every plain check still passes. A MAC keyed by
:data:`ROW_KEY_ENV` closes that: each row records, at insert, an HMAC-SHA256 over
its identity and its digests (:func:`result_mac`, :func:`card_mac`), and every read,
card and receipt recomputes it (``assurance.economics.report``, checks
``result_mac`` and ``card_mac``). A row rewritten past the records' rules -- or
with its MAC blanked -- no longer verifies, and is served as a refusal, never as a
number. The database holds the MACs, never the key.

The key is read from the environment, in code, exactly as
``ATHENA_ECONOMICS_RECEIPT_REVIEW`` is (:func:`assurance.economics.review_service.review_gate`):
never from a settings module and never from the database. A value shorter than
:data:`ROW_KEY_MIN_CHARS` is no key. WITHOUT a key:

- a new result or card is recorded with no MAC (its ``row_mac`` is empty);
- the MAC checks are not run: a report lists only the checks it ran
  (:func:`assurance.economics.report.integrity_checks`), so it never claims one;
- NO receipt is signed (``row_key_unavailable``): the delivered figure needs the
  binding. A receipt recorded earlier is still served as stored;
- nothing on a stop path changes: no stop reads this module, and nothing Django
  loads at start calls it.

WITH a key, a row without a MAC (recorded while there was none, or blanked) fails its
check like a rewritten one. Rows recorded before the key was provisioned are bound
once by ``manage.py bind_economics_rows`` (:func:`bind_stored_rows`), which MACs only
rows whose digests still verify.
"""

from __future__ import annotations

import hashlib
import hmac
import os

#: The environment variable the row key is read from, in code only.
ROW_KEY_ENV = "ATHENA_ECONOMICS_ROW_KEY"
#: The shortest value read as a key: 32 characters (at least 128 bits of a random
#: hex or base64 key). Anything shorter is no key.
ROW_KEY_MIN_CHARS = 32
#: How a MAC is written in a row.
MAC_PREFIX = "hmac-sha256:"
#: What every MAC is taken over first, so a MAC of one kind is never another's.
DOMAIN = "athena.economics.row-mac/v1"


def row_key() -> bytes | None:
    """The row key, read from :data:`ROW_KEY_ENV` now, or ``None`` where it is unset
    or shorter than :data:`ROW_KEY_MIN_CHARS`. Never raises."""
    value = os.environ.get(ROW_KEY_ENV)
    if not isinstance(value, str) or len(value) < ROW_KEY_MIN_CHARS:
        return None
    return value.encode("utf-8")


def _mac(key: bytes, kind: str, fields) -> str:
    message = "\n".join([DOMAIN, kind, *("" if value is None else str(value) for value in fields)])
    return MAC_PREFIX + hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def result_fields(result) -> tuple:
    """What a result's MAC is taken over: its identity (uuid, tenant, scenario
    version, remediation option), its seed and draws, its outcome, and both digests
    -- the inputs' and the record's."""
    return (
        result.uuid, result.deployment_id, result.scenario_id, result.remediation_id, result.seed, result.draws,
        result.status, result.refusal_code, result.input_digest, result.result_digest,
    )


def card_fields(card) -> tuple:
    """What a card's MAC is taken over: its identity (uuid, tenant, scenario version,
    the result it cards) and both digests -- the card's document's (which states its
    grade; the grade column is checked against it) and its sensitivity analysis'."""
    return (
        card.uuid, card.deployment_id, card.scenario_id, card.simulation_id, card.card_digest,
        card.sensitivity_digest,
    )


def result_mac(result, key: bytes) -> str:
    return _mac(key, "simulation-result", result_fields(result))


def card_mac(card, key: bytes) -> str:
    return _mac(key, "validity-card", card_fields(card))


def macs_equal(stored, expected: str) -> bool:
    """Whether the MAC a row ``stored`` is ``expected``, compared in constant time.
    A row with none, or one that is not text, does not hold it. Never raises."""
    if not isinstance(stored, str):
        return False
    return hmac.compare_digest(stored.encode("utf-8"), expected.encode("utf-8"))


def bind_stored_rows(*, dry_run: bool = False) -> dict:
    """Give every stored result and card WITHOUT a MAC its MAC under the row key, where
    its digests still verify (``report``'s digest and card checks); leave every
    other row as it is. A row whose digests fail is never bound: it stays a refusal.
    The one write to a recorded economics row besides migration 0074's backfill,
    and like it, it only fills an empty column. Returns the counts. Refuses
    (``RuntimeError``) without a key."""
    from . import report
    from .models import FinancialValidityCard, SimulationResult

    key = row_key()
    if key is None:
        raise RuntimeError(f"{ROW_KEY_ENV} is not set (or shorter than {ROW_KEY_MIN_CHARS} characters): nothing bound")
    counts = {"results_bound": 0, "cards_bound": 0, "left_unbound": 0}
    for result in SimulationResult._base_manager.filter(row_mac="").order_by("pk").iterator():
        if report.result_digest_failures(result):
            counts["left_unbound"] += 1
            continue
        counts["results_bound"] += 1
        if not dry_run:
            SimulationResult._base_manager.filter(pk=result.pk, row_mac="").update(row_mac=result_mac(result, key))
    for card in FinancialValidityCard._base_manager.filter(row_mac="").order_by("pk").iterator():
        result = SimulationResult._base_manager.filter(pk=card.simulation_id).first()
        if result is None or report.result_digest_failures(result) or report.card_digest_failures(card, result):
            counts["left_unbound"] += 1
            continue
        counts["cards_bound"] += 1
        if not dry_run:
            FinancialValidityCard._base_manager.filter(pk=card.pk, row_mac="").update(row_mac=card_mac(card, key))
    return counts


__all__ = [
    "DOMAIN",
    "MAC_PREFIX",
    "ROW_KEY_ENV",
    "ROW_KEY_MIN_CHARS",
    "bind_stored_rows",
    "card_fields",
    "card_mac",
    "macs_equal",
    "result_fields",
    "result_mac",
    "row_key",
]
