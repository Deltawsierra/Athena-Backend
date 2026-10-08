"""The ISO 4217 currency table Economic Exposure reads: mythos-core's.

There is ONE currency table for the capability, :mod:`mythos_core.currency`
(Mythos-Core#49): each code's minor unit, whether it is active or retired, the
code that succeeded a retired one, and which codes no amount may be reported in.
Phase E0 carried a copy of its own here (``data/iso4217.json``); core's table was
made from that copy entry for entry, and phase E1 dropped the copy, so this
module is a thin adapter. It adds no entry, changes none and caches nothing of
its own: every name below is core's object.

What it adds is a pin. Core pins the bytes of its own file; this service pins the
digest of the ENTRIES it was reviewed against (:data:`PINNED_ENTRIES_SHA256`, the
value #141's working copy had), and that core's ``REPORTABLE_MINOR_UNITS`` -- the
codes an amount may be reported in, which this service refuses others against --
is exactly the set those entries give. A mythos-core bump that adds, drops or
changes an entry therefore fails here, loudly, until the pin moves in the same reviewed
change -- never a silent change to how an amount is shown or which codes may be
reported in. ``tests/test_economics_engine.py`` pins the same value, and core's
file digest, beside the entries #141 pinned (JPY 0, USD 2, KWD 3, the retired
HRK, GRD and PTE and their successor).

The refusal is LAZY and economics-only. The pin is checked once, at import, and
its result recorded (:data:`PIN_REFUSAL`); importing never raises. Every use of the
table -- :func:`currency`, :func:`minor_units`, :func:`current_successor`,
:func:`reporting_refusal`, and through them every ``Money``, rate and policy --
raises :class:`CurrencyTableInvalid` while the pin does not hold. This module is
imported when Django loads ``assurance.models``, so a refusal at import would take
``django.setup()`` down, and every route with it, the scan's Stop and every other
stop among them. The safety rule forbids that: an economics fault refuses
economics, and nothing else.

Every amount is a ``Decimal`` with an ISO 4217 code beside it, and the currency
is never inferred from a locale (owner's specification, sections 9 and 19). The
minor unit says how a value is shown (JPY has none, USD two, KWD three), never
how precisely it is computed.

A code is REPORTABLE when it is active and has a minor unit. A code the table
holds but no amount may be reported in -- a retired code, or one with no minor
unit -- is refused as a reporting (or base) currency with core's own code,
``currency_retired``; a code the table does not hold with ``currency_unknown``
(:func:`reporting_refusal`), exactly as :mod:`mythos_core.exposure_receipt`
refuses them.
"""

from __future__ import annotations

from collections.abc import Mapping

from mythos_core import currency as _core

Currency = _core.Currency
CurrencyTableInvalid = _core.CurrencyTableInvalid
ACTIVE = _core.ACTIVE
RETIRED = _core.RETIRED

#: SHA-256 (hex) over the canonical JSON of the table's entries
#: (:func:`mythos_core.currency.entries_digest`): the 216 entries athena-backend
#: #141 reviewed and Mythos-Core#49 carried over. Moving it is a reviewed change
#: to the entries, with tests/test_economics_engine.py in the same change.
PINNED_ENTRIES_SHA256 = "00cb16d39eea4ed912c1f8fb9d43b58e19d96328090a3ad766f9cf03a868038a"

#: core's refusal codes, spelled as mythos_core.exposure_receipt spells them
#: (CURRENCY_UNKNOWN, CURRENCY_RETIRED, CURRENCY_MISMATCH); a test holds them equal.
CURRENCY_UNKNOWN = "currency_unknown"
CURRENCY_RETIRED = "currency_retired"
CURRENCY_MISMATCH = "currency_mismatch"


class UnknownCurrency(LookupError):
    """A code the table does not hold. Never guessed at, never normalised: ``usd``
    and ``US$`` are unknown, not USD."""


def reportable_from(currencies: Mapping[str, Currency]) -> dict[str, int]:
    """The minor unit of every code an amount may be reported in, derived from the
    entries themselves: active, with a minor unit."""
    return {
        code: entry.minor_units
        for code, entry in currencies.items()
        if entry.status == ACTIVE and entry.minor_units is not None
    }


def pin_refusal(
    currencies: Mapping[str, Currency],
    reportable: Mapping[str, int] | None = None,
    pinned: str = PINNED_ENTRIES_SHA256,
) -> str | None:
    """``None`` when ``currencies`` hold exactly the entries this service pinned and
    ``reportable`` (core's ``REPORTABLE_MINOR_UNITS`` unless given) is exactly the
    set those entries give; otherwise why not. Never raises."""
    if reportable is None:
        reportable = _core.REPORTABLE_MINOR_UNITS
    try:
        digest = _core.entries_digest(currencies)
        derived = reportable_from(currencies)
        given = dict(reportable)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        # A table core cannot even digest is a refusal too, recorded, never raised here.
        return f"mythos-core's currency table could not be read: {type(exc).__name__}: {exc}"
    if digest != pinned:
        return (
            f"mythos-core's currency entries digest to {digest}, not the {pinned} athena-backend pinned: "
            "a core bump that changes the table moves PINNED_ENTRIES_SHA256 in the same reviewed change"
        )
    if given != derived:
        differ = sorted(set(given.items()) ^ set(derived.items()))
        return (
            "mythos-core's REPORTABLE_MINOR_UNITS is not the set its own entries give (active, with a minor "
            f"unit); they differ on {differ[:10]}"
        )
    return None


def check_pinned(
    currencies: Mapping[str, Currency],
    reportable: Mapping[str, int] | None = None,
    pinned: str = PINNED_ENTRIES_SHA256,
) -> None:
    """Raise :class:`CurrencyTableInvalid` unless :func:`pin_refusal` finds none."""
    refusal = pin_refusal(currencies, reportable, pinned)
    if refusal is not None:
        raise CurrencyTableInvalid(refusal)


#: Why core's table is not the one pinned, recorded once at import; ``None`` when it
#: is. Importing never raises on it: :func:`require_pinned` does, on use.
PIN_REFUSAL: str | None = pin_refusal(_core.CURRENCIES, _core.REPORTABLE_MINOR_UNITS)


def require_pinned() -> None:
    """Raise :class:`CurrencyTableInvalid` while core's table is not the one pinned.
    Called by every use of the table, never at import."""
    if PIN_REFUSAL is not None:
        raise CurrencyTableInvalid(PIN_REFUSAL)

#: Every currency the table holds, by code (core's mapping, read-only).
CURRENCIES: Mapping[str, Currency] = _core.CURRENCIES
#: The table's ``source`` and ``review`` records: where its entries came from and
#: how far they are checked.
RECORDS: Mapping = _core.RECORDS
#: The SHA-256 of core's table file, as core pins it.
TABLE_SHA256: str = _core.TABLE_SHA256
#: The minor unit of every code an amount may be reported in.
REPORTABLE_MINOR_UNITS: Mapping[str, int] = _core.REPORTABLE_MINOR_UNITS


def entries_digest() -> str:
    """The digest of the entries in force, as core computes it."""
    return _core.entries_digest(CURRENCIES)


def currency(code: str) -> Currency:
    """The currency ``code`` names, exactly as written. Raises :class:`UnknownCurrency`,
    and :class:`CurrencyTableInvalid` while the pin does not hold."""
    require_pinned()
    try:
        return CURRENCIES[code]
    except (KeyError, TypeError):
        raise UnknownCurrency(f"{code!r} is not an ISO 4217 code in the table") from None


def minor_units(code: str) -> int | None:
    """The minor-unit exponent of ``code``: 0 for JPY, 2 for USD, 3 for KWD; ``None``
    where ISO 4217 gives none."""
    require_pinned()
    return currency(code).minor_units


def current_successor(code: str) -> Currency | None:
    """The active currency a retired one's successors lead to (HRK leads to EUR), or
    ``None`` when ``code`` is active. Core's table guarantees every line of
    successors ends at an active code."""
    require_pinned()
    step = currency(code)
    if step.status == ACTIVE:
        return None
    while step.status != ACTIVE and step.successor is not None:
        step = CURRENCIES[step.successor]
    return step if step.status == ACTIVE else None


def reporting_refusal(code) -> str | None:
    """``None`` when an amount may be reported in ``code``; otherwise core's code
    for why not: ``currency_unknown`` (the table does not hold it) or
    ``currency_retired`` (retired, or no minor unit). Raises
    :class:`CurrencyTableInvalid` while the pin does not hold."""
    require_pinned()
    if not isinstance(code, str) or code not in CURRENCIES:
        return CURRENCY_UNKNOWN
    if code not in REPORTABLE_MINOR_UNITS:
        return CURRENCY_RETIRED
    return None
