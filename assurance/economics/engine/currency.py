"""The ISO 4217 currency table Economic Exposure reads: mythos-core's.

There is ONE currency table for the capability, :mod:`mythos_core.currency`
(Mythos-Core#49): each code's minor unit, whether it is active or retired, the
code that succeeded a retired one, and which codes no amount may be reported in.
Phase E0 carried a copy of its own here (``data/iso4217.json``); core's table was
made from that copy entry for entry, and phase E1 dropped the copy, so this
module is a thin adapter. It adds no entry, changes none and caches nothing of
its own: every table name below is core's object.

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

NOTHING HAPPENS AT IMPORT, AND THE REFUSAL IS ECONOMICS-ONLY. This module is
imported when Django loads ``assurance.models``, so anything it did at import that
could fail -- importing core's module, which reads core's table file, or checking
the pin -- could take ``django.setup()`` down, and every route with it, the scan's
Stop and every other stop among them. The safety rule forbids that: an economics
fault refuses economics, and nothing else. So importing this module imports no
part of mythos-core and checks nothing. On the first economics use, core's module
is imported -- a failure is recorded, ``mythos_core.currency cannot be imported``,
never raised past here -- and the pin is checked once and its result recorded
(:data:`PIN_REFUSAL`). Every use of the table -- :func:`currency`,
:func:`minor_units`, :func:`current_successor`, :func:`reporting_refusal`, the
table names, and through them every ``Money``, rate and policy -- raises
:class:`CurrencyTableInvalid` while core's module cannot be imported or the pin
does not hold. :class:`CurrencyTableInvalid` is core's own class when core's
module imports, and a local one when it does not.

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

import logging
from collections.abc import Mapping

logger = logging.getLogger(__name__)

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

#: What economics refuses with when mythos-core's currency module cannot be
#: imported at all, before any pin can be checked.
CORE_UNAVAILABLE = "mythos_core.currency cannot be imported"


class UnknownCurrency(LookupError):
    """A code the table does not hold. Never guessed at, never normalised: ``usd``
    and ``US$`` are unknown, not USD."""


class LocalCurrencyTableInvalid(ValueError):
    """What :class:`CurrencyTableInvalid` is when mythos-core's currency module
    cannot be imported, so economics still refuses with one class, on use."""


_UNSET = object()
#: What the first use found: core's module (or ``None``), why it could not be
#: imported, and the pin's result. Filled on first use, never at import.
_state: dict = {"core": _UNSET, "unavailable": None, "pin": _UNSET}

#: The names this adapter reads from core's module; one missing is a module that
#: cannot be used, refused like one that cannot be imported.
_CORE_NAMES = (
    "CURRENCIES",
    "REPORTABLE_MINOR_UNITS",
    "RECORDS",
    "TABLE_SHA256",
    "Currency",
    "CurrencyTableInvalid",
    "ACTIVE",
    "RETIRED",
    "entries_digest",
)


def _load_core():
    """mythos-core's currency module, imported on the first economics use and never
    at this module's import; ``None`` when it cannot be imported or lacks a name
    this adapter reads, with why recorded. Never raises."""
    if _state["core"] is _UNSET:
        try:
            from mythos_core import currency as core

            present = set(dir(core))
            missing = [name for name in _CORE_NAMES if name not in present]
            if missing:
                raise AttributeError(f"it has no {missing}")
        except Exception as exc:
            # Logged and recorded, never raised: an economics fault refuses economics.
            logger.exception("%s; Economic Exposure refuses on use", CORE_UNAVAILABLE)
            _state["core"] = None
            _state["unavailable"] = f"{CORE_UNAVAILABLE}: {type(exc).__name__}: {exc}"
        else:
            _state["core"] = core
    return _state["core"]


def _invalid() -> type[Exception]:
    """The class economics refuses with: core's ``CurrencyTableInvalid``, or the
    local one when core's module cannot be imported."""
    core = _load_core()
    return core.CurrencyTableInvalid if core is not None else LocalCurrencyTableInvalid


def _core():
    """Core's module, or :class:`CurrencyTableInvalid` naming why there is none."""
    core = _load_core()
    if core is None:
        raise LocalCurrencyTableInvalid(_state["unavailable"])
    return core


def reportable_from(currencies: Mapping) -> dict[str, int]:
    """The minor unit of every code an amount may be reported in, derived from the
    entries themselves: active, with a minor unit."""
    active = _core().ACTIVE
    return {
        code: entry.minor_units
        for code, entry in currencies.items()
        if entry.status == active and entry.minor_units is not None
    }


def pin_refusal(
    currencies: Mapping,
    reportable: Mapping[str, int] | None = None,
    pinned: str = PINNED_ENTRIES_SHA256,
) -> str | None:
    """``None`` when ``currencies`` hold exactly the entries this service pinned and
    ``reportable`` (core's ``REPORTABLE_MINOR_UNITS`` unless given) is exactly the
    set those entries give; otherwise why not. Never raises."""
    core = _load_core()
    if core is None:
        return _state["unavailable"]
    if reportable is None:
        reportable = core.REPORTABLE_MINOR_UNITS
    try:
        digest = core.entries_digest(currencies)
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
    currencies: Mapping,
    reportable: Mapping[str, int] | None = None,
    pinned: str = PINNED_ENTRIES_SHA256,
) -> None:
    """Raise :class:`CurrencyTableInvalid` unless :func:`pin_refusal` finds none."""
    refusal = pin_refusal(currencies, reportable, pinned)
    if refusal is not None:
        raise _invalid()(refusal)


def _pin_in_force() -> str | None:
    """Why core's table in force is not the one pinned (or cannot be imported),
    checked once, on the first use, and recorded; ``None`` when it is."""
    if _state["pin"] is _UNSET:
        core = _load_core()
        _state["pin"] = (
            _state["unavailable"] if core is None else pin_refusal(core.CURRENCIES, core.REPORTABLE_MINOR_UNITS)
        )
    return _state["pin"]


def require_pinned() -> None:
    """Raise :class:`CurrencyTableInvalid` while core's table cannot be imported or
    is not the one pinned. Called by every use of the table, never at import."""
    refusal = _pin_in_force()
    if refusal is not None:
        raise _invalid()(refusal)


def _table() -> Mapping:
    return _core().CURRENCIES


#: The names read from core's module on use (PEP 562): each is core's own object,
#: read from core's module at the moment it is asked for, never at import.
#: :data:`PIN_REFUSAL` is the pin's recorded result; :class:`CurrencyTableInvalid`
#: core's class, or the local one. Spelled out one by one, so no name is looked up
#: at runtime.
_ON_USE = {
    "CURRENCIES": lambda: _core().CURRENCIES,
    "REPORTABLE_MINOR_UNITS": lambda: _core().REPORTABLE_MINOR_UNITS,
    "RECORDS": lambda: _core().RECORDS,
    "TABLE_SHA256": lambda: _core().TABLE_SHA256,
    "Currency": lambda: _core().Currency,
    "ACTIVE": lambda: _core().ACTIVE,
    "RETIRED": lambda: _core().RETIRED,
    "CurrencyTableInvalid": _invalid,
    "PIN_REFUSAL": _pin_in_force,
}


def __getattr__(name: str):
    reader = _ON_USE.get(name)
    if reader is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return reader()


def entries_digest() -> str:
    """The digest of the entries in force, as core computes it."""
    return _core().entries_digest(_table())


def currency(code: str):
    """The currency ``code`` names, exactly as written. Raises :class:`UnknownCurrency`,
    and :class:`CurrencyTableInvalid` while the pin does not hold."""
    require_pinned()
    try:
        return _table()[code]
    except (KeyError, TypeError):
        raise UnknownCurrency(f"{code!r} is not an ISO 4217 code in the table") from None


def minor_units(code: str) -> int | None:
    """The minor-unit exponent of ``code``: 0 for JPY, 2 for USD, 3 for KWD; ``None``
    where ISO 4217 gives none."""
    require_pinned()
    return currency(code).minor_units


def current_successor(code: str):
    """The active currency a retired one's successors lead to (HRK leads to EUR), or
    ``None`` when ``code`` is active. Core's table guarantees every line of
    successors ends at an active code."""
    require_pinned()
    active = _core().ACTIVE
    step = currency(code)
    if step.status == active:
        return None
    table = _table()
    while step.status != active and step.successor is not None:
        step = table[step.successor]
    return step if step.status == active else None


def reporting_refusal(code) -> str | None:
    """``None`` when an amount may be reported in ``code``; otherwise core's code
    for why not: ``currency_unknown`` (the table does not hold it) or
    ``currency_retired`` (retired, or no minor unit). Raises
    :class:`CurrencyTableInvalid` while the pin does not hold."""
    require_pinned()
    if not isinstance(code, str) or code not in _table():
        return CURRENCY_UNKNOWN
    if code not in _core().REPORTABLE_MINOR_UNITS:
        return CURRENCY_RETIRED
    return None
