"""The ISO 4217 currency table: each code's minor unit, whether it is active or
retired, and the code that succeeded a retired one.

Every amount is a ``Decimal`` with an ISO 4217 code beside it, and the currency
is never inferred from a locale (owner's specification, sections 9 and 19). The
minor unit is stored separately from the amount: it says how a value is shown
(JPY has none, USD two, KWD three), never how precisely it is computed.

The table is data, not code: ``data/iso4217.json``, a reviewed file that records
its own source and review state. It is read and checked once, when this module is
imported, and a table that fails a check does not load at all
(:class:`CurrencyTableInvalid`): a currency engine with a half-read table would
show amounts at the wrong precision without saying so. ``tests/test_economics_engine.py``
pins JPY, USD, KWD and a retired code, and the digest of the whole document -- the
entries and the ``source`` and ``review`` records that say where they came from and
how far they are checked -- so an edit to any of it is a reviewed change to the
test as well.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

#: The schema the data file declares; any other is refused.
TABLE_SCHEMA = "mythos.economics.currency-table/v1"
TABLE_PATH = Path(__file__).resolve().parent / "data" / "iso4217.json"

ACTIVE = "active"
RETIRED = "retired"
STATUSES = frozenset({ACTIVE, RETIRED})

#: The largest minor unit ISO 4217 assigns (CLF and UYW have four).
MAX_MINOR_UNITS = 4

_CODE = re.compile(r"[A-Z]{3}")
_FIELDS = frozenset({"code", "name", "minor_units", "status", "successor"})


class CurrencyTableInvalid(ValueError):
    """The currency data file breaks one of the table's rules. Nothing is loaded."""


class UnknownCurrency(LookupError):
    """A code the table does not hold. Never guessed at, never normalised: ``usd``
    and ``US$`` are unknown, not USD."""


@dataclass(frozen=True)
class Currency:
    code: str
    name: str
    #: Digits after the decimal point in the minor unit; ``None`` where ISO 4217
    #: assigns none (precious metals, bond-market units, the SDR, XTS, XXX).
    minor_units: int | None
    status: str
    #: The code that replaced a retired currency; ``None`` for an active one. It
    #: says WHICH currency replaced it, never at what rate.
    successor: str | None

    @property
    def active(self) -> bool:
        return self.status == ACTIVE


def _check_entry(entry) -> Currency:
    if not isinstance(entry, dict) or set(entry) != _FIELDS:
        raise CurrencyTableInvalid(f"an entry must have exactly the fields {sorted(_FIELDS)}: {entry!r}")
    code, name, minor, status, successor = (entry[k] for k in ("code", "name", "minor_units", "status", "successor"))
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        raise CurrencyTableInvalid(f"a code is three capital letters: {code!r}")
    if not isinstance(name, str) or not name.strip():
        raise CurrencyTableInvalid(f"{code} has no name")
    if minor is not None and (
        isinstance(minor, bool) or not isinstance(minor, int) or not 0 <= minor <= MAX_MINOR_UNITS
    ):
        raise CurrencyTableInvalid(f"{code}: minor units are null or an integer from 0 to {MAX_MINOR_UNITS}: {minor!r}")
    if status not in STATUSES:
        raise CurrencyTableInvalid(f"{code}: status is one of {sorted(STATUSES)}: {status!r}")
    if status == ACTIVE and successor is not None:
        raise CurrencyTableInvalid(f"{code} is active and names a successor ({successor!r})")
    if successor is not None and (not isinstance(successor, str) or successor == code):
        raise CurrencyTableInvalid(f"{code}: a successor is another code: {successor!r}")
    return Currency(code=code, name=name, minor_units=minor, status=status, successor=successor)


def table_digest(document) -> str:
    """SHA-256 over the canonical JSON of the whole table document (sorted keys,
    compact separators, the discipline the receipt's digests keep): the schema, the
    entries, and the source and review records. A change to any entry, or to what
    the file says about its source or its review, moves it; a change to the file's
    whitespace does not."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_table(path: Path = TABLE_PATH) -> tuple[Mapping[str, Currency], Mapping, str]:
    """Read and check the table at ``path``: the currencies by code, the file's
    ``source`` and ``review`` records, and the digest of the whole document. Raises
    :class:`CurrencyTableInvalid` on any broken rule."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != TABLE_SCHEMA:
        raise CurrencyTableInvalid(f"the table declares schema {TABLE_SCHEMA!r}")
    for record in ("source", "review"):
        if not isinstance(document.get(record), dict) or not document[record]:
            raise CurrencyTableInvalid(f"the table records its {record}")
    entries = document.get("currencies")
    if not isinstance(entries, list) or not entries:
        raise CurrencyTableInvalid("the table holds no currencies")
    table: dict[str, Currency] = {}
    for entry in entries:
        currency_ = _check_entry(entry)
        if currency_.code in table:
            raise CurrencyTableInvalid(f"{currency_.code} appears twice")
        table[currency_.code] = currency_
    for currency_ in table.values():
        seen = {currency_.code}
        step = currency_
        while step.successor is not None:
            if step.successor not in table:
                raise CurrencyTableInvalid(f"{step.code}'s successor {step.successor} is not in the table")
            step = table[step.successor]
            if step.code in seen:
                raise CurrencyTableInvalid(f"the successors from {currency_.code} go round in a circle")
            seen.add(step.code)
    meta = MappingProxyType({"source": document["source"], "review": document["review"]})
    return MappingProxyType(table), meta, table_digest(document)


#: Every currency the table holds, by code; its source and review records; and the
#: digest of the whole document.
CURRENCIES, TABLE_RECORDS, TABLE_DIGEST = load_table()


def currency(code: str) -> Currency:
    """The currency ``code`` names, exactly as written. Raises :class:`UnknownCurrency`."""
    try:
        return CURRENCIES[code]
    except (KeyError, TypeError):
        raise UnknownCurrency(f"{code!r} is not an ISO 4217 code in the table") from None


def minor_units(code: str) -> int | None:
    """The minor-unit exponent of ``code``: 0 for JPY, 2 for USD, 3 for KWD."""
    return currency(code).minor_units


def current_successor(code: str) -> Currency | None:
    """The active currency a retired one's successors lead to (HRK leads to EUR), or
    ``None`` when ``code`` is active or its line of successors ends without one."""
    step = currency(code)
    if step.active:
        return None
    while step.successor is not None:
        step = CURRENCIES[step.successor]
        if step.active:
            return step
    return None
