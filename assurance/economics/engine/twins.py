"""The vectorised twins of the formula catalogue (phase E2, MVP step 7b;
``docs/economics/spec-v1.md``, section 25.3).

Each formula of :data:`.formulas.CATALOGUE` that a simulation may evaluate has a
twin here, keyed by the same formula id and version: the same expression, in
binary64, over arrays of draws (one value per draw of every input). The Decimal
formula stays the source of truth. A twin is proven equal to its formula at the
step-4 known-answer fixtures and at random points drawn at fixed seeds, within
:data:`RELATIVE_TOLERANCE` (``tests/test_economics_scenario_simulation.py``), its
complement (``1 - recovery_rate``), clipping (``min`` with a cap) and the
direction of every input included.

A formula with no twin is refused by name (:class:`TwinMissing`): nothing falls
back to an approximation, and a new formula version needs a new twin and its proof
before a simulation reads it.

Every twin is a sum and product of non-negative inputs, a ``1 - ratio`` and a
``min``: no ``exp``, ``log`` or ``pow``, so a twin's result is the same on every
IEEE-754 platform (section 23.8). A twin never writes to its inputs (they are the
read-only draw vectors) and returns a new float64 array.

Pure: no Django, no database, no I/O.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType

import numpy as np

#: The version of the twins as a set: a change to any twin's arithmetic (its
#: order of operations included) is a new version, recorded with every run.
TWINS_VERSION = 1

#: How close a twin is to its Decimal formula: ``|twin - formula| <= tolerance x
#: |formula|``, with the formula evaluated in Decimal at the very binary64 values
#: the twin read (so the tolerance measures the twin's arithmetic, not the
#: rounding of a Decimal input to binary64, which every draw has anyway). A twin
#: makes at most six roundings of half a unit in the last place (2^-53 each),
#: about 7e-16 relative; the tolerance leaves a margin of more than a hundred.
#: Where the formula gives exactly zero, the twin gives exactly zero.
RELATIVE_TOLERANCE = Decimal("1E-13")


class TwinMissing(LookupError):
    """A formula id and version with no vectorised twin."""

    def __init__(self, formula_id, version):
        self.formula_id = formula_id
        self.version = version
        super().__init__(f"{formula_id!r} version {version!r} has no vectorised twin")


@dataclass(frozen=True)
class Twin:
    """The vectorised twin of one formula: its id and version and the function
    that evaluates it over arrays of draws, one array per input, by input name."""

    formula_id: str
    version: int
    calculate: Callable[[Mapping[str, np.ndarray]], np.ndarray] = field(repr=False, compare=False)

    @property
    def key(self) -> tuple[str, int]:
        return (self.formula_id, self.version)

    def __call__(self, values: Mapping[str, np.ndarray]) -> np.ndarray:
        return np.asarray(self.calculate(values), dtype=np.float64)


def _complement(ratio):
    """``1 - ratio``: what is NOT recovered. Exact in binary64 for a ratio from
    one half to one (Sterbenz), and within half an ulp below it."""
    return np.subtract(1.0, ratio, dtype=np.float64)


def _twins() -> tuple[Twin, ...]:
    return (
        Twin(
            "repeat_loss",
            1,
            # repeat_count x loss_per_event x (1 - recovery_rate)
            lambda v: v["loss_per_event"] * (v["repeat_count"] * _complement(v["recovery_rate"])),
        ),
        Twin(
            "repeat_in_window",
            1,
            # transactions_per_day / 24 x window_hours x success_rate x value_per_transaction x (1 - recovery_rate)
            lambda v: v["value_per_transaction"]
            * ((v["transactions_per_day"] / 24.0) * v["window_hours"] * v["success_rate"] * _complement(v["recovery_rate"])),
        ),
        Twin(
            "interruption",
            1,
            # interruption_hours x value_per_hour
            lambda v: v["value_per_hour"] * v["interruption_hours"],
        ),
        Twin(
            "fixed_plus_hours",
            1,
            # fixed_cost + hourly_rate x hours
            lambda v: v["fixed_cost"] + v["hourly_rate"] * v["hours"],
        ),
        Twin(
            "per_affected_plus_fixed",
            1,
            # affected x unit_cost + fixed_cost
            lambda v: v["unit_cost"] * v["affected"] + v["fixed_cost"],
        ),
        Twin(
            "per_affected",
            1,
            # affected x amount_per_affected
            lambda v: v["amount_per_affected"] * v["affected"],
        ),
        Twin(
            "support_contacts",
            1,
            # affected x contact_rate x handling_hours x loaded_rate
            lambda v: v["loaded_rate"] * (v["affected"] * v["contact_rate"] * v["handling_hours"]),
        ),
        Twin(
            "capped_credit",
            1,
            # min(credit_per_hour x breach_hours, contract_cap)
            lambda v: np.minimum(v["credit_per_hour"] * v["breach_hours"], v["contract_cap"]),
        ),
        Twin(
            "replacement_share",
            1,
            # replacement_cost x share_compromised
            lambda v: v["replacement_cost"] * v["share_compromised"],
        ),
        Twin(
            "churned_margin",
            1,
            # customers x churn_rate x margin_per_customer_per_year x recovery_years
            lambda v: v["margin_per_customer_per_year"] * (v["customers"] * v["churn_rate"] * v["recovery_years"]),
        ),
        Twin(
            "premium_increase",
            1,
            # premium_increase_per_year x years
            lambda v: v["premium_increase_per_year"] * v["years"],
        ),
        Twin(
            "lump_sum",
            1,
            # amount: a copy, never the read-only draw vector itself
            lambda v: np.array(v["amount"], dtype=np.float64, copy=True),
        ),
        Twin(
            "share_price_reaction",
            1,
            # market_capitalisation x price_decline
            lambda v: v["market_capitalisation"] * v["price_decline"],
        ),
    )


#: Every twin, by ``(formula_id, version)``. Read-only.
TWINS: Mapping[tuple[str, int], Twin] = MappingProxyType({t.key: t for t in _twins()})


def twin(formula_id: str, version: int) -> Twin:
    """The twin of ``formula_id`` at ``version``; :class:`TwinMissing` otherwise,
    never an approximation."""
    found = TWINS.get((formula_id, version)) if isinstance(formula_id, str) and type(version) is int else None
    if found is None:
        raise TwinMissing(formula_id, version)
    return found


__all__ = ["RELATIVE_TOLERANCE", "TWINS", "TWINS_VERSION", "Twin", "TwinMissing", "twin"]
