"""The confidence grades a scenario's estimate carries: A, B, C, D and Unknown.

A grade says how much of an estimate rests on evidence and how much on
assumption (owner's specification, section 8). It never stands alone: a report
shows the range, the grade and the reason for it together. ``Unknown`` is a grade
of its own, not the absence of one: Mythos cannot responsibly quantify the
scenario, and says so rather than printing a number.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class ConfidenceGrade(StrEnum):
    """Strongest first. The value is the stable code, spelled as section 8 spells
    the grade."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    UNKNOWN = "Unknown"


#: Each grade's name and its typical evidence mix (section 8), published beside it.
GRADES: Mapping[ConfidenceGrade, tuple[str, str]] = MappingProxyType(
    {
        ConfidenceGrade.A: (
            "Evidence rich",
            (
                "strong customer data, an observed Mythos effect, current authoritative external data, and "
                "little unresolved uncertainty"
            ),
        ),
        ConfidenceGrade.B: (
            "Supported",
            "good technical and customer evidence with some benchmark assumptions",
        ),
        ConfidenceGrade.C: (
            "Indicative",
            "material assumptions depend on industry benchmarks or sparse customer data",
        ),
        ConfidenceGrade.D: (
            "Exploratory",
            "sparse data, mostly assumptions or weak priors: for scenario planning, not capital-grade decisions",
        ),
        ConfidenceGrade.UNKNOWN: (
            "Unknown",
            "insufficient evidence or conflicting inputs: Mythos cannot responsibly quantify the scenario",
        ),
    }
)

