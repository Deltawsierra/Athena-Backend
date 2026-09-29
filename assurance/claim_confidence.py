"""A claim's confidence: read from mythos-core's evidence-class table, and only while
its status stands on supporting evidence (roadmap P2.7).

An :class:`~assurance.models.AssuranceClaim` carries a ``confidence``. It is not a
probability that the claim is true: it is the ORDINAL strength of the weakest class
of evidence supporting the claim, as mythos-core's evidence-class table gives it
(:func:`mythos_core.evidence.strength_from_evidence_class`, Mythos-Core#31, where the
table is written out once, strongest class first, and its tests hold the comment to
the code). Only the order of the values means anything.

That table is the only place the number comes from. This app used to compute it
inline as ``max(0.1, 1.0 - 0.12 * rank)`` -- the same values, from a second
vocabulary documented nowhere a reader of mythos-core would find it -- and every
reading here now goes to the core's module at the moment it is taken.

**It follows the status, whoever set it.** :func:`claim_confidence` is a function of
the claim's status and its evidence class, and nothing else: the table's strength
for the class while the status is SUPPORTED, PARTIALLY_VERIFIED or VERIFIED, and
``None`` for every other status -- UNKNOWN (never a 0 that reads as a scored pass),
CONTRADICTED (a statement read as false has no supporting confidence), STALE (its
evidence expired or a retest is due), REVOKED, DRAFT. Every writer of a claim's
status writes the confidence this function gives for the status it writes: the
deriver, a person's move (:func:`assurance.claims.apply_claim_transition`), a
refresh that keeps a person's status, an evidence audit's hold and release, a stale
mark. A confidence used to be the deriver's for the deriver's status and was left
there when a person moved the claim: a claim a person moved back to SUPPORTED read
``None``, and one a person moved to UNKNOWN kept the deriver's 0.88.

A SUPERSEDED version is closed history, and keeps the confidence it carried when it
was closed, beside the evidence class it carried; :func:`confidence_basis` says so.

Never a typed-in number: nothing here, and nothing that calls it, writes a figure of
its own (``tests/test_a_number_nobody_computed.py`` reads the source for one).
"""

from __future__ import annotations

from mythos_core import evidence as core_evidence

from .models import AssuranceClaim

Status = AssuranceClaim.ClaimStatus

#: The statuses that stand on supporting evidence: the only ones a claim carries a
#: confidence under.
SUPPORTING_STATUSES = frozenset(
    {Status.SUPPORTED.value, Status.PARTIALLY_VERIFIED.value, Status.VERIFIED.value}
)

#: Where the number is read from, as a basis names it.
TABLE = "mythos_core.evidence.strength_from_evidence_class"

#: Why a claim at each status that does not stand on supporting evidence carries no
#: confidence -- true on every path that sets the status, so none names a cause.
_NONE_BECAUSE = {
    Status.UNKNOWN.value: (
        "the claim is unknown, and an unknown carries no number (never a 0 that reads as a scored pass)"
    ),
    Status.CONTRADICTED.value: "the claim is contradicted, and a statement read as false has no supporting confidence",
    Status.STALE.value: "the claim is stale: its evidence expired or a retest is due, so no current evidence supports it",
    Status.REVOKED.value: "the claim was withdrawn",
    Status.DRAFT.value: "the claim has not been assessed",
    Status.SUPERSEDED.value: "this version is superseded, and it carried no confidence when it was closed",
}


def claim_confidence(status, evidence_class) -> float | None:
    """The confidence a claim at ``status`` carries on evidence of ``evidence_class``.

    mythos-core's strength for the class while ``status`` stands on supporting
    evidence, and ``None`` for every other status. Read from the core's table at
    every call. Pure: reads nothing else and writes nothing."""
    if str(status) not in SUPPORTING_STATUSES:
        return None
    return core_evidence.strength_from_evidence_class(evidence_class)


def confidence_basis(status, evidence_class, confidence) -> str:
    """What a claim's ``confidence`` is, in one line, for whatever serves it.

    With a number: mythos-core's basis line for a class-derived strength
    (``CLASS_BASIS``), then which class and which table -- and, on a superseded
    version, that it is what the version carried when it was closed. With none:
    ``"none: "`` and why, by the claim's status. A stored number that is not the
    table's strength for the claim's class is never described as read from the table.
    """
    status = str(status)
    if confidence is None:
        return "none: " + _NONE_BECAUSE.get(status, "no confidence is recorded for this claim")
    table_value = core_evidence.strength_from_evidence_class(evidence_class)
    if confidence != table_value:
        return (
            f"unexplained: {confidence!r} is not the strength {TABLE} gives class {str(evidence_class)!r} "
            f"now ({table_value!r}); do not read it as that table's strength."
        )
    basis = (
        f"{core_evidence.CLASS_BASIS} Class {str(evidence_class)!r} "
        f"({core_evidence.qualitative_label(evidence_class)}): the strength {TABLE} gives it."
    )
    if status == Status.SUPERSEDED.value:
        basis += " This version is superseded: the number is what it carried when it was closed, not a reading of the claim now."
    elif status not in SUPPORTING_STATUSES:
        basis += f" The claim reads {status}, which does not stand on supporting evidence."
    return basis
