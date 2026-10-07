"""A finding's repair contract, agreed and held to, for the closure tests.

A retest-gated closure now stands only on a replay held to the finding's current
repair contract (``assurance/repair_contract.py``), and a remediation moves into a
working state only once one is agreed. The closure suites that close a finding
build that precondition with these, so what each of them tests -- the fixtures, the
replay, the origin, the timing -- is judged exactly as it was.
"""

from __future__ import annotations

import copy

EFFECT = "an unauthenticated caller reads another customer's orders through the search parameter"
BEHAVIOURS = ("customer searches own orders", "admin order export")


def agree(finding, *, effect=EFFECT, behaviours=BEHAVIOURS, by=None):
    """Agree the next version of ``finding``'s repair contract."""
    from assurance import repair_contract

    return repair_contract.agree(
        finding, prohibited_effect=effect,
        preserved_behaviours=list(behaviours) if isinstance(behaviours, tuple) else behaviours, agreed_by=by,
    )


def held_to(finding, **readings):
    """The ``contract`` block of a replay held to ``finding``'s current contract:
    every preserved behaviour read ``retained`` unless ``readings`` says otherwise."""
    from assurance import repair_contract

    current = repair_contract.current_contract(finding)
    assert current is not None, "agree the finding's repair contract first"
    preserved = {name: "retained" for name in current.preserved_behaviours}
    preserved.update(readings)
    return {"digest": current.content_digest, "preserved": preserved}


def replay(finding, fixtures, *, origin="independent"):
    """A complete replay document for ``finding`` -- the effect gone on the original
    scenario and two variants, legitimate use retained -- carrying ``fixtures`` and
    held to the finding's current contract."""
    return {
        "finding_type": finding.finding_type,
        "finding_ref": str(finding.uuid),
        "engine": "replay-under-test",
        "origin": str(origin),
        "remediation": {"kind": "parameterised query", "control_changed": "orders search query"},
        "replay": {
            "reached": True,
            "original_effect": "gone",
            "variants": {"restored_reachability": "gone", "displaced_effects": "gone"},
            "utility": "retained",
        },
        "fixtures": copy.deepcopy(fixtures),
        "contract": held_to(finding),
    }
