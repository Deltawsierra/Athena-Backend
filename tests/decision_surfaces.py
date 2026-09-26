"""Every surface that publishes a deployment's decision, read side by side.

The stored decision is published by the deployment detail, the assurance receipt
and ``revision.read_decision``; decision-support computes it live and publishes the
stored revision beside it. A write that moves an input without refreshing the
stored decision shows up as those four disagreeing, which is the one assertion the
tests that use this make. Read in this order on purpose: the detail reconciles the
stored decision with the keyring first, as every published read does.
"""

from __future__ import annotations

from assurance.models import Deployment
from assurance.revision import read_decision


def surfaces(dep, client) -> dict:
    base = f"/api/assurance/deployments/{dep.uuid}/"
    detail = client.get(base).json()
    support = client.get(base + "decision-support/").json()
    receipt = client.get(base + "assurance-receipt/").json()
    stored = read_decision(Deployment.objects.get(pk=dep.pk))
    return {
        "detail": (detail["decision"], detail["decision_revision"]),
        "decision-support": (support["decision"], support["revision"]),
        "read_decision": (stored["decision"], stored["revision"]),
        "receipt": receipt["result"]["decision"],
    }


def stamped_under_the_rules_in_force(dep):
    """Stamp ``dep``'s stored decision with the policy pin in force, and return it.

    For a test that writes a decision by hand -- through the one writer, or a
    QuerySet update -- to stand for one the rules computed. A stored decision with no
    stamp names no rules it was computed under, and every publishing read recomputes
    it (``decision.current_decision``); stamped here, the hand-written decision is
    published as written, which is what such a test is about."""
    from assurance.policy import policy_pin

    Deployment.objects.filter(pk=dep.pk).update(decision_policy=policy_pin())
    dep.decision_policy = policy_pin()
    return dep


def one_decision(dep, client) -> str | None:
    """The decision every surface publishes, asserting they publish ONE -- the same
    decision under the same revision."""
    seen = surfaces(dep, client)
    assert len({seen["detail"], seen["decision-support"], seen["read_decision"]}) == 1, seen
    assert seen["receipt"] == seen["detail"][0], seen
    return seen["detail"][0]
