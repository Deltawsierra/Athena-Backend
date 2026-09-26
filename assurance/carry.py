"""What a release that did not carry a claim's watches and legal ruling left behind,
brought to the claim's current version -- wherever its writes are next seen.

This release carries both at the re-derive (``claims._supersede``): every live latent
condition moves to the new version, and the new version starts with its
predecessor's legal status (``legal.ruling_for_next_version``). The release before
it did neither, and 0037 and 0038 repair what it left -- once, at the migration.

A rolling deploy keeps the release before writing AFTER the migration (that is what
the database defaults 0036-0039 give their columns are for). Its re-derive opened the
new version "not assessed" and left the watches on the version it closed, where
nothing evaluates them; and read a claim a fired condition holds back to a pass,
resolving its retest. Nothing one-shot can repair a write made after it ran, so this
is idempotent and runs wherever such a write is next seen:

- at every ``migrate`` (the post_migrate receiver in :mod:`assurance.signals`);
- on every refresh of a stored decision -- the after-commit backstop every write
  schedules, which evaluates the conditions straight after
  (:func:`assurance.decision.refresh_stored_decisions`);
- at the first publishing read of a decision a writer that does not stamp it moved
  (:func:`assurance.decision.current_decision`).

And the decision does not wait for it: it reads a fired condition's hold, an unread
condition, and the legal axis the carry leaves, on every version of the claim
(:func:`assurance.decision.claim_decision_signal`). A watch left pending on a closed
version is read as unread there -- nothing evaluates it until it is carried -- so
until the carry and the evaluation after it the decision is held at needs more
evidence, never read as watched. What this makes right is the record itself -- the
watch evaluated again, the retest open, the ruling on the row.

Each part writes in its own short transactions and schedules no refresh while it
runs; the caller brings the decision current once, after. Never inside a stop.
"""

from __future__ import annotations

import logging

from django.db.models import Exists, OuterRef

from .models import LATENT_LIVE_STATES, AssuranceClaim, LatentCondition, LegalStatus

logger = logging.getLogger(__name__)


def converge(deployment, *, now=None) -> dict:
    """Carry ``deployment``'s watches and legal rulings to each claim's current
    version and put back every hold a fired condition keeps; what it did, counted.

    Idempotent: a deployment already converged costs three reads and writes nothing.
    The refresh of this deployment its writes would schedule is deferred -- the
    caller refreshes once, after."""
    from .latent import carry_conditions_to_current, restore_fired_holds
    from .legal import carry_rulings_to_current
    from .signals import refresh_deferred

    with refresh_deferred(deployment.pk):
        return {
            # Watches first: a FIRED one carried to the current version holds that
            # version, which is what the restore below puts back.
            "watches_carried": carry_conditions_to_current(deployment, now=now),
            "rulings_carried": carry_rulings_to_current(deployment, now=now),
            "holds_restored": restore_fired_holds(deployment, now=now),
        }


def deployments_to_converge() -> list:
    """Every deployment where a release that did not carry left something to carry
    or a hold to put back, by pk: a live condition on a closed version of a claim
    with a current version; a current version "not assessed" or "pending" on the
    legal axis beside a closed version of the same claim that is neither; a fired
    condition whose hold is lifted. A few queries across every deployment."""
    from .latent import deployments_with_a_lifted_hold

    left = set(
        LatentCondition.objects.filter(state__in=LATENT_LIVE_STATES, claim__in=AssuranceClaim.objects.closed())
        .filter(
            Exists(
                AssuranceClaim.objects.current().filter(
                    deployment_id=OuterRef("deployment_id"), fingerprint=OuterRef("claim__fingerprint")
                )
            )
        )
        .values_list("deployment_id", flat=True)
    )
    ruled = set(
        AssuranceClaim.objects.current()
        .filter(legal_status__in=(LegalStatus.NOT_ASSESSED, LegalStatus.REVIEW_PENDING))
        .filter(
            Exists(
                AssuranceClaim.objects.closed()
                .filter(deployment_id=OuterRef("deployment_id"), fingerprint=OuterRef("fingerprint"))
                .exclude(legal_status=LegalStatus.NOT_ASSESSED)
            )
        )
        .values_list("deployment_id", flat=True)
    )
    return sorted(left | ruled | set(deployments_with_a_lifted_hold()))
