"""A person's legal ruling is read as the carry leaves it -- by the live reader, by
0037 at the migration, and by the revalidation plan -- whatever the row of the claim's
current version says.

A re-derive of the release before opens the claim's new version "not assessed", and
the ruling a person recorded stays on the version it closed. The live reader walks the
claim's versions back from the current one (``superseded_by``), as 0037 does, and
carries the ruling forward: both must agree on every shape the links can take, the
corrupt ones included. And the plan must name such a claim as work, as the decision
reads it, not call it current off the row.
"""

from __future__ import annotations

import datetime
import time

import pytest
from django.db import transaction
from django.utils import timezone

from assurance.models import AssuranceClaim, Deployment
from tests.test_latent_conditions_in_production import Status, _run_data_steps, _user

pytestmark = pytest.mark.django_db

STALE = "legally_stale"
NOT_ASSESSED = "legally_not_assessed"


def _versions(shape, n=3):
    """One claim identity in ``n`` versions linked by ``superseded_by`` in ``shape``: a
    person's STALE ruling on the first, the later ones opened "not assessed" by the
    release before. Returns (deployment, current version)."""
    from assurance.models import LegalObligation, MaterialityDecision

    owner = _user()
    dep = Deployment.objects.create(name=f"shape-{shape}-{Deployment.objects.count()}", owner=owner)
    obligation = LegalObligation.objects.create(
        jurisdiction="EU", authority_tier=LegalObligation.AuthorityTier.REGULATION, source=f"GDPR-{shape}",
        source_version="1", operative_date=datetime.date(2026, 1, 1),
    )
    start = timezone.now() - datetime.timedelta(days=1)
    minute = datetime.timedelta(minutes=1)
    versions = []
    for i in range(n):
        versions.append(AssuranceClaim.objects.create(
            deployment=dep, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY, statement="s", fingerprint="fp",
            system_fingerprint=f"s{i}", policy_version="p", environment=dep.environment, status=Status.VERIFIED,
            legal_status=STALE if i == 0 else NOT_ASSESSED, valid_from=start + i * minute,
            valid_to=None if i == n - 1 else start + (i + 1) * minute, effective_from=start + i * minute,
        ))
    for older, newer in zip(versions, versions[1:]):
        AssuranceClaim.objects.filter(pk=older.pk).update(superseded_by=newer)
    ruling = MaterialityDecision.objects.create(
        claim=versions[0], obligation=obligation, decided_by=owner, material=True, rationale="material"
    )
    MaterialityDecision.objects.filter(pk=ruling.pk).update(decided_at=start + 0.5 * minute)
    head = versions[-1]
    if shape == "cycle":  # the current version also links back to the first: corrupt data
        AssuranceClaim.objects.filter(pk=head.pk).update(superseded_by=versions[0])
    if shape == "fork":  # a second closed version also links to the current one
        extra = AssuranceClaim.objects.create(
            deployment=dep, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY, statement="s", fingerprint="fp",
            system_fingerprint="sx", policy_version="p", environment=dep.environment, status=Status.VERIFIED,
            legal_status=NOT_ASSESSED, valid_from=start + (n - 1) * minute - datetime.timedelta(seconds=30),
            valid_to=start + (n - 1) * minute, effective_from=start,
        )
        AssuranceClaim.objects.filter(pk=extra.pk).update(superseded_by=head)
    if shape == "broken":  # the middle version's link is lost
        AssuranceClaim.objects.filter(pk=versions[1].pk).update(superseded_by=None)
    return dep, AssuranceClaim.objects.get(pk=head.pk)


@pytest.mark.parametrize(
    ("shape", "n", "carried"),
    [("chain", 3, STALE), ("cycle", 3, STALE), ("fork", 3, NOT_ASSESSED), ("broken", 3, NOT_ASSESSED),
     ("long", 1500, STALE)],
)
def test_the_live_reader_and_0037_carry_the_same_ruling_on_every_shape_of_versions(shape, n, carried):
    """A cycle is walked once, not forever; a fork or a lost link carries nothing past
    it. A long chain is walked in time proportional to it."""
    from assurance.legal import carried_legal_statuses

    dep, head = _versions(shape, n)
    started = time.perf_counter()
    live = carried_legal_statuses(dep.pk, [head]).get(head.pk, head.legal_status)
    live_seconds = time.perf_counter() - started
    with transaction.atomic():
        undo = transaction.savepoint()
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        by_0037 = AssuranceClaim.objects.get(pk=head.pk).legal_status
        transaction.savepoint_rollback(undo)

    assert live == by_0037 == carried
    assert live_seconds < 5, f"{live_seconds:.2f}s to walk {n} versions"


def test_the_plan_names_a_claim_whose_ruling_only_the_carry_holds():
    """The current version's row reads "not assessed"; the person's STALE ruling is on
    the version before. The decision reads the carry and is held back; the plan read
    the row and called the claim current, with nothing to re-run."""
    from assurance.decision import claim_decision_signal
    from assurance.revalidation import plan_revalidation

    dep, head = _versions("chain")
    assert head.legal_status == NOT_ASSESSED

    signal = claim_decision_signal(Deployment.objects.get(pk=dep.pk))
    plan = plan_revalidation(Deployment.objects.get(pk=dep.pk))

    assert [c.pk for c in signal["legally_stale"]] == [head.pk]
    assert [w["claim_uuid"] for w in plan["required"]] == [str(head.uuid)]
    assert plan["still_current"] == []
    assert "Nothing needs to be re-run" not in plan["note"]
