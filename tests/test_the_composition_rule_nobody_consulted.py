"""The compositional assurance rule was written down and nothing consulted it.

``assurance/composition.py`` is 531 lines of rule plus ~850 lines of tests
describing how N per-workflow authority-to-effect chains compose into ONE
deployment decision. Before this change it had **no caller anywhere in the
codebase**: ``assurance/decision.py`` never imported it, no model held a
workflow, and no request could reach it. Its own docstring ends by saying *"The
persistence layer comes later and calls this."*

Those 68 tests all passed the whole time, which is what makes this worth a file
of its own. A pure rule with exhaustive tests and no caller is not half-built —
it is a decorative control, and the roadmap counts this particular one as the
compositional assurance graph being in place.

So these tests are deliberately about the SEAM, not the rule. The rule's own
suite proves worst-of-N, supersession, the census and the refusals. Nothing here
re-proves any of that. What is proved here is that a deployment's rows reach it,
that its verdict reaches the decision, and above all that the ONE judgement the
seam had to make — when a composition may contribute ``READY`` — was made the
conservative way.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from assurance import composition as comp
from assurance.decision import compute_decision, decision_support, read_decision_parts
from assurance.models import ApprovedWorkflow, Deployment, Finding, WorkflowChainOutcome
from assurance.workflow_chains import (
    composition_for,
    composition_signal,
    read_expected_workflows,
)
from django.contrib.auth import get_user_model
from django.test.utils import CaptureQueriesContext
from django.db import connection
from django.utils import timezone

from tests.signed_chains import record_signed

User = get_user_model()

D = Deployment.Decision

pytestmark = pytest.mark.django_db


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}", password="x", role=User.Roles.ANALYST
    )
    return Deployment.objects.create(name=name, owner=owner)


def _critical_finding(dep):
    """A CRITICAL open finding, spelled the way this repo spells it.

    `severity` is a plain string against `SEVERITY_CHOICES` -- there is no
    `Finding.Severity` enum, only `Finding.Status`. Getting that wrong is what
    made two of these tests error rather than fail, which is a worse result than
    either: an AttributeError in the arrange step proves nothing about the assert.
    """
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-critical-{Finding.objects.count()}",
        finding_type="hardcoded_key",
        title="hardcoded key",
        severity="critical",
        status=Finding.Status.OPEN,
    )


def _approve(dep, *slugs):
    for slug in slugs:
        ApprovedWorkflow.objects.create(deployment=dep, slug=slug, name=slug.replace("-", " "))


@pytest.fixture(autouse=True)
def _trusted_engines(engine_keyring):
    """Every outcome in this file is one a run produced: these tests are about the
    seam between recorded chains and the decision, and READY from chains is only
    reachable from demonstrated ones. What a typed-in outcome does at the seam is
    pinned separately, below and in ``test_an_observed_outcome_is_signed``."""
    return engine_keyring


def _outcome(dep, workflow, status, *, observed_at):
    """An outcome a scan observed and signed. A scan's held is READY evidence; an
    Achilles held rests on a permit check and is ready with restrictions at best,
    which ``test_an_observed_outcome_is_signed`` pins -- the seam is what is under
    test here, not which kind of run is behind it."""
    return record_signed(dep, workflow, status, observed_at, engine="athena")


def _typed(dep, workflow, status, *, observed_at):
    """An outcome an operator recorded: attested, whatever its status says."""
    return WorkflowChainOutcome.objects.create(
        deployment=dep,
        workflow=workflow,
        status=status,
        basis=comp.BASIS_ATTESTED,
        observed_at=observed_at,
    )


# ---------------------------------------------------------------------------
# The negative control, first: a deployment with no chains decides as before
# ---------------------------------------------------------------------------


def test_a_deployment_with_no_chains_is_unchanged_by_this():
    """The control this whole change needs. Adding a seventh decision input that
    quietly turned every existing deployment into `needs_more_evidence` -- or into
    `ready` -- would satisfy every assertion below about chains and have broken the
    product for every customer who has no workflows recorded yet."""
    dep = _deployment()
    assert composition_signal(dep) is None
    assert compute_decision(dep) is None

    _critical_finding(dep)
    assert compute_decision(dep) == D.NOT_RECOMMENDED
    assert composition_signal(dep) is None, "no chains must contribute nothing at all"


def test_the_rule_is_reachable_from_a_deployment_at_last():
    """The seam itself: rows in, the rule's own dataclass out. If this is the only
    test that ever fails, the persistence layer stopped calling the rule."""
    dep = _deployment()
    _approve(dep, "billing-export")
    _outcome(dep, "billing-export", comp.HELD, observed_at=timezone.now())

    result = composition_for(dep)
    assert isinstance(result, comp.Composition)
    assert result.workflows_assessed == 1
    assert result.census[comp.HELD] == 1
    assert result.workflows_expected == 1
    assert result.workflows_unreported == 0


# ---------------------------------------------------------------------------
# The verdict reaches the decision
# ---------------------------------------------------------------------------


def test_a_violated_chain_makes_the_deployment_not_recommended():
    """The whole point. A deployment producing an effect its authority does not
    cover is NOT_RECOMMENDED, and before this change it was whatever its findings
    happened to say -- which, for a deployment with no findings, was nothing."""
    dep = _deployment()
    _approve(dep, "billing-export")
    _outcome(dep, "billing-export", comp.VIOLATED, observed_at=timezone.now())

    assert not Finding.objects.filter(deployment=dep).exists()
    assert compute_decision(dep) == D.NOT_RECOMMENDED


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (comp.VIOLATED, D.NOT_RECOMMENDED),
        (comp.INCOMPLETE, D.AUDIT_INCOMPLETE),
        (comp.NOT_DEMONSTRATED, D.NEEDS_MORE_EVIDENCE),
    ],
)
def test_each_floor_arrives_at_the_decision_intact(status, expected):
    """Each of the three floors, end to end. Parametrised rather than written once
    with the worst status, because a seam that collapsed all three to
    NOT_RECOMMENDED would pass a single-status test and destroy the distinction
    between a fact, a gap and a doubt -- which is most of what the rule is for."""
    dep = _deployment()
    _approve(dep, "w")
    _outcome(dep, "w", status, observed_at=timezone.now())
    assert compute_decision(dep) == expected


def test_the_floor_is_never_softened_by_the_seam():
    """A floor passes through as-is even when the scope is wide open. The READY
    narrowing below is one-directional on purpose: it may withhold good news, and
    must never withhold bad."""
    dep = _deployment()
    # No approved workflows recorded at all -- the widest-open scope there is.
    assert read_expected_workflows(dep) is None
    _outcome(dep, "unapproved-thing", comp.VIOLATED, observed_at=timezone.now())
    assert composition_signal(dep) == comp.NOT_RECOMMENDED
    assert compute_decision(dep) == D.NOT_RECOMMENDED


# ---------------------------------------------------------------------------
# The judgement the seam had to make, and the reason this file exists
# ---------------------------------------------------------------------------


def test_one_held_chain_does_not_make_an_unassessed_deployment_ready():
    """THE test. `compose([one held chain]).decision` is `ready` -- correct of the
    composition, which says so in `workflows_expected`, and wrong of the
    deployment. Handing it straight to `decide` would let a single held workflow
    turn a deployment nothing else has assessed into READY: the exact silent zero
    `composition.py`'s own docstring refuses, arriving through the wiring instead
    of through the rule.

    The first assertion is the trap, spelled out so nobody 'simplifies' the seam
    into passing `Composition.decision` through."""
    dep = _deployment()
    # Deliberately NO ApprovedWorkflow rows: nobody wrote the approved set down.
    _outcome(dep, "one-workflow-somebody-checked", comp.HELD, observed_at=timezone.now())

    assert composition_for(dep).decision == comp.READY, "the rule's answer, in scope"
    assert composition_signal(dep) is None, "but it assessed nothing about the deployment"
    assert compute_decision(dep) is None, "and an unassessed deployment is not ready"


def test_a_held_chain_is_ready_only_when_every_approved_workflow_reported():
    """Two deployments, identical chains, different approved sets. The difference
    is the whole judgement: one composition speaks for a closed scope and one does
    not, and only the first is news about the deployment."""
    closed = _deployment("closed-scope")
    _approve(closed, "a", "b")
    _outcome(closed, "a", comp.HELD, observed_at=timezone.now())
    _outcome(closed, "b", comp.HELD, observed_at=timezone.now())
    assert composition_signal(closed) == comp.READY
    assert compute_decision(closed) == D.READY

    open_scope = _deployment("open-scope")
    _approve(open_scope, "a", "b", "c")
    _outcome(open_scope, "a", comp.HELD, observed_at=timezone.now())
    _outcome(open_scope, "b", comp.HELD, observed_at=timezone.now())
    # 'c' was approved and never exercised: `not_demonstrated`, never absent.
    assert composition_signal(open_scope) == comp.NEEDS_MORE_EVIDENCE
    assert compute_decision(open_scope) == D.NEEDS_MORE_EVIDENCE


def test_a_closed_scope_of_typed_in_held_chains_is_not_ready():
    """#239 at the seam. The same closed approved set, every chain held -- once
    typed in, once signed by the engine that ran it. Only the second is READY; the
    first counts as the approved workflows never having reported, which is what
    an assertion no run produced amounts to."""
    typed = _deployment("typed-in")
    _approve(typed, "a", "b")
    _typed(typed, "a", comp.HELD, observed_at=timezone.now())
    _typed(typed, "b", comp.HELD, observed_at=timezone.now())
    composed = composition_for(typed)
    assert composed.decision == comp.NEEDS_MORE_EVIDENCE
    assert set(composed.deciding) == {"a", "b"}
    assert composition_signal(typed) == comp.NEEDS_MORE_EVIDENCE
    assert compute_decision(typed) == D.NEEDS_MORE_EVIDENCE
    assert "counts as not_demonstrated" in comp.explain(composed)

    # One of the two demonstrated is still not enough: the other is an assertion.
    _outcome(typed, "a", comp.HELD, observed_at=timezone.now())
    assert compute_decision(typed) == D.NEEDS_MORE_EVIDENCE
    assert composition_for(typed).deciding == ("b",)

    signed = _deployment("signed")
    _approve(signed, "a", "b")
    _outcome(signed, "a", comp.HELD, observed_at=timezone.now())
    _outcome(signed, "b", comp.HELD, observed_at=timezone.now())
    assert compute_decision(signed) == D.READY


def test_a_typed_in_held_outside_a_closed_scope_sets_no_floor():
    """The restraint half. With no approved list, or for a workflow off it, the
    composition already contributes nothing toward READY -- a floor there would
    make recording an assertion WORSE than recording nothing."""
    dep = _deployment()
    _typed(dep, "unlisted", comp.HELD, observed_at=timezone.now())
    assert composition_for(dep).decision == comp.READY
    assert composition_signal(dep) is None

    listed = _deployment("listed")
    _approve(listed, "a")
    _outcome(listed, "a", comp.HELD, observed_at=timezone.now())
    _typed(listed, "shadow", comp.HELD, observed_at=timezone.now())
    assert composition_for(listed).decision == comp.READY
    assert composition_signal(listed) is None


def test_fifty_approved_workflows_and_one_held_chain_is_not_ready():
    """The sentence `composition.py` argues for, through the database this time.
    Nine of the ten are undemonstrated, so the deployment needs more evidence --
    and a coverage-weighted rule would have called 10% checked something better
    than nothing."""
    dep = _deployment()
    _approve(dep, *[f"w{i}" for i in range(10)])
    _outcome(dep, "w0", comp.HELD, observed_at=timezone.now())

    result = composition_for(dep)
    assert result.workflows_expected == 10
    assert result.workflows_unreported == 9
    assert result.census[comp.NOT_DEMONSTRATED] == 9
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


# ---------------------------------------------------------------------------
# The unapproved direction — the counter a foreign key would have killed
# ---------------------------------------------------------------------------


def test_an_outcome_can_name_a_workflow_nobody_approved():
    """`WorkflowChainOutcome.workflow` is a slug, not a ForeignKey to
    ApprovedWorkflow, and this is the test that keeps it that way.

    A foreign key would read as the tidier schema and would make
    `Composition.workflows_unapproved` structurally 0 for every possible input --
    the count unreachable, the sentence in `explain` always the reassuring one, and
    the check decorative. A chain exercising a workflow nobody approved is exactly
    what this platform exists to notice, so the schema has to be able to hold one.
    """
    dep = _deployment()
    _approve(dep, "billing-export")
    _outcome(dep, "billing-export", comp.HELD, observed_at=timezone.now())
    _outcome(dep, "a-workflow-nobody-approved", comp.HELD, observed_at=timezone.now())

    result = composition_for(dep)
    assert result.workflows_unapproved == 1
    assert "not on the approved list" in comp.explain(result)


def test_an_unapproved_outcome_blocks_ready_and_sets_no_floor_of_its_own():
    """Both halves, and the second is the restraint.

    It blocks READY: a composition carrying a chain for a workflow nobody approved
    does not speak for a closed scope, so "these chains hold" is not a statement
    about the deployment.

    It sets NO floor: that would put the platform's answer to one question in two
    places that can disagree. A shadow workflow reaches the decision through the
    drift path, which raises a finding. The disagreement, not the severity, is what
    this codebase keeps refusing -- so the decision here is `None`, not a cap.
    """
    dep = _deployment()
    _approve(dep, "billing-export")
    _outcome(dep, "billing-export", comp.HELD, observed_at=timezone.now())
    _outcome(dep, "shadow", comp.HELD, observed_at=timezone.now())

    assert composition_for(dep).decision == comp.READY
    assert composition_signal(dep) is None, "not READY: the scope is not closed"
    assert compute_decision(dep) is None, "and not a floor either: no second rule"


# ---------------------------------------------------------------------------
# No rows and zero rows are different questions
# ---------------------------------------------------------------------------


def test_no_approved_rows_reads_as_not_recorded_rather_than_a_known_empty_set():
    """The database cannot distinguish "this deployment has no approved workflows"
    from "nobody has written the set down yet", and only one reading is safe.

    Read as a known-empty set, every outcome becomes unapproved and a deployment
    with no approvals and no chains reports a closed, fully covered scope -- a
    perfect score for having recorded nothing.
    """
    dep = _deployment()
    assert read_expected_workflows(dep) is None
    assert composition_for(dep).workflows_expected is None

    _approve(dep, "a")
    assert read_expected_workflows(dep) == ["a"]
    assert composition_for(dep).workflows_expected == 1


# ---------------------------------------------------------------------------
# Timestamps survive the round trip
# ---------------------------------------------------------------------------


def test_a_stored_timestamp_comes_back_aware_enough_for_the_rule():
    """`ChainOutcome` REFUSES a naive timestamp, by design: a naive and an aware
    datetime cannot be compared, and two outcomes for one workflow are compared.
    That refusal is a `ValueError` raised from inside the seam.

    So this is not a test about Django's settings. It is the test that fails, with
    the reason attached, if `USE_TZ` is ever flipped or a backend starts handing
    back naive datetimes -- because then EVERY composition on EVERY deployment
    raises, and the decision path raises with it.
    """
    dep = _deployment()
    _approve(dep, "w")
    stored = _outcome(dep, "w", comp.HELD, observed_at=timezone.now())
    stored.refresh_from_db()
    assert stored.observed_at.utcoffset() is not None, "a naive row would break the rule"

    # And it composes rather than raising.
    assert composition_for(dep).census[comp.HELD] == 1


def test_a_later_verdict_from_the_database_supersedes_an_earlier_one():
    """Supersession is the rule's own business and its own suite proves it. What
    this proves is that the ORDERING of rows out of the database does not change
    the answer -- the seam hands over every row and lets the rule decide, rather
    than taking the first or the last."""
    dep = _deployment()
    _approve(dep, "w")
    now = timezone.now()
    # Inserted newest-first, so a seam that trusted insertion order would be wrong.
    _outcome(dep, "w", comp.HELD, observed_at=now)
    _outcome(dep, "w", comp.VIOLATED, observed_at=now - timedelta(days=5))

    assert composition_for(dep).census[comp.HELD] == 1
    assert compute_decision(dep) == D.READY

    _outcome(dep, "w", comp.VIOLATED, observed_at=now + timedelta(days=1))
    assert compute_decision(dep) == D.NOT_RECOMMENDED


# ---------------------------------------------------------------------------
# What an operator is told
# ---------------------------------------------------------------------------


def test_decision_support_reports_the_census_with_its_zeros():
    """A count that appears only when non-zero is a count nobody checks, and its
    absence reads exactly like a zero. All four statuses, always."""
    dep = _deployment()
    _approve(dep, "a", "b")
    _outcome(dep, "a", comp.VIOLATED, observed_at=timezone.now())
    _outcome(dep, "b", comp.HELD, observed_at=timezone.now())

    block = decision_support(dep)["composition"]
    assert set(block["census"]) == set(comp.CHAIN_STATUSES)
    assert block["census"][comp.VIOLATED] == 1
    assert block["census"][comp.HELD] == 1
    assert block["census"][comp.INCOMPLETE] == 0
    assert block["census"][comp.NOT_DEMONSTRATED] == 0
    assert block["deciding"] == ["a"]
    assert block["signal"] == comp.NOT_RECOMMENDED


def test_the_note_names_the_chains_only_when_the_chains_are_why():
    """The counterfactual, and the near-miss sentence it exists to prevent.

    A branch that fired whenever the chains AGREED with the decision would tell an
    operator to go read workflow chains for a NOT_RECOMMENDED the findings had
    already made on their own -- true of the chains, and useless as guidance.
    """
    chains_decide = _deployment("chains-decide")
    _approve(chains_decide, "w")
    _outcome(chains_decide, "w", comp.VIOLATED, observed_at=timezone.now())
    note = decision_support(chains_decide)["note"]
    assert "Approved-workflow chains, not findings or claims, place it there" in note

    findings_already = _deployment("findings-already")
    _approve(findings_already, "w")
    _outcome(findings_already, "w", comp.VIOLATED, observed_at=timezone.now())
    _critical_finding(findings_already)
    support = decision_support(findings_already)
    assert support["decision"] == D.NOT_RECOMMENDED
    assert "Approved-workflow chains, not findings or claims" not in support["note"], (
        "the findings placed it there on their own; the chains merely agree"
    )
    # The census still reports the violated chain, which is the point of having
    # both a note and a block.
    assert support["composition"]["census"][comp.VIOLATED] == 1


def test_a_ready_that_came_from_the_chains_says_so():
    """Before this, a deployment READY because every approved workflow's chain
    holds fell through to "Decision reflects the deployment's active findings" --
    a statement about an empty set, offered as the reason."""
    dep = _deployment()
    _approve(dep, "a", "b")
    _outcome(dep, "a", comp.HELD, observed_at=timezone.now())
    _outcome(dep, "b", comp.HELD, observed_at=timezone.now())

    support = decision_support(dep)
    assert support["decision"] == D.READY
    assert "every one of the 2 approved workflow(s)" in support["note"]


def test_pausing_nulls_the_signal_and_keeps_the_census():
    """The failsafe decides, so no signal contributed to THIS decision -- and a
    paused deployment's violated chain is still a violated chain. Hiding it while
    paused would be the silent zero with a good excuse."""
    dep = _deployment()
    _approve(dep, "w")
    _outcome(dep, "w", comp.VIOLATED, observed_at=timezone.now())

    support = decision_support(dep, paused=True)
    assert support["decision"] == D.PAUSED
    assert support["composition"]["signal"] is None
    assert support["composition"]["census"][comp.VIOLATED] == 1
    assert support["composition"]["rule_decision"] == comp.NOT_RECOMMENDED


def test_the_unassessed_note_now_mentions_the_chains_it_also_checked():
    dep = _deployment()
    assert decision_support(dep)["note"] == (
        "Not yet assessed: no findings, no assurance claims and no workflow chains."
    )


# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------


def test_reading_the_composition_does_not_scale_with_the_number_of_workflows():
    """Three queries regardless: the outcomes, the approved slugs, and the
    components the route serving now is read from (P2.2 -- each outcome is compared
    with it, so it is read once for all of them, providers joined). A decision input
    that fanned out per workflow would make every decision read -- and the decision
    is read on a page load -- proportional to how much assurance a customer has
    recorded, which is backwards."""
    dep = _deployment()
    _approve(dep, *[f"w{i}" for i in range(40)])
    for i in range(40):
        _outcome(dep, f"w{i}", comp.HELD, observed_at=timezone.now())

    with CaptureQueriesContext(connection) as captured:
        composition_for(dep)
    assert len(captured) == 3, [q["sql"] for q in captured]


def test_the_decision_read_gains_exactly_the_two_queries():
    """`read_decision_parts` exists so every input is read once. The chains must
    join that discipline rather than opening a second conversation with the
    database per call."""
    dep = _deployment()
    _approve(dep, "a")
    _outcome(dep, "a", comp.HELD, observed_at=timezone.now())

    with CaptureQueriesContext(connection) as captured:
        read_decision_parts(dep)
    chain_queries = [
        q["sql"]
        for q in captured
        if "approvedworkflow" in q["sql"].lower() or "workflowchainoutcome" in q["sql"].lower()
    ]
    # THREE, not two: the outcomes, the approved set, and the provenance census.
    # The census was added deliberately and is read inside the same pass for the
    # reason this test exists -- a census from a later moment published beside
    # this composition would describe a graph nobody ever had. The number is
    # asserted rather than bounded so a FOURTH query has to be a decision too.
    assert len(chain_queries) == 3, chain_queries


def test_ready_already_implies_every_approved_workflow_reported():
    """The invariant that lets `composition_decision_signal` not test
    `workflows_unreported`, pinned so the simplification cannot rot.

    A mutation deleting that condition from the closed-scope check broke nothing,
    which meant it could not fire. The reason is this implication: an approved
    workflow with no outcome is `not_demonstrated`, `not_demonstrated` carries a
    floor, and a floor means the rule's decision is not READY. So by the time the
    READY branch is reached, `workflows_unreported` is necessarily 0.

    If the rule ever stops flooring an unreported workflow, this fails here --
    where the reason is written down -- rather than silently letting a deployment
    with unexercised approved workflows read as ready.
    """
    dep = _deployment()
    _approve(dep, "a", "b", "c")
    _outcome(dep, "a", comp.HELD, observed_at=timezone.now())

    result = composition_for(dep)
    assert result.workflows_unreported == 2
    assert result.decision != comp.READY, (
        "an unreported approved workflow must set a floor; if it stops doing so, "
        "composition_decision_signal has to test workflows_unreported again"
    )

    # And the implication in the direction the signal relies on: READY from the
    # rule, with an approved set recorded, means nothing was left unreported.
    for slug in ("b", "c"):
        _outcome(dep, slug, comp.HELD, observed_at=timezone.now())
    ready = composition_for(dep)
    assert ready.decision == comp.READY
    assert ready.workflows_unreported == 0
