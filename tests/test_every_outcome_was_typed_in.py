"""The compositional assurance graph now says where its inputs came from.

Every other counter in the composition payload describes what the chains SAID.
None described who said it. ``source`` has been recorded per row since the model
was written and serialised per row by the outcome routes, but it was never
aggregated anywhere a reader of the graph would meet it -- so a graph assembled
entirely by one operator with a REST client read exactly like one fed by real
campaign runs.

That is not hypothetical. Across this platform's repositories the only writer of a
chain outcome is this app's own admin POST route: no engine, no campaign, no scan
and no dispatch writes one. So every composition that exists today rests on
hand-entered input, and until now the graph could not say so.

What these hold is the census and the three things it must not do: invent a source
for a workflow that produced no outcome, drop a row that named no source, or hide
rows behind its cap without saying how many.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from assurance import composition as comp
from assurance.decision import decision_support, read_decision_parts
from assurance.models import ApprovedWorkflow, Deployment, WorkflowChainOutcome
from assurance.workflow_chains import (
    PROVENANCE_LIMIT,
    UNATTRIBUTED,
    composition_decision_signal,
    composition_for,
    composition_payload,
    read_chain_provenance,
)

User = get_user_model()

pytestmark = pytest.mark.django_db


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}",
        password="x",
        role=User.Roles.ANALYST,
    )
    return Deployment.objects.create(name=name, owner=owner)


def _approve(dep, *slugs):
    for slug in slugs:
        ApprovedWorkflow.objects.create(
            deployment=dep, slug=slug, name=slug.replace("-", " ")
        )


def _outcome(dep, workflow, status=comp.HELD, *, source="", observed_at=None):
    return WorkflowChainOutcome.objects.create(
        deployment=dep,
        workflow=workflow,
        status=status,
        source=source,
        observed_at=observed_at,
    )


def test_a_graph_fed_only_by_an_operator_says_so():
    """The finding this census exists for, as a test.

    Today this is not one case among many: it is every composition in existence,
    because nothing but this app's admin route writes an outcome.
    """
    dep = _deployment()
    _approve(dep, "checkout")
    _outcome(dep, "checkout", source="operator")

    provenance = read_chain_provenance(dep)

    assert provenance["sources"] == {"operator": 1}
    assert provenance["recorded"] == 1
    assert provenance["distinct"] == 1


def test_an_outcome_that_named_no_source_is_counted_under_its_own_name():
    """Never dropped, and never folded in with something attributed.

    A row that does not say where it came from is a fact about the graph. Dropping
    it would make `recorded` disagree with the census for no stated reason; folding
    it into a real source would attribute evidence to a producer that did not send
    it, which is worse than saying nothing.
    """
    dep = _deployment()
    _outcome(dep, "a", source="campaign")
    _outcome(dep, "b", source="")
    _outcome(dep, "c", source="   ")

    provenance = read_chain_provenance(dep)

    assert provenance["sources"] == {UNATTRIBUTED: 2, "campaign": 1}
    assert provenance["recorded"] == 3
    assert sum(provenance["sources"].values()) == provenance["recorded"]


def test_a_superseded_outcome_still_counts_as_something_that_fed_the_graph():
    """The census answers "what has ever fed this graph", not "what decides it".

    A superseded operator entry answers that as much as a standing one. So these
    counts deliberately do NOT track `workflows_assessed`, and this test pins the
    divergence rather than leaving it to a reader to discover.
    """
    dep = _deployment()
    now = timezone.now()
    _outcome(
        dep,
        "checkout",
        comp.VIOLATED,
        source="operator",
        observed_at=now - timedelta(days=1),
    )
    _outcome(dep, "checkout", comp.HELD, source="campaign", observed_at=now)

    composition = composition_for(dep)
    provenance = read_chain_provenance(dep)

    assert composition.workflows_assessed == 1
    assert composition.superseded == 1
    assert provenance["recorded"] == 2
    assert provenance["sources"] == {"campaign": 1, "operator": 1}


def test_a_workflow_that_produced_no_outcome_gets_no_invented_source():
    """The rule synthesises `not_demonstrated` for an approved workflow nobody
    exercised. That is the ABSENCE of an outcome, not an outcome from nowhere.

    Giving it a provenance entry would invent a source for a row that does not
    exist — and in a census whose whole job is to say what is real, a fabricated
    entry is the one thing that would make it worse than having none.
    """
    dep = _deployment()
    _approve(dep, "checkout", "refund", "export")
    _outcome(dep, "checkout", source="operator")

    composition = composition_for(dep)
    provenance = read_chain_provenance(dep)

    assert composition.workflows_unreported == 2
    assert composition.census[comp.NOT_DEMONSTRATED] == 2
    assert provenance["recorded"] == 1
    assert provenance["sources"] == {"operator": 1}


def test_the_cap_says_how_many_rows_it_hid():
    """A census that dropped rows silently would understate a producer nobody has
    noticed, which is the whole thing this census is for."""
    dep = _deployment()
    for n in range(PROVENANCE_LIMIT + 5):
        _outcome(dep, f"w{n}", source=f"producer-{n:03d}")
    # One source with a count high enough to be kept whatever the tie order.
    for n in range(3):
        _outcome(dep, f"loud{n}", source="loud-producer")

    provenance = read_chain_provenance(dep)

    # Spelled out because the first version of this test got it wrong and the
    # CODE was right: the loud producer occupies one of the kept slots, so only
    # PROVENANCE_LIMIT - 1 of the single-count producers survive the cap.
    singles = PROVENANCE_LIMIT + 5
    hidden = singles - (PROVENANCE_LIMIT - 1)

    assert len(provenance["sources"]) == PROVENANCE_LIMIT
    assert provenance["distinct"] == singles + 1
    assert provenance["recorded"] == singles + 3
    assert provenance["truncated"] is True
    assert provenance["not_shown"] == hidden
    # The total is still recoverable: what is shown plus what is not.
    assert (
        sum(provenance["sources"].values()) + provenance["not_shown"]
        == (provenance["recorded"])
    )
    # The busiest producer is never the one hidden.
    assert provenance["sources"]["loud-producer"] == 3


def test_an_uncapped_census_says_it_hid_nothing():
    dep = _deployment()
    _outcome(dep, "a", source="operator")

    provenance = read_chain_provenance(dep)

    assert provenance["truncated"] is False
    assert provenance["not_shown"] == 0


def test_the_census_is_the_same_twice_for_an_unchanged_deployment():
    """Ties are ordered deterministically, so a payload cannot change without the
    deployment changing — otherwise a consumer cannot diff two reads."""
    dep = _deployment()
    for n in range(6):
        _outcome(dep, f"w{n}", source=f"same-count-{n}")

    assert read_chain_provenance(dep) == read_chain_provenance(dep)


def test_a_graph_nobody_fed_reports_a_count_rather_than_nothing():
    """`recorded: 0` is a measurement: the census was taken and found nothing.

    Distinguishable from a census nobody took, which cannot happen — the field is
    required, so there is no shape in which the key is simply absent.
    """
    dep = _deployment()

    provenance = read_chain_provenance(dep)

    assert provenance == {
        "sources": {},
        "distinct": 0,
        "recorded": 0,
        "truncated": False,
        "not_shown": 0,
    }


def test_the_payload_builder_refuses_to_publish_without_a_census():
    """Required rather than defaulted, for the reason the builder exists at all.

    A default would let a new publisher omit provenance and still render, and the
    omission would read as a graph with nothing to say about its sources rather
    than as a caller that did not look.
    """
    dep = _deployment()
    composition = composition_for(dep)

    with pytest.raises(TypeError):
        composition_payload(composition, signal=None)  # type: ignore[call-arg]


def test_both_publishers_report_the_same_census_for_one_deployment():
    """The two call sites describe the same deployment, so they must agree.

    An operator who records an outcome and reads `provenance` back from the write
    route, then reads a different census from the decision route, has been told two
    incompatible things about one graph — the failure the shared builder and the
    transactions around it exist together to prevent.
    """
    dep = _deployment()
    _approve(dep, "checkout")
    _outcome(dep, "checkout", source="operator")

    from_decision = decision_support(dep)["composition"]["provenance"]

    composition = composition_for(dep)
    from_ingest = composition_payload(
        composition,
        signal=composition_decision_signal(composition),
        provenance=read_chain_provenance(dep),
    )["provenance"]

    assert from_decision == from_ingest


def test_the_census_travels_with_the_decision_and_takes_no_part_in_it():
    """It is reported, never decided with.

    A census that moved the decision would be this module scoring provenance, and
    `decide` has no business knowing who typed a row in. Same deployment, same
    chains, two different source strings: the decision must not move.
    """
    from assurance.decision import decide

    first = _deployment("one")
    _approve(first, "checkout")
    _outcome(first, "checkout", comp.VIOLATED, source="operator")

    second = _deployment("two")
    _approve(second, "checkout")
    _outcome(second, "checkout", comp.VIOLATED, source="campaign")

    parts_one = read_decision_parts(first)
    parts_two = read_decision_parts(second)

    assert parts_one.chain_provenance != parts_two.chain_provenance
    assert decide(parts_one) == decide(parts_two)
