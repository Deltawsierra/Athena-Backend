"""A SPINE path's work follows its own deployment, not the database around it
(Phase 5 item 3: optimize SPINE query/traversal paths).

Measured on master a32f63a with the seeded corpus (:mod:`tests.spine_corpus`;
the table is docs/performance/spine-queries.md):

- the refresh of a decision another writer left (a rollout's: the backstop's claim,
  the watches read, the decision brought current) asked whether its watches were read
  through ``claim__in=AssuranceClaim.objects.closed()`` and ``.current()`` -- lists
  SQLite built by scanning every claim version of EVERY deployment, so the refresh
  of one deployment cost more for every other deployment's claims (the same kind of
  list in ``conditions_the_decision_reads``, on every decision path, is #176's,
  merged at cf14de0; the database-size test below holds it too);
- a recompute read the deployment's accepted risks through the related manager with
  ``deployment`` deferred, and Django fetched it back one query per accepted
  finding: 130 statements for a deployment carrying 88 accepted risks, 56 without;
- a recompute read the asset table nine times -- once per reader of the graph, and
  twice more for the route serving now -- and fetched each provider the route map
  named one query at a time; a re-derive read it three times;
- every read of a deployment's CURRENT claims walked every version the deployment
  ever had, so its cost grew with the claims' history.

Each assertion below is deterministic: statement counts, the tables a statement's
EXPLAIN QUERY PLAN reads whole (``SCAN``), and the exact SQLite VM steps a statement
takes, compared within one run -- never wall time. Every one fails on master
cf14de0 (and on a32f63a, where this was measured).
"""

from __future__ import annotations

import re

import pytest

from tests import spine_corpus as sc

pytestmark = pytest.mark.django_db

#: A small deployment of the corpus: enough of every kind of row for every reader.
SMALL = sc.Shape(agents=2, tools=3, data_stores=1, findings=6, versions=1, claim_evidence=3)

#: Ranks whose profiles between them carry every input the paths read: a fired
#: condition holding its claim, an authority chain, accepted risks, an open retest.
TARGETS = (3, 4)

#: The VM steps a statement that reads only its own deployment's rows may take more
#: once other deployments' rows sit beside them in an index: the comparison that ends
#: its key range now lands on a neighbour's entry instead of the end of the index --
#: one step per range end. The four deployments built beside the targets add dozens
#: of rows to every table these statements read; reading even one of them costs more
#: (a step to move to it, one per column it reads, one to compare it), and an
#: unscoped list of claim versions costs over a hundred more.
RANGE_END = 2


@pytest.fixture
def corpus(monkeypatch, tmp_path):
    clock = sc.Clock()
    sc.hold_still(monkeypatch, clock, sc.SeededUUIDs(), tmp_path / "keyring.json")
    from django.contrib.auth import get_user_model

    return sc.Corpus(clock=clock, admin=sc._user("corpus-admin", get_user_model().Roles.ADMIN))


def _paths(clock) -> dict:
    from assurance.claims import derive_claims
    from assurance.decision import recompute_decision, refresh_stored_decisions
    from assurance.models import Deployment
    from assurance.ripple import assess_ripple

    def foreign(pk):
        # A decision another writer left: the refresh claims it, reads the watches,
        # and brings it current.
        Deployment.objects.filter(pk=pk).update(decision_policy="")
        refresh_stored_decisions([pk])

    return {
        "derive_claims": lambda pk: derive_claims(Deployment.objects.get(pk=pk), now=clock.now()),
        "assess_ripple": lambda pk: assess_ripple(
            Deployment.objects.prefetch_related("assets__provider__assertions", "findings__asset").get(pk=pk)
        ),
        "recompute_decision": lambda pk: recompute_decision(Deployment.objects.get(pk=pk)),
        "refresh_stored_decisions": lambda pk: refresh_stored_decisions([pk]),
        "refresh_of_another_writers_decision": foreign,
    }


def _shape(sql: str) -> str:
    """A statement as compared: a savepoint's name carries a counter."""
    return re.sub(r'"s\d+_x\d+"', '"s_x"', sql)


def _read(fn, pk, tables) -> list[dict]:
    fn(pk)  # what a change left is done by the first call; the second is the path's own cost
    return sc.each_statement(sc.measure(lambda: fn(pk)), tables)


# ------------------------------------------------------------------ database size


def test_no_path_does_more_work_for_other_deployments_data(corpus):
    tables = sc.per_deployment_tables()
    targets = [sc.build_deployment(corpus, rank, SMALL) for rank in TARGETS]
    paths = _paths(corpus.clock)
    alone = {(t.pk, name): _read(fn, t.pk, tables) for t in targets for name, fn in paths.items()}

    for rank in (10, 11, 12, 13):
        sc.build_deployment(corpus, rank, SMALL)
    crowded = {(t.pk, name): _read(fn, t.pk, tables) for t in targets for name, fn in paths.items()}

    for key, before in alone.items():
        after = crowded[key]
        # The same statements: nothing is read once per other deployment.
        assert [_shape(s["sql"]) for s in after] == [_shape(s["sql"]) for s in before], key
        for b, a in zip(before, after):
            # No statement reads a table of deployment-owned rows whole...
            assert not a["scans"], (key, a["scans"], a["sql"][:400])
            # ...and no read visits a row of theirs, by any index.
            assert a["steps"] is None or a["steps"] - b["steps"] <= RANGE_END, (key, b["steps"], a["steps"], a["sql"][:400])


# ------------------------------------------------------------- its own deployment


def _recompute(pk):
    from assurance.decision import recompute_decision
    from assurance.models import Deployment

    return recompute_decision(Deployment.objects.get(pk=pk))


def test_a_recompute_reads_its_accepted_risks_in_one_statement(corpus):
    from assurance.decision import accepted_risk_signal
    from assurance.models import Deployment, Finding

    few = sc.build_deployment(corpus, 4, sc.Shape(**{**SMALL.__dict__, "findings": 2}))
    many = sc.build_deployment(corpus, 4 + 6, sc.Shape(**{**SMALL.__dict__, "findings": 24}))
    accepted = {
        d.pk: Finding.objects.filter(deployment=d, status=Finding.Status.ACCEPTED).count() for d in (few, many)
    }
    assert accepted[many.pk] >= accepted[few.pk] + 20

    for dep in (few, many):
        reading = Deployment.objects.get(pk=dep.pk)
        signal = sc.measure(lambda: accepted_risk_signal(reading, now=corpus.clock.now()))
        assert len(signal.statements) == 1, [s[:200] for s, _ in signal.statements]
        assert len(signal.result["standing"]) + len(signal.result["lapsed"]) == accepted[dep.pk]

    _recompute(few.pk), _recompute(many.pk)
    counts = {dep.pk: len(sc.measure(lambda: _recompute(dep.pk)).statements) for dep in (few, many)}
    assert counts[few.pk] == counts[many.pk], counts


def _graph_reads(measured) -> list[str]:
    """The table each statement of ``measured`` that reads the components or their
    providers reads, in order."""
    out = []
    for sql, _ in measured.statements:
        table = sql.split(" WHERE ")[0].rstrip().split(" FROM ")[-1].split()[0].strip('"')
        if table in ("assurance_asset", "assurance_provider"):
            out.append(table)
    return out


def test_a_recompute_reads_the_component_graph_once(corpus):
    from assurance.models import Asset, Provider

    dep = sc.build_deployment(corpus, 0, SMALL)
    _recompute(dep.pk)
    before = sc.measure(lambda: _recompute(dep.pk))
    # One read of the components with their providers, for every reader of the graph
    # and for the route serving now (assurance.served_route.route_held).
    assert _graph_reads(before) == ["assurance_asset"], _graph_reads(before)

    # More provider-backed components cost the recompute no further statement.
    for n in range(8):
        provider, _ = Provider.objects.get_or_create(name=f"corpus-extra-{n}", kind="model_provider")
        Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name=f"extra-model-{n}",
                             identifier=f"extra-model-{n}", provider=provider)
    _recompute(dep.pk)
    after = sc.measure(lambda: _recompute(dep.pk))
    assert len(after.statements) == len(before.statements), (len(before.statements), len(after.statements))


def test_a_re_derive_reads_the_component_graph_once(corpus):
    from assurance.claims import derive_claims
    from assurance.models import Deployment

    dep = sc.build_deployment(corpus, 0, SMALL)

    def derive():
        return derive_claims(Deployment.objects.get(pk=dep.pk), now=corpus.clock.now())

    derive()
    # The plan's one prefetch of the components and then their providers -- the
    # receipt it digests reads the route serving now from that graph, not the table.
    assert _graph_reads(sc.measure(derive)).count("assurance_asset") == 1


def test_a_pause_reads_no_component_of_the_graph(corpus):
    """The graph is read once for a recompute that reads inputs -- and not at all for
    a pause, which reads nothing: no stop waits on the read added here."""
    from assurance.decision import recompute_decision
    from assurance.models import Deployment

    dep = sc.build_deployment(corpus, 0, SMALL)
    paused = sc.measure(lambda: recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True))
    assert paused.result == Deployment.Decision.PAUSED
    assert _graph_reads(paused) == []


def test_the_current_claims_are_found_without_reading_their_history(corpus):
    from django.db import connection

    from assurance.models import AssuranceClaim

    dep = sc.build_deployment(corpus, 0, SMALL)
    # As the decision reads them (claim_decision_signal) and the re-derive's
    # staleness pass does (claims._mark_stale).
    reads = (
        lambda: dep.assurance_claims.current().exclude(status=AssuranceClaim.ClaimStatus.REVOKED),
        lambda: AssuranceClaim.objects.filter(deployment=dep).current(),
    )

    def cost():
        out = []
        for qs in reads:
            sql, params = qs().query.sql_with_params()
            with connection.cursor() as cursor:
                cursor.execute("EXPLAIN QUERY PLAN " + sql, params)
                plan = [row[-1] for row in cursor.fetchall()]
            out.append((plan, sc.each_statement(sc.measure(lambda: list(qs())), frozenset())[0]["steps"]))
        return out

    young = cost()
    for v in range(12):
        sc.churn(dep, v, corpus.clock)
    old = cost()
    assert AssuranceClaim.objects.filter(deployment=dep).closed().count() >= 24
    for (plan, steps), (_, aged) in zip(young, old):
        # Found by key on all three columns current() reads...
        assert any("valid_to=? AND effective_to=?" in step for step in plan), plan
        # ...so twenty-four closed versions more cost the read nothing.
        assert aged == steps, (steps, aged)


def test_a_held_route_answers_only_for_the_instance_that_holds_the_graph(corpus):
    """The route serving now is read once for the instance whose graph a reading holds
    -- and for no other instance of the deployment: a refresh that reading sets off
    reads its own instance after other writers may have committed, and notes the
    route it reads. Held for the deployment, it would note a route that no longer
    serves."""
    from django.db.models import Prefetch

    from assurance.models import Asset, Deployment
    from assurance.served_route import route_held, serving_route_now

    dep = sc.build_deployment(corpus, 0, SMALL)
    holding = Deployment.objects.prefetch_related(
        Prefetch("assets", queryset=Asset.objects.select_related("provider"))
    ).get(pk=dep.pk)
    before = serving_route_now(Deployment.objects.get(pk=dep.pk))
    with route_held(holding):
        # Another writer adds a component that serves inference after the graph was read.
        Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="late-model", identifier="late-model",
                             classification=Asset.Classification.APPROVED)
        assert serving_route_now(holding) == before
        assert serving_route_now(Deployment.objects.get(pk=dep.pk)) != before
    assert serving_route_now(Deployment.objects.get(pk=dep.pk)) != before
