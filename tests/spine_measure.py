"""Record the golden fixture and measure the SPINE paths (Phase 5 item 3).

Not a test module: pytest collects it only when it is named on the command line.

    pytest tests/spine_measure.py::test_record_golden   # writes tests/fixtures/spine_golden.json
    SPINE_MEASURE_OUT=out.json pytest tests/spine_measure.py::test_measure

The golden fixture is recorded ONCE, from the code before an optimization; the
golden test then compares every later tree with it. Re-recording it after a change
would make the test compare a tree with itself.
"""

from __future__ import annotations

import pathlib

import pytest

from tests import spine_corpus as sc

pytestmark = pytest.mark.django_db

GOLDEN = pathlib.Path(__file__).resolve().parent / "fixtures" / "spine_golden.json"


def test_record_golden(monkeypatch, tmp_path):
    clock = sc.Clock()
    sc.hold_still(monkeypatch, clock, sc.SeededUUIDs(), tmp_path / "keyring.json")
    corpus = sc.build_corpus(clock)
    GOLDEN.write_text(sc.canonical(sc.run_paths(corpus)), encoding="utf-8")


#: A realistic deployment for the measurements: dozens of components, eighty-odd
#: findings, claims re-derived through eight versions, forty evidence items.
REALISTIC = sc.Shape(agents=6, tools=14, data_stores=4, findings=80, versions=8, claim_evidence=40)
#: How many other deployments the database-size measurement adds, and how many
#: re-derives the history measurement adds.
OTHERS = 7
HISTORY = 30
CPU_RUNS = 15


def _paths(clock):
    from assurance.claims import derive_claims
    from assurance.decision import current_decision, decision_support, recompute_decision, refresh_stored_decisions
    from assurance.models import Deployment
    from assurance.ripple import assess_ripple

    def support(pk):
        dep = Deployment.objects.get(pk=pk)
        current_decision(dep)
        return decision_support(dep)

    def foreign(pk):
        Deployment.objects.filter(pk=pk).update(decision_policy="")
        refresh_stored_decisions([pk])

    return {
        "derive_claims": lambda pk: derive_claims(Deployment.objects.get(pk=pk), now=clock.now()),
        "assess_ripple": lambda pk: assess_ripple(
            Deployment.objects.prefetch_related("assets__provider__assertions", "findings__asset").get(pk=pk)
        ),
        "recompute_decision": lambda pk: recompute_decision(Deployment.objects.get(pk=pk)),
        "refresh (backstop)": lambda pk: refresh_stored_decisions([pk]),
        "refresh (another writer's decision)": foreign,
        "decision_support": support,
    }


def _measure(clock, pk, tables, *, cpu=False) -> dict:
    out = {}
    for name, fn in _paths(clock).items():
        fn(pk)  # warm: the first call may do the work a change left
        m = sc.measure(lambda: fn(pk))
        row = {
            "queries": len(m.statements),
            "vm_steps": m.vm_steps,
            "full_scans": sorted({t for t, _ in sc.full_scans(m.statements, tables)}),
        }
        if cpu:
            times = sorted(sc.cpu_seconds(lambda: fn(pk), repeat=CPU_RUNS))
            row["cpu_ms_median"] = round(1000 * times[len(times) // 2], 2)
            row["cpu_ms_min"] = round(1000 * times[0], 2)
            row["cpu_n"] = CPU_RUNS
        out[name] = row
    return out


def test_measure(monkeypatch, tmp_path):
    import json
    import os

    clock = sc.Clock()
    sc.hold_still(monkeypatch, clock, sc.SeededUUIDs(), tmp_path / "keyring.json")
    tables = sc.per_deployment_tables()
    corpus = sc.Corpus(clock=clock, admin=sc._user("corpus-admin", "admin"))
    # Two targets: a deployment with a critical open (rank 0), and one whose every
    # finding is an accepted risk (rank 4) -- the profile the accepted-risk read is
    # sized by.
    targets = {"critical-open": sc.build_deployment(corpus, 0, REALISTIC),
               "all-accepted": sc.build_deployment(corpus, 4, REALISTIC)}
    report = {"shape": REALISTIC.__dict__, "others": OTHERS, "history": HISTORY}
    for label, dep in targets.items():
        report[label] = {"alone": _measure(clock, dep.pk, tables, cpu=True)}
    for rank in range(10, 10 + OTHERS):
        sc.build_deployment(corpus, rank, REALISTIC)
    for label, dep in targets.items():
        report[label]["with_others"] = _measure(clock, dep.pk, tables)
    for label, dep in targets.items():
        for v in range(100, 100 + HISTORY):
            sc.churn(dep, v, clock)
        report[label]["with_history"] = _measure(clock, dep.pk, tables)
    from assurance.models import AssuranceClaim, Finding

    report["rows"] = {
        label: {"claims": AssuranceClaim.objects.filter(deployment=dep).count(),
                "findings": Finding.objects.filter(deployment=dep).count()}
        for label, dep in targets.items()
    }
    out = os.environ.get("SPINE_MEASURE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(report, indent=1, sort_keys=True))
    print(json.dumps(report, indent=1, sort_keys=True))
