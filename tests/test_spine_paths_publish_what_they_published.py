"""SPINE's query paths publish, byte for byte, what they published before they were
made faster (Phase 5 item 3: optimize SPINE query/traversal paths).

The quality bar of the roadmap item: claim derivation and decision recompute get
faster *with identical outputs*, a golden-output test guarding correctness. This is
that test. A seeded corpus (:mod:`tests.spine_corpus`: several deployments, claims
re-derived through several versions, retest obligations, latent conditions pending,
fired and unobservable, evidence recorded against claims, approved workflows,
signed chain outcomes and recorded authority chains) is built with the clock held
and every UUID seeded; then derivation, the ripple traversal and the decision
recompute run over every deployment -- through the recompute writer, the backstop's
refresh and the refresh of a decision another writer left -- and every decision,
claim row, claim event, retest, latent condition, decision transition, the
decision-support payload, the ripple assessment and the assurance receipt are
compared with what the code before the optimization produced
(``tests/fixtures/spine_golden.json``, recorded from master a32f63a by
``tests/spine_measure.py``). Any change to any of them fails here.

Autoincrement ids are not compared (an id depends on every row an earlier test of
the session committed): each foreign key is published as the uuid or username of
the row it names, which the seeded corpus fixes.
"""

from __future__ import annotations

import difflib
import pathlib

import pytest

from tests import spine_corpus as sc

pytestmark = pytest.mark.django_db

GOLDEN = pathlib.Path(__file__).resolve().parent / "fixtures" / "spine_golden.json"


def test_spine_paths_publish_what_they_published(monkeypatch, tmp_path):
    clock = sc.Clock()
    sc.hold_still(monkeypatch, clock, sc.SeededUUIDs(), tmp_path / "keyring.json")
    corpus = sc.build_corpus(clock)

    produced = sc.canonical(sc.run_paths(corpus))

    expected = GOLDEN.read_text(encoding="utf-8")
    if produced != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True), produced.splitlines(keepends=True),
                "spine_golden.json (master)", "this tree", n=2,
            )
        )
        pytest.fail(f"a SPINE path published something different from master:\n{diff[:6000]}")
