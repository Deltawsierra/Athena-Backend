"""SPINE's statement budget (Phase 5.5): each SPINE path issues exactly the number of SQL
statements its line in ``tests/spine_statement_budget.toml`` holds, over the seeded corpus.

Phase 5 item 3 (#179) cut what SPINE's paths issue -- ``recompute_decision`` from 56
statements to 30 on a deployment with a critical finding open, and from 130 to 29 on one
whose every finding is an accepted risk; ``refresh_stored_decisions`` by about half -- and
nothing held them there. An N+1 put back, or a reader that reads the component graph
again, changes no output: the golden test (``test_spine_paths_publish_what_they_published``)
passes, and the database-size test (``test_spine_queries_follow_their_own_deployment``)
compares a path with itself. This holds each path's count, per finding profile of the
corpus.

The margin is nought. A statement count over the seeded corpus is exact -- the clock is
held, every id is seeded and the keys are fixed (:mod:`tests.spine_corpus`) -- so any
difference is a real change in what a path does, and each is settled in the pull request
that makes it:

- a path that issues MORE statements than its line fails until the line is raised, and a
  raised line says why on the same line (``approved = "..."``), so the diff shows the rise
  and its reason together. :func:`test_a_raised_line_carries_a_reason_of_its_own` refuses
  a rise with no reason of its own, against the budget as the change found it;
- a path that issues FEWER fails until the line is lowered, so the budget never keeps
  headroom that a later rise could spend unseen.

What is counted is every statement Django sends through ``connection.execute_wrapper``
(savepoints included) on the path's second call: the first does what an earlier write
left, the second is the path's own cost, and a third must count the same as the second or
the count is not deterministic and no budget could hold it. The paths are the ones Phase 5
item 3 measured (docs/performance/spine-queries.md), each called as the routes and the
backstop call it.
"""

from __future__ import annotations

import functools
import os
import pathlib
import re
import subprocess
import tomllib
from collections import Counter

import pytest

from tests import spine_corpus as sc

BUDGET = pathlib.Path(__file__).resolve().parent / "spine_statement_budget.toml"
ROOT = BUDGET.parent.parent
#: The budget file as git names it, from the root of the checkout.
BUDGET_IN_GIT = "tests/spine_statement_budget.toml"

#: The SPINE paths the budget holds, in the order each deployment runs them.
PATHS = (
    "derive_claims",
    "assess_ripple",
    "recompute_decision",
    "refresh_stored_decisions",
    # The refresh of a decision another writer -- a rollout's release before -- left: the
    # claim, the watches read, the recompute that brings it current.
    "refresh_of_another_writers_decision",
    "decision_support",
)

#: The corpus's finding profiles (``spine_corpus._PROFILES``), by the rank that builds
#: each, with what makes each one that profile: the worst severity it opens with, and its
#: kind. A corpus whose profiles move fails the well-formed test below until the names --
#: and the budget's lines -- move with them.
PROFILES = {
    "critical-open": ("critical", "mixed"),
    "high-open": ("high", "mixed"),
    "medium-and-below": ("medium", "mixed"),
    "all-closed": ("critical", "closed"),
    "all-accepted": ("high", "accepted"),
    "no-findings": (None, "none"),
}

#: The longest reason a line may carry: one line, read in a diff.
REASON_MAX = 200

#: What a line may hold.
FIELDS = frozenset({"statements", "approved"})


def _read(text: str, where: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        pytest.fail(f"{where} is not TOML: {exc}")


def _budget() -> dict:
    return _read(BUDGET.read_text(encoding="utf-8"), BUDGET_IN_GIT)


def _is_reason(value) -> bool:
    """One line saying why: text, not blank, no line break, at most :data:`REASON_MAX`."""
    return (
        isinstance(value, str)
        and value.strip() != ""
        and "\n" not in value
        and "\r" not in value
        and len(value) <= REASON_MAX
    )


def _count(entry):
    """A line's statement count, or ``None`` where the line holds none that reads as one
    (the well-formed test names it)."""
    if not isinstance(entry, dict):
        return None
    statements = entry.get("statements")
    return statements if type(statements) is int and statements >= 0 else None


def _line(path: str, profile: str, statements: int, reason: str | None = None) -> str:
    """A budget line as it is written in the file."""
    tail = "" if reason is None else f', approved = "{reason}"'
    return f"{path}.{profile} = {{ statements = {statements}{tail} }}"


# ------------------------------------------------------------------ the file itself


def test_the_budget_has_one_well_formed_line_per_path_and_profile():
    assert [(severities[0] if severities else None, kind) for severities, kind in sc._PROFILES] == list(
        PROFILES.values()
    ), "the corpus's finding profiles moved: rename PROFILES here, and the budget's lines with them"

    budget = _budget()
    wrong = []
    for name in sorted(set(budget) - set(PATHS)):
        wrong.append(f"{name}: no SPINE path of that name is measured; take its lines out")
    for path in PATHS:
        lines = budget.get(path)
        if not isinstance(lines, dict):
            wrong.append(f"{path}: no lines; add one per profile ({', '.join(PROFILES)})")
            continue
        for profile in sorted(set(lines) - set(PROFILES)):
            wrong.append(f"{path}.{profile}: the corpus builds no profile of that name; take the line out")
        for profile in PROFILES:
            if profile not in lines:
                wrong.append(f"{path}.{profile}: no line; add one with the count the budget test reports")
                continue
            entry = lines[profile]
            if not isinstance(entry, dict):
                wrong.append(f"{path}.{profile}: not a line of the form {_line(path, profile, 0)}")
                continue
            for field in sorted(set(entry) - FIELDS):
                wrong.append(f"{path}.{profile}: {field!r} is not a field of a line (only {sorted(FIELDS)})")
            if _count(entry) is None:
                wrong.append(f"{path}.{profile}: statements must be a whole number, not {entry.get('statements')!r}")
            if "approved" in entry and not _is_reason(entry["approved"]):
                wrong.append(
                    f"{path}.{profile}: approved must be one line, at most {REASON_MAX} characters, saying why "
                    f"the path issues more -- not {entry['approved']!r}"
                )
    assert not wrong, f"{BUDGET_IN_GIT} is not as the budget test reads it:\n" + "\n".join(wrong)


# --------------------------------------------------------------- a rise needs a reason


def _git(*args: str) -> str:
    where = (
        "set SPINE_BUDGET_BASE to the commit this change starts from (CI sets HEAD^1, the base side "
        "of the pull request's merge commit, and checks out two commits deep)"
    )
    try:
        done = subprocess.run(
            ["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8", check=False
        )
    except OSError as exc:
        pytest.fail(f"cannot run git to read the budget this change started from ({exc}); {where}")
    if done.returncode != 0:
        pytest.fail(f"git {' '.join(args)} failed ({done.stderr.strip()}); {where}")
    return done.stdout


def _base() -> tuple[str, dict]:
    """The budget as the change under test found it, and the commit it was read from:
    the file at ``SPINE_BUDGET_BASE`` if that is set, else where HEAD left origin/master.
    Empty where that commit has no budget file yet."""
    named = os.environ.get("SPINE_BUDGET_BASE", "").strip()
    if named:
        commit = _git("rev-parse", "--verify", f"{named}^{{commit}}").strip()
    else:
        commit = _git("merge-base", "HEAD", "origin/master").strip()
    if not _git("ls-tree", "--name-only", commit, "--", BUDGET_IN_GIT).strip():
        return commit, {}
    return commit, _read(_git("show", f"{commit}:{BUDGET_IN_GIT}"), f"{BUDGET_IN_GIT} at {commit}")


def test_a_raised_line_carries_a_reason_of_its_own():
    """A line whose count is higher than the budget the change found says why, on the same
    line -- with a reason of its own: none, a blank one, or the reason the line already
    carried (a rise someone else explained, spent again) is refused."""
    commit, base = _base()
    unexplained = []
    for path, lines in sorted(_budget().items()):
        if not isinstance(lines, dict):
            continue  # the well-formed test names it
        before_lines = base.get(path) if isinstance(base.get(path), dict) else {}
        for profile, entry in sorted(lines.items()):
            now, was = _count(entry), _count(before_lines.get(profile))
            if now is None or was is None or now <= was:
                continue
            reason = entry.get("approved")
            before = before_lines[profile].get("approved")
            if _is_reason(reason) and reason != before:
                continue
            if reason is None:
                why = "no reason"
            elif reason == before:
                why = "the reason it already carried"
            else:
                why = f"a reason that is not one line of at most {REASON_MAX} characters ({reason!r})"
            unexplained.append(
                f"{path}.{profile}: raised from {was} to {now} statements with {why}. Say on the line why "
                f"the path now issues more:\n    {_line(path, profile, now, '<one line: why>')}"
            )
    assert not unexplained, (
        f"a raised line of {BUDGET_IN_GIT} must say why (budget at {commit[:12]} -> this tree):\n"
        + "\n".join(unexplained)
    )


# ------------------------------------------------------------------- the measurement


def _paths(clock) -> dict:
    from assurance.claims import derive_claims
    from assurance.decision import current_decision, decision_support, recompute_decision, refresh_stored_decisions
    from assurance.models import Deployment
    from assurance.ripple import assess_ripple

    def derive(pk):
        return derive_claims(Deployment.objects.get(pk=pk), now=clock.now())

    def ripple(pk):
        # With the ripple route's prefetch.
        return assess_ripple(
            Deployment.objects.prefetch_related("assets__provider__assertions", "findings__asset").get(pk=pk)
        )

    def recompute(pk):
        return recompute_decision(Deployment.objects.get(pk=pk))

    def backstop(pk):
        return refresh_stored_decisions([pk])

    def another_writers(pk):
        Deployment.objects.filter(pk=pk).update(decision_policy="")
        return refresh_stored_decisions([pk])

    def support(pk):
        # The published read: the stored decision brought current, then its support.
        reading = Deployment.objects.get(pk=pk)
        current_decision(reading)
        return decision_support(reading)

    return dict(zip(PATHS, (derive, ripple, recompute, backstop, another_writers, support), strict=True))


def _shape(sql: str) -> str:
    """A statement as two are compared: a savepoint's name carries a counter."""
    return re.sub(r'"s\d+_x\d+"', '"s_x"', sql)


_SAVEPOINTS = ("SAVEPOINT", "RELEASE", "ROLLBACK")


def _most_repeated(statements, *, top: int = 2) -> str:
    """The statements a path issued most often, savepoints aside -- where an N+1 shows --
    each with its column list cut, so the table and the condition read."""
    reads = Counter(_shape(sql) for sql, _ in statements if not sql.lstrip().upper().startswith(_SAVEPOINTS))
    repeated = [
        f"{n} x " + re.sub(r"^SELECT .+? FROM ", "SELECT ... FROM ", sql, flags=re.S)[:160]
        for sql, n in reads.most_common(top)
        if n > 1
    ]
    return "; ".join(repeated) or "none repeated"


def statements_per_path(monkeypatch, tmp_path) -> tuple[dict, list[str]]:
    """``{(path, profile): (count, statements)}`` over the seeded corpus, and each
    ``path.profile`` whose count differed between two identical calls."""
    clock = sc.Clock()
    sc.hold_still(monkeypatch, clock, sc.SeededUUIDs(), tmp_path / "keyring.json")
    corpus = sc.build_corpus(clock, deployments=len(PROFILES))
    runs = _paths(clock)
    counted, unsteady = {}, []
    for profile, dep in zip(PROFILES, corpus.deployments, strict=True):
        for path, run in runs.items():
            call = functools.partial(run, dep.pk)
            call()  # what an earlier write left is done here; the next calls are the path's own cost
            first, second = sc.measure(call), sc.measure(call)
            if len(first.statements) != len(second.statements):
                unsteady.append(
                    f"{path}.{profile}: {len(first.statements)} statements, then {len(second.statements)} "
                    "on the same call"
                )
            counted[(path, profile)] = (len(second.statements), second.statements)
    return counted, unsteady


@pytest.mark.django_db
def test_each_spine_path_issues_exactly_its_budgeted_statements(monkeypatch, tmp_path):
    budget = _budget()
    counted, unsteady = statements_per_path(monkeypatch, tmp_path)
    assert not unsteady, (
        "a SPINE path's statement count is not deterministic over the seeded corpus, so no budget can hold "
        "it; find what differs between two identical calls:\n" + "\n".join(unsteady)
    )

    off = []
    for (path, profile), (count, statements) in counted.items():
        lines = budget.get(path) if isinstance(budget.get(path), dict) else {}
        entry = lines.get(profile)
        held = _count(entry)
        if held is None:
            off.append(
                f"{path}.{profile}: {count} statements, and no line holds it. Add:\n    {_line(path, profile, count)}"
            )
        elif count > held:
            off.append(
                f"{path}.{profile}: {count} statements, budget {held} -- {count - held} MORE. "
                f"Its most repeated statements: {_most_repeated(statements)}.\n"
                "    If the rise is meant, raise the line and say on it why the path now issues more:\n"
                f"    {_line(path, profile, count, '<one line: why>')}\n"
                "    If not, find the statements the change added."
            )
        elif count < held:
            kept = entry.get("approved")
            off.append(
                f"{path}.{profile}: {count} statements, budget {held} -- {held - count} FEWER. "
                "Lower the line, so the budget keeps no headroom a later rise could spend unseen:\n"
                f"    {_line(path, profile, count)}"
                + (
                    ""
                    if kept is None
                    else f'\n    (keep its reason, approved = "{kept}", only if the rise it explains still stands)'
                )
            )
    assert not off, (
        f"SPINE's statement budget ({BUDGET_IN_GIT}; README, \"SPINE's statement budget\") does not hold over "
        "the seeded corpus:\n" + "\n".join(off)
    )
