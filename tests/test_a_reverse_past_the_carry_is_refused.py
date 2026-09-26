"""A reverse past an irreversible migration is refused BEFORE anything is unapplied
(#105, round 3).

0037 and 0038 cannot be reversed, and said so: ``migrate assurance 0036`` raised
IrreversibleError. But Django checks reversibility one migration at a time as it
reaches each, and commits each unapply on its own -- so on a database at 0039 it
first unapplied 0039, dropping the decision stamp, the served-route notes, every
accepted severity and every outcome's route binding, committed that, and only then
refused at 0038. "Leaves the data intact" was false. The refusal now reads the whole
plan first (``assurance.signals.refuse_a_reverse_past_an_irreversible_step``).

Tested for real: the migrate command, run against a copy of this test database,
and the copy read afterwards.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from django.apps import apps
from django.db import connection
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.loader import MigrationLoader

from assurance import signals

pytestmark = pytest.mark.django_db

ROOT = Path(__file__).resolve().parent.parent

#: What 0039 adds, each of which a reverse of it drops.
ADDED_BY_0039 = {
    ("assurance_deployment", "decision_policy"),
    ("assurance_finding", "risk_accepted_severity"),
    ("assurance_workflowchainoutcome", "route_fingerprint"),
}


def _copy_of_this_database(tmp_path) -> Path:
    """This test database as migrated, copied: committed state, read through a
    connection of its own."""
    copy = tmp_path / "reverse.sqlite3"
    source = sqlite3.connect(connection.settings_dict["NAME"])
    target = sqlite3.connect(copy)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    return copy


def _migrate(database: Path, *args) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "config.settings",
        "DJANGO_DB_PATH": str(database),
        "DJANGO_SECRET_KEY": os.environ.get("DJANGO_SECRET_KEY", "reverse-test"),
        "DJANGO_DEBUG": "1",
    }
    return subprocess.run(
        [sys.executable, "-B", "manage.py", "migrate", "assurance", *args, "--no-input"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=600,
    )


def _state(database: Path) -> dict:
    db = sqlite3.connect(database)
    try:
        applied = {
            name for (name,) in db.execute("SELECT name FROM django_migrations WHERE app = 'assurance'")
        }
        columns = {
            (table, column)
            for table, column in ADDED_BY_0039
            for (column_name,) in db.execute(f"SELECT name FROM pragma_table_info('{table}')")
            if column_name == column
        }
        notes = db.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'assurance_servedroutenote'"
        ).fetchone()[0]
    finally:
        db.close()
    return {"applied": applied, "columns": columns, "served_route_notes": bool(notes)}


def test_a_migrate_back_past_the_carry_migrations_is_refused_with_nothing_unapplied(tmp_path):
    copy = _copy_of_this_database(tmp_path)
    before = _state(copy)
    assert "0039_bind_chain_outcomes_to_their_route" in before["applied"]
    assert before["columns"] == ADDED_BY_0039 and before["served_route_notes"]

    refused = _migrate(copy, "0036")

    assert refused.returncode != 0, refused.stdout
    assert "IrreversibleError" in refused.stderr and "refused before anything is unapplied" in refused.stderr
    assert _state(copy) == before, "a migrate that was refused unapplied something first"

    # A reverse that stops short of the irreversible step is not refused: only 0039.
    allowed = _migrate(copy, "0038")
    assert allowed.returncode == 0, allowed.stderr
    after = _state(copy)
    assert "0039_bind_chain_outcomes_to_their_route" not in after["applied"]
    assert after["columns"] == set() and not after["served_route_notes"]


def _plan(*steps):
    loader = MigrationLoader(None, ignore_no_migrations=True)
    return [(loader.get_migration("assurance", name), backwards) for name, backwards in steps]


def test_the_refusal_reads_the_whole_plan_and_only_refuses_an_irreversible_backwards_step():
    receiver = signals.refuse_a_reverse_past_an_irreversible_step
    assurance = apps.get_app_config("assurance")
    with pytest.raises(IrreversibleError, match="0038"):
        receiver(assurance, plan=_plan(("0039_bind_chain_outcomes_to_their_route", True),
                                       ("0038_latent_conditions_stay_watched", True)))
    receiver(assurance, plan=_plan(("0039_bind_chain_outcomes_to_their_route", True)))
    receiver(assurance, plan=_plan(("0037_carry_watches_and_legal_rulings", False),
                                   ("0038_latent_conditions_stay_watched", False)))
    # Read once, on this app's signal: another app's is the same plan.
    receiver(apps.get_app_config("auth"), plan=_plan(("0038_latent_conditions_stay_watched", True)))
