"""Round 3 (#333 with #105): ``migrate assurance 0043`` must complete.

Rolling back past 0044 (the claim's evidence audit columns) unapplied both
migrations and then crashed in a ``post_migrate`` receiver: the #105 hook that
puts back the holds a fired condition keeps
(``signals.carry_what_a_release_that_did_not_carry_left`` ->
``latent._lifted_holds``) loaded claims through the CURRENT model, whose
columns the rolled-back schema no longer has -- ``no such column:
assurance_assuranceclaim.evidence_verdict`` (round-3 ``g_migrations.out``).
The receivers' guard asked only whether the decision stamp was migrated.

Now every receiver of this app's ``post_migrate`` asks whether the schema is at
the code's models -- every concrete column of every model it can read -- and
does nothing, reading nothing, on a schema behind them.
"""

from __future__ import annotations

import pytest
from django.core.management.sql import emit_post_migrate_signal
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.test.utils import CaptureQueriesContext

from assurance import signals

pytestmark = pytest.mark.django_db


def _state_apps(target):
    loader = MigrationLoader(connection)
    return loader.project_state(("assurance", target)).apps


#: The assurance migrations above 0043, newest first: the order a rollback unapplies them.
_ABOVE_0043 = (
    "0046_claim_audit_weighing",
    "0045_claim_evidence_invalidated_by_username",
    "0044_claim_evidence_audit",
)


def _plan_back_to(target):
    """The backwards plan ``migrate assurance <target>`` runs from head."""
    loader = MigrationLoader(connection)
    above = _ABOVE_0043[: _ABOVE_0043.index(target)] if target in _ABOVE_0043 else _ABOVE_0043
    return [(loader.get_migration("assurance", name), True) for name in above]


@pytest.mark.parametrize(
    "target",
    [
        # Below the models and columns the audit added.
        "0043_dispatch_markers",
        # The claim's audit columns there; the evidence attribution column and the weighing table not.
        "0044_claim_evidence_audit",
    ],
)
def test_a_rollback_below_the_claims_audit_columns_runs_no_receiver_that_reads_a_claim(target):
    apps = _state_apps(target)
    with CaptureQueriesContext(connection) as queries:
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default", apps=apps, plan=_plan_back_to(target))
    read = [q["sql"] for q in queries.captured_queries if "assurance_" in q["sql"]]
    assert read == [], read[:3]


def test_the_schema_guard_reads_the_models_columns_not_only_the_decision_stamp():
    from django.apps import apps as live_apps

    config = live_apps.get_app_config("assurance")
    assert signals._the_decision_columns_are_migrated(config, "default", _state_apps("0043_dispatch_markers")) is False
    head = MigrationLoader(connection).graph.leaf_nodes("assurance")[0]
    assert signals._the_decision_columns_are_migrated(config, "default", _state_apps(head[1])) is True
    # Every model there and one column not: a column the code's model has is a column it reads.
    state = MigrationLoader(connection).project_state(head)
    state.remove_field("assurance", "assuranceclaim", "evidence_verdict")
    assert signals._the_decision_columns_are_migrated(config, "default", state.apps) is False
    # A flush hands over no state: the database is asked, and here it is at head.
    assert signals._the_decision_columns_are_migrated(config, "default", None) is True
