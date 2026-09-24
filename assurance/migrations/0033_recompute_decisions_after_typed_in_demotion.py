from django.db import migrations


class Migration(migrations.Migration):
    """Marks the point after which stored decisions resting on chains are stale.

    0032 demoted every typed-in ``demonstrated`` row to ``attested``, and the rule
    now floors an approved workflow's attested ``held`` at NEEDS_MORE_EVIDENCE.
    Neither recomputes the STORED decision, which the receipt and the bundle read:
    a READY computed from typed-in chains before the upgrade would go on being
    reported after it, while decision-support computed the new answer live.

    The recompute is NOT done here. It needs the decision rule, which is live code
    over live models, and a migration that imports live models works only until a
    later migration changes one of them: a database that crosses this migration
    and that later one in the same ``migrate`` would meet the live code with a
    schema that does not have its columns yet. So this migration is an empty
    marker, and :func:`assurance.signals.recompute_decisions_after_demotion` -- a
    ``post_migrate`` receiver, which runs once the whole plan has applied and the
    schema is the one the live code expects -- does the recompute when, and only
    when, this migration was in the plan it just applied.
    """

    dependencies = [
        ("assurance", "0032_signed_chain_outcomes"),
    ]

    operations = []
